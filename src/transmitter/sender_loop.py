#!/usr/bin/env python3.7
# -*- coding: utf-8 -*-

"""
TFC - Onion-routed, endpoint secure messaging system
Copyright (C) 2013-2019  Markus Ottela

This file is part of TFC.

TFC is free software: you can redistribute it and/or modify it under the terms
of the GNU General Public License as published by the Free Software Foundation,
either version 3 of the License, or (at your option) any later version.

TFC is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with TFC. If not, see <https://www.gnu.org/licenses/>.
"""

import time
import typing

from typing import Any, Dict, List, Optional, Tuple

from src.common.misc    import ignored
from src.common.statics import (COMMAND_PACKET_QUEUE, DATAGRAM_HEADER_LENGTH, EXIT, EXIT_QUEUE, KEY_MANAGEMENT_QUEUE,
                                LOG_PACKET_QUEUE, MESSAGE_PACKET_QUEUE, RELAY_PACKET_QUEUE, SENDER_MODE_QUEUE,
                                TM_COMMAND_PACKET_QUEUE, TM_FILE_PACKET_QUEUE, TM_MESSAGE_PACKET_QUEUE,
                                TM_NOISE_COMMAND_QUEUE, TM_NOISE_PACKET_QUEUE, TRAFFIC_MASKING,
                                TRAFFIC_MASKING_QUEUE_CHECK_DELAY, UNENCRYPTED_EXIT_COMMAND, UNENCRYPTED_WIPE_COMMAND,
                                WINDOW_SELECT_QUEUE, WIPE)

from src.transmitter.packet          import send_packet
from src.transmitter.traffic_masking import HideRunTime

if typing.TYPE_CHECKING:
    from multiprocessing        import Queue
    from src.common.db_keys     import KeyList
    from src.common.db_settings import Settings
    from src.common.gateway     import Gateway
    QueueDict      = Dict[bytes, Queue[Any]]
    Message_buffer = Dict[bytes, List[Tuple[bytes, bytes, bool, bool, bytes]]]


def sender_loop(queues:    'QueueDict',
                settings:  'Settings',
                gateway:   'Gateway',
                key_list:  'KeyList',
                unit_test: bool = False
                ) -> None:
    """Output packets from queues based on queue priority.

    Depending on traffic masking setting adjusted by the user, enable
    either traffic masking or standard sender loop for packet output.
    """
    m_buffer = dict()  # type: Message_buffer

    while True:
        if settings.traffic_masking:
            settings = traffic_masking_loop(queues, settings, gateway, key_list)
        else:
            settings, m_buffer = standard_sender_loop(queues, gateway, key_list, m_buffer)
        if unit_test:
            break


def traffic_masking_loop(queues:   'QueueDict',
                         settings: 'Settings',
                         gateway:  'Gateway',
                         key_list: 'KeyList',
                         ) -> 'Settings':
    """Run Transmitter Program in traffic masking mode.

    The traffic masking loop loads assembly packets from a set of queues.
    As Python's multiprocessing lacks priority queues, several queues are
    prioritized based on their status.

    Files are only transmitted when messages are not being output: This
    is because file transmission is usually very slow and the user might
    need to send messages in the meantime. Command datagrams are output
    from Source Computer between each message datagram. The frequency in
    output allows commands to take effect as soon as possible but this
    unfortunately slows down message/file delivery by half. Each contact
    in the window is cycled in order.

    When this loop is active, making changes to the recipient list is
    prevented to protect the user from accidentally revealing the use of
    TFC.

    The traffic is masked the following way: If both m_queue and f_queue
    are empty, a noise assembly packet is loaded from np_queue. If no
    command packet is available in c_queue, a noise command packet is
    loaded from nc_queue. Both noise queues are filled by independent
    processes that ensure both noise queues always have packets to
    output.

    TFC does its best to hide the assembly packet loading times and
    encryption duration by using constant time context manager with
    CSPRNG spawned jitter, constant time queue status lookup and constant
    time XChaCha20 cipher. However, since TFC is written in a high-level
    language, it is impossible to guarantee Source Computer never
    reveals to Networked Computer when the user operates the Source
    Computer.
    """
    ws_queue  = queues[WINDOW_SELECT_QUEUE]
    m_queue   = queues[TM_MESSAGE_PACKET_QUEUE]
    f_queue   = queues[TM_FILE_PACKET_QUEUE]
    c_queue   = queues[TM_COMMAND_PACKET_QUEUE]
    np_queue  = queues[TM_NOISE_PACKET_QUEUE]
    nc_queue  = queues[TM_NOISE_COMMAND_QUEUE]
    rp_queue  = queues[RELAY_PACKET_QUEUE]
    log_queue = queues[LOG_PACKET_QUEUE]
    sm_queue  = queues[SENDER_MODE_QUEUE]

    while True:
        with ignored(EOFError, KeyboardInterrupt):
            while ws_queue.qsize() == 0:
                time.sleep(0.01)
            window_contacts = ws_queue.get()

            # Window selection command to Receiver Program.
            while c_queue.qsize() == 0:
                time.sleep(0.01)
            send_packet(key_list, gateway, log_queue, c_queue.get())
            break

    while True:
        with ignored(EOFError, KeyboardInterrupt):
            # Load message/file assembly packet.
            with HideRunTime(settings, duration=TRAFFIC_MASKING_QUEUE_CHECK_DELAY):

                # Choosing element from list is constant time.
                #
                #         First queue we evaluate: if m_queue has data                  Second to evaluate. If m_queue
                #         in it, False is evaluated as 0, and we load                   has no data but f_queue has, the
                #         the first nested list. At that point we load                  False is evaluated as 0 meaning
                #         from m_queue regardless of f_queue state.                     f_queue (True as 1 and np_queue)
                #                                                 |                     |
                #                                                 v                     v
                queue = [[m_queue, m_queue], [f_queue, np_queue]][m_queue.qsize() == 0][f_queue.qsize() == 0]

                # Regardless of queue, each .get() returns a tuple with identical
                # amount of data: 256 bytes long bytestring and two booleans.
                assembly_packet, log_messages, log_as_ph = queue.get()  # type: bytes, bool, bool

            for c in window_contacts:
                # Message/file assembly packet to window contact.
                with HideRunTime(settings, delay_type=TRAFFIC_MASKING):
                    send_packet(key_list, gateway, log_queue, assembly_packet, c.onion_pub_key, log_messages)

                # Send a command between each assembly packet for each contact.
                with HideRunTime(settings, delay_type=TRAFFIC_MASKING):

                    # Choosing element from list is constant time.
                    queue = [c_queue, nc_queue][c_queue.qsize() == 0]

                    # Each loaded command and noise command is a 256 long bytestring.
                    command = queue.get()  # type: bytes

                    send_packet(key_list, gateway, log_queue, command)

                    # The two queues below are empty until the user is willing to reveal to
                    # Networked Computer they are either disabling Traffic masking or exiting
                    # TFC. Until that happens, queue status check takes constant time.

                    # Check for unencrypted commands that close TFC.
                    if rp_queue.qsize() != 0:
                        packet  = rp_queue.get()
                        command = packet[DATAGRAM_HEADER_LENGTH:]
                        if command in [UNENCRYPTED_EXIT_COMMAND, UNENCRYPTED_WIPE_COMMAND]:
                            gateway.write(packet)
                            time.sleep(gateway.settings.local_testing_mode * 0.1)
                            time.sleep(gateway.settings.data_diode_sockets * 1.5)
                            signal = WIPE if command == UNENCRYPTED_WIPE_COMMAND else EXIT
                            queues[EXIT_QUEUE].put(signal)

            # If traffic masking has been disabled, wait until queued messages are sent before returning.
            if sm_queue.qsize() != 0 and all(q.qsize() == 0 for q in (m_queue, f_queue, c_queue)):
                settings = sm_queue.get()
                return settings


def standard_sender_loop(queues:   'QueueDict',
                         gateway:  'Gateway',
                         key_list: 'KeyList',
                         m_buffer: Optional['Message_buffer'] = None
                         ) -> Tuple['Settings', 'Message_buffer']:
    """Run Transmitter program in standard send mode.

    The standard sender loop loads assembly packets from a set of queues.
    As Python's multiprocessing lacks priority queues, several queues are
    prioritized based on their status:

    KEY_MANAGEMENT_QUEUE has the highest priority. This is to ensure the
    no queued message/command is encrypted with expired keyset.

    COMMAND_PACKET_QUEUE has the second highest priority, to ensure
    commands are issued swiftly to Receiver program. Some commands like
    screen clearing might need to be issued quickly.

    RELAY_PACKET_QUEUE has third highest priority. These are still
    commands but since Relay Program does not handle sensitive data,
    issuing commands to that devices does not take priority.

    Buffered messages have fourth highest priority. This ensures that if
    for whatever reason the keyset is removed, buffered messages do not
    get lost. Packets are loaded from the buffer in FIFO basis ensuring
    packets arrive to the recipient in order.

    MESSAGE_PACKET_QUEUE has fifth highest priority. Any buffered
    messages need to arrive earlier, thus new messages must be
    prioritized after the buffered ones.

    SENDER_MODE_QUEUE has sixth highest priority. This prevents outgoing
    packets from being left in the queues used by this loop. This queue
    returns up-to-date settings object for `sender_loop` parent loop,
    that in turn uses it to start `traffic_masking_loop`.

    Along with settings, this function returns the m_buffer status so that
    assembly packets that could not have been sent due to missing key
    can be output later, if the user resumes to standard_sender_loop and
    adds new keys for the contact.
    """
    km_queue  = queues[KEY_MANAGEMENT_QUEUE]
    c_queue   = queues[COMMAND_PACKET_QUEUE]
    rp_queue  = queues[RELAY_PACKET_QUEUE]
    m_queue   = queues[MESSAGE_PACKET_QUEUE]
    sm_queue  = queues[SENDER_MODE_QUEUE]
    log_queue = queues[LOG_PACKET_QUEUE]

    if m_buffer is None:
        m_buffer = dict()

    while True:
        with ignored(EOFError, KeyboardInterrupt):
            if km_queue.qsize() != 0:
                key_list.manage(*km_queue.get())
                continue

            # Commands to Receiver
            if c_queue.qsize() != 0:
                if key_list.has_local_keyset():
                    send_packet(key_list, gateway, log_queue, c_queue.get())
                continue

            # Commands/files to Networked Computer
            if rp_queue.qsize() != 0:
                packet = rp_queue.get()
                gateway.write(packet)

                command = packet[DATAGRAM_HEADER_LENGTH:]
                if command in [UNENCRYPTED_EXIT_COMMAND, UNENCRYPTED_WIPE_COMMAND]:
                    time.sleep(gateway.settings.local_testing_mode * 0.1)
                    time.sleep(gateway.settings.data_diode_sockets * 1.5)
                    signal = WIPE if command == UNENCRYPTED_WIPE_COMMAND else EXIT
                    queues[EXIT_QUEUE].put(signal)
                continue

            # Buffered messages
            for onion_pub_key in m_buffer:
                if key_list.has_keyset(onion_pub_key) and m_buffer[onion_pub_key]:
                    send_packet(key_list, gateway, log_queue, *m_buffer[onion_pub_key].pop(0)[:-1])
                    continue

            # New messages
            if m_queue.qsize() != 0:
                queue_data    = m_queue.get()  # type: Tuple[bytes, bytes, bool, bool, bytes]
                onion_pub_key = queue_data[1]

                if key_list.has_keyset(onion_pub_key):
                    send_packet(key_list, gateway, log_queue, *queue_data[:-1])
                else:
                    m_buffer.setdefault(onion_pub_key, []).append(queue_data)
                continue

            # If traffic masking has been enabled, switch send mode when all queues are empty.
            if sm_queue.qsize() != 0 and all(q.qsize() == 0 for q in (km_queue, c_queue, rp_queue, m_queue)):
                settings = sm_queue.get()
                return settings, m_buffer

            time.sleep(0.01)
