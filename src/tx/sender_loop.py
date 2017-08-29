#!/usr/bin/env python3.6
# -*- coding: utf-8 -*-

"""
Copyright (C) 2013-2017  Markus Ottela

This file is part of TFC.

TFC is free software: you can redistribute it and/or modify it under the terms
of the GNU General Public License as published by the Free Software Foundation,
either version 3 of the License, or (at your option) any later version.

TFC is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with TFC. If not, see <http://www.gnu.org/licenses/>.
"""

import time
import typing

from typing import Dict, List, Tuple

from src.common.misc    import ignored
from src.common.statics import *

from src.tx.packet          import send_packet, transmit
from src.tx.traffic_masking import ConstantTime

if typing.TYPE_CHECKING:
    from multiprocessing        import Queue
    from src.common.db_keys     import KeyList
    from src.common.db_settings import Settings
    from src.common.gateway     import Gateway
    from src.common.db_settings import Settings


def sender_loop(queues:   Dict[bytes, 'Queue'],
                settings: 'Settings',
                gateway:  'Gateway',
                key_list: 'KeyList',
                unittest: bool = False) -> None:
    """Output packets from queues based on queue priority.

    Sender loop loads assembly packets from a set of queues. As
    Python's multiprocessing lacks priority queues, several queues are
    prioritized based on their status. Whether or not traffic masking
    is enabled, files are only transmitted when no messages are being
    output. This is because file transmission is usually very slow and
    user might need to send messages in the meantime. When traffic
    masking is disabled, commands take highest priority as they are not
    output all the time. When traffic masking is enabled, commands are
    output between each output message packet. This allows commands to
    take effect as soon as possible but slows down message/file
    delivery by half. Each contact in window is cycled in order.

    Making changes to recipient list during use is prevented to protect
    user from accidentally revealing use of TFC. When traffic masking
    is enabled, if no packets are available in either m_queue or f_queue,
    a noise assembly packet is loaded from np_queue. If no command packet
    is available in c_queue, a noise command packet is loaded from
    nc_queue. TFC does it's best to hide the loading times and encryption
    duration by using constant time context manager with CSPRNG spawned
    jitter, constant time queue status lookup, and constant time XSalsa20
    cipher. However, since TFC is written with in a high-level language,
    it is impossible to guarantee TxM never reveals it's user-operation
    schedule to NH.
    """
    m_queue  = queues[MESSAGE_PACKET_QUEUE]
    f_queue  = queues[FILE_PACKET_QUEUE]
    c_queue  = queues[COMMAND_PACKET_QUEUE]
    n_queue  = queues[NH_PACKET_QUEUE]
    l_queue  = queues[LOG_PACKET_QUEUE]
    km_queue = queues[KEY_MANAGEMENT_QUEUE]
    np_queue = queues[NOISE_PACKET_QUEUE]
    nc_queue = queues[NOISE_COMMAND_QUEUE]
    ws_queue = queues[WINDOW_SELECT_QUEUE]

    m_buffer = dict()  # type: Dict[str, List[Tuple[bytes, Settings, str, str, bool]]]
    f_buffer = dict()  # type: Dict[str, List[Tuple[bytes, Settings, str, str, bool]]]

    if settings.session_traffic_masking:

        while ws_queue.qsize() == 0:
            time.sleep(0.01)

        window, log_messages = ws_queue.get()

        while True:
            with ignored(EOFError, KeyboardInterrupt):
                with ConstantTime(settings, length=TRAFFIC_MASKING_QUEUE_CHECK_DELAY):
                    queue = [[m_queue, m_queue], [f_queue, np_queue]][m_queue.qsize()==0][f_queue.qsize()==0]

                    packet, lm, log_as_ph = queue.get()

                    if lm is not None:  # Ignores None sent by noise_packet_loop that does not alter log setting
                        log_messages = lm

                for c in window:

                    with ConstantTime(settings, d_type=TRAFFIC_MASKING):
                        send_packet(key_list, gateway, l_queue, packet, settings, c.rx_account, c.tx_account, log_messages, log_as_ph)

                    with ConstantTime(settings, d_type=TRAFFIC_MASKING):
                        queue       = [c_queue, nc_queue][c_queue.qsize()==0]
                        command, lm = queue.get()

                        if lm is not None:  # Log setting is only updated with 'logging' command
                            log_messages = lm

                        send_packet(key_list, gateway, l_queue, command, settings)

                        if n_queue.qsize() != 0:
                            packet, delay, settings = n_queue.get()
                            transmit(packet, settings, gateway, delay)
                            if packet[1:] == UNENCRYPTED_EXIT_COMMAND:
                                queues[EXIT_QUEUE].put(EXIT)
                            elif packet[1:] == UNENCRYPTED_WIPE_COMMAND:
                                queues[EXIT_QUEUE].put(WIPE)

                if unittest:
                    break

    else:
        while True:
            try:
                if km_queue.qsize() != 0:
                    key_list.manage(*km_queue.get())
                    continue

                # Commands to RxM
                if c_queue.qsize() != 0:
                    if key_list.has_local_key():
                        send_packet(key_list, gateway, l_queue, *c_queue.get())
                        continue

                # Commands/exported files to NH
                if n_queue.qsize() != 0:
                    packet, delay, settings = n_queue.get()
                    transmit(packet, settings, gateway, delay)

                    if packet[1:] == UNENCRYPTED_EXIT_COMMAND:
                        queues[EXIT_QUEUE].put(EXIT)
                    elif packet[1:] == UNENCRYPTED_WIPE_COMMAND:
                        queues[EXIT_QUEUE].put(WIPE)
                    continue

                # Buffered messages
                for rx_account in m_buffer:
                    if key_list.has_keyset(rx_account) and m_buffer[rx_account]:
                        send_packet(key_list, gateway, l_queue, *m_buffer[rx_account].pop(0)[:-1])  # Strip window UID as it's only used to cancel packets
                        continue

                # New messages
                if m_queue.qsize() != 0:
                    q_data     = m_queue.get()
                    rx_account = q_data[2]

                    if key_list.has_keyset(rx_account):
                        send_packet(key_list, gateway, l_queue, *q_data[:-1])
                    else:
                        m_buffer.setdefault(rx_account, []).append(q_data)
                    continue

                # Buffered files
                for rx_account in m_buffer:
                    if key_list.has_keyset(rx_account) and f_buffer[rx_account]:
                        send_packet(key_list, gateway, l_queue, *f_buffer[rx_account].pop(0)[:-1])
                        continue

                # New files
                if f_queue.qsize() != 0:
                    q_data     = f_queue.get()
                    rx_account = q_data[2]

                    if key_list.has_keyset(rx_account):
                        send_packet(key_list, gateway, l_queue, *q_data[:-1])
                    else:
                        f_buffer.setdefault(rx_account, []).append(q_data)

                if unittest and queues[UNITTEST_QUEUE].qsize() != 0:
                    break

                time.sleep(0.01)

            except (EOFError, KeyboardInterrupt):
                pass
