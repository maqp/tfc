#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
TFC - Onion-routed, endpoint secure messaging system
Copyright (C) 2013-2026  Markus Ottela

This file is part of TFC.
TFC is free software: you can redistribute it and/or modify it under the terms
of the GNU General Public License as published by the Free Software Foundation,
either version 3 of the License, or (at your option) any later version. TFC is
distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without
even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
See the GNU General Public License for more details. You should have received a
copy of the GNU General Public License along with TFC. If not, see
<https://www.gnu.org/licenses/>.
"""

import random
import threading
import time

from typing import Any, Optional as O, TYPE_CHECKING

from src.common.exceptions import ignored, SoftError
from src.common.replay import resend_cached_packets, should_cache_gateway_packets
from src.common.statics import CTDelayType, Delay
from src.common.types_custom import FloatTMDelay
from src.transmitter.sender.shared import monitor_proxy, send_message, send_command
from src.transmitter.sender.sender_normal import process_key_mgmt_command

if TYPE_CHECKING:
    from src.common.entities.contact import Contact
    from src.common.gateway import Gateway
    from src.common.queues import TxQueue
    from src.database.db_keys import KeyStore
    from src.database.db_local_key import LocalKeyDB
    from src.database.db_settings import Settings


def traffic_masking_sender(queues       : 'TxQueue',
                           settings     : 'Settings',
                           gateway      : 'Gateway',
                           key_store    : 'KeyStore',
                           local_key_db : 'LocalKeyDB',
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
    ws_queue  = queues.tm_recipient_list
    m_queue   = queues.tm_message_packet
    f_queue   = queues.tm_file_packet
    c_queue   = queues.tm_command_packet
    np_queue  = queues.tm_noise_packet
    nc_queue  = queues.tm_noise_command
    rp_queue  = queues.relay_packet
    rs_queue  = queues.resend_packet_numbers
    log_queue = queues.log_packet
    sm_queue  = queues.sender_mode
    su_queue  = queues.sender_setting_update

    while True:
        with ignored(EOFError, KeyboardInterrupt, SoftError):
            while su_queue.qsize():
                key, value = su_queue.get()
                settings.set_setting_value(key, value)

            process_key_mgmt_command(queues, key_store, local_key_db)

            cache_packet = should_cache_gateway_packets(settings.require_resends,
                                                        settings.autoreplay_times,
                                                        settings.autoreplay_loop)

            while ws_queue.qsize() == 0:
                time.sleep(0.01)
            window_contacts: list['Contact'] = ws_queue.get()

            # Window selection command to Receiver Program.
            while c_queue.qsize() == 0:
                time.sleep(0.01)
            send_command(local_key_db,
                         gateway,
                         c_queue.get(),
                         settings.autoreplay_times,
                         cache_packet=cache_packet)
            break

    while True:
        with ignored(EOFError, KeyboardInterrupt, SoftError):
            while su_queue.qsize():
                key, value = su_queue.get()
                settings.set_setting_value(key, value)

            process_key_mgmt_command(queues, key_store, local_key_db)

            cache_packet = should_cache_gateway_packets(settings.require_resends,
                                                        settings.autoreplay_times,
                                                        settings.autoreplay_loop)

            if rs_queue.qsize():
                resend_cached_packets(gateway, rs_queue.get())
                continue

            # Load message/file assembly packet.
            with HideRunTime(settings, duration=FloatTMDelay(Delay.TRAFFIC_MASKING_QUEUE_CHECK_DELAY.value)):

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
                assembly_packet, log_messages, log_as_ph = queue.get()

            for contact in window_contacts:
                # Message/file assembly packet to window contact.
                with HideRunTime(settings, delay_type=CTDelayType.TRAFFIC_MASKING):
                    send_message(key_store,
                                 gateway,
                                 log_queue,
                                 assembly_packet,
                                 contact.onion_pub_key,
                                 log_messages,
                                 log_as_ph,
                                 settings.autoreplay_times,
                                 cache_packet=cache_packet)

                # Send a command between each assembly packet for each contact.
                with HideRunTime(settings, delay_type=CTDelayType.TRAFFIC_MASKING):

                    # Choosing element from list is constant time.
                    command_queue = [c_queue, nc_queue][c_queue.qsize() == 0]

                    # Each loaded command and noise command is a 256 bytes long bytestring.
                    send_command(local_key_db,
                                 gateway,
                                 command_queue.get(),
                                 settings.autoreplay_times,
                                 cache_packet=cache_packet)

                    # Relay packets are in practice only EXIT and
                    # WIPE signals so we consume any immediately.
                    while rp_queue.qsize() != 0:
                        packet_number = gateway.write(rp_queue.get(), cache_packet=cache_packet)
                        for _ in range(max(0, settings.autoreplay_times - 1)):
                            gateway.resend_cached_packet(packet_number)

                    monitor_proxy(queues, gateway)

            # If traffic masking has been disabled, wait until queued messages are sent before returning.
            if sm_queue.qsize() != 0 and all(q.qsize() == 0 for q in (m_queue, f_queue, c_queue)):
                settings = sm_queue.get()
                return settings

    raise RuntimeError('Broke out of loop')


class HideRunTime:
    """Runtime hiding time context manager.

    By joining a thread that sleeps for a longer time than it takes for
    the function to run, this context manager hides the actual running
    time of the function.

    Note that random.SystemRandom() uses the Kernel CSPRNG (/dev/urandom),
    not Python's weak PRNG based on Mersenne Twister:
        https://docs.python.org/2/library/random.html#random.SystemRandom
    """

    def __init__(self,
                 settings   : O['Settings'] = None,
                 delay_type : CTDelayType   = CTDelayType.STATIC,
                 duration   : FloatTMDelay  = FloatTMDelay(0.0)
                 ) -> None:
        """Create new HideRunTime context manager."""
        if delay_type == CTDelayType.TRAFFIC_MASKING and settings is not None:
            self.length  = float(settings.tm_static_delay)
            self.length += random.SystemRandom().uniform(0, float(settings.tm_random_delay))

        elif delay_type == CTDelayType.STATIC:
            self.length = duration

    def __enter__(self) -> None:
        """Start the sleeper thread that enforces the minimum runtime."""
        self.timer = threading.Thread(target=time.sleep, args=(self.length,))
        self.timer.start()

    def __exit__(self,
                 exc_type  : Any,
                 exc_value : Any,
                 traceback : Any
                 ) -> None:
        """Wait for the sleeper thread so the block lasts at least `self.length`."""
        self.timer.join()
