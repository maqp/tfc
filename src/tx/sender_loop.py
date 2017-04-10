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

from typing import Dict

from typing          import List, Tuple

from src.common.statics import *
from src.tx.packet      import send_packet
from src.tx.trickle     import ConstantTime

if typing.TYPE_CHECKING:
    from multiprocessing        import Queue
    from src.common.db_keys     import KeyList
    from src.common.db_settings import Settings
    from src.common.gateway     import Gateway
    from src.common.db_settings import Settings
    from src.tx.windows         import Window


def sender_loop(settings: 'Settings',
                queues:   Dict[bytes, 'Queue'],
                gateway:  'Gateway',
                key_list: 'KeyList') -> None:
    """Load assembly packets from queues based on their priority, encrypt and output them.

    Sender loop handles a set of queues. As Python's multiprocessing lacks priority queues,
    several queues are prioritized based on their status. In both trickle and non-trickle
    mode, file are only transmitted when no messages are being output. This is because file
    transmission is usually very slow and user might need to send messages in the meantime.
    In normal (non-trickle) mode commands take highest priority as they are not output
    all the time. In trickle mode commands are output between each output message packet.
    This allows commands to take effect as soon as possible but slows down message/file delivery
    by half. In trickle mode each contact in window is cycled in order. Making changes to
    recipient list during use is prevented to protect user from accidentally revealing use
    of TFC. In trickle mode, if no packets are available in either m_queue or f_queue,
    a noise assembly packet is loaded from np_queue. If no command packet is available in
    c_queue, a noise command packet is loaded from nc_queue. TFC does it's best to hide the
    loading times and encryption duration by using constant time context manager and constant
    time queue status lookup, as well as constant time XSalsa20 cipher.
    """
    m_queue  = queues[MESSAGE_PACKET_QUEUE]
    f_queue  = queues[FILE_PACKET_QUEUE]
    c_queue  = queues[COMMAND_PACKET_QUEUE]
    l_queue  = queues[LOG_PACKET_QUEUE]
    km_queue = queues[KEY_MANAGEMENT_QUEUE]
    np_queue = queues[NOISE_PACKET_QUEUE]
    nc_queue = queues[NOISE_COMMAND_QUEUE]
    ws_queue = queues[WINDOW_SELECT_QUEUE]

    m_buffer = []  # type: List[Tuple[bytes, Settings, str, str, bool, Window]]
    f_buffer = []  # type: List[Tuple[bytes, Settings, str, str, bool, Window]]


    if settings.session_trickle:

        while ws_queue.empty():
            time.sleep(0.01)

        window = ws_queue.get()

        while True:
            try:
                with ConstantTime(settings, length=TRICKLE_QUEUE_CHECK_DELAY):
                    queue            = [[m_queue, m_queue], [f_queue, np_queue]][m_queue.empty()][f_queue.empty()]
                    packet, log_dict = queue.get()

                for c in window:

                    with ConstantTime(settings, d_type='trickle'):
                        send_packet(packet, key_list, settings, gateway, l_queue, c.rx_account, c.tx_account, log_dict[c.rx_account])

                    with ConstantTime(settings, d_type='trickle'):
                        queue   = [c_queue, nc_queue][c_queue.empty()]
                        command = queue.get()
                        send_packet(command, key_list, settings, gateway, l_queue)

            except (EOFError, KeyboardInterrupt):
                pass

    else:
        while True:
            try:
                time.sleep(0.001)

                # Keylist database management packets have highest priority.
                if not km_queue.empty():
                    command, *params = km_queue.get()
                    key_list.manage(command, *params)
                    continue

                # packets from c_queue come only from local contact. Until keys for local contact
                # have been added, no command is loaded. Commands have second highest priority.
                if not c_queue.empty():
                    if key_list.has_local_key():
                        command, settings = c_queue.get()
                        send_packet(command, key_list, settings, gateway, l_queue)
                        continue

                # Iterate through buffer list that contains tuples of transmission information
                # loaded from m_queue in the order they were placed into the buffer. As soon as
                # keys are available, send packet. Restart the loop to prioritize keylist
                # management and command packets before going through the buffer list again.
                for i, params in enumerate(m_buffer):
                    packet, settings, rx_account, tx_account, logging, window = params
                    if key_list.has_keyset(rx_account):
                        m_buffer.pop(i)
                        send_packet(packet, key_list, settings, gateway, l_queue, rx_account, tx_account, logging)
                        continue

                # Any new messages take priority only after the ones in buffer are sent.
                # If key is not on list, place the message packet into the buffer.
                if not m_queue.empty():
                    packet, settings, rx_account, tx_account, logging, window = m_queue.get()
                    if key_list.has_keyset(rx_account):
                        send_packet(packet, key_list, settings, gateway, l_queue, rx_account, tx_account, logging)
                    else:
                        m_buffer.append((packet, settings, rx_account, tx_account, logging, window))
                    continue

                # When no more messages can be processed, check if the
                # file buffer has packets that can be sent to contacts.
                for i, params in enumerate(f_buffer):
                    packet, settings, rx_account, tx_account, logging, window = params
                    if key_list.has_keyset(rx_account):
                        f_buffer.pop(i)
                        send_packet(packet, key_list, settings, gateway, l_queue, rx_account, tx_account, logging)
                        continue

                # If file buffer is empty, check if new file packets are available. If there are and
                # contact has key, send file packet, otherwise place it into the file packet buffer.
                if not f_queue.empty():
                    packet, settings, rx_account, tx_account, logging, window = f_queue.get()
                    if key_list.has_keyset(rx_account):
                        send_packet(packet, key_list, settings, gateway, l_queue, rx_account, tx_account, logging)
                    else:
                        f_buffer.append((packet, settings, rx_account, tx_account, logging, window))

            except (EOFError, KeyboardInterrupt):
                pass
