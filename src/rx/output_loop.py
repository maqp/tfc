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

import os
import sys
import time
import typing

from typing import Dict, List, Tuple

from src.common.exceptions import FunctionReturn
from src.common.output     import clear_screen
from src.common.statics    import *

from src.rx.commands      import process_command
from src.rx.files         import process_imported_file
from src.rx.key_exchanges import process_local_key, process_public_key
from src.rx.messages      import process_message
from src.rx.packet        import PacketList
from src.rx.windows       import WindowList

if typing.TYPE_CHECKING:
    from datetime                import datetime
    from multiprocessing         import Queue
    from src.common.db_contacts  import ContactList
    from src.common.db_groups    import GroupList
    from src.common.db_keys      import KeyList
    from src.common.db_masterkey import MasterKey
    from src.common.db_settings  import Settings


def output_loop(queues:       Dict[bytes, 'Queue'],
                settings:     'Settings',
                contact_list: 'ContactList',
                key_list:     'KeyList',
                group_list:   'GroupList',
                master_key:   'MasterKey',
                stdin_fd:     int,
                unittest:     bool = False) -> None:
    """Process received packets according to their priority."""
    l_queue = queues[LOCAL_KEY_PACKET_HEADER]
    p_queue = queues[PUBLIC_KEY_PACKET_HEADER]
    m_queue = queues[MESSAGE_PACKET_HEADER]
    c_queue = queues[COMMAND_PACKET_HEADER]
    i_queue = queues[IMPORTED_FILE_HEADER]
    e_queue = queues[EXIT_QUEUE]

    sys.stdin   = os.fdopen(stdin_fd)
    packet_buf  = dict()  # type: Dict[str, List[Tuple[datetime, bytes]]]
    pubkey_buf  = dict()  # type: Dict[str, bytes]
    packet_list = PacketList(settings, contact_list)
    window_list = WindowList(settings, contact_list, group_list, packet_list)

    clear_screen()
    while True:
        try:
            if l_queue.qsize() != 0:
                ts, packet = l_queue.get()
                process_local_key(ts, packet, window_list, contact_list, key_list, settings)

            if not contact_list.has_local_contact():
                time.sleep(0.01)
                continue

            if c_queue.qsize() != 0:
                ts, packet = c_queue.get()
                process_command(ts, packet, window_list, packet_list, contact_list, key_list, group_list, settings, master_key, pubkey_buf, e_queue)
                continue

            if p_queue.qsize() != 0:
                ts, packet = p_queue.get()
                process_public_key(ts, packet, window_list, settings, pubkey_buf)
                continue

            if window_list.active_win is not None and window_list.active_win.uid == WIN_TYPE_FILE:
                window_list.active_win.redraw_file_win()

            # Prioritize buffered messages
            for rx_account in packet_buf:
                if contact_list.has_contact(rx_account) and key_list.has_rx_key(rx_account) and packet_buf[rx_account]:
                    ts, packet = packet_buf[rx_account].pop(0)
                    process_message(ts, packet, window_list, packet_list, contact_list, key_list, group_list, settings, master_key)
                    continue

            if m_queue.qsize() != 0:
                ts, packet = m_queue.get()
                rx_account = packet[PACKET_LENGTH:].decode()

                if contact_list.has_contact(rx_account) and key_list.has_rx_key(rx_account):
                    process_message(ts, packet, window_list, packet_list, contact_list, key_list, group_list, settings, master_key)
                else:
                    packet_buf.setdefault(rx_account, []).append((ts, packet))
                continue

            if i_queue.qsize() != 0:
                ts, packet = i_queue.get()
                process_imported_file(ts, packet, window_list, settings)
                continue

            time.sleep(0.01)

            if unittest and queues[UNITTEST_QUEUE].qsize() != 0:
                break

        except (FunctionReturn, KeyboardInterrupt):
            pass
