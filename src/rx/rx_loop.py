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

from src.common.errors    import FunctionReturn
from src.common.misc      import clear_screen
from src.common.statics   import *
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


def rx_loop(settings:     'Settings',
            queues:       Dict[bytes, 'Queue'],
            contact_list: 'ContactList',
            key_list:     'KeyList',
            group_list:   'GroupList',
            master_key:   'MasterKey',
            file_no:      int  # stdin file descriptor
            ) -> None:
    """Process received packets depending on their priorities."""
    l_queue = queues[LOCAL_KEY_PACKET_HEADER]
    p_queue = queues[PUBLIC_KEY_PACKET_HEADER]
    m_queue = queues[MESSAGE_PACKET_HEADER]
    c_queue = queues[COMMAND_PACKET_HEADER]
    f_queue = queues[IMPORTED_FILE_CT_HEADER]

    packet_buf  = dict()  # type: Dict[str, List[Tuple[datetime, bytes]]]
    pubkey_buf  = dict()  # type: Dict[str, str]
    sys.stdin   = os.fdopen(file_no)
    packet_list = PacketList(contact_list, settings)
    window_list = WindowList(contact_list, group_list, packet_list, settings)

    clear_screen()
    while True:
        try:
            if not l_queue.empty():
                ts, packet = l_queue.get()
                process_local_key(packet, contact_list, key_list)

            if not contact_list.has_local_contact():
                time.sleep(0.01)
                continue

            if not p_queue.empty():
                ts, packet = p_queue.get()
                process_public_key(ts, packet, window_list, settings, pubkey_buf)
                continue

            if not c_queue.empty():
                ts, packet = c_queue.get()
                process_command(ts, packet, window_list, packet_list, contact_list, key_list, group_list, settings, master_key, pubkey_buf)
                continue

            if window_list.active_win is not None and window_list.active_win.uid == FILE_R_WIN_ID_BYTES.decode():
                window_list.active_win.redraw()

            # Check if keys have been added by contact and process all messages immediately.
            for rx_account in packet_buf:
                if contact_list.has_contact(rx_account):
                    for _ in packet_buf[rx_account]:
                        ts, packet = packet_buf[rx_account].pop(0)
                        process_message(ts, packet, window_list, packet_list, contact_list, key_list, group_list, settings, master_key)
                    continue

            if not m_queue.empty():
                ts, packet = m_queue.get()
                rx_account = packet[346:].decode()  # header (1) + ct (24 + 8 + 16 + 24 + 256 + 16) + origin (1)

                if contact_list.has_contact(rx_account):
                    process_message(ts, packet, window_list, packet_list, contact_list, key_list, group_list, settings, master_key)
                else:
                    # If contact derives X25519 shared key first and sends message before user has created
                    # their copy of shared key, buffer received messages until decryption keys are received.
                    if rx_account not in packet_buf:
                        packet_buf[rx_account] = []
                    packet_buf[rx_account].append((ts, packet))
                    continue

            if not f_queue.empty():
                ts, packet = f_queue.get()
                process_imported_file(ts, packet, window_list)
                continue

            time.sleep(0.01)

        except (FunctionReturn, KeyboardInterrupt):
            pass
