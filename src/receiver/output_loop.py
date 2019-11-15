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

import os
import sys
import time
import typing

from typing import Any, Dict, List, Tuple

from src.common.database   import MessageLog
from src.common.exceptions import FunctionReturn
from src.common.output     import clear_screen
from src.common.statics    import (COMMAND_DATAGRAM_HEADER, EXIT_QUEUE, FILE_DATAGRAM_HEADER, LOCAL_KEY_DATAGRAM_HEADER,
                                   MESSAGE_DATAGRAM_HEADER, ONION_SERVICE_PUBLIC_KEY_LENGTH, UNIT_TEST_QUEUE,
                                   WIN_UID_FILE)

from src.receiver.commands      import process_command
from src.receiver.files         import new_file, process_file
from src.receiver.key_exchanges import process_local_key
from src.receiver.messages      import process_message
from src.receiver.packet        import PacketList
from src.receiver.windows       import WindowList

if typing.TYPE_CHECKING:
    from datetime                import datetime
    from multiprocessing         import Queue
    from src.common.db_contacts  import ContactList
    from src.common.db_groups    import GroupList
    from src.common.db_keys      import KeyList
    from src.common.db_masterkey import MasterKey
    from src.common.db_settings  import Settings
    from src.common.gateway      import Gateway


def output_loop(queues:       Dict[bytes, 'Queue[Any]'],
                gateway:      'Gateway',
                settings:     'Settings',
                contact_list: 'ContactList',
                key_list:     'KeyList',
                group_list:   'GroupList',
                master_key:   'MasterKey',
                message_log:  'MessageLog',
                stdin_fd:     int,
                unit_test:    bool = False
                ) -> None:
    """Process packets in message queues according to their priority."""
    local_key_queue = queues[LOCAL_KEY_DATAGRAM_HEADER]
    message_queue   = queues[MESSAGE_DATAGRAM_HEADER]
    file_queue      = queues[FILE_DATAGRAM_HEADER]
    command_queue   = queues[COMMAND_DATAGRAM_HEADER]
    exit_queue      = queues[EXIT_QUEUE]

    sys.stdin     = os.fdopen(stdin_fd)
    packet_buffer = dict()  # type: Dict[bytes, List[Tuple[datetime, bytes]]]
    file_buffer   = dict()  # type: Dict[bytes, Tuple[datetime, bytes]]
    file_keys     = dict()  # type: Dict[bytes, bytes]

    kdk_hashes    = []  # type: List[bytes]
    packet_hashes = []  # type: List[bytes]

    packet_list = PacketList(settings, contact_list)
    window_list = WindowList(settings, contact_list, group_list, packet_list)

    clear_screen()
    while True:
        try:
            if local_key_queue.qsize() != 0:
                ts, packet = local_key_queue.get()
                process_local_key(ts, packet, window_list, contact_list, key_list,
                                  settings, kdk_hashes, packet_hashes, local_key_queue)
                continue

            if not contact_list.has_local_contact():
                time.sleep(0.1)
                continue

            # Commands
            if command_queue.qsize() != 0:
                ts, packet = command_queue.get()
                process_command(ts, packet, window_list, packet_list, contact_list, key_list,
                                group_list, settings, master_key, gateway, exit_queue)
                continue

            # File window refresh
            if window_list.active_win is not None and window_list.active_win.uid == WIN_UID_FILE:
                window_list.active_win.redraw_file_win()

            # Cached message packets
            for onion_pub_key in packet_buffer:
                if (contact_list.has_pub_key(onion_pub_key)
                        and key_list.has_rx_mk(onion_pub_key)
                        and packet_buffer[onion_pub_key]):
                    ts, packet = packet_buffer[onion_pub_key].pop(0)
                    process_message(ts, packet, window_list, packet_list, contact_list, key_list,
                                    group_list, settings, file_keys, message_log)
                    continue

            # New messages
            if message_queue.qsize() != 0:
                ts, packet    = message_queue.get()
                onion_pub_key = packet[:ONION_SERVICE_PUBLIC_KEY_LENGTH]

                if contact_list.has_pub_key(onion_pub_key) and key_list.has_rx_mk(onion_pub_key):
                    process_message(ts, packet, window_list, packet_list, contact_list, key_list,
                                    group_list, settings, file_keys, message_log)
                else:
                    packet_buffer.setdefault(onion_pub_key, []).append((ts, packet))
                continue

            # Cached files
            if file_buffer:
                for k in file_buffer:
                    key_to_remove = b''
                    try:
                        if k in file_keys:
                            key_to_remove = k
                            ts_, file_ct  = file_buffer[k]
                            dec_key       = file_keys[k]
                            onion_pub_key = k[:ONION_SERVICE_PUBLIC_KEY_LENGTH]
                            process_file(ts_, onion_pub_key, file_ct, dec_key, contact_list, window_list, settings)
                    finally:
                        if key_to_remove:
                            file_buffer.pop(k)
                            file_keys.pop(k)
                            break

            # New files
            if file_queue.qsize() != 0:
                ts, packet = file_queue.get()
                new_file(ts, packet, file_keys, file_buffer, contact_list, window_list, settings)

            time.sleep(0.01)

            if unit_test and queues[UNIT_TEST_QUEUE].qsize() != 0:
                break

        except (FunctionReturn, KeyError, KeyboardInterrupt):
            pass
