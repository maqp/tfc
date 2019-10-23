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
import readline
import sys
import typing

from typing import Dict, NoReturn

from src.common.exceptions import FunctionReturn
from src.common.misc       import get_tab_completer, ignored
from src.common.statics    import COMMAND, FILE, MESSAGE

from src.transmitter.commands      import process_command
from src.transmitter.contact       import add_new_contact
from src.transmitter.key_exchanges import export_onion_service_data, new_local_key
from src.transmitter.packet        import queue_file, queue_message
from src.transmitter.user_input    import get_input
from src.transmitter.windows       import TxWindow

if typing.TYPE_CHECKING:
    from multiprocessing         import Queue
    from src.common.db_contacts  import ContactList
    from src.common.db_groups    import GroupList
    from src.common.db_masterkey import MasterKey
    from src.common.db_onion     import OnionService
    from src.common.db_settings  import Settings
    from src.common.gateway      import Gateway


def input_loop(queues:        Dict[bytes, 'Queue[bytes]'],
               settings:      'Settings',
               gateway:       'Gateway',
               contact_list:  'ContactList',
               group_list:    'GroupList',
               master_key:    'MasterKey',
               onion_service: 'OnionService',
               stdin_fd:      int
               ) -> NoReturn:
    """Get input from user and process it accordingly.

    Running this loop as a process allows handling different functions
    including inputs, key exchanges, file loading and assembly packet
    generation, separate from assembly packet output.
    """
    sys.stdin = os.fdopen(stdin_fd)
    window    = TxWindow(contact_list, group_list)

    while True:
        with ignored(EOFError, FunctionReturn, KeyboardInterrupt):
            readline.set_completer(get_tab_completer(contact_list, group_list, settings, gateway))
            readline.parse_and_bind('tab: complete')

            window.update_window(group_list)

            while not onion_service.is_delivered:
                export_onion_service_data(contact_list, settings, onion_service, gateway)

            while not contact_list.has_local_contact():
                new_local_key(contact_list, settings, queues)

            while not contact_list.has_contacts():
                add_new_contact(contact_list, group_list, settings, queues, onion_service)

            while not window.is_selected():
                window.select_tx_window(settings, queues, onion_service, gateway)

            user_input = get_input(window, settings)

            if user_input.type == MESSAGE:
                queue_message(user_input, window, settings, queues)

            elif user_input.type == FILE:
                queue_file(window, settings, queues)

            elif user_input.type == COMMAND:
                process_command(
                    user_input, window, contact_list, group_list, settings, queues, master_key, onion_service, gateway)
