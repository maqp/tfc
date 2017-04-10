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
import readline
import sys
import typing

from typing import Dict

from src.common.errors    import FunctionReturn
from src.common.misc      import get_tab_completer
from src.common.statics   import *
from src.tx.commands      import process_command
from src.tx.contact       import add_new_contact
from src.tx.files         import queue_file
from src.tx.key_exchanges import new_local_key
from src.tx.messages      import queue_message
from src.tx.user_input    import UserInput
from src.tx.windows       import Window

if typing.TYPE_CHECKING:
    from multiprocessing         import Queue
    from src.common.db_contacts  import ContactList
    from src.common.db_groups    import GroupList
    from src.common.db_masterkey import MasterKey
    from src.common.db_settings  import Settings
    from src.common.gateway      import Gateway


def tx_loop(settings:     'Settings',
            queues:       Dict[bytes, 'Queue'],
            gateway:      'Gateway',
            contact_list: 'ContactList',
            group_list:   'GroupList',
            master_key:   'MasterKey',
            file_no:      int  # stdin input file descriptor
            ) -> None:
    """Get input from user and process it accordingly.

    Tx side of TFC runs two processes -- input and output loop -- separate from
    one another. This approach allows queueing assembly packets and their output
    based on priority of different packets. tx_loop handles TxM-side functions
    excluding message encryption, output and hash ratchet key/counter updates in
    key_list database and log file writes.
    """
    sys.stdin = os.fdopen(file_no)
    window    = Window(contact_list, group_list)

    while True:
        try:
            readline.set_completer(get_tab_completer(contact_list, group_list, settings))
            readline.parse_and_bind('tab: complete')

            window.update_group_win_members(group_list)

            while not contact_list.has_local_contact():
                new_local_key(contact_list, settings, queues, gateway)

            while not contact_list.has_contacts():
                add_new_contact(contact_list, group_list, settings, queues, gateway)

            while not window.is_selected():
                window.select_tx_window(settings, queues)

            user_input = UserInput(window, settings)

            if user_input.type == 'message':
                queue_message(user_input, window, settings, queues[MESSAGE_PACKET_QUEUE])

            elif user_input.type == 'file':
                queue_file(window, settings, queues[FILE_PACKET_QUEUE], gateway)

            elif user_input.type == 'command':
                process_command(user_input, window, settings, queues, contact_list, group_list, gateway, master_key)

        except (EOFError, FunctionReturn, KeyboardInterrupt):
            pass
