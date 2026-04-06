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

import os
import readline
import sys

from typing import TYPE_CHECKING

from src.common.exceptions import SoftError, ignored
from src.transmitter.commands.dispatch_command import dispatch_command
from src.transmitter.key_exchanges.add_contact import add_new_contact
from src.transmitter.key_exchanges.local_key import new_local_key
from src.transmitter.key_exchanges.onion_service import export_onion_service_data
from src.transmitter.queue_packet.queue_packet import queue_message, queue_file
from src.ui.common.utils import get_tab_completer
from src.ui.transmitter.user_input import GetUserInput
from src.ui.transmitter.window_tx import TxWindow

if TYPE_CHECKING:
    from src.common.gateway import Gateway
    from src.common.queues import TxQueue
    from src.common.types_custom import IntStdInFD
    from src.database.db_contacts import ContactList
    from src.database.db_groups import GroupList
    from src.database.db_local_key import LocalKeyDB
    from src.database.db_logs import MessageLog
    from src.database.db_masterkey import MasterKey
    from src.database.db_onion import OnionService
    from src.database.db_settings import Settings


def input_process(queues        : 'TxQueue',
                  settings      : 'Settings',
                  gateway       : 'Gateway',
                  contact_list  : 'ContactList',
                  local_key_db  : 'LocalKeyDB',
                  group_list    : 'GroupList',
                  message_log   : 'MessageLog',
                  master_key    : 'MasterKey',
                  onion_service : 'OnionService',
                  stdin_fd      : 'IntStdInFD'
                  ) -> None:
    """Get input from user and process it accordingly.

    This process decouples anything that requires user-input, from sending
    files and assembly packets. This includes key exchanges, file loading
    and assembly packet parsing. This ensures the slower output interface
    does not slow down using Transmitter Program.
    """
    sys.stdin = os.fdopen(stdin_fd)
    window    = TxWindow(contact_list, group_list)

    while True:
        with ignored(EOFError, KeyboardInterrupt, SoftError):

            readline.set_completer(get_tab_completer(contact_list, group_list, settings, gateway))
            readline.parse_and_bind('tab: complete')

            window.update_window(group_list)

            while not onion_service .is_delivered: export_onion_service_data (settings,                 contact_list,                                                   onion_service, gateway,            )
            while not local_key_db  .has_keyset:   new_local_key             (settings, queues,                                                           local_key_db,                                    )
            while not contact_list  .has_contacts: add_new_contact           (settings, queues,         contact_list, group_list,             master_key, local_key_db, onion_service                      )
            while not window        .is_selected:  window.select_tx_window   (settings, queues,                                               master_key, local_key_db, onion_service, gateway             )
            user_input = GetUserInput(settings, window).get_input()

            if   user_input.is_message: queue_message                        (settings, queues, window,                           user_input                                                               )
            elif user_input.is_file:    queue_file                           (settings, queues, window                                                                                                     )
            elif user_input.is_command: dispatch_command                     (settings, queues, window, contact_list, group_list, user_input, master_key, local_key_db, onion_service, gateway, message_log)
