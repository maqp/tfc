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

from typing import TYPE_CHECKING

from src.common.exceptions import SoftError
from src.common.statics import TxCommand
from src.transmitter.commands.management.manage_contacts import remove_contact
from src.transmitter.commands.management.manage_groups import process_group_command
from src.transmitter.commands.management.manage_logs import log_command, remove_log
from src.transmitter.commands.management.manage_onion_service import send_onion_service_key
from src.transmitter.commands.management.manage_replay import (resend_received_file,
                                                               resend_from_rep_to_rxp,
                                                               resend_from_txp_to_rep,
                                                               clear_ciphertext_caches)
from src.transmitter.commands.management.manage_settings_contact import change_contact_setting
from src.transmitter.commands.management.manage_settings_system import change_system_setting
from src.transmitter.commands.management.manage_window import (rxp_show_sys_win, select_window, change_win_handle,
                                                               rxp_display_unread)
from src.transmitter.commands.security.change_master_key import change_master_key
from src.transmitter.commands.security.clear_screens import clear_screens
from src.transmitter.commands.security.exit_wipe import exit_tfc, wipe
from src.transmitter.commands.security.verify_fingerprints import verify
from src.transmitter.commands.security.whisper import whisper
from src.transmitter.key_exchanges.add_contact import add_new_contact
from src.transmitter.key_exchanges.local_key import new_local_key
from src.transmitter.key_exchanges.pre_shared_key import rxp_load_psk
from src.transmitter.queue_packet.cancel_packet import cancel_file, cancel_message
from src.ui.transmitter.print_info import print_about, print_help, print_recipients, print_settings, whois

if TYPE_CHECKING:
    from src.common.gateway import Gateway
    from src.common.queues import TxQueue
    from src.database.db_contacts import ContactList
    from src.database.db_groups import GroupList
    from src.database.db_local_key import LocalKeyDB
    from src.database.db_logs import MessageLog
    from src.database.db_masterkey import MasterKey
    from src.database.db_onion import OnionService
    from src.database.db_settings import Settings
    from src.ui.transmitter.user_input import UserInput
    from src.ui.transmitter.window_tx import TxWindow


def dispatch_command(settings      : 'Settings',
                     queues        : 'TxQueue',
                     window        : 'TxWindow',
                     contact_list  : 'ContactList',
                     group_list    : 'GroupList',
                     user_input    : 'UserInput',
                     master_key    : 'MasterKey',
                     local_key_db  : 'LocalKeyDB',
                     onion_service : 'OnionService',
                     gateway       : 'Gateway',
                     message_log   : 'MessageLog',
                     ) -> None:
    """\
    Select function based on the first keyword of the
    issued command, and pass relevant parameters to it.

    The massive elif structure is preferred over dict
    as this allows validation of parameter types. Dict
    was ~6x faster here, but the gain was about ~0.2μs.
    """
    try:
        command_str = user_input.plaintext.split()[0]
    except (IndexError, UnboundLocalError):
        raise SoftError(f'Error: Missing command.', clear_before=True)
    try:
        tx_command  = TxCommand(command_str)
    except ValueError:
        raise SoftError(f'Error: Unknown command {command_str}.', clear_before=True)

    if   tx_command == TxCommand.ABOUT:    print_about            (                                                                                                                             )
    elif tx_command == TxCommand.ADD:      add_new_contact        (settings, queues,         contact_list, group_list,             master_key, local_key_db, onion_service                      )
    elif tx_command == TxCommand.CC:       clear_ciphertext_caches(settings, queues                                                                                                             )
    elif tx_command == TxCommand.CF:       cancel_file            (settings, queues, window,                                                                                                    )
    elif tx_command == TxCommand.CM:       cancel_message         (settings, queues, window,                                                                                                    )
    elif tx_command == TxCommand.CLEAR:    clear_screens          (settings, queues, window,                           user_input,                                                              )
    elif tx_command == TxCommand.CMD:      rxp_show_sys_win       (settings, queues, window,                           user_input,                                                              )
    elif tx_command == TxCommand.CONNECT:  send_onion_service_key (settings,                 contact_list,                                                   onion_service, gateway             )
    elif tx_command == TxCommand.EXIT:     exit_tfc               (settings, queues,                                                                                        gateway             )
    elif tx_command == TxCommand.EXPORT:   log_command            (settings, queues, window, contact_list, group_list, user_input, master_key                                                   )
    elif tx_command == TxCommand.FW:       rxp_show_sys_win       (settings, queues, window,                           user_input,                                                              )
    elif tx_command == TxCommand.GROUP:    process_group_command  (settings, queues,         contact_list, group_list, user_input, master_key                                                   )
    elif tx_command == TxCommand.HELP:     print_help             (settings,                                                                                                                    )
    elif tx_command == TxCommand.HISTORY:  log_command            (settings, queues, window, contact_list, group_list, user_input, master_key                                                   )
    elif tx_command == TxCommand.LOCALKEY: new_local_key          (settings, queues,                                                           local_key_db                                     )
    elif tx_command == TxCommand.LOGGING:  change_contact_setting (settings, queues, window, contact_list, group_list, user_input,                                                              )
    elif tx_command == TxCommand.MSG:      select_window          (settings, queues, window,                           user_input, master_key, local_key_db, onion_service, gateway             )
    elif tx_command == TxCommand.NAMES:    print_recipients       (                          contact_list, group_list,                                                                          )
    elif tx_command == TxCommand.NICK:     change_win_handle      (settings, queues, window, contact_list, group_list, user_input,                                                              )
    elif tx_command == TxCommand.NOTIFY:   change_contact_setting (settings, queues, window, contact_list, group_list, user_input,                                                              )
    elif tx_command == TxCommand.PASSWD:   change_master_key      (settings, queues,         contact_list, group_list, user_input, master_key,               onion_service,          message_log)
    elif tx_command == TxCommand.PSK:      rxp_load_psk           (settings, queues, window, contact_list,                                                                                      )
    elif tx_command == TxCommand.RESET:    clear_screens          (settings, queues, window,                           user_input,                                                              )
    elif tx_command == TxCommand.RM:       remove_contact         (settings, queues, window, contact_list, group_list, user_input, master_key                                                   )
    elif tx_command == TxCommand.RF:       resend_received_file   (settings, queues,                                   user_input                                                               )
    elif tx_command == TxCommand.RMLOGS:   remove_log             (settings, queues,         contact_list, group_list, user_input, master_key                                                   )
    elif tx_command == TxCommand.RR:       resend_from_rep_to_rxp (settings, queues,                                   user_input                                                               )
    elif tx_command == TxCommand.RT:       resend_from_txp_to_rep (settings, queues,                                   user_input                                                               )
    elif tx_command == TxCommand.SET:      change_system_setting  (settings, queues, window, contact_list, group_list, user_input, master_key,                              gateway             )
    elif tx_command == TxCommand.SETTINGS: print_settings         (settings,                                                                                                gateway             )
    elif tx_command == TxCommand.STORE:    change_contact_setting (settings, queues, window, contact_list, group_list, user_input,                                                              )
    elif tx_command == TxCommand.UNREAD:   rxp_display_unread     (settings, queues,                                                                                                            )
    elif tx_command == TxCommand.VERIFY:   verify                 (                  window, contact_list                                                                                       )
    elif tx_command == TxCommand.WHISPER:  whisper                (settings, queues, window,                           user_input,                                                              )
    elif tx_command == TxCommand.WHOIS:    whois                  (                          contact_list, group_list, user_input,                                                              )
    elif tx_command == TxCommand.WIPE:     wipe                   (settings, queues,                                                                                        gateway             )
