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

import typing

from typing import Dict

from src.common.db_logs    import remove_logs
from src.common.exceptions import FunctionReturn
from src.common.input      import box_input, yes
from src.common.misc       import ignored, validate_account, validate_key_exchange, validate_nick
from src.common.output     import box_print, c_print, clear_screen, print_fingerprint
from src.common.statics    import *

from src.tx.key_exchanges import create_pre_shared_key, start_key_exchange
from src.tx.packet        import queue_command

if typing.TYPE_CHECKING:
    from multiprocessing         import Queue
    from src.common.db_contacts  import ContactList
    from src.common.db_groups    import GroupList
    from src.common.db_masterkey import MasterKey
    from src.common.db_settings  import Settings
    from src.tx.user_input       import UserInput
    from src.tx.windows          import TxWindow


def add_new_contact(contact_list: 'ContactList',
                    group_list:   'GroupList',
                    settings:     'Settings',
                    queues:       Dict[bytes, 'Queue']) -> None:
    """Prompt for contact account details and initialize desired key exchange."""
    try:
        if settings.session_traffic_masking:
            raise FunctionReturn("Error: Command is disabled during traffic masking.")

        if len(contact_list) >= settings.max_number_of_contacts:
            raise FunctionReturn(f"Error: TFC settings only allow {settings.max_number_of_contacts} accounts.")

        clear_screen()
        c_print("Add new contact", head=1)

        contact_account = box_input("Contact account", validator=validate_account).strip()
        user_account    = box_input("Your account",    validator=validate_account).strip()
        default_nick    = contact_account.split('@')[0].capitalize()
        contact_nick    = box_input(f"Contact nick [{default_nick}]", default=default_nick, validator=validate_nick,
                                    validator_args=(contact_list, group_list, contact_account)).strip()
        key_exchange    = box_input("Key exchange ([X25519],PSK) ", default=X25519, validator=validate_key_exchange).strip()

        if key_exchange.lower() in X25519:
            start_key_exchange(contact_account, user_account, contact_nick, contact_list, settings, queues)

        elif key_exchange.lower() in PSK:
            create_pre_shared_key(contact_account, user_account, contact_nick, contact_list, settings, queues)

    except KeyboardInterrupt:
        raise FunctionReturn("Contact creation aborted.", head_clear=True)


def remove_contact(user_input:   'UserInput',
                   window:       'TxWindow',
                   contact_list: 'ContactList',
                   group_list:   'GroupList',
                   settings:     'Settings',
                   queues:       Dict[bytes, 'Queue'],
                   master_key:   'MasterKey') -> None:
    """Remove contact on TxM/RxM."""
    if settings.session_traffic_masking:
        raise FunctionReturn("Error: Command is disabled during traffic masking.")

    try:
        selection = user_input.plaintext.split()[1]
    except IndexError:
        raise FunctionReturn("Error: No account specified.")

    if not yes(f"Remove {selection} completely?", head=1):
        raise FunctionReturn("Removal of contact aborted.")

    rm_logs = yes(f"Also remove logs for {selection}?", head=1)

    # Load account if selector was nick
    if selection in contact_list.get_list_of_nicks():
        selection = contact_list.get_contact(selection).rx_account

    packet = CONTACT_REMOVE_HEADER + selection.encode()
    queue_command(packet, settings, queues[COMMAND_PACKET_QUEUE])

    if rm_logs:
        packet = LOG_REMOVE_HEADER + selection.encode()
        queue_command(packet, settings, queues[COMMAND_PACKET_QUEUE])
        with ignored(FunctionReturn):
            remove_logs(selection, settings, master_key)

    queues[KEY_MANAGEMENT_QUEUE].put((KDB_REMOVE_ENTRY_HEADER, selection))

    if selection in contact_list.get_list_of_accounts():
        contact_list.remove_contact(selection)
        box_print(f"Removed {selection} from contacts.", head=1, tail=1)
    else:
        box_print(f"TxM has no {selection} to remove.",  head=1, tail=1)

    if any([g.remove_members([selection]) for g in group_list]):
        box_print(f"Removed {selection} from group(s).", tail=1)

    if window.type == WIN_TYPE_CONTACT:
        if selection == window.uid:
            window.deselect_window()

    if window.type == WIN_TYPE_GROUP:
        for c in window:
            if selection == c.rx_account:
                window.update_group_win_members(group_list)

                # If last member from group is removed, deselect group.
                # Deselection is not done in update_group_win_members
                # because it would prevent selecting the empty group
                # for group related commands such as notifications.
                if not window.window_contacts:
                    window.deselect_window()


def change_nick(user_input:   'UserInput',
                window:       'TxWindow',
                contact_list: 'ContactList',
                group_list:   'GroupList',
                settings:     'Settings',
                c_queue:      'Queue') -> None:
    """Change nick of contact."""
    if window.type == WIN_TYPE_GROUP:
        raise FunctionReturn("Error: Group is selected.")

    try:
        nick = user_input.plaintext.split()[1]
    except IndexError:
        raise FunctionReturn("Error: No nick specified.")

    rx_account = window.contact.rx_account
    error_msg  = validate_nick(nick, (contact_list, group_list, rx_account))
    if error_msg:
        raise FunctionReturn(error_msg)

    window.contact.nick = nick
    window.name         = nick
    contact_list.store_contacts()

    packet = CHANGE_NICK_HEADER + rx_account.encode() + US_BYTE + nick.encode()
    queue_command(packet, settings, c_queue)


def contact_setting(user_input:   'UserInput',
                    window:       'TxWindow',
                    contact_list: 'ContactList',
                    group_list:   'GroupList',
                    settings:     'Settings',
                    c_queue:      'Queue') -> None:
    """\
    Change logging, file reception, or received message
    notification setting of group or (all) contact(s).
    """
    try:
        parameters = user_input.plaintext.split()
        cmd_key    = parameters[0]
        cmd_header = {LOGGING: CHANGE_LOGGING_HEADER,
                      STORE:   CHANGE_FILE_R_HEADER,
                      NOTIFY:  CHANGE_NOTIFY_HEADER}[cmd_key]

        s_value, b_value = dict(on =(ENABLE,  True),
                                off=(DISABLE, False))[parameters[1]]

    except (IndexError, KeyError):
        raise FunctionReturn("Error: Invalid command.")

    # If second parameter 'all' is included, apply setting for all contacts and groups
    try:
        target = b''
        if parameters[2] == ALL:
            cmd_value = s_value.upper() + US_BYTE
        else:
            raise FunctionReturn("Error: Invalid command.")
    except IndexError:
        target    = window.uid.encode()
        cmd_value = s_value + US_BYTE + target

    if target:
        if window.type == WIN_TYPE_CONTACT:
            if cmd_key == LOGGING: window.contact.log_messages   = b_value
            if cmd_key == STORE:   window.contact.file_reception = b_value
            if cmd_key == NOTIFY:  window.contact.notifications  = b_value
            contact_list.store_contacts()

        if window.type == WIN_TYPE_GROUP:
            if cmd_key == LOGGING: window.group.log_messages = b_value
            if cmd_key == STORE:
                for c in window:
                    c.file_reception = b_value
            if cmd_key == NOTIFY: window.group.notifications = b_value
            group_list.store_groups()

    else:
        for contact in contact_list:
            if cmd_key == LOGGING: contact.log_messages   = b_value
            if cmd_key == STORE:   contact.file_reception = b_value
            if cmd_key == NOTIFY:  contact.notifications  = b_value
        contact_list.store_contacts()

        for group in group_list:
            if cmd_key == LOGGING: group.log_messages  = b_value
            if cmd_key == NOTIFY:  group.notifications = b_value
        group_list.store_groups()

    packet = cmd_header + cmd_value

    if settings.session_traffic_masking and cmd_key == LOGGING:
        window.update_log_messages()
        queue_command(packet, settings, c_queue, window)
    else:
        window.update_log_messages()
        queue_command(packet, settings, c_queue)


def show_fingerprints(window: 'TxWindow') -> None:
    """Print domain separated fingerprints of public keys on TxM.

    Comparison of fingerprints over authenticated channel can be
    used to verify users are not under man-in-the-middle attack.
    """
    if window.type == WIN_TYPE_GROUP:
        raise FunctionReturn('Group is selected.')

    if window.contact.tx_fingerprint == bytes(FINGERPRINT_LEN):
        raise FunctionReturn(f"Pre-shared keys have no fingerprints.")

    clear_screen()
    print_fingerprint(window.contact.tx_fingerprint, "   Your fingerprint (you read)   ")
    print_fingerprint(window.contact.rx_fingerprint, "Contact's fingerprint (they read)")
    print('')
