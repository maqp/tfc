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

from src.common.errors    import FunctionReturn
from src.common.input     import box_input, yes
from src.common.misc      import clear_screen, validate_account, validate_key_exchange, validate_nick
from src.common.output    import box_print, c_print, print_fingerprints
from src.common.statics   import *
from src.tx.key_exchanges import new_psk, start_key_exchange
from src.tx.packet        import queue_command

if typing.TYPE_CHECKING:
    from multiprocessing        import Queue
    from src.common.db_contacts import ContactList
    from src.common.db_groups   import GroupList
    from src.common.db_settings import Settings
    from src.common.gateway     import Gateway
    from src.tx.user_input      import UserInput
    from src.tx.windows         import Window


def add_new_contact(contact_list: 'ContactList',
                    group_list:   'GroupList',
                    settings:     'Settings',
                    queues:       Dict[bytes, 'Queue'],
                    gateway:      'Gateway') -> None:
    """Prompt for contact account details and initialize desired key exchange method."""
    try:
        if settings.session_trickle:
            raise FunctionReturn("Command disabled during trickle connection.")

        if len(contact_list) >= settings.m_number_of_accnts:
            raise FunctionReturn(f"Error: TFC settings only allow {settings.m_number_of_accnts} accounts.")

        clear_screen()
        c_print("Add new contact", head=1)

        acco = box_input("Contact account",                              tail=1, validator=validate_account).strip()
        user = box_input("Your account",                                 tail=1, validator=validate_account).strip()
        defn = acco.split('@')[0].capitalize()
        nick = box_input(f"Contact nick [{defn}]",      default=defn,    tail=1, validator=validate_nick, validator_args=(contact_list, group_list, acco)).strip()
        keyx = box_input("Key exchange ([ECDHE],PSK) ", default='ECDHE', tail=1, validator=validate_key_exchange).strip()

        if keyx.lower() in 'ecdhe':
            start_key_exchange(acco, user, nick, contact_list, settings, queues, gateway)

        elif keyx.lower() in 'psk':
            new_psk(           acco, user, nick, contact_list, settings, queues)

    except KeyboardInterrupt:
        raise FunctionReturn("Contact creation aborted.")


def remove_contact(user_input:   'UserInput',
                   window:       'Window',
                   contact_list: 'ContactList',
                   group_list:   'GroupList',
                   settings:     'Settings',
                   queues:       Dict[bytes, 'Queue']) -> None:
    """Remove contact on TxM/RxM."""
    if settings.session_trickle:
        raise FunctionReturn("Command disabled during trickle connection.")

    try:
        selection = user_input.plaintext.split()[1]
    except IndexError:
        raise FunctionReturn("Error: No account specified.")

    if not yes(f"Remove {selection} completely?", head=1):
        raise FunctionReturn("Removal of contact aborted.")

    # Load account if user enters nick
    if selection in contact_list.get_list_of_nicks():
        selection = contact_list.get_contact(selection).rx_account

    packet = CONTACT_REMOVE_HEADER + selection.encode()
    queue_command(packet, settings, queues[COMMAND_PACKET_QUEUE])

    if selection in contact_list.get_list_of_accounts():
        queues[KEY_MANAGEMENT_QUEUE].put(('REM', selection))
        contact_list.remove_contact(selection)
        box_print(f"Removed {selection} from contacts.", head=1, tail=1)
    else:
        box_print(f"TxM has no {selection} to remove.",  head=1, tail=1)

    if any([g.remove_members([selection]) for g in group_list]):
        box_print(f"Removed {selection} from group(s).", tail=1)

    for c in window:
        if selection == c.rx_account:
            if window.type == 'contact':
                window.deselect()
            elif window.type == 'group':
                window.update_group_win_members(group_list)

                # If last member from group is removed, deselect group.
                # This is not done in update_group_win_members because
                # It would prevent selecting the empty group for group
                # related commands such as notifications.
                if not window.window_contacts:
                    window.deselect()


def change_nick(user_input:   'UserInput',
                window:       'Window',
                contact_list: 'ContactList',
                group_list:   'GroupList',
                settings:     'Settings',
                c_queue:      'Queue') -> None:
    """Change nick of contact."""
    if window.type == 'group':
        raise FunctionReturn("Error: Group is selected.")

    try:
        nick = user_input.plaintext.split()[1]
    except IndexError:
        raise FunctionReturn("Error: No nick specified.")

    rx_acco            = window.contact.rx_account
    success, error_msg = validate_nick(nick, (contact_list, group_list, rx_acco))
    if not success:
        raise FunctionReturn(error_msg)
    window.contact.nick = nick
    window.name         = nick
    contact_list.store_contacts()

    packet = CHANGE_NICK_HEADER + rx_acco.encode() + US_BYTE + nick.encode()
    queue_command(packet, settings, c_queue)

    box_print(f"Changed {rx_acco} nick to {nick}.")


def contact_setting(user_input:   'UserInput',
                    window:       'Window',
                    contact_list: 'ContactList',
                    group_list:   'GroupList',
                    settings:     'Settings',
                    c_queue:      'Queue') -> None:
    """Change logging, file reception, or message notification setting of (all) contact(s)."""
    try:
        parameters = user_input.plaintext.split()
        cmd_key    = parameters[0]
        cmd_header = dict(logging=CHANGE_LOGGING_HEADER,
                          store  =CHANGE_FILE_R_HEADER,
                          notify =CHANGE_NOTIFY_HEADER)[cmd_key]

        s_value = dict(on=b'e', off=b'd' )[parameters[1]]
        b_value = dict(on=True, off=False)[parameters[1]]

    except (IndexError, KeyError):
        raise FunctionReturn("Error: Invalid command.")

    # If second parameter 'all' is included, apply setting for all contacts and groups
    try:
        target = b''
        if parameters[2] == 'all':
            cmd_value = s_value.upper()
        else:
            raise FunctionReturn("Error: Invalid command.")
    except IndexError:
        target    = window.uid.encode()
        cmd_value = s_value + US_BYTE + target

    if target:
        if window.type == 'contact':
            if cmd_key == 'logging': window.contact.log_messages   = b_value
            if cmd_key == 'store':   window.contact.file_reception = b_value
            if cmd_key == 'notify':  window.contact.notifications  = b_value
            contact_list.store_contacts()

        if window.type == 'group':
            if cmd_key == 'logging': window.group.log_messages  = b_value
            if cmd_key == 'store':
                for c in window:
                    c.file_reception = b_value
            if cmd_key == 'notify':  window.group.notifications = b_value
            group_list.store_groups()

    else:
        for contact in contact_list:
            if cmd_key == 'logging': contact.log_messages   = b_value
            if cmd_key == 'store':   contact.file_reception = b_value
            if cmd_key == 'notify':  contact.notifications  = b_value
        contact_list.store_contacts()

        for group in group_list:
            if cmd_key == 'logging': group.log_messages  = b_value
            if cmd_key == 'notify':  group.notifications = b_value
        group_list.store_groups()

    packet = cmd_header + cmd_value
    queue_command(packet, settings, c_queue)


def fingerprints(window: 'Window') -> None:
    """Print domain separated fingerprints of shared secret on TxM."""
    if window.type == 'group':
        raise FunctionReturn('Group is selected.')

    if window.contact.tx_fingerprint == bytes(32):
        raise FunctionReturn(f"Key have been pre-shared with {window.name} and thus have no fingerprints.")

    clear_screen()
    print_fingerprints(window.contact.tx_fingerprint, "   Your fingerprint (you read)   ")
    print_fingerprints(window.contact.rx_fingerprint, "Contact's fingerprint (they read)")
    print('')
