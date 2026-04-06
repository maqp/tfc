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

from datetime import datetime
from typing import TYPE_CHECKING

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from src.common.entities.window_uid import WindowUID
from src.common.exceptions import SoftError
from src.common.crypto.keys.onion_service_keys import OnionPublicKeyContact
from src.common.statics import RxCommand, FieldLength, ContactSettingValueHeader, ContactSettingAttr
from src.common.types_custom import (BoolFileReception, BoolIsFileCommand, BoolLogMessages, BoolSettingValue,
                                     BoolShowNotifications)
from src.common.utils.strings import separate_header

if TYPE_CHECKING:
    from src.common.entities.serialized_command import SerializedCommand
    from src.common.entities.contact import Contact
    from src.common.entities.group import Group
    from src.database.db_contacts import ContactList
    from src.database.db_groups import GroupList
    from src.ui.receiver.window_rx import WindowList


def get_contact_setting(contact: 'Contact', attr: ContactSettingAttr) -> bool:
    """Return a contact-level boolean setting."""
    if attr == ContactSettingAttr.LOG_MESSAGES:
        return contact.log_messages
    if attr == ContactSettingAttr.FILE_RECEPTION:
        return contact.file_reception
    if attr == ContactSettingAttr.NOTIFICATIONS:
        return contact.notifications
    raise ValueError(f'Invalid contact setting attribute {attr}.')


def set_contact_setting(contact : 'Contact',
                        attr    : ContactSettingAttr,
                        value   : BoolSettingValue
                        ) -> None:
    """Update a contact-level boolean setting."""
    if attr == ContactSettingAttr.LOG_MESSAGES:
        contact.log_messages = BoolLogMessages(bool(value))
        return
    if attr == ContactSettingAttr.FILE_RECEPTION:
        contact.file_reception = BoolFileReception(bool(value))
        return
    if attr == ContactSettingAttr.NOTIFICATIONS:
        contact.notifications = BoolShowNotifications(bool(value))
        return
    raise ValueError(f'Invalid contact setting attribute {attr}.')


def get_group_setting(group : 'Group',
                      attr  : ContactSettingAttr
                      ) -> bool:
    """Return a group-level boolean setting."""
    if attr == ContactSettingAttr.LOG_MESSAGES:
        return group.log_messages
    if attr == ContactSettingAttr.NOTIFICATIONS:
        return group.notifications
    raise ValueError(f'Invalid group setting attribute {attr}.')


def set_group_setting(group: 'Group',
                      attr: ContactSettingAttr,
                      value: BoolSettingValue
                      ) -> None:
    """Update a group-level boolean setting."""
    if attr == ContactSettingAttr.LOG_MESSAGES:
        group.log_messages = BoolLogMessages(bool(value))
        return
    if attr == ContactSettingAttr.NOTIFICATIONS:
        group.notifications = BoolShowNotifications(bool(value))
        return
    raise ValueError(f'Invalid group setting attribute {attr}.')


def change_setting_for_one_window(attr         : ContactSettingAttr,
                                  is_file_cmd  : BoolIsFileCommand,
                                  b_value      : BoolSettingValue,
                                  contact_list : 'ContactList',
                                  group_list   : 'GroupList',
                                  window_list  : 'WindowList',
                                  window_uid   : WindowUID,
                                  ) -> tuple[str, str, str, str]:
    """Change setting for contacts in specified window."""
    if not window_list.has_window(window_uid):
        onion_pub_key = OnionPublicKeyContact(Ed25519PublicKey.from_public_bytes(window_uid.raw_bytes))
        raise SoftError(f"Error: Found no window for '{onion_pub_key.short_address}'.")

    window = window_list.get_or_create_window(window_uid)

    if is_file_cmd:
        enabled = [get_contact_setting(member, attr) for member in window.window_contacts]
        changed = not all(enabled) if b_value else any(enabled)
    else:
        if window.is_group_window:
            group   = window.group
            assert group is not None
            changed = get_group_setting(group, attr) != b_value
        else:
            contact = window.contact
            assert contact is not None
            changed = get_contact_setting(contact, attr) != b_value

    status    = 'has been'    if changed                               else 'was already'
    specifier = 'members in ' if (is_file_cmd and window.is_group_window) else ''
    w_type    = window.window_type
    w_name    = f' {window.window_name}.'

    # Set values
    if window.is_contact_window or (window.is_group_window and is_file_cmd):
        for c in window.window_contacts:
            set_contact_setting(c, attr, b_value)
        contact_list.store_contacts()

    elif window.is_group_window and window.group is not None:
        set_group_setting(window.group, attr, b_value)
        group_list.store_groups()

    return status, specifier, w_type, w_name


def change_setting_for_all_contacts(attr         : ContactSettingAttr,
                                    file_cmd     : BoolIsFileCommand,
                                    b_value      : BoolSettingValue,
                                    contact_list : 'ContactList',
                                    group_list   : 'GroupList'
                                    ) -> tuple[str, str, str, str]:
    """Change settings for all contacts (and groups)."""
    enabled  = [get_contact_setting(contact, attr) for contact in contact_list.get_list_of_contacts()]
    enabled += [get_group_setting(group, attr) for group in group_list] if not file_cmd else []

    status    = ('was already' if ((all(enabled) and b_value) or (not any(enabled) and not b_value)) else 'has been')
    specifier = 'every '
    w_type    = 'contact'
    w_name    = '.' if file_cmd else ' and group.'

    # Set values
    for c in contact_list.get_list_of_contacts():
        set_contact_setting(c, attr, b_value)

    contact_list.store_contacts()

    if not file_cmd:
        for g in group_list:
            set_group_setting(g, attr, b_value)
        group_list.store_groups()

    return status, specifier, w_type, w_name


def change_contact_setting(ser_cmd      : 'SerializedCommand',
                           ts           : datetime,
                           window_list  : 'WindowList',
                           contact_list : 'ContactList',
                           group_list   : 'GroupList',
                           header       : RxCommand
                           ) -> None:
    """Change contact/group related setting."""
    setting, win_uid_bytes        = separate_header(ser_cmd.command_bytes, FieldLength.CONTACT_SETTING_HEADER)
    rx_command, desc, is_file_cmd = {RxCommand.CH_LOGGING:   ( ContactSettingAttr.LOG_MESSAGES,   'Logging of messages',   BoolIsFileCommand(False) ),
                                     RxCommand.CH_FILE_RECV: ( ContactSettingAttr.FILE_RECEPTION, 'Reception of files'   , BoolIsFileCommand( True) ),
                                     RxCommand.CH_NOTIFY:    ( ContactSettingAttr.NOTIFICATIONS,  'Message notifications', BoolIsFileCommand(False) )}[header]

    setting_header = ContactSettingValueHeader(setting)
    change_all     = setting_header in [ContactSettingValueHeader.ENABLE_ALL,
                                        ContactSettingValueHeader.DISABLE_ALL]

    action, b_value = {
        ContactSettingValueHeader.ENABLE:      ('enabled',  BoolSettingValue( True)),
        ContactSettingValueHeader.ENABLE_ALL:  ('enabled',  BoolSettingValue( True)),
        ContactSettingValueHeader.DISABLE:     ('disabled', BoolSettingValue(False)),
        ContactSettingValueHeader.DISABLE_ALL: ('disabled', BoolSettingValue(False)),
    }[setting_header]

    if change_all: status, specifier, w_type, w_name = change_setting_for_all_contacts(rx_command, is_file_cmd, b_value, contact_list, group_list)
    else:          status, specifier, w_type, w_name = change_setting_for_one_window  (rx_command, is_file_cmd, b_value, contact_list, group_list,
                                                                                       window_list, WindowUID(win_uid_bytes))

    message = f'{desc} {status} {action} for {specifier}{w_type}{w_name}'

    sys_msg_win = window_list.sys_msg_win
    sys_msg_win.add_new_system_message(ts, message, output=True)
