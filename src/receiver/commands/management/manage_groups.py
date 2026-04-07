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

from src.common.entities.window_uid import WindowUID
from src.common.entities.group_id import GroupID
from src.common.entities.group_name import GroupName
from src.common.utils.encoding import b58encode
from src.common.exceptions import SoftError, ValidationError
from src.common.crypto.keys.onion_service_keys import OnionPublicKeyContact
from src.common.utils.strings import split_byte_string, separate_header
from src.common.utils.validators import validate_group_name
from src.common.statics import GroupMsgID, Separator, FieldLength
from src.ui.common.output.print_message import print_message
from src.ui.common.output.print_group_mgmt_msg import group_management_print

if TYPE_CHECKING:
    from src.common.entities.serialized_command import SerializedCommand
    from src.database.db_contacts import ContactList
    from src.database.db_groups import GroupList
    from src.database.db_settings import Settings
    from src.ui.receiver.window_rx import WindowList



def get_contact_pub_keys(contact_list: 'ContactList') -> set[OnionPublicKeyContact]:
    """Return stored contact public keys as contact-key objects.

    Receiver trusts Transmitter to enforce key-exchange policy, so any
    known contact is eligible for Receiver-side group updates.
    """
    return {OnionPublicKeyContact(contact.onion_pub_key.ed_25519_pub_key)
            for contact in contact_list.get_list_of_contacts()}


def group_create(ser_cmd      : 'SerializedCommand',
                 ts           : datetime,
                 window_list  : 'WindowList',
                 contact_list : 'ContactList',
                 group_list   : 'GroupList',
                 settings     : 'Settings'
                 ) -> None:
    """Create a new group."""
    group_id, variable_len_data   = separate_header(ser_cmd.command_bytes, FieldLength.GROUP_ID)
    group_name_bytes, ser_members = variable_len_data.split(Separator.US_BYTE, 1)
    group_name                    = GroupName(group_name_bytes.decode())

    enc_addresses   = split_byte_string(ser_members, FieldLength.ONION_ADDRESS)
    o_purp_pub_keys = {OnionPublicKeyContact.from_onion_address_bytes(enc_addr) for enc_addr in enc_addresses}
    o_pub_keys      = get_contact_pub_keys(contact_list)
    o_accepted      = list(o_purp_pub_keys & o_pub_keys)
    o_rejected      = list(o_purp_pub_keys - o_pub_keys)

    if len(o_accepted) > settings.max_number_of_group_members:
        raise SoftError(f'Error: TFC settings only allow {settings.max_number_of_group_members} members per group.')

    if len(group_list) == settings.max_number_of_groups:
        raise SoftError(f'Error: TFC settings only allow {settings.max_number_of_groups} groups.')

    accepted_contacts = [contact_list.get_contact_by_pub_key(o_pub_key) for o_pub_key in o_accepted]
    group_list.add_group(group_name,
                         GroupID(group_id),
                         settings.log_messages_by_default,
                         settings.show_notifications_by_default,
                         accepted_contacts)

    group = group_list.get_group(group_name)

    window_list.get_or_create_window(WindowUID.for_group(group))

    group_management_print(GroupMsgID.NEW_GROUP,        o_accepted, contact_list, group_name)
    group_management_print(GroupMsgID.UNKNOWN_ACCOUNTS, o_rejected, contact_list, group_name)

    sys_msg_win = window_list.sys_msg_win
    sys_msg_win.add_new_system_message(ts, f'Created new group {group_name}.')


def group_add(ser_cmd      : 'SerializedCommand',
              ts           : datetime,
              window_list  : 'WindowList',
              contact_list : 'ContactList',
              group_list   : 'GroupList',
              settings     : 'Settings'
              ) -> None:
    """Add member(s) to group."""
    group_id, ser_members = separate_header(ser_cmd.command_bytes, FieldLength.GROUP_ID)

    enc_addresses   = split_byte_string(ser_members, FieldLength.ONION_ADDRESS)
    o_purp_pub_keys = {OnionPublicKeyContact.from_onion_address_bytes(enc_addr) for enc_addr in enc_addresses}

    try:
        group_name = group_list.get_group_by_id(GroupID(group_id)).group_name
    except KeyError:
        raise SoftError(f"Error: No group with ID '{b58encode(group_id)}' found.")

    o_pub_keys          = get_contact_pub_keys(contact_list)
    o_before_adding     = set(group_list.get_group(group_name).get_list_of_member_pub_keys())
    o_ok_pub_keys_set   = o_pub_keys & o_purp_pub_keys
    o_new_in_group_set  = o_ok_pub_keys_set - o_before_adding

    end_assembly               = list(o_before_adding | o_new_in_group_set)
    o_already_in_g_contacts    = list(o_purp_pub_keys & o_before_adding)
    o_unknown_users            = list(o_purp_pub_keys - o_pub_keys)
    o_new_in_group_contacts    = list(o_new_in_group_set)

    if len(end_assembly) > settings.max_number_of_group_members:
        raise SoftError(f'Error: TFC settings only allow {settings.max_number_of_group_members} members per group.')

    group = group_list.get_group(group_name)
    group.add_members([contact_list.get_contact_by_pub_key(o_pub_key) for o_pub_key in o_new_in_group_contacts])

    group_management_print(GroupMsgID.ADDED_MEMBERS,    o_new_in_group_contacts, contact_list, group_name)
    group_management_print(GroupMsgID.ALREADY_MEMBER,   o_already_in_g_contacts, contact_list, group_name)
    group_management_print(GroupMsgID.UNKNOWN_ACCOUNTS, o_unknown_users,         contact_list, group_name)

    sys_msg_win = window_list.sys_msg_win
    sys_msg_win.add_new_system_message(ts, f'Added members to group {group_name}.')


def group_remove(ser_cmd      : 'SerializedCommand',
                 ts           : datetime,
                 window_list  : 'WindowList',
                 contact_list : 'ContactList',
                 group_list   : 'GroupList'
                 ) -> None:
    """Remove member(s) from the group."""
    group_id, ser_members = separate_header(ser_cmd.command_bytes, FieldLength.GROUP_ID)

    enc_addresses   = split_byte_string(ser_members, FieldLength.ONION_ADDRESS)
    o_purp_pub_keys = {OnionPublicKeyContact.from_onion_address_bytes(enc_addr) for enc_addr in enc_addresses}

    try:
        group_name = group_list.get_group_by_id(GroupID(group_id)).group_name
    except KeyError:
        raise SoftError(f"Error: No group with ID '{b58encode(group_id)}' found.")

    o_pub_keys         = get_contact_pub_keys(contact_list)
    o_before_removal   = set(group_list.get_group(group_name).get_list_of_member_pub_keys())
    o_ok_pub_keys_set  = o_purp_pub_keys & o_pub_keys
    o_removable_set    = o_before_removal & o_ok_pub_keys_set

    o_not_in_group = list(o_ok_pub_keys_set - o_before_removal)
    o_rejected     = list(o_purp_pub_keys   - o_pub_keys)
    o_removable    = list(o_removable_set)

    group = group_list.get_group(group_name)
    group.remove_members(o_removable)

    group_management_print(GroupMsgID.REMOVED_MEMBERS,  o_removable,    contact_list, group_name)
    group_management_print(GroupMsgID.NOT_IN_GROUP,     o_not_in_group, contact_list, group_name)
    group_management_print(GroupMsgID.UNKNOWN_ACCOUNTS, o_rejected,     contact_list, group_name)

    sys_msg_win = window_list.sys_msg_win
    sys_msg_win.add_new_system_message(ts, f'Removed members from group {group_name}.')


def group_delete(ser_cmd     : 'SerializedCommand',
                 ts          : datetime,
                 window_list : 'WindowList',
                 group_list  : 'GroupList'
                 ) -> None:
    """Remove the group."""
    group_id = GroupID(ser_cmd.command_bytes)

    if not group_list.has_group_id(group_id):
        raise SoftError(f"Error: No group with ID '{group_id.hr_value}' found.")

    name = group_list.get_group_by_id(group_id).group_name
    window_list.remove_window(WindowUID(group_id.raw_bytes))
    group_list.remove_group_by_id(group_id)

    message = f"Removed group '{name}'."
    print_message(message, bold=True, padding_top=1, padding_bottom=1)

    sys_msg_win = window_list.sys_msg_win
    sys_msg_win.add_new_system_message(ts, message)


def group_rename(ser_cmd      : 'SerializedCommand',
                 ts           : datetime,
                 window_list  : 'WindowList',
                 contact_list : 'ContactList',
                 group_list   : 'GroupList'
                 ) -> None:
    """Rename the group."""
    group_id_bytes, new_name_bytes = separate_header(ser_cmd.command_bytes, FieldLength.GROUP_ID)

    group_id = GroupID(group_id_bytes)

    try:
        group = group_list.get_group_by_id(group_id)
    except KeyError:
        raise SoftError(f"Error: No group with ID '{group_id.hr_value}' found.")

    try:
        new_name_str = new_name_bytes.decode()
    except UnicodeError:
        raise SoftError(f"Error: New name for group '{group.group_name}' was invalid.")

    try:
        validate_group_name(new_name_str, contact_list, group_list)
    except ValidationError as e:
        raise SoftError(e.args[0])

    old_name         = group.group_name
    group.group_name = GroupName(new_name_str)
    group_list.store_groups()

    message     = f"Renamed group '{old_name}' to '{new_name_str}'."
    sys_msg_win = window_list.sys_msg_win
    sys_msg_win.add_new_system_message(ts, message, output=True)
