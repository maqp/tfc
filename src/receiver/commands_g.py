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

import typing

from src.common.encoding import b58encode
from src.common.exceptions import SoftError
from src.common.misc import separate_header, split_byte_string, validate_group_name
from src.common.output import group_management_print, m_print
from src.common.statics import (
    ADDED_MEMBERS,
    ALREADY_MEMBER,
    GROUP_ID_LENGTH,
    NEW_GROUP,
    NOT_IN_GROUP,
    ONION_SERVICE_PUBLIC_KEY_LENGTH,
    REMOVED_MEMBERS,
    UNKNOWN_ACCOUNTS,
    US_BYTE,
    WIN_UID_COMMAND,
)

if typing.TYPE_CHECKING:
    from datetime import datetime
    from src.common.db_contacts import ContactList
    from src.common.db_groups import GroupList
    from src.common.db_settings import Settings
    from src.receiver.windows import WindowList


def group_create(
    cmd_data: bytes,
    ts: "datetime",
    window_list: "WindowList",
    contact_list: "ContactList",
    group_list: "GroupList",
    settings: "Settings",
) -> None:
    """Create a new group."""
    group_id, variable_len_data = separate_header(cmd_data, GROUP_ID_LENGTH)
    group_name_bytes, ser_members = variable_len_data.split(US_BYTE, 1)
    group_name = group_name_bytes.decode()

    purp_pub_keys = set(split_byte_string(ser_members, ONION_SERVICE_PUBLIC_KEY_LENGTH))
    pub_keys = set(contact_list.get_list_of_pub_keys())
    accepted = list(purp_pub_keys & pub_keys)
    rejected = list(purp_pub_keys - pub_keys)

    if len(accepted) > settings.max_number_of_group_members:
        raise SoftError(
            f"Error: TFC settings only allow {settings.max_number_of_group_members} "
            f"members per group."
        )

    if len(group_list) == settings.max_number_of_groups:
        raise SoftError(
            f"Error: TFC settings only allow {settings.max_number_of_groups} groups."
        )

    accepted_contacts = [contact_list.get_contact_by_pub_key(k) for k in accepted]
    group_list.add_group(
        group_name,
        group_id,
        settings.log_messages_by_default,
        settings.show_notifications_by_default,
        accepted_contacts,
    )

    group = group_list.get_group(group_name)
    window = window_list.get_window(group.group_id)
    window.window_contacts = accepted_contacts
    window.message_log = []
    window.unread_messages = 0
    window.create_handle_dict()

    group_management_print(NEW_GROUP, accepted, contact_list, group_name)
    group_management_print(UNKNOWN_ACCOUNTS, rejected, contact_list, group_name)

    cmd_win = window_list.get_window(WIN_UID_COMMAND)
    cmd_win.add_new(ts, f"Created new group {group_name}.")


def group_add(
    cmd_data: bytes,
    ts: "datetime",
    window_list: "WindowList",
    contact_list: "ContactList",
    group_list: "GroupList",
    settings: "Settings",
) -> None:
    """Add member(s) to group."""
    group_id, ser_members = separate_header(cmd_data, GROUP_ID_LENGTH)
    purp_pub_keys = set(split_byte_string(ser_members, ONION_SERVICE_PUBLIC_KEY_LENGTH))

    try:
        group_name = group_list.get_group_by_id(group_id).name
    except StopIteration:
        raise SoftError(f"Error: No group with ID '{b58encode(group_id)}' found.")

    pub_keys = set(contact_list.get_list_of_pub_keys())
    before_adding = set(group_list.get_group(group_name).get_list_of_member_pub_keys())
    ok_accounts = set(pub_keys & purp_pub_keys)
    new_in_group_set = set(ok_accounts - before_adding)

    end_assembly = list(before_adding | new_in_group_set)
    already_in_g = list(purp_pub_keys & before_adding)
    rejected = list(purp_pub_keys - pub_keys)
    new_in_group = list(new_in_group_set)

    if len(end_assembly) > settings.max_number_of_group_members:
        raise SoftError(
            f"Error: TFC settings only allow {settings.max_number_of_group_members} "
            f"members per group."
        )

    group = group_list.get_group(group_name)
    group.add_members([contact_list.get_contact_by_pub_key(k) for k in new_in_group])

    window = window_list.get_window(group.group_id)
    window.add_contacts(new_in_group)
    window.create_handle_dict()

    group_management_print(ADDED_MEMBERS, new_in_group, contact_list, group_name)
    group_management_print(ALREADY_MEMBER, already_in_g, contact_list, group_name)
    group_management_print(UNKNOWN_ACCOUNTS, rejected, contact_list, group_name)

    cmd_win = window_list.get_window(WIN_UID_COMMAND)
    cmd_win.add_new(ts, f"Added members to group {group_name}.")


def group_remove(
    cmd_data: bytes,
    ts: "datetime",
    window_list: "WindowList",
    contact_list: "ContactList",
    group_list: "GroupList",
) -> None:
    """Remove member(s) from the group."""
    group_id, ser_members = separate_header(cmd_data, GROUP_ID_LENGTH)
    purp_pub_keys = set(split_byte_string(ser_members, ONION_SERVICE_PUBLIC_KEY_LENGTH))

    try:
        group_name = group_list.get_group_by_id(group_id).name
    except StopIteration:
        raise SoftError(f"Error: No group with ID '{b58encode(group_id)}' found.")

    pub_keys = set(contact_list.get_list_of_pub_keys())
    before_removal = set(group_list.get_group(group_name).get_list_of_member_pub_keys())
    ok_accounts_set = set(purp_pub_keys & pub_keys)
    removable_set = set(before_removal & ok_accounts_set)

    not_in_group = list(ok_accounts_set - before_removal)
    rejected = list(purp_pub_keys - pub_keys)
    removable = list(removable_set)

    group = group_list.get_group(group_name)
    group.remove_members(removable)

    window = window_list.get_window(group.group_id)
    window.remove_contacts(removable)

    group_management_print(REMOVED_MEMBERS, removable, contact_list, group_name)
    group_management_print(NOT_IN_GROUP, not_in_group, contact_list, group_name)
    group_management_print(UNKNOWN_ACCOUNTS, rejected, contact_list, group_name)

    cmd_win = window_list.get_window(WIN_UID_COMMAND)
    cmd_win.add_new(ts, f"Removed members from group {group_name}.")


def group_delete(
    group_id: bytes, ts: "datetime", window_list: "WindowList", group_list: "GroupList"
) -> None:
    """Remove the group."""
    if not group_list.has_group_id(group_id):
        raise SoftError(f"Error: No group with ID '{b58encode(group_id)}' found.")

    name = group_list.get_group_by_id(group_id).name
    window_list.remove_window(group_id)
    group_list.remove_group_by_id(group_id)

    message = f"Removed group '{name}'."
    m_print(message, bold=True, head=1, tail=1)

    cmd_win = window_list.get_window(WIN_UID_COMMAND)
    cmd_win.add_new(ts, message)


def group_rename(
    cmd_data: bytes,
    ts: "datetime",
    window_list: "WindowList",
    contact_list: "ContactList",
    group_list: "GroupList",
) -> None:
    """Rename the group."""
    group_id, new_name_bytes = separate_header(cmd_data, GROUP_ID_LENGTH)

    try:
        group = group_list.get_group_by_id(group_id)
    except StopIteration:
        raise SoftError(f"Error: No group with ID '{b58encode(group_id)}' found.")

    try:
        new_name = new_name_bytes.decode()
    except UnicodeError:
        raise SoftError(f"Error: New name for group '{group.name}' was invalid.")

    error_msg = validate_group_name(new_name, contact_list, group_list)
    if error_msg:
        raise SoftError(error_msg)

    old_name = group.name
    group.name = new_name
    group_list.store_groups()

    window = window_list.get_window(group.group_id)
    window.name = new_name

    message = f"Renamed group '{old_name}' to '{new_name}'."
    cmd_win = window_list.get_window(WIN_UID_COMMAND)
    cmd_win.add_new(ts, message, output=True)
