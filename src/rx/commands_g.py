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

from src.common.exceptions import FunctionReturn
from src.common.output     import box_print, group_management_print
from src.common.statics    import *

if typing.TYPE_CHECKING:
    from datetime               import datetime
    from src.common.db_contacts import ContactList
    from src.common.db_groups   import GroupList
    from src.common.db_settings import Settings
    from src.rx.windows         import WindowList


def group_create(cmd_data:     bytes,
                 ts:           'datetime',
                 window_list:  'WindowList',
                 contact_list: 'ContactList',
                 group_list:   'GroupList',
                 settings:     'Settings') -> None:
    """Create a new group."""
    fields     = [f.decode() for f in cmd_data.split(US_BYTE)]
    group_name = fields[0]

    purp_accounts = set(fields[1:])
    accounts      = set(contact_list.get_list_of_accounts())
    accepted      = list(accounts      & purp_accounts)
    rejected      = list(purp_accounts - accounts)

    if len(accepted) > settings.max_number_of_group_members:
        raise FunctionReturn(f"Error: TFC settings only allow {settings.max_number_of_group_members} members per group.")

    if len(group_list) == settings.max_number_of_groups:
        raise FunctionReturn(f"Error: TFC settings only allow {settings.max_number_of_groups} groups.")

    accepted_contacts = [contact_list.get_contact(c) for c in accepted]
    group_list.add_group(group_name,
                         settings.log_messages_by_default,
                         settings.show_notifications_by_default,
                         accepted_contacts)

    window                 = window_list.get_window(group_name)
    window.window_contacts = accepted_contacts
    window.message_log     = []
    window.unread_messages = 0
    window.create_handle_dict()

    group_management_print(NEW_GROUP,        accepted, contact_list, group_name)
    group_management_print(UNKNOWN_ACCOUNTS, rejected, contact_list, group_name)

    local_win = window_list.get_window(LOCAL_ID)
    local_win.add_new(ts, f"Created new group {group_name}.")


def group_add_member(cmd_data:     bytes,
                     ts:           'datetime',
                     window_list:  'WindowList',
                     contact_list: 'ContactList',
                     group_list:   'GroupList',
                     settings:     'Settings') -> None:
    """Add member(s) to group."""
    fields     = [f.decode() for f in cmd_data.split(US_BYTE)]
    group_name = fields[0]

    purp_accounts    = set(fields[1:])
    accounts         = set(contact_list.get_list_of_accounts())
    before_adding    = set(group_list.get_group(group_name).get_list_of_member_accounts())
    ok_accounts      = set(accounts    & purp_accounts)
    new_in_group_set = set(ok_accounts - before_adding)

    end_assembly = list(before_adding | new_in_group_set)
    rejected     = list(purp_accounts - accounts)
    already_in_g = list(before_adding & purp_accounts)
    new_in_group = list(new_in_group_set)

    if len(end_assembly) > settings.max_number_of_group_members:
        raise FunctionReturn(f"Error: TFC settings only allow {settings.max_number_of_group_members} members per group.")

    group = group_list.get_group(group_name)
    group.add_members([contact_list.get_contact(a) for a in new_in_group])

    window = window_list.get_window(group_name)
    window.add_contacts(new_in_group)
    window.create_handle_dict()

    group_management_print(ADDED_MEMBERS,    new_in_group, contact_list, group_name)
    group_management_print(ALREADY_MEMBER,   already_in_g, contact_list, group_name)
    group_management_print(UNKNOWN_ACCOUNTS, rejected,     contact_list, group_name)

    local_win = window_list.get_window(LOCAL_ID)
    local_win.add_new(ts, f"Added members to group {group_name}.")


def group_rm_member(cmd_data:     bytes,
                    ts:           'datetime',
                    window_list:  'WindowList',
                    contact_list: 'ContactList',
                    group_list:   'GroupList') -> None:
    """Remove member(s) from group."""
    fields     = [f.decode() for f in cmd_data.split(US_BYTE)]
    group_name = fields[0]

    purp_accounts   = set(fields[1:])
    accounts        = set(contact_list.get_list_of_accounts())
    before_removal  = set(group_list.get_group(group_name).get_list_of_member_accounts())
    ok_accounts_set = set(purp_accounts  & accounts)
    removable_set   = set(before_removal & ok_accounts_set)

    not_in_group    = list(ok_accounts_set - before_removal)
    rejected        = list(purp_accounts   - accounts)
    removable       = list(removable_set)

    group = group_list.get_group(group_name)
    group.remove_members(removable)

    window = window_list.get_window(group_name)
    window.remove_contacts(removable)

    group_management_print(REMOVED_MEMBERS,  removable,    contact_list, group_name)
    group_management_print(NOT_IN_GROUP,     not_in_group, contact_list, group_name)
    group_management_print(UNKNOWN_ACCOUNTS, rejected,     contact_list, group_name)

    local_win = window_list.get_window(LOCAL_ID)
    local_win.add_new(ts, f"Removed members from group {group_name}.")


def remove_group(cmd_data:    bytes,
                 ts:          'datetime',
                 window_list: 'WindowList',
                 group_list:  'GroupList') -> None:
    """Remove group."""
    group_name = cmd_data.decode()

    window_list.remove_window(group_name)

    if group_name not in group_list.get_list_of_group_names():
        raise FunctionReturn(f"RxM has no group '{group_name}' to remove.")

    group_list.remove_group(group_name)

    message = f"Removed group {group_name}."
    box_print(message, head=1, tail=1)

    local_win = window_list.get_window(LOCAL_ID)
    local_win.add_new(ts, message)
