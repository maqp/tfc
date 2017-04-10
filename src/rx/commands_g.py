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

from src.common.errors  import FunctionReturn
from src.common.output  import box_print, g_mgmt_print
from src.common.statics import *

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

    purpaccs = set(fields[1:])
    accounts = set(contact_list.get_list_of_accounts())

    accepted = list(accounts & purpaccs)
    rejected = list(purpaccs - accounts)

    if len(accepted) > settings.m_members_in_group:
        raise FunctionReturn("Error: TFC settings only allow {} members per group.".format(settings.m_members_in_group))

    if len(group_list) == settings.m_number_of_groups:
        raise FunctionReturn("Error: TFC settings only allow {} groups.".format(settings.m_number_of_groups))

    a_contacts = [contact_list.get_contact(c) for c in accepted]
    group_list.add_group(group_name,
                         settings.log_msg_by_default,
                         settings.n_m_notify_privacy,
                         a_contacts)

    g_mgmt_print('new_g', accepted, contact_list, group_name)
    g_mgmt_print('unkwn', rejected, contact_list, group_name)

    # Reset members in window.
    window                 = window_list.get_window(group_name)
    window.window_contacts = a_contacts
    window.message_log     = []
    window.unread_messages = 0

    local_win = window_list.get_window('local')
    local_win.print_new(ts, f"Created new group {group_name}.", print_=False)


def group_add_member(cmd_data:     bytes,
                     ts:           'datetime',
                     window_list:  'WindowList',
                     contact_list: 'ContactList',
                     group_list:   'GroupList',
                     settings:     'Settings') -> None:
    """Add member(s) to group."""
    fields     = [f.decode() for f in cmd_data.split(US_BYTE)]
    group_name = fields[0]

    purpaccs = set(fields[1:])
    accounts = set(contact_list.get_list_of_accounts())
    before_a = set(group_list.get_group(group_name).get_list_of_member_accounts())
    ok_accos = set(accounts & purpaccs)
    new_in_g = set(ok_accos - before_a)

    e_asmbly = list(before_a | new_in_g)
    rejected = list(purpaccs - accounts)
    in_alrdy = list(before_a & purpaccs)
    n_in_g_l = list(new_in_g)

    if len(e_asmbly) > settings.m_members_in_group:
        raise FunctionReturn("Error: TFC settings only allow {} members per group.".format(settings.m_members_in_group))

    group = group_list.get_group(group_name)
    group.add_members([contact_list.get_contact(a) for a in new_in_g])

    g_mgmt_print('add_m', n_in_g_l, contact_list, group_name)
    g_mgmt_print('add_a', in_alrdy, contact_list, group_name)
    g_mgmt_print('unkwn', rejected, contact_list, group_name)

    window = window_list.get_window(group_name)
    window.add_contacts(n_in_g_l)

    local_win = window_list.get_window('local')
    local_win.print_new(ts, f"Added members to group {group_name}.", print_=False)


def group_rm_member(cmd_data:     bytes,
                    ts:           'datetime',
                    window_list:  'WindowList',
                    contact_list: 'ContactList',
                    group_list:   'GroupList') -> None:
    """Remove member(s) from group."""
    fields     = [f.decode() for f in cmd_data.split(US_BYTE)]
    group_name = fields[0]

    purpaccs = set(fields[1:])
    accounts = set(contact_list.get_list_of_accounts())
    before_r = set(group_list.get_group(group_name).get_list_of_member_accounts())
    ok_accos = set(purpaccs & accounts)
    remove_s = set(before_r & ok_accos)

    not_in_g = list(ok_accos - before_r)
    rejected = list(purpaccs - accounts)
    remove_l = list(remove_s)

    group = group_list.get_group(group_name)
    group.remove_members(remove_l)

    g_mgmt_print('rem_m', remove_l, contact_list, group_name)
    g_mgmt_print('rem_n', not_in_g, contact_list, group_name)
    g_mgmt_print('unkwn', rejected, contact_list, group_name)

    window = window_list.get_window(group_name)
    window.remove_contacts(remove_l)

    local_win = window_list.get_window('local')
    local_win.print_new(ts, f"Removed members from group {group_name}.", print_=False)


def remove_group(cmd_data:    bytes,
                 ts:          'datetime',
                 window_list: 'WindowList',
                 group_list:  'GroupList') -> None:
    """Remove group."""
    group_name = cmd_data.decode()

    if group_name not in group_list.get_list_of_group_names():
        raise FunctionReturn(f"RxM has no group {group_name} to remove.")

    group_list.remove_group(group_name)

    box_print(f"Removed group {group_name}", head=1, tail=1)
    local_win = window_list.get_window('local')
    local_win.print_new(ts, f"Removed group {group_name}.", print_=False )
