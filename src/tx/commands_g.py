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

import re
import typing

from typing import Dict, List

from src.common.errors  import FunctionReturn
from src.common.input   import yes
from src.common.output  import box_print, g_mgmt_print
from src.common.statics import *
from src.tx.messages    import Message, queue_message
from src.tx.packet      import queue_command

if typing.TYPE_CHECKING:
    from multiprocessing        import Queue
    from src.common.db_contacts import Contact, ContactList
    from src.common.db_groups   import Group, GroupList
    from src.common.db_settings import Settings
    from src.tx.user_input      import UserInput


class MockWindow(object):
    """Mock window simplifies queueing of message assembly packets."""

    def __init__(self, uid: str, contacts: List['Contact']) -> None:
        """Create new mock window."""
        self.uid             = uid
        self.window_contacts = contacts
        self.type            = 'contact'
        self.group           = None  # type: Group
        self.name            = None  # type: str

    def __iter__(self) -> 'MockWindow':
        """Iterate over contact objects in window."""
        for c in self.window_contacts:
            yield c


def process_group_command(user_input:   'UserInput',
                          contact_list: 'ContactList',
                          group_list:   'GroupList',
                          settings:     'Settings',
                          queues:       Dict[bytes, 'Queue']) -> None:
    """Parse group command and process it accordingly."""
    if settings.session_trickle:
        raise FunctionReturn("Command disabled during trickle connection.")

    params = user_input.plaintext

    try:
        command_type = params.split()[1]
    except IndexError:
        raise FunctionReturn("Invalid group command.")

    if command_type not in ['create', 'add', 'rm']:
        raise FunctionReturn("Invalid group command.")

    try:
        group_name = params.split()[2]
    except IndexError:
        raise FunctionReturn("No group name specified.")

    purp_members = params.split()[3:]

    # Swap specified nicks to rx_accounts
    for i, m in enumerate(purp_members):
        if m in contact_list.get_list_of_nicks():
            purp_members[i] = contact_list.get_contact(m).rx_account

    func = dict(create=group_create,
                add   =group_add_member,
                rm    =group_rm_member)[command_type]

    func(group_name, purp_members, group_list, contact_list, settings, queues)


def group_create(group_name:   str,          # Name of group to manage
                 purp_members: List[str],    # Members specified by user
                 group_list:   'GroupList',
                 contact_list: 'ContactList',
                 settings:     'Settings',
                 queues:       Dict[bytes, 'Queue']) -> None:
    """Create a new group.
    
    Validate group name and determine what members that can be added.
    """
    # Avoids collision with delimiters
    if not group_name.isprintable():
        raise FunctionReturn("Group name must be printable.")

    # Length limited by database's unicode padding
    if len(group_name) > 254:
        raise FunctionReturn("Group name must be less than 255 chars long.")

    if group_name == 'dummy_group':
        raise FunctionReturn("Group name can't use name reserved for database padding.")

    if re.match(ACCOUNT_FORMAT, group_name):
        raise FunctionReturn("Group name can't have format of an account.")

    if group_name in contact_list.get_list_of_nicks():
        raise FunctionReturn("Group name can't be nick of contact.")

    if group_name in group_list.get_list_of_group_names():
        if not yes(f"Group with name {group_name} already exists. Overwrite?"):
            raise FunctionReturn("Group creation aborted.")

    accounts = set(contact_list.get_list_of_accounts())
    purpaccs = set(purp_members)

    accepted = list(accounts & purpaccs)
    rejected = list(purpaccs - accounts)

    if len(accepted) > settings.m_members_in_group:
        raise FunctionReturn("Error: TFC settings only allow {} members per group."
                             .format(settings.m_members_in_group))

    if len(group_list) == settings.m_number_of_groups:
        raise FunctionReturn("Error: TFC settings only allow {} groups."
                             .format(settings.m_number_of_groups))

    a_contacts = [contact_list.get_contact(c) for c in accepted]
    group_list.add_group(group_name,
                         settings.log_msg_by_default,
                         settings.n_m_notify_privacy,
                         a_contacts)

    fields = [f.encode() for f in ([group_name] + accepted)]
    packet = GROUP_CREATE_HEADER + US_BYTE.join(fields)
    queue_command(packet, settings, queues[COMMAND_PACKET_QUEUE])

    g_mgmt_print('new_g', accepted, contact_list, group_name)
    g_mgmt_print('unkwn', rejected, contact_list, group_name)

    if accepted:
        if yes("Publish list of group members to participants?"):
            for member in accepted:
                m_list = accepted[:]
                m_list.remove(member)
                message  = Message(US_STR.join([group_name] + m_list))
                contact  = contact_list.get_contact(member)
                mock_win = MockWindow(contact.rx_account, [contact])
                queue_message(message, mock_win, settings, queues[MESSAGE_PACKET_QUEUE], header=GROUP_MSG_INVITATION_HEADER)

    else:
        box_print(f"Created an empty group {group_name}.", head=1)
    print('')


def group_add_member(group_name:   str,
                     purp_members: List['str'],
                     group_list:   'GroupList',
                     contact_list: 'ContactList',
                     settings:     'Settings',
                     queues:       Dict[bytes, 'Queue']) -> None:
    """Add new member(s) to group."""
    if group_name not in group_list.get_list_of_group_names():
        if yes(f"Group {group_name} was not found. Create new group?"):
            group_create(group_name, purp_members, group_list, contact_list, settings, queues)
            return None
        else:
            raise FunctionReturn("Group creation aborted.")

    purpaccs = set(purp_members)
    accounts = set(contact_list.get_list_of_accounts())
    before_a = set(group_list.get_group(group_name).get_list_of_member_accounts())
    ok_accos = set(accounts & purpaccs)
    new_in_g = set(ok_accos - before_a)

    e_asmbly = list(before_a | new_in_g)
    rejected = list(purpaccs - accounts)
    in_alrdy = list(before_a & purpaccs)
    n_in_g_l = list(new_in_g)
    ok_accol = list(ok_accos)

    if len(e_asmbly) > settings.m_members_in_group:
        raise FunctionReturn("Error: TFC settings only allow {} members per group."
                             .format(settings.m_members_in_group))

    group = group_list.get_group(group_name)
    group.add_members([contact_list.get_contact(a) for a in new_in_g])

    fields = [f.encode() for f in ([group_name] + ok_accol)]
    packet = GROUP_ADD_HEADER + US_BYTE.join(fields)
    queue_command(packet, settings, queues[COMMAND_PACKET_QUEUE])

    g_mgmt_print('add_m', n_in_g_l, contact_list, group_name)
    g_mgmt_print('add_a', in_alrdy, contact_list, group_name)
    g_mgmt_print('unkwn', rejected, contact_list, group_name)

    if new_in_g:
        if yes("Publish new list of members to involved?"):
            for member in before_a:
                message  = Message(US_STR.join([group_name] + n_in_g_l))
                contact  = contact_list.get_contact(member)
                mock_win = MockWindow(contact.rx_account, [contact])
                queue_message(message, mock_win, settings, queues[MESSAGE_PACKET_QUEUE],
                              header=GROUP_MSG_ADD_NOTIFY_HEADER)

            for member_ in new_in_g:
                m_list = e_asmbly[:]
                m_list.remove(member_)
                message  = Message(US_STR.join([group_name] + m_list))
                contact  = contact_list.get_contact(member_)
                mock_win = MockWindow(contact.rx_account, [contact])
                queue_message(message, mock_win, settings, queues[MESSAGE_PACKET_QUEUE], header=GROUP_MSG_INVITATION_HEADER)
    print('')


def group_rm_member(group_name:   str,
                    purp_members: List[str],
                    group_list:   'GroupList',
                    contact_list: 'ContactList',
                    settings:     'Settings',
                    queues:       Dict[bytes, 'Queue']) -> None:
    """Remove member(s) from group or group itself if no members are specified. """
    purpaccs = set(purp_members)

    if not purpaccs:
        if not yes(f"Remove group '{group_name}'?", head=1):
            raise FunctionReturn("Group removal aborted.")

        packet = GROUP_DELETE_HEADER + group_name.encode()
        queue_command(packet, settings, queues[COMMAND_PACKET_QUEUE])

        if group_name not in group_list.get_list_of_group_names():
            raise FunctionReturn(f"TxM has no group {group_name} to remove.")

        group = group_list.get_group(group_name)
        if group.has_members():
            if yes("Notify members about leaving the group?"):
                message = Message(group_name)
                for member in group:
                    mock_win = MockWindow(member.rx_account, [member])
                    queue_message(message, mock_win, settings, queues[MESSAGE_PACKET_QUEUE], header=GROUP_MSG_EXIT_GROUP_HEADER)

        group_list.remove_group(group_name)
        raise FunctionReturn(f"Removed group {group_name}.")

    if group_name not in group_list.get_list_of_group_names():
        raise FunctionReturn(f"Group '{group_name}' does not exist.")

    accounts = set(contact_list.get_list_of_accounts())
    before_r = set(group_list.get_group(group_name).get_list_of_member_accounts())
    ok_accos = set(purpaccs & accounts)
    remove_s = set(before_r & ok_accos)

    e_asmbly = list(before_r - remove_s)
    not_in_g = list(ok_accos - before_r)
    rejected = list(purpaccs - accounts)
    remove_l = list(remove_s)
    ok_accol = list(ok_accos)

    group = group_list.get_group(group_name)
    group.remove_members(remove_l)

    fields = [f.encode() for f in ([group_name] + ok_accol)]
    packet = GROUP_REMOVE_M_HEADER + US_BYTE.join(fields)
    queue_command(packet, settings, queues[COMMAND_PACKET_QUEUE])

    g_mgmt_print('rem_m', remove_l, contact_list, group_name)
    g_mgmt_print('rem_n', not_in_g, contact_list, group_name)
    g_mgmt_print('unkwn', rejected, contact_list, group_name)

    if remove_l and e_asmbly:
        if yes("Publish list of removed members to remaining members?"):
            for member_ in e_asmbly:
                message  = Message(US_STR.join([group_name] + remove_l))
                contact  = contact_list.get_contact(member_)
                mock_win = MockWindow(contact.rx_account, [contact])
                queue_message(message, mock_win, settings, queues[MESSAGE_PACKET_QUEUE], header=GROUP_MSG_MEMBER_RM_HEADER)
    print('')
