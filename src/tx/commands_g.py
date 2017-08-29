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

from typing import Callable, Dict, List

from src.common.db_logs    import remove_logs
from src.common.exceptions import FunctionReturn
from src.common.input      import yes
from src.common.misc       import ignored
from src.common.output     import box_print, group_management_print
from src.common.statics    import *

from src.tx.user_input import UserInput
from src.tx.packet     import queue_command, queue_message
from src.tx.windows    import MockWindow

if typing.TYPE_CHECKING:
    from multiprocessing         import Queue
    from src.common.db_contacts  import ContactList
    from src.common.db_groups    import GroupList
    from src.common.db_masterkey import MasterKey
    from src.common.db_settings  import Settings


def process_group_command(user_input:   'UserInput',
                          contact_list: 'ContactList',
                          group_list:   'GroupList',
                          settings:     'Settings',
                          queues:       Dict[bytes, 'Queue'],
                          master_key:   'MasterKey') -> None:
    """Parse group command and process it accordingly."""
    if settings.session_traffic_masking:
        raise FunctionReturn("Error: Command is disabled during traffic masking.")

    try:
        command_type = user_input.plaintext.split()[1]  # type: str
    except IndexError:
        raise FunctionReturn("Error: Invalid group command.")

    if command_type not in ['create', 'add', 'rm', 'join']:
        raise FunctionReturn("Error: Invalid group command.")

    try:
        group_name = user_input.plaintext.split()[2]  # type: str
    except IndexError:
        raise FunctionReturn("Error: No group name specified.")

    purp_members = user_input.plaintext.split()[3:]  # type: List[str]

    # Swap specified nicks to rx_accounts
    for i, m in enumerate(purp_members):
        if m in contact_list.get_list_of_nicks():
            purp_members[i] = contact_list.get_contact(m).rx_account

    func_d = dict(create=group_create,
                  join  =group_create,
                  add   =group_add_member,
                  rm    =group_rm_member)  # type: Dict[str, Callable]

    func = func_d[command_type]
    func(group_name, purp_members, group_list, contact_list, settings, queues, master_key)
    print('')


def validate_group_name(group_name: str, contact_list: 'ContactList', group_list: 'GroupList') -> None:
    """Check that group name is valid."""
    # Avoids collision with delimiters
    if not group_name.isprintable():
        raise FunctionReturn("Error: Group name must be printable.")

    # Length limited by database's unicode padding
    if len(group_name) >= PADDING_LEN:
        raise FunctionReturn("Error: Group name must be less than 255 chars long.")

    if group_name == DUMMY_GROUP:
        raise FunctionReturn("Error: Group name can't use name reserved for database padding.")

    if re.match(ACCOUNT_FORMAT, group_name):
        raise FunctionReturn("Error: Group name can't have format of an account.")

    if group_name in contact_list.get_list_of_nicks():
        raise FunctionReturn("Error: Group name can't be nick of contact.")

    if group_name in group_list.get_list_of_group_names():
        if not yes(f"Group with name '{group_name}' already exists. Overwrite?", head=1):
            raise FunctionReturn("Group creation aborted.")


def group_create(group_name:   str,
                 purp_members: List[str],
                 group_list:   'GroupList',
                 contact_list: 'ContactList',
                 settings:     'Settings',
                 queues:       Dict[bytes, 'Queue'],
                 _:            'MasterKey') -> None:
    """Create a new group.
    
    Validate group name and determine what members that can be added.
    """
    validate_group_name(group_name, contact_list, group_list)

    accounts      = set(contact_list.get_list_of_accounts())
    purp_accounts = set(purp_members)
    accepted      = list(accounts      & purp_accounts)
    rejected      = list(purp_accounts - accounts)

    if len(accepted) > settings.max_number_of_group_members:
        raise FunctionReturn(f"Error: TFC settings only allow {settings.max_number_of_group_members} members per group.")

    if len(group_list) == settings.max_number_of_groups:
        raise FunctionReturn(f"Error: TFC settings only allow {settings.max_number_of_groups} groups.")

    group_list.add_group(group_name,
                         settings.log_messages_by_default,
                         settings.show_notifications_by_default,
                         members=[contact_list.get_contact(c) for c in accepted])

    fields  = [f.encode() for f in ([group_name] + accepted)]
    command = GROUP_CREATE_HEADER + US_BYTE.join(fields)
    queue_command(command, settings, queues[COMMAND_PACKET_QUEUE])

    group_management_print(NEW_GROUP,        accepted, contact_list, group_name)
    group_management_print(UNKNOWN_ACCOUNTS, rejected, contact_list, group_name)

    if accepted:
        if yes("Publish list of group members to participants?"):
            for member in accepted:
                m_list = [m for m in accepted if m != member]
                queue_message(user_input=UserInput(US_STR.join([group_name] + m_list), MESSAGE),
                              window    =MockWindow(member, [contact_list.get_contact(member)]),
                              settings  =settings,
                              m_queue   =queues[MESSAGE_PACKET_QUEUE],
                              header    =GROUP_MSG_INVITEJOIN_HEADER,
                              log_as_ph =True)
    else:
        box_print(f"Created an empty group '{group_name}'", head=1)


def group_add_member(group_name:   str,
                     purp_members: List['str'],
                     group_list:   'GroupList',
                     contact_list: 'ContactList',
                     settings:     'Settings',
                     queues:       Dict[bytes, 'Queue'],
                     master_key:   'MasterKey') -> None:
    """Add new member(s) to group."""
    if group_name not in group_list.get_list_of_group_names():
        if yes(f"Group {group_name} was not found. Create new group?", head=1):
            group_create(group_name, purp_members, group_list, contact_list, settings, queues, master_key)
            return None
        else:
            raise FunctionReturn("Group creation aborted.")

    purp_accounts    = set(purp_members)
    accounts         = set(contact_list.get_list_of_accounts())
    before_adding    = set(group_list.get_group(group_name).get_list_of_member_accounts())
    ok_accounts_set  = set(accounts        & purp_accounts)
    new_in_group_set = set(ok_accounts_set - before_adding)

    end_assembly = list(before_adding | new_in_group_set)
    rejected     = list(purp_accounts - accounts)
    already_in_g = list(before_adding & purp_accounts)
    new_in_group = list(new_in_group_set)
    ok_accounts  = list(ok_accounts_set)

    if len(end_assembly) > settings.max_number_of_group_members:
        raise FunctionReturn(f"Error: TFC settings only allow {settings.max_number_of_group_members} members per group.")

    group = group_list.get_group(group_name)
    group.add_members([contact_list.get_contact(a) for a in new_in_group])

    fields  = [f.encode() for f in ([group_name] + ok_accounts)]
    command = GROUP_ADD_HEADER + US_BYTE.join(fields)
    queue_command(command, settings, queues[COMMAND_PACKET_QUEUE])

    group_management_print(ADDED_MEMBERS,    new_in_group, contact_list, group_name)
    group_management_print(ALREADY_MEMBER,   already_in_g, contact_list, group_name)
    group_management_print(UNKNOWN_ACCOUNTS, rejected,     contact_list, group_name)

    if new_in_group:
        if yes("Publish new list of members to involved?"):
            for member in before_adding:
                queue_message(user_input=UserInput(US_STR.join([group_name] + new_in_group), MESSAGE),
                              window    =MockWindow(member, [contact_list.get_contact(member)]),
                              settings  =settings,
                              m_queue   =queues[MESSAGE_PACKET_QUEUE],
                              header    =GROUP_MSG_MEMBER_ADD_HEADER,
                              log_as_ph =True)

            for member in new_in_group:
                m_list = [m for m in end_assembly if m != member]
                queue_message(user_input=UserInput(US_STR.join([group_name] + m_list), MESSAGE),
                              window    =MockWindow(member, [contact_list.get_contact(member)]),
                              settings  =settings,
                              m_queue   =queues[MESSAGE_PACKET_QUEUE],
                              header    =GROUP_MSG_INVITEJOIN_HEADER,
                              log_as_ph =True)


def group_rm_member(group_name:   str,
                    purp_members: List[str],
                    group_list:   'GroupList',
                    contact_list: 'ContactList',
                    settings:     'Settings',
                    queues:       Dict[bytes, 'Queue'],
                    master_key:   'MasterKey') -> None:
    """Remove member(s) from group or group itself."""
    if not purp_members:
        group_rm_group(group_name, group_list, settings, queues, master_key)

    if group_name not in group_list.get_list_of_group_names():
        raise FunctionReturn(f"Group '{group_name}' does not exist.")

    purp_accounts   = set(purp_members)
    accounts        = set(contact_list.get_list_of_accounts())
    before_removal  = set(group_list.get_group(group_name).get_list_of_member_accounts())
    ok_accounts_set = set(purp_accounts  & accounts)
    removable_set   = set(before_removal & ok_accounts_set)

    end_assembly = list(before_removal  - removable_set)
    not_in_group = list(ok_accounts_set - before_removal)
    rejected     = list(purp_accounts   - accounts)
    removable    = list(removable_set)
    ok_accounts  = list(ok_accounts_set)

    group = group_list.get_group(group_name)
    group.remove_members(removable)

    fields  = [f.encode() for f in ([group_name] + ok_accounts)]
    command = GROUP_REMOVE_M_HEADER + US_BYTE.join(fields)
    queue_command(command, settings, queues[COMMAND_PACKET_QUEUE])

    group_management_print(REMOVED_MEMBERS,  removable,    contact_list, group_name)
    group_management_print(NOT_IN_GROUP,     not_in_group, contact_list, group_name)
    group_management_print(UNKNOWN_ACCOUNTS, rejected,     contact_list, group_name)

    if removable and end_assembly and yes("Publish list of removed members to remaining members?"):
        for member in end_assembly:
            queue_message(user_input=UserInput(US_STR.join([group_name] + removable), MESSAGE),
                          window    =MockWindow(member, [contact_list.get_contact(member)]),
                          settings  =settings,
                          m_queue   =queues[MESSAGE_PACKET_QUEUE],
                          header    =GROUP_MSG_MEMBER_REM_HEADER,
                          log_as_ph =True)


def group_rm_group(group_name: str,
                   group_list: 'GroupList',
                   settings:   'Settings',
                   queues:     Dict[bytes, 'Queue'],
                   master_key: 'MasterKey'):
    """Remove group with it's members."""
    if not yes(f"Remove group '{group_name}'?", head=1):
        raise FunctionReturn("Group removal aborted.")

    rm_logs = yes("Also remove logs for the group?", head=1)

    command = GROUP_DELETE_HEADER + group_name.encode()
    queue_command(command, settings, queues[COMMAND_PACKET_QUEUE])

    if rm_logs:
        command = LOG_REMOVE_HEADER + group_name.encode()
        queue_command(command, settings, queues[COMMAND_PACKET_QUEUE])
        with ignored(FunctionReturn):
            remove_logs(group_name, settings, master_key)

    if group_name not in group_list.get_list_of_group_names():
        raise FunctionReturn(f"TxM has no group '{group_name}' to remove.")

    group = group_list.get_group(group_name)
    if group.has_members() and yes("Notify members about leaving the group?"):
        for member in group:
            queue_message(user_input=UserInput(group_name, MESSAGE),
                          window    =MockWindow(member.rx_account, [member]),
                          settings  =settings,
                          m_queue   =queues[MESSAGE_PACKET_QUEUE],
                          header    =GROUP_MSG_EXIT_GROUP_HEADER,
                          log_as_ph =True)

    group_list.remove_group(group_name)
    raise FunctionReturn(f"Removed group '{group_name}'")
