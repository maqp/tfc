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

import os
import typing

from typing import Any, Callable, Dict, List, Optional

from src.common.db_logs    import remove_logs
from src.common.encoding   import b58decode, int_to_bytes
from src.common.exceptions import FunctionReturn
from src.common.input      import yes
from src.common.misc       import ignored, validate_group_name
from src.common.output     import group_management_print, m_print
from src.common.statics    import *

from src.transmitter.packet     import queue_command, queue_to_nc
from src.transmitter.user_input import UserInput

if typing.TYPE_CHECKING:
    from multiprocessing         import Queue
    from src.common.db_contacts  import ContactList
    from src.common.db_groups    import GroupList
    from src.common.db_masterkey import MasterKey
    from src.common.db_settings  import Settings
    from src.transmitter.windows import TxWindow
    QueueDict = Dict[bytes, Queue[Any]]
    FuncDict  = (Dict[str, Callable[[str,
                                     List[bytes],
                                     ContactList,
                                     GroupList,
                                     Settings,
                                     QueueDict,
                                     MasterKey,
                                     Optional[bytes]],
                                    None]])


def process_group_command(user_input:   'UserInput',
                          contact_list: 'ContactList',
                          group_list:   'GroupList',
                          settings:     'Settings',
                          queues:       'QueueDict',
                          master_key:   'MasterKey'
                          ) -> None:
    """Parse a group command and process it accordingly."""
    if settings.traffic_masking:
        raise FunctionReturn("Error: Command is disabled during traffic masking.", head_clear=True)

    input_parameters = user_input.plaintext.split()  # type: List[str]

    try:
        command_type = input_parameters[1]
    except IndexError:
        raise FunctionReturn("Error: Invalid group command.", head_clear=True)

    if command_type not in ['create', 'join', 'add', 'rm']:
        raise FunctionReturn("Error: Invalid group command.")

    group_id = None  # type: Optional[bytes]
    if command_type == 'join':
        try:
            group_id_s = input_parameters[2]
        except IndexError:
            raise FunctionReturn("Error: No group ID specified.", head_clear=True)
        try:
            group_id = b58decode(group_id_s)
        except ValueError:
            raise FunctionReturn("Error: Invalid group ID.", head_clear=True)

        if group_id in group_list.get_list_of_group_ids():
            raise FunctionReturn("Error: Group with matching ID already exists.", head_clear=True)

    try:
        name_index = 3 if command_type == 'join' else 2
        group_name = input_parameters[name_index]
    except IndexError:
        raise FunctionReturn("Error: No group name specified.", head_clear=True)

    member_index = 4 if command_type == 'join' else 3
    purp_members = input_parameters[member_index:]

    # Swap specified strings to public keys
    selectors = contact_list.contact_selectors()
    pub_keys  = [contact_list.get_contact_by_address_or_nick(m).onion_pub_key for m in purp_members if m in selectors]

    func_d = dict(create=group_create,
                  join  =group_create,
                  add   =group_add_member,
                  rm    =group_rm_member) # type: FuncDict

    func = func_d[command_type]

    func(group_name, pub_keys, contact_list, group_list, settings, queues, master_key, group_id)
    print('')


def group_create(group_name:   str,
                 purp_members: List[bytes],
                 contact_list: 'ContactList',
                 group_list:   'GroupList',
                 settings:     'Settings',
                 queues:       'QueueDict',
                 _:            'MasterKey',
                 group_id:     Optional[bytes] = None
                 ) -> None:
    """Create a new group.
    
    Validate the group name and determine what members can be added.
    """
    error_msg = validate_group_name(group_name, contact_list, group_list)
    if error_msg:
        raise FunctionReturn(error_msg, head_clear=True)

    public_keys   = set(contact_list.get_list_of_pub_keys())
    purp_pub_keys = set(purp_members)
    accepted      = list(purp_pub_keys & public_keys)
    rejected      = list(purp_pub_keys - public_keys)

    if len(accepted) > settings.max_number_of_group_members:
        raise FunctionReturn(f"Error: TFC settings only allow {settings.max_number_of_group_members} "
                             f"members per group.", head_clear=True)

    if len(group_list) == settings.max_number_of_groups:
        raise FunctionReturn(f"Error: TFC settings only allow {settings.max_number_of_groups} groups.", head_clear=True)

    header = GROUP_MSG_INVITE_HEADER if group_id is None else GROUP_MSG_JOIN_HEADER

    if group_id is None:
        while True:
            group_id = os.urandom(GROUP_ID_LENGTH)
            if group_id not in group_list.get_list_of_group_ids():
                break

    group_list.add_group(group_name,
                         group_id,
                         settings.log_messages_by_default,
                         settings.show_notifications_by_default,
                         members=[contact_list.get_contact_by_pub_key(k) for k in accepted])

    command = GROUP_CREATE + group_id + group_name.encode() + US_BYTE + b''.join(accepted)
    queue_command(command, settings, queues)

    group_management_print(NEW_GROUP,        accepted, contact_list, group_name)
    group_management_print(UNKNOWN_ACCOUNTS, rejected, contact_list, group_name)

    if accepted:
        if yes("Publish the list of group members to participants?", abort=False):
            create_packet = header + group_id + b''.join(accepted)
            queue_to_nc(create_packet, queues[RELAY_PACKET_QUEUE])

    else:
        m_print(f"Created an empty group '{group_name}'.", bold=True, head=1)


def group_add_member(group_name:   str,
                     purp_members: List['bytes'],
                     contact_list: 'ContactList',
                     group_list:   'GroupList',
                     settings:     'Settings',
                     queues:       'QueueDict',
                     master_key:   'MasterKey',
                     _:            Optional[bytes] = None
                     ) -> None:
    """Add new member(s) to a specified group."""
    if group_name not in group_list.get_list_of_group_names():
        if yes(f"Group {group_name} was not found. Create new group?", abort=False, head=1):
            group_create(group_name, purp_members, contact_list, group_list, settings, queues, master_key)
            return None
        else:
            raise FunctionReturn("Group creation aborted.", head=0, delay=1, tail_clear=True)

    purp_pub_keys    = set(purp_members)
    pub_keys         = set(contact_list.get_list_of_pub_keys())
    before_adding    = set(group_list.get_group(group_name).get_list_of_member_pub_keys())
    ok_pub_keys_set  = set(pub_keys        & purp_pub_keys)
    new_in_group_set = set(ok_pub_keys_set - before_adding)

    end_assembly = list(before_adding | new_in_group_set)
    rejected     = list(purp_pub_keys - pub_keys)
    already_in_g = list(before_adding & purp_pub_keys)
    new_in_group = list(new_in_group_set)
    ok_pub_keys  = list(ok_pub_keys_set)

    if len(end_assembly) > settings.max_number_of_group_members:
        raise FunctionReturn(f"Error: TFC settings only allow {settings.max_number_of_group_members} "
                             f"members per group.", head_clear=True)

    group = group_list.get_group(group_name)
    group.add_members([contact_list.get_contact_by_pub_key(k) for k in new_in_group])

    command = GROUP_ADD + group.group_id + b''.join(ok_pub_keys)
    queue_command(command, settings, queues)

    group_management_print(ADDED_MEMBERS,    new_in_group, contact_list, group_name)
    group_management_print(ALREADY_MEMBER,   already_in_g, contact_list, group_name)
    group_management_print(UNKNOWN_ACCOUNTS, rejected,     contact_list, group_name)

    if new_in_group:
        if yes("Publish the list of new members to involved?", abort=False):
            add_packet = (GROUP_MSG_MEMBER_ADD_HEADER
                          + group.group_id
                          + int_to_bytes(len(before_adding))
                          + b''.join(before_adding)
                          + b''.join(new_in_group))
            queue_to_nc(add_packet, queues[RELAY_PACKET_QUEUE])


def group_rm_member(group_name:   str,
                    purp_members: List[bytes],
                    contact_list: 'ContactList',
                    group_list:   'GroupList',
                    settings:     'Settings',
                    queues:       'QueueDict',
                    master_key:   'MasterKey',
                    _:            Optional[bytes] = None
                    ) -> None:
    """Remove member(s) from the specified group or remove the group itself."""
    if not purp_members:
        group_rm_group(group_name, contact_list, group_list, settings, queues, master_key)

    if group_name not in group_list.get_list_of_group_names():
        raise FunctionReturn(f"Group '{group_name}' does not exist.", head_clear=True)

    purp_pub_keys   = set(purp_members)
    pub_keys        = set(contact_list.get_list_of_pub_keys())
    before_removal  = set(group_list.get_group(group_name).get_list_of_member_pub_keys())
    ok_pub_keys_set = set(purp_pub_keys  & pub_keys)
    removable_set   = set(before_removal & ok_pub_keys_set)

    remaining    = list(before_removal  - removable_set)
    not_in_group = list(ok_pub_keys_set - before_removal)
    rejected     = list(purp_pub_keys   - pub_keys)
    removable    = list(removable_set)
    ok_pub_keys  = list(ok_pub_keys_set)

    group = group_list.get_group(group_name)
    group.remove_members(removable)

    command = GROUP_REMOVE + group.group_id + b''.join(ok_pub_keys)
    queue_command(command, settings, queues)

    group_management_print(REMOVED_MEMBERS,  removable,    contact_list, group_name)
    group_management_print(NOT_IN_GROUP,     not_in_group, contact_list, group_name)
    group_management_print(UNKNOWN_ACCOUNTS, rejected,     contact_list, group_name)

    if removable and remaining and yes("Publish the list of removed members to remaining members?", abort=False):
        rem_packet = (GROUP_MSG_MEMBER_REM_HEADER
                      + group.group_id
                      + int_to_bytes(len(remaining))
                      + b''.join(remaining)
                      + b''.join(removable))
        queue_to_nc(rem_packet, queues[RELAY_PACKET_QUEUE])


def group_rm_group(group_name:   str,
                   contact_list: 'ContactList',
                   group_list:   'GroupList',
                   settings:     'Settings',
                   queues:       'QueueDict',
                   master_key:   'MasterKey',
                   _:            Optional[bytes] = None
                   ) -> None:
    """Remove the group with its members."""
    if not yes(f"Remove group '{group_name}'?", abort=False):
        raise FunctionReturn("Group removal aborted.", head=0, delay=1, tail_clear=True)

    if group_name in group_list.get_list_of_group_names():
        group_id = group_list.get_group(group_name).group_id
    else:
        try:
            group_id = b58decode(group_name)
        except ValueError:
            raise FunctionReturn("Error: Invalid group name/ID.", head_clear=True)

    command = LOG_REMOVE + group_id
    queue_command(command, settings, queues)

    command = GROUP_DELETE + group_id
    queue_command(command, settings, queues)

    if group_list.has_group(group_name):
        with ignored(FunctionReturn):
            remove_logs(contact_list, group_list, settings, master_key, group_id)
    else:
        raise FunctionReturn(f"Transmitter has no group '{group_name}' to remove.")

    group = group_list.get_group(group_name)
    if not group.empty() and yes("Notify members about leaving the group?", abort=False):
        exit_packet = (GROUP_MSG_EXIT_GROUP_HEADER
                       + group.group_id
                       + b''.join(group.get_list_of_member_pub_keys()))
        queue_to_nc(exit_packet, queues[RELAY_PACKET_QUEUE])

    group_list.remove_group_by_name(group_name)
    raise FunctionReturn(f"Removed group '{group_name}'.", head=0, delay=1, tail_clear=True, bold=True)


def group_rename(new_name:     str,
                 window:       'TxWindow',
                 contact_list: 'ContactList',
                 group_list:   'GroupList',
                 settings:     'Settings',
                 queues:       'QueueDict',
                 ) -> None:
    """Rename the active group."""
    if window.type == WIN_TYPE_CONTACT or window.group is None:
        raise FunctionReturn("Error: Selected window is not a group window.", head_clear=True)

    error_msg = validate_group_name(new_name, contact_list, group_list)
    if error_msg:
        raise FunctionReturn(error_msg, head_clear=True)

    command = GROUP_RENAME + window.uid + new_name.encode()
    queue_command(command, settings, queues)

    old_name          = window.group.name
    window.group.name = new_name
    group_list.store_groups()

    raise FunctionReturn(f"Renamed group '{old_name}' to '{new_name}'.", delay=1, tail_clear=True)
