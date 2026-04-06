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

from typing import Optional as O, TYPE_CHECKING

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from src.common.crypto.keys.onion_service_keys import OnionPublicKeyContact
from src.common.entities.group_id import GroupID
from src.common.entities.group_name import GroupName
from src.common.entities.serialized_command import SerializedCommand
from src.common.exceptions import SoftError, ValidationError, raise_if_traffic_masking, ignored
from src.common.statics import GroupMsgID, RxCommand, Separator, WindowType, GroupMgmtCommand
from src.common.utils.validators import validate_group_name
from src.database.db_logs import MessageLog
from src.datagrams.relay.group_management.group_msg_add_rem import DatagramGroupAddMember, DatagramGroupRemMember
from src.datagrams.relay.group_management.group_msg_flat import DatagramGroupInvite, DatagramGroupJoin, DatagramGroupExit
from src.transmitter.queue_packet.queue_packet import queue_command
from src.ui.common.input.get_yes import get_yes
from src.ui.common.output.print_group_mgmt_msg import group_management_print
from src.ui.common.output.print_message import print_message

if TYPE_CHECKING:
    from src.common.queues import TxQueue
    from src.common.types_custom import StrWindowName
    from src.database.db_contacts import ContactList
    from src.database.db_groups import GroupList
    from src.database.db_masterkey import MasterKey
    from src.database.db_settings import Settings
    from src.ui.transmitter.user_input import UserInput
    from src.ui.transmitter.window_tx import TxWindow


def process_group_command(settings     : 'Settings',
                          queues       : 'TxQueue',
                          contact_list : 'ContactList',
                          group_list   : 'GroupList',
                          user_input   : 'UserInput',
                          master_key   : 'MasterKey'
                          ) -> None:
    """Parse a group command and process it accordingly."""
    raise_if_traffic_masking(settings)

    input_parameters = user_input.plaintext.split()

    command_type, group_id, group_name, purp_members = parse_group_command_parameters(input_parameters, group_list)

    # Swap specified strings to public keys
    selectors      = contact_list.get_contact_selectors()
    onion_pub_keys = [contact_list.get_contact_by_address_or_nick(m).onion_pub_key for m in purp_members if m in selectors]

    if   command_type == 'create': group_create    (group_name, onion_pub_keys, contact_list, group_list, settings, queues, master_key, group_id)
    elif command_type == 'join':   group_create    (group_name, onion_pub_keys, contact_list, group_list, settings, queues, master_key, group_id)
    elif command_type == 'add':    group_add_member(group_name, onion_pub_keys, contact_list, group_list, settings, queues, master_key, group_id)
    else:                          group_rm_member (group_name, onion_pub_keys, contact_list, group_list, settings, queues, master_key, group_id)
    print('')


def parse_group_command_parameters(input_parameters : list[str],
                                   group_list       : 'GroupList'
                                   ) -> tuple[GroupMgmtCommand, O[GroupID], GroupName, list[str]]:
    """Parse parameters for group command issued by the user."""
    try:
        command_type_str = input_parameters[1]
    except IndexError:
        raise SoftError('Error: Invalid group command.', clear_before=True)

    try:
        command_type = GroupMgmtCommand(command_type_str)
    except ValueError:
        raise SoftError('Error: Invalid group command.')

    group_id = validate_group_id(input_parameters, command_type, group_list)

    try:
        name_index = 3 if command_type == GroupMgmtCommand.JOIN else 2
        group_name = GroupName(input_parameters[name_index])
    except IndexError:
        raise SoftError('Error: No group name specified.', clear_before=True)

    member_index = 4 if command_type == GroupMgmtCommand.JOIN else 3
    purp_members = input_parameters[member_index:]

    return command_type, group_id, group_name, purp_members


def validate_group_id(input_parameters : list[str],
                      command_type     : GroupMgmtCommand,
                      group_list       : 'GroupList'
                      ) -> O[GroupID]:
    """Validate group ID for group command."""
    group_id = None  # type: O[GroupID]

    if command_type == GroupMgmtCommand.JOIN:
        try:
            group_id_s = input_parameters[2]
        except IndexError:
            raise SoftError('Error: No group ID specified.', clear_before=True)
        try:
            group_id = GroupID.from_string(group_id_s)
        except ValueError:
            raise SoftError('Error: Invalid group ID.', clear_before=True)

        if group_id in group_list.get_list_of_group_ids():
            raise SoftError('Error: Group with matching ID already exists.', clear_before=True)

    return group_id


def group_create(group_name   : GroupName,
                 purp_members : list[OnionPublicKeyContact],
                 contact_list : 'ContactList',
                 group_list   : 'GroupList',
                 settings     : 'Settings',
                 queues       : 'TxQueue',
                 _            : 'MasterKey',
                 group_id     : O[GroupID] = None
                 ) -> None:
    """Create a new group.

    Validate the group name and determine what members can be added.
    """
    new_group = group_id is None

    try:
        validate_group_name(group_name.value, contact_list, group_list)
    except ValidationError as e:
        raise SoftError(e.args[0], clear_before=True)

    purp_onion_pub_keys = {pk.public_bytes_raw for pk in purp_members}
    known_pub_keys      = {pk.public_bytes_raw for pk in contact_list.get_list_of_pub_keys()}
    eligible_pub_keys   = {pk.public_bytes_raw for pk in contact_list.get_list_of_group_eligible_pub_keys()}
    accepted            = list(purp_onion_pub_keys & eligible_pub_keys)
    invalid_kex         = list((purp_onion_pub_keys & known_pub_keys) - eligible_pub_keys)
    rejected            = list(purp_onion_pub_keys - known_pub_keys)

    if len(accepted) > settings.max_number_of_group_members:
        raise SoftError(f'Error: TFC settings only allow {settings.max_number_of_group_members} members per group.',
                        clear_before=True)

    if len(group_list) == settings.max_number_of_groups:
        raise SoftError(f'Error: TFC settings only allow {settings.max_number_of_groups} groups.',
                        clear_before=True)

    group_id = group_list.new_group_id() if group_id is None else group_id

    group_list.add_group(group_name,
                         group_id,
                         settings.log_messages_by_default,
                         settings.show_notifications_by_default,
                         members=[contact_list.get_contact_by_pub_key(OnionPublicKeyContact(bytes(k)))
                                  for k in accepted])

    o_accepted = [OnionPublicKeyContact(bytes(k)) for k in accepted]
    o_rejected = [OnionPublicKeyContact(bytes(k)) for k in rejected]

    serialized_pub_keys = b''.join(pub_key.serialize() for pub_key in o_accepted)
    serialized_fields   = (group_id.raw_bytes
                           + group_name.value.encode()
                           + Separator.US_BYTE.value
                           + serialized_pub_keys)

    queue_command(settings, queues, SerializedCommand(RxCommand.GROUP_CREATE, serialized_fields))

    group_management_print(GroupMsgID.NEW_GROUP,        o_accepted, contact_list, group_name)
    group_management_print(GroupMsgID.INVALID_KEX,      [OnionPublicKeyContact(bytes(k)) for k in invalid_kex], contact_list, group_name)
    group_management_print(GroupMsgID.UNKNOWN_ACCOUNTS, o_rejected, contact_list, group_name)

    if accepted:
        if get_yes('Publish the list of group members to participants?', abort=False):
            if new_group: queues.relay_packet.put(DatagramGroupInvite(group_id, o_accepted))
            else:         queues.relay_packet.put(DatagramGroupJoin  (group_id, o_accepted))
    else:
        print_message(f"Created an empty group '{group_name}'.", bold=True, padding_top=1)


def group_add_member(group_name   : GroupName,
                     purp_members : list[OnionPublicKeyContact],
                     contact_list : 'ContactList',
                     group_list   : 'GroupList',
                     settings     : 'Settings',
                     queues       : 'TxQueue',
                     master_key   : 'MasterKey',
                     _            : O[GroupID] = None
                     ) -> None:
    """Add new member(s) to a specified group."""
    if group_name not in group_list.get_list_of_group_names():
        if not get_yes(f'Group {group_name} was not found. Create new group?', abort=False, head=1):
            raise SoftError('Group creation aborted.', padding_top=0, clear_delay=1, clear_after=True)
        group_create(group_name, purp_members, contact_list, group_list, settings, queues, master_key)
        return None

    purp_onion_pub_keys = {pk.public_bytes_raw for pk in purp_members}
    known_pub_keys      = {pk.public_bytes_raw for pk in contact_list.get_list_of_pub_keys()}
    eligible_pub_keys   = {pk.public_bytes_raw for pk in contact_list.get_list_of_group_eligible_pub_keys()}
    before_adding       = set(group_list.get_group(group_name).get_list_of_raw_pub_keys())
    ok_pub_keys_set     = eligible_pub_keys & purp_onion_pub_keys
    new_in_group_set    = ok_pub_keys_set - before_adding

    end_assembly = list(before_adding | new_in_group_set)
    new_in_group = list(new_in_group_set)
    already_in_g = list(before_adding & purp_onion_pub_keys)
    invalid_kex  = list((purp_onion_pub_keys & known_pub_keys) - before_adding - eligible_pub_keys)
    rejected     = list(purp_onion_pub_keys - known_pub_keys)

    if len(end_assembly) > settings.max_number_of_group_members:
        raise SoftError(f'Error: TFC settings only allow {settings.max_number_of_group_members} members per group.',
                        clear_before=True)

    group = group_list.get_group(group_name)
    group.add_members([contact_list.get_contact_by_pub_key(OnionPublicKeyContact(bytes(k))) for k in new_in_group])

    o_ok_pub_keys           = [OnionPublicKeyContact( Ed25519PublicKey.from_public_bytes(k) ) for k in ok_pub_keys_set]
    o_already_in_g_contacts = [OnionPublicKeyContact( Ed25519PublicKey.from_public_bytes(k) ) for k in already_in_g]
    o_new_in_group_contacts = [OnionPublicKeyContact( Ed25519PublicKey.from_public_bytes(k) ) for k in new_in_group]
    o_unknown_users         = [OnionPublicKeyContact( Ed25519PublicKey.from_public_bytes(k) ) for k in rejected]

    serialized_pub_keys   = b''.join(k.serialize() for k in o_ok_pub_keys)
    serialized_fields     = group.group_id.raw_bytes + serialized_pub_keys

    queue_command(settings, queues, SerializedCommand(RxCommand.GROUP_ADD, serialized_fields))

    group_management_print(GroupMsgID.ADDED_MEMBERS,    o_new_in_group_contacts, contact_list, group_name)
    group_management_print(GroupMsgID.ALREADY_MEMBER,   o_already_in_g_contacts, contact_list, group_name)
    group_management_print(GroupMsgID.INVALID_KEX,      [OnionPublicKeyContact(Ed25519PublicKey.from_public_bytes(k)) for k in invalid_kex], contact_list, group_name)
    group_management_print(GroupMsgID.UNKNOWN_ACCOUNTS, o_unknown_users,         contact_list, group_name)

    if new_in_group and get_yes('Publish the list of new members to involved?', abort=False):
        queues.relay_packet.put( DatagramGroupAddMember(group.group_id, o_already_in_g_contacts, o_new_in_group_contacts) )

    return None


def group_rm_member(group_name   : GroupName,
                    purp_members : list[OnionPublicKeyContact],
                    contact_list : 'ContactList',
                    group_list   : 'GroupList',
                    settings     : 'Settings',
                    queues       : 'TxQueue',
                    master_key   : 'MasterKey',
                    _            : O[GroupID] = None
                    ) -> None:
    """Remove member(s) from the specified group or remove the group itself."""
    if not purp_members:
        group_rm_group(group_name, contact_list, group_list, settings, queues, master_key)
        return None

    if group_name not in group_list.get_list_of_group_names():
        raise SoftError(f"Group '{group_name}' does not exist.", clear_before=True)

    purp_onion_pub_keys = set([pk.public_bytes_raw for pk in purp_members])
    pub_keys            = set([pk.public_bytes_raw for pk in contact_list.get_list_of_pub_keys()])
    before_removal      = set(group_list.get_group(group_name).get_list_of_raw_pub_keys())
    ok_pub_keys_set     = set(purp_onion_pub_keys  & pub_keys)
    removable_set       = set(before_removal & ok_pub_keys_set)

    removable    = list(removable_set)
    ok_pub_keys  = list(ok_pub_keys_set)
    remaining    = list(before_removal      - removable_set)
    not_in_group = list(ok_pub_keys_set     - before_removal)
    rejected     = list(purp_onion_pub_keys - pub_keys)

    o_removable    = [OnionPublicKeyContact( Ed25519PublicKey.from_public_bytes(k) ) for k in removable]
    o_ok_pub_keys  = [OnionPublicKeyContact( Ed25519PublicKey.from_public_bytes(k) ) for k in ok_pub_keys]
    o_remaining    = [OnionPublicKeyContact( Ed25519PublicKey.from_public_bytes(k) ) for k in remaining]
    o_not_in_group = [OnionPublicKeyContact( Ed25519PublicKey.from_public_bytes(k) ) for k in not_in_group]
    o_rejected     = [OnionPublicKeyContact( Ed25519PublicKey.from_public_bytes(k) ) for k in rejected]

    group = group_list.get_group(group_name)
    group.remove_members(o_removable)

    group_management_print(GroupMsgID.REMOVED_MEMBERS,  o_removable,    contact_list, group_name)
    group_management_print(GroupMsgID.NOT_IN_GROUP,     o_not_in_group, contact_list, group_name)
    group_management_print(GroupMsgID.UNKNOWN_ACCOUNTS, o_rejected,     contact_list, group_name)

    serialized_pub_keys = b''.join(pub_key.serialize() for pub_key in o_ok_pub_keys)
    serialized_fields   = group.group_id.raw_bytes + serialized_pub_keys
    queue_command(settings, queues, SerializedCommand(RxCommand.GROUP_REMOVE, serialized_fields))

    if removable and remaining and get_yes('Publish the list of removed members to remaining members?', abort=False):
        queues.relay_packet.put( DatagramGroupRemMember(group.group_id, o_remaining, o_removable) )

    return None

def group_rm_group(group_name   : GroupName,
                   contact_list : 'ContactList',
                   group_list   : 'GroupList',
                   settings     : 'Settings',
                   queues       : 'TxQueue',
                   master_key   : 'MasterKey',
                   _            : O[bytes] = None
                   ) -> None:
    """Remove the group with its members."""
    if not get_yes(f"Remove group '{group_name}'?", abort=False):
        raise SoftError('Group removal aborted.', padding_top=0, clear_delay=1, clear_after=True)

    if group_name not in group_list.get_list_of_group_names():
        raise SoftError('Error: Invalid group name/ID.', clear_before=True)

    group_id = group_list.get_group(group_name).group_id

    queue_command(settings, queues, SerializedCommand(RxCommand.LOG_REMOVE,   group_id.raw_bytes))
    queue_command(settings, queues, SerializedCommand(RxCommand.GROUP_DELETE, group_id.raw_bytes))

    if group_list.has_group(group_name):
        with ignored(SoftError):
            MessageLog(master_key, settings).remove_logs(contact_list, group_list, group_id.raw_bytes)
    else:
        raise SoftError(f"Transmitter has no group '{group_name}' to remove.")

    group = group_list.get_group(group_name)
    if not group.empty() and get_yes('Notify members about leaving the group?', abort=False):
        queues.relay_packet.put( DatagramGroupExit(group.group_id, group.get_list_of_member_pub_keys()) )

    group_list.remove_group_by_name(group_name)
    raise SoftError(f"Removed group '{group_name}'.", padding_top=0, clear_delay=1, clear_after=True, bold=True)


def group_rename(group_name_str : 'StrWindowName',
                 window         : 'TxWindow',
                 contact_list   : 'ContactList',
                 group_list     : 'GroupList',
                 settings       : 'Settings',
                 queues         : 'TxQueue',
                 ) -> None:
    """Rename the active group."""
    if window.window_type == WindowType.CONTACT or window.group is None:
        raise SoftError('Error: Selected window is not a group window.', clear_before=True)

    try:
         validate_group_name(group_name_str, contact_list, group_list)
    except ValidationError as e:
        raise SoftError(e.args[0], clear_before=True)

    serialized_fields = window.uid_bytes + group_name_str.encode()
    queue_command(settings, queues, SerializedCommand(RxCommand.GROUP_RENAME, serialized_fields))

    old_name                = window.group.group_name
    window.group.group_name = GroupName(group_name_str)
    group_list.store_groups()

    raise SoftError(f"Renamed group '{old_name}' to '{group_name_str}'.", clear_delay=1, clear_after=True)
