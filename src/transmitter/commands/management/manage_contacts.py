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

from typing import TYPE_CHECKING

from src.common.entities.serialized_command import SerializedCommand
from src.common.exceptions import SoftError, raise_if_traffic_masking, ignored
from src.common.statics import FieldLength, RxCommand, KeyDBMgmt
from src.common.types_custom import StrSelection
from src.ui.common.input.get_yes import get_yes
from src.ui.common.output.print_message import print_message
from src.common.utils.validators import validate_second_field
from src.database.db_logs import MessageLog
from src.datagrams.relay.command.contact_remove import DatagramRelayRemoveContact
from src.transmitter.queue_packet.queue_packet import queue_command

if TYPE_CHECKING:
    from src.common.crypto.keys.onion_service_keys import OnionPublicKeyContact
    from src.common.queues import TxQueue
    from src.database.db_contacts import ContactList
    from src.database.db_groups import GroupList
    from src.database.db_masterkey import MasterKey
    from src.database.db_settings import Settings
    from src.ui.transmitter.user_input import UserInput
    from src.ui.transmitter.window_tx import TxWindow


def remove_contact(settings     : 'Settings',
                   queues       : 'TxQueue',
                   window       : 'TxWindow',
                   contact_list : 'ContactList',
                   group_list   : 'GroupList',
                   user_input   : 'UserInput',
                   master_key   : 'MasterKey'
                   ) -> None:
    """Remove contact from TFC."""
    from src.transmitter.commands.management.manage_window import deselect_window_if_necessary

    raise_if_traffic_masking(settings)

    selection = validate_second_field(user_input, key='account')

    if selection not in contact_list.get_contact_selectors():
        raise SoftError('Error: Invalid selection.', padding_top=0, clear_delay=1, clear_after=True)

    contact = contact_list.get_contact_by_address_or_nick(selection)

    if not get_yes(f"Remove contact '{selection}'?", abort=False, head=1):
        raise SoftError('Removal of contact aborted.', padding_top=0, clear_delay=1, clear_after=True)

    queue_command(settings, queues, SerializedCommand(RxCommand.REMOVE_CONTACT, contact.onion_pub_key.serialize()))

    with ignored(SoftError):
        MessageLog(master_key, settings).remove_logs(contact_list, group_list, contact.onion_pub_key.public_bytes_raw)

    queues.key_store_mgmt.put((KeyDBMgmt.DELETE_ROW, contact.onion_pub_key))

    queues.relay_packet.put( DatagramRelayRemoveContact(contact.onion_pub_key) )

    target = determine_target(StrSelection(selection), contact.onion_pub_key, contact_list)
    if any([g.remove_members([contact.onion_pub_key]) for g in group_list]):
        print_message(f'Removed {target} from group(s).', padding_bottom=1)

    deselect_window_if_necessary(contact.onion_pub_key, window, group_list)


def determine_target(selection     : StrSelection,
                     onion_pub_key : 'OnionPublicKeyContact',
                     contact_list  : 'ContactList'
                     ) -> str:
    """Determine name of the target that will be removed."""
    if contact_list.has_onion_pub_key(onion_pub_key):
        contact = contact_list.get_contact_by_pub_key(onion_pub_key)
        target  = f'{contact.nick} ({contact.short_address})'
        contact_list.remove_contact(onion_pub_key)
        print_message(f'Removed {target} from contacts.', padding_top=1, padding_bottom=1)
    else:
        target = f'{selection[:FieldLength.ONION_ADDRESS_TRUNC]}'
        print_message(f'Transmitter has no {target} to remove.', padding_top=1, padding_bottom=1)

    return target
