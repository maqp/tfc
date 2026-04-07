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

import time

from typing import TYPE_CHECKING

from src.common.entities.group_id import GroupID
from src.common.exceptions import ignored, ValidationError
from src.common.crypto.keys.onion_service_keys import OnionPublicKeyContact
from src.common.statics import FieldLength, DatagramHeader, CryptoVarLength, QueueSignal
from src.common.types_custom import BoolUnitTesting, BytesGroupMsgData
from src.ui.common.output.print_message import print_message
from src.common.utils.strings import separate_header, split_byte_string

if TYPE_CHECKING:
    from src.common.queues import RelayQueue


def process_group_msg_manager(queues       : 'RelayQueue',
                              unit_testing : BoolUnitTesting = BoolUnitTesting(False)
                              ) -> None:
    """Show group management messages according to contact list state.

    This process keeps track of existing contacts for whom there's a
    `client` process. When a group management message from a contact
    is received, existing contacts are displayed under 'known contacts',
    and non-existing contacts are displayed under 'unknown contacts'.
    """
    queue = queues.from_cli_to_gmm_group_mgmt_messages

    existing_contacts : list[OnionPublicKeyContact] = []
    while True:
        with ignored(EOFError, KeyboardInterrupt):
            while queue.qsize() == 0:
                time.sleep(0.01)

            header, payload, pub_key_contact = queue.get()
            group_id_bytes, data             = separate_header(payload, FieldLength.GROUP_ID.value)

            try:
                group_id = GroupID(group_id_bytes)
            except ValidationError:
                continue

            existing_contacts = update_list_of_existing_contacts(queues, existing_contacts)

            handle_group_management_message(BytesGroupMsgData(data),
                                            existing_contacts,
                                            group_id,
                                            header,
                                            pub_key_contact)

            if unit_testing and queues.unit_test.qsize() != 0:
                break


def handle_group_management_message(data              : BytesGroupMsgData,
                                    existing_contacts : list[OnionPublicKeyContact],
                                    group_id          : GroupID,
                                    header            : DatagramHeader,
                                    pub_key_contact   : OnionPublicKeyContact
                                    ) -> None:
    """Handle group management message."""
    trunc_addr = pub_key_contact.short_address

    if header in [DatagramHeader.GROUP_INVITE,     DatagramHeader.GROUP_JOIN,
                  DatagramHeader.GROUP_ADD_MEMBER, DatagramHeader.GROUP_REM_MEMBER]:

        pub_keys       = split_byte_string(data, CryptoVarLength.ONION_SERVICE_PUBLIC_KEY.value)
        pub_key_length = CryptoVarLength.ONION_SERVICE_PUBLIC_KEY.value

        members = [OnionPublicKeyContact(k) for k in pub_keys if len(k) == pub_key_length]
        known   = [f'  * {m.onion_address}' for m in members  if m in     existing_contacts]
        unknown = [f'  * {m.onion_address}' for m in members  if m not in existing_contacts]

        line_list = []
        if known:
            line_list.extend(['Known contacts'] + known)
        if unknown:
            line_list.extend(['Unknown contacts'] + unknown)

        if header in [DatagramHeader.GROUP_INVITE, DatagramHeader.GROUP_JOIN]:
            action  = 'invited you to' if header == DatagramHeader.GROUP_INVITE else 'joined'
            postfix = ' with'          if members                               else ''
            print_message([f'{trunc_addr} has {action} group {group_id.hr_value}{postfix}'] + line_list, box=True)

        elif header in [DatagramHeader.GROUP_ADD_MEMBER, DatagramHeader.GROUP_REM_MEMBER]:
            if members:
                action, p = ('added', 'to') if header == DatagramHeader.GROUP_ADD_MEMBER else ('removed', 'from')
                print_message([f'{trunc_addr} has {action} following members {p} group {group_id.hr_value}'] + line_list, box=True)

    elif header == DatagramHeader.GROUP_EXIT_GROUP:
        print_message([f'{trunc_addr} has left group {group_id.hr_value}',
                 '', 'Warning',
                 'Unless you remove the contact from the group, they',
                 'can still read messages you send to the group.'], box=True)


def update_list_of_existing_contacts(queues            : 'RelayQueue',
                                     existing_contacts : list[OnionPublicKeyContact]
                                     ) -> list[OnionPublicKeyContact]:
    """Update list of existing contacts."""
    queue = queues.from_rec_to_crm_contact_list_mgmt

    while queue.qsize() > 0:
        command, changing_onion_pub_keys = queue.get()

        if command == QueueSignal.RP_ADD_CONTACT_HEADER:
            existing_contacts = list(set(existing_contacts) | set(changing_onion_pub_keys))
        elif command == QueueSignal.RP_REMOVE_CONTACT_HEADER:
            existing_contacts = list(set(existing_contacts) - set(changing_onion_pub_keys))

    return existing_contacts
