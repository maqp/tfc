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

from src.common.statics import GroupMsgID
from src.ui.common.output.print_message import print_message

if TYPE_CHECKING:
    from src.common.crypto.keys.onion_service_keys import OnionPublicKeyContact
    from src.database.db_contacts import ContactList
    from src.common.entities.group_name import GroupName


def group_management_print(group_msg_id : GroupMsgID,
                           onion_pub_keys: list['OnionPublicKeyContact'],
                           contact_list : 'ContactList',
                           group_name   : O['GroupName'] = None
                           ) -> None:
    """Print group management command results."""
    group_name_str = '' if group_name is None else group_name.value
    m = {GroupMsgID.NEW_GROUP        : "Created new group '{}' with following members:".format(group_name_str),
         GroupMsgID.ADDED_MEMBERS    : "Added following accounts to group '{}':"       .format(group_name_str),
         GroupMsgID.ALREADY_MEMBER   : "Following accounts were already in group '{}':".format(group_name_str),
         GroupMsgID.REMOVED_MEMBERS  : "Removed following members from group '{}':"    .format(group_name_str),
         GroupMsgID.NOT_IN_GROUP     : "Following accounts were not in group '{}':"    .format(group_name_str),
         GroupMsgID.INVALID_KEX      : 'Following accounts were ignored because their key exchange status does not allow group membership:',
         GroupMsgID.UNKNOWN_ACCOUNTS : 'Following unknown accounts were ignored:'}[group_msg_id]

    if onion_pub_keys:
        m_list = (  [contact_list.get_nick(a).value for a in onion_pub_keys if     contact_list.has_onion_pub_key(a)]
                  + [a.onion_address                for a in onion_pub_keys if not contact_list.has_onion_pub_key(a)])

        just_len  = max(len(m) for m in m_list)
        justified = [m] + [f'  * {m.ljust(just_len)}' for m in m_list]
        print_message(justified, box=True)
