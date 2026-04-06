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

from datetime import datetime
from typing import TYPE_CHECKING

from src.common.entities.group_id import GroupID
from src.common.exceptions import SoftError
from src.common.statics import Origin, FieldLength
from src.common.types_custom import BoolIsWhisperedMessage, BoolLogMessages, BytesAssembledMessage
from src.common.utils.strings import separate_header

if TYPE_CHECKING:
    from src.common.entities.contact import Contact
    from src.database.db_groups import GroupList
    from src.ui.receiver.window_rx import WindowList


def process_group_message(ts            : datetime,
                          assembled_msg : BytesAssembledMessage,
                          contact       : 'Contact',
                          origin        : Origin,
                          whisper       : BoolIsWhisperedMessage,
                          group_list    : 'GroupList',
                          window_list   : 'WindowList'
                          ) -> BoolLogMessages:
    """Process a group message."""
    group_id_bytes, assembled = separate_header(assembled_msg, FieldLength.GROUP_ID)
    group_id                  = GroupID(group_id_bytes)

    if not group_list.has_group_id(group_id):
        raise SoftError('Error: Received message to an unknown group.', output=False)

    group = group_list.get_group_by_id(group_id)
    if not group.has_member(contact.onion_pub_key):
        raise SoftError('Error: Account is not a member of the group.', output=False)

    group_msg_id, group_message = separate_header(assembled, FieldLength.GROUP_MSG_ID)

    try:
        group_message_str = group_message.decode()
    except UnicodeError:
        raise SoftError('Error: Received an invalid group message.')

    window = window_list.get_or_create_window(group_id.win_uid)

    # All copies of group messages the user sends to members contain
    # the same message ID. This allows the Receiver Program to ignore
    # duplicates of outgoing messages sent by the user to each member.
    if origin == Origin.USER:
        if window.group_msg_id != group_msg_id:
            window.group_msg_id = group_msg_id
            window.add_new_message(ts, contact, origin, group_message_str, output=True, whisper=whisper)

    elif origin == Origin.CONTACT:
        window.add_new_message(ts, contact, origin, group_message_str, output=True, whisper=whisper)

    # Return the group's logging setting because it might be different
    # from the logging setting of the contact who sent group message.
    return group.log_messages
