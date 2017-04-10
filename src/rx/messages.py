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

import struct
import typing

from src.common.db_logs  import write_log_entry
from src.common.encoding import bytes_to_double
from src.common.errors   import FunctionReturn
from src.common.output   import box_print
from src.common.statics  import *
from src.rx.packet       import decrypt_assembly_packet

from typing import List

if typing.TYPE_CHECKING:
    from datetime                import datetime
    from src.common.db_contacts  import ContactList
    from src.common.db_groups    import GroupList
    from src.common.db_keys      import KeyList
    from src.common.db_masterkey import MasterKey
    from src.common.db_settings  import Settings
    from src.rx.packet           import PacketList
    from src.rx.windows          import WindowList


def process_message(ts:                 'datetime',
                    assembly_packet_ct: bytes,
                    window_list:        'WindowList',
                    packet_list:        'PacketList',
                    contact_list:       'ContactList',
                    key_list:           'KeyList',
                    group_list:         'GroupList',
                    settings:           'Settings',
                    master_key:         'MasterKey') -> None:
    """Process received private / group message.

    Group management messages have automatic formatting and window
    redirection based on group configuration managed by user.
    """
    assembly_packet, account, origin = decrypt_assembly_packet(assembly_packet_ct, window_list, contact_list, key_list)

    p_type = 'file' if assembly_packet[:1].isupper() else 'message'
    packet = packet_list.get_packet(account, origin, p_type)
    packet.add_packet(assembly_packet)

    if not packet.is_complete:
        return None

    if p_type == 'file':
        packet.assemble_and_store_file()

        if contact_list.get_contact(account).log_messages and settings.log_dummy_file_a_p:
            # Store placeholder data.
            for _ in packet.assembly_pt_list:
                place_holder = F_S_HEADER + bytes(255)
                write_log_entry(place_holder, account, settings, master_key, origin)

    if p_type == 'message':
        assembled = packet.assemble_message_packet()
        header    = assembled[:1]
        assembled = assembled[1:]

        # Messages to group

        if header == GROUP_MESSAGE_HEADER:

            try:
                timestamp = bytes_to_double(assembled[:8])
            except struct.error:
                raise FunctionReturn("Received an invalid group timestamp.")

            try:
                group_name = assembled[8:].split(US_BYTE)[0].decode()
            except (UnicodeError, IndexError):
                raise FunctionReturn("Group name had invalid encoding.")

            try:
                group_message = assembled[8:].split(US_BYTE)[1]
            except (ValueError, IndexError):
                raise FunctionReturn("Received an invalid group message.")

            if not group_list.has_group(group_name):
                raise FunctionReturn("Received message to unknown group.", output=False)

            window = window_list.get_window(group_name)
            group  = group_list.get_group(group_name)

            if not group.has_member(account):
                raise FunctionReturn("Group message to group contact is not member of.", output=False)

            if window.has_contact(account):
                # All copies of group messages user sends to members contain same timestamp header.
                # This allows RxM to ignore copies of messages sent by the user.
                if origin == ORIGIN_USER_HEADER:
                    if window.group_timestamp == timestamp:
                        return None
                    window.group_timestamp = timestamp
                window.print_new(ts, group_message.decode(), account, origin)

                if group_list.get_group(group_name).log_messages:
                    for p in packet.assembly_pt_list:
                        write_log_entry(p, account, settings, master_key, origin)
            return None

        # Messages to contact

        else:
            if header == PRIVATE_MESSAGE_HEADER:
                window = window_list.get_window(account)
                window.print_new(ts, assembled.decode(), account, origin)

            # Group management messages
            else:
                local_win = window_list.get_local_window()
                nick      = contact_list.get_contact(account).nick

                group_name, *members = [f.decode() for f in assembled.split(US_BYTE)]

                # Ignore group management messages from user
                if origin == ORIGIN_USER_HEADER:
                    return None

                if header == GROUP_MSG_INVITATION_HEADER:
                    action = 'invited you to'
                    if group_list.has_group(group_name) and group_list.get_group(group_name).has_member(account):
                        action  = 'joined'
                    message = ["{} has {} group '{}'".format(nick, action, group_name)]  # type: List[str]
                    lw_msg  =  "{} has {} group '{}'".format(nick, action, group_name)   # type: str

                    # Print group management message
                    if members:
                        message[0] += " with following members:"
                        known       = [contact_list.get_contact(m).nick for m in members if contact_list.has_contact(m)]
                        unknown     = [m for m in members if not contact_list.has_contact(m)]
                        just_len    = len(max(known + unknown, key=len))
                        message    += ["  * {}".format(m.ljust(just_len)) for m in (known + unknown)]
                        lw_msg     += " with members " + ", ".join(known + unknown)

                    box_print(message, head=1, tail=1)

                    # Persistent message in cmd window
                    local_win.print_new(ts, lw_msg, print_=False)

                elif header in [GROUP_MSG_ADD_NOTIFY_HEADER, GROUP_MSG_MEMBER_RM_HEADER]:
                    action   = "added following member(s) to" if header == GROUP_MSG_ADD_NOTIFY_HEADER else "removed following member(s) from"
                    message_ = ["{} has {} group {}: ".format(nick, action, group_name)]  # type: List[str]
                    lw_msg_  =  "{} has {} group {}: ".format(nick, action, group_name)   # type: str

                    if members:
                        known     = [contact_list.get_contact(m).nick for m in members if contact_list.has_contact(m)]
                        unknown   = [m for m in members if not contact_list.has_contact(m)]
                        just_len  = len(max(known + unknown, key=len))
                        lw_msg_  += ", ".join(known + unknown)
                        message_ += ["  * {}".format(m.ljust(just_len)) for m in (known + unknown)]

                        box_print(message_, head=1, tail=1)
                        local_win.print_new(ts, lw_msg_, print_=False)

                elif header == GROUP_MSG_EXIT_GROUP_HEADER:
                    box_print(["{} has left group {}.".format(nick, group_name), '', 'Warning',
                               "Unless you remove the contact from the group, they",
                               "can still decrypt messages you send to the group."],
                              head=1, tail=1)
                else:
                    raise FunctionReturn(f"Message from had invalid header.")

            if contact_list.get_contact(account).log_messages:
                for p in packet.assembly_pt_list:
                    write_log_entry(p, account, settings, master_key, origin)
