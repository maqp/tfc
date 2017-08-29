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

from typing import Any, List, Tuple

from src.common.db_logs    import write_log_entry
from src.common.exceptions import FunctionReturn
from src.common.output     import box_print
from src.common.statics    import *

from src.rx.packet import decrypt_assembly_packet

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

    p_type  = FILE if assembly_packet[:1].isupper() else MESSAGE
    packet  = packet_list.get_packet(account, origin, p_type)
    logging = contact_list.get_contact(account).log_messages

    def log_masking_packets(completed: bool = False) -> None:
        """Add masking packets to log file.

        If logging and logfile masking are enabled this function will
        in case of erroneous transmissions, store the correct number
        of placeholder data packets to log file to hide quantity of
        communication that log file observation would reveal.
        """
        if logging and settings.logfile_masking and (packet.log_masking_ctr or completed):
            iterator = packet.assembly_pt_list if completed else range(packet.log_masking_ctr)  # type: Any
            for _ in iterator:
                write_log_entry(PLACEHOLDER_DATA, account, settings, master_key, origin)
        packet.log_masking_ctr = 0

    try:
        packet.add_packet(assembly_packet)
    except FunctionReturn:
        log_masking_packets()
        raise
    log_masking_packets()

    if not packet.is_complete:
        return None

    try:
        if p_type == FILE:
            packet.assemble_and_store_file()
            # Raise FunctionReturn for packets stored as placeholder data.
            raise FunctionReturn("File storage complete.", output=False)

        elif p_type == MESSAGE:
            assembled = packet.assemble_message_packet()
            header    = assembled[:1]
            assembled = assembled[1:]

            if header == GROUP_MESSAGE_HEADER:
                logging = process_group_message(assembled, ts, account, origin, group_list, window_list)

            elif header == PRIVATE_MESSAGE_HEADER:
                window = window_list.get_window(account)
                window.add_new(ts, assembled.decode(), account, origin, output=True)

            elif header == WHISPER_MESSAGE_HEADER:
                window = window_list.get_window(account)
                window.add_new(ts, assembled.decode(), account, origin, output=True, whisper=True)
                raise FunctionReturn("Key message message complete.", output=False)

            else:
                process_group_management_message(header, assembled, ts, account, origin, contact_list, group_list, window_list)
                raise FunctionReturn("Group management message complete.", output=False)

            if logging:
                for p in packet.assembly_pt_list:
                    write_log_entry(p, account, settings, master_key, origin)

    except (FunctionReturn, UnicodeError):
        log_masking_packets(completed=True)
        raise
    finally:
        packet.clear_assembly_packets()


def process_group_message(assembled:   bytes,
                          ts:          'datetime',
                          account:     str,
                          origin:      bytes,
                          group_list:  'GroupList',
                          window_list: 'WindowList') -> bool:
    """Process a group message."""
    group_msg_id = assembled[:GROUP_MSG_ID_LEN]
    group_packet = assembled[GROUP_MSG_ID_LEN:]

    try:
        group_name, group_message = [f.decode() for f in group_packet.split(US_BYTE)]
    except (IndexError, UnicodeError):
        raise FunctionReturn("Error: Received an invalid group message.")

    if not group_list.has_group(group_name):
        raise FunctionReturn("Error: Received message to unknown group.", output=False)

    group  = group_list.get_group(group_name)
    window = window_list.get_window(group_name)

    if not group.has_member(account):
        raise FunctionReturn("Error: Account is not member of group.", output=False)

    # All copies of group messages user sends to members contain same UNIX timestamp.
    # This allows RxM to ignore copies of outgoing messages sent by the user.
    if origin == ORIGIN_USER_HEADER:
        if window.group_msg_id != group_msg_id:
            window.group_msg_id = group_msg_id
            window.add_new(ts, group_message, account, origin, output=True)

    elif origin == ORIGIN_CONTACT_HEADER:
        window.add_new(ts, group_message, account, origin, output=True)

    return group_list.get_group(group_name).log_messages


def process_group_management_message(header:       bytes,
                                     assembled:    bytes,
                                     ts:           'datetime',
                                     account:      str,
                                     origin:       bytes,
                                     contact_list: 'ContactList',
                                     group_list:   'GroupList',
                                     window_list:  'WindowList') -> None:
    """Process group management message."""
    local_win = window_list.get_local_window()
    nick      = contact_list.get_contact(account).nick

    try:
        group_name, *members = [f.decode() for f in assembled.split(US_BYTE)]
    except UnicodeError:
        raise FunctionReturn("Error: Received group management message had invalid encoding.")

    if origin == ORIGIN_USER_HEADER:
        raise FunctionReturn("Ignored group management message from user.", output=False)

    account_in_group = group_list.has_group(group_name) and group_list.get_group(group_name).has_member(account)

    def get_members() -> Tuple[List[str], str]:
        known     = [contact_list.get_contact(m).nick for m in members if     contact_list.has_contact(m)]
        unknown   = [                               m for m in members if not contact_list.has_contact(m)]
        just_len  = len(max(known + unknown, key=len))
        listed_m_ = [f"  * {m.ljust(just_len)}" for m in (known + unknown)]
        joined_m_ = ", ".join(known + unknown)
        return listed_m_, joined_m_

    if header == GROUP_MSG_INVITEJOIN_HEADER:
        lw_msg  = f"{nick} has {'joined' if account_in_group else 'invited you to'} group '{group_name}'"
        message = [lw_msg]
        if members:
            listed_m, joined_m = get_members()
            message[0]        += " with following members:"
            message           += listed_m
            lw_msg            += " with members " + joined_m

        box_print(message, head=1, tail=1)
        local_win.add_new(ts, lw_msg)

    elif header in [GROUP_MSG_MEMBER_ADD_HEADER, GROUP_MSG_MEMBER_REM_HEADER]:
        if account_in_group:
            action  = {GROUP_MSG_MEMBER_ADD_HEADER: "added following member(s) to",
                       GROUP_MSG_MEMBER_REM_HEADER: "removed following member(s) from"}[header]
            lw_msg  = f"{nick} has {action} group {group_name}: "
            message = [lw_msg]
            if members:
                listed_m, joined_m = get_members()
                message           += listed_m
                lw_msg            += joined_m

                box_print(message, head=1, tail=1)
                local_win.add_new(ts, lw_msg)

    elif header == GROUP_MSG_EXIT_GROUP_HEADER:
        if account_in_group:
            box_print([f"{nick} has left group {group_name}.", '', "Warning",
                       "Unless you remove the contact from the group, they",
                       "can still read messages you send to the group."],
                      head=1, tail=1)
    else:
        raise FunctionReturn("Error: Message from contact had an invalid header.")
