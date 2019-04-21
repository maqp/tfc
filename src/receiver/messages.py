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

import base64
import typing

from typing import Dict

from src.common.db_logs    import write_log_entry
from src.common.encoding   import bytes_to_bool
from src.common.exceptions import FunctionReturn
from src.common.misc       import separate_header, separate_headers
from src.common.statics    import *

from src.receiver.packet import decrypt_assembly_packet

if typing.TYPE_CHECKING:
    from datetime                import datetime
    from src.common.db_contacts  import ContactList
    from src.common.db_groups    import GroupList
    from src.common.db_keys      import KeyList
    from src.common.db_masterkey import MasterKey
    from src.common.db_settings  import Settings
    from src.receiver.packet     import PacketList
    from src.receiver.windows    import WindowList


def process_message(ts:                 'datetime',
                    assembly_packet_ct: bytes,
                    window_list:        'WindowList',
                    packet_list:        'PacketList',
                    contact_list:       'ContactList',
                    key_list:           'KeyList',
                    group_list:         'GroupList',
                    settings:           'Settings',
                    master_key:         'MasterKey',
                    file_keys:          Dict[bytes, bytes]
                    ) -> None:
    """Process received private / group message."""
    local_window = window_list.get_local_window()

    onion_pub_key, origin, assembly_packet_ct \
        = separate_headers(assembly_packet_ct, [ONION_SERVICE_PUBLIC_KEY_LENGTH, ORIGIN_HEADER_LENGTH])

    if onion_pub_key == LOCAL_PUBKEY:
        raise FunctionReturn("Warning! Received packet masqueraded as a command.",   window=local_window)
    if origin not in [ORIGIN_USER_HEADER, ORIGIN_CONTACT_HEADER]:
        raise FunctionReturn("Error: Received packet had an invalid origin-header.", window=local_window)

    assembly_packet = decrypt_assembly_packet(assembly_packet_ct, onion_pub_key, origin,
                                              window_list, contact_list, key_list)

    p_type  = FILE if assembly_packet[:ASSEMBLY_PACKET_HEADER_LENGTH].isupper() else MESSAGE
    packet  = packet_list.get_packet(onion_pub_key, origin, p_type)
    logging = contact_list.get_contact_by_pub_key(onion_pub_key).log_messages

    def log_masking_packets(completed: bool = False) -> None:
        """Add masking packets to log file.

        If logging and log file masking are enabled, this function will
        in case of erroneous transmissions, store the correct number of
        placeholder data packets to log file to hide the quantity of
        communication that log file observation would otherwise reveal.
        """
        if logging and settings.log_file_masking and (packet.log_masking_ctr or completed):
            no_masking_packets = len(packet.assembly_pt_list) if completed else packet.log_masking_ctr
            for _ in range(no_masking_packets):
                write_log_entry(PLACEHOLDER_DATA, onion_pub_key, settings, master_key, origin)
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
            packet.assemble_and_store_file(ts, onion_pub_key, window_list)
            raise FunctionReturn("File storage complete.", output=False)  # Raising allows calling log_masking_packets

        elif p_type == MESSAGE:
            whisper_byte, header, assembled = separate_headers(packet.assemble_message_packet(),
                                                               [WHISPER_FIELD_LENGTH, MESSAGE_HEADER_LENGTH])
            if len(whisper_byte) != WHISPER_FIELD_LENGTH:
                raise FunctionReturn("Error: Message from contact had an invalid whisper header.")

            whisper = bytes_to_bool(whisper_byte)

            if header == GROUP_MESSAGE_HEADER:
                logging = process_group_message(assembled, ts, onion_pub_key, origin, whisper, group_list, window_list)

            elif header == PRIVATE_MESSAGE_HEADER:
                window = window_list.get_window(onion_pub_key)
                window.add_new(ts, assembled.decode(), onion_pub_key, origin, output=True, whisper=whisper)

            elif header == FILE_KEY_HEADER:
                nick = process_file_key_message(assembled, onion_pub_key, origin, contact_list, file_keys)
                raise FunctionReturn(f"Received file decryption key from {nick}", window=local_window)

            else:
                raise FunctionReturn("Error: Message from contact had an invalid header.")

            if whisper:
                raise FunctionReturn("Whisper message complete.", output=False)

            if logging:
                for p in packet.assembly_pt_list:
                    write_log_entry(p, onion_pub_key, settings, master_key, origin)

    except (FunctionReturn, UnicodeError):
        log_masking_packets(completed=True)
        raise
    finally:
        packet.clear_assembly_packets()


def process_group_message(assembled:     bytes,        # Group message and its headers
                          ts:            'datetime',   # Timestamp of group message
                          onion_pub_key: bytes,        # Onion address of associated contact
                          origin:        bytes,        # Origin of group message (user / contact)
                          whisper:       bool,         # When True, message is not logged.
                          group_list:    'GroupList',  # GroupList object
                          window_list:   'WindowList'  # WindowList object
                          ) -> bool:
    """Process a group message."""
    group_id, assembled = separate_header(assembled, GROUP_ID_LENGTH)
    if not group_list.has_group_id(group_id):
        raise FunctionReturn("Error: Received message to an unknown group.", output=False)

    group = group_list.get_group_by_id(group_id)
    if not group.has_member(onion_pub_key):
        raise FunctionReturn("Error: Account is not a member of the group.", output=False)

    group_msg_id, group_message = separate_header(assembled, GROUP_MSG_ID_LENGTH)

    try:
        group_message_str = group_message.decode()
    except UnicodeError:
        raise FunctionReturn("Error: Received an invalid group message.")

    window = window_list.get_window(group.group_id)

    # All copies of group messages the user sends to members contain
    # the same message ID. This allows the Receiver Program to ignore
    # duplicates of outgoing messages sent by the user to each member.
    if origin == ORIGIN_USER_HEADER:
        if window.group_msg_id != group_msg_id:
            window.group_msg_id = group_msg_id
            window.add_new(ts, group_message_str, onion_pub_key, origin, output=True, whisper=whisper)

    elif origin == ORIGIN_CONTACT_HEADER:
        window.add_new(ts, group_message_str, onion_pub_key, origin, output=True, whisper=whisper)

    return group.log_messages


def process_file_key_message(assembled:     bytes,              # File decryption key
                             onion_pub_key: bytes,              # Onion address of associated contact
                             origin:        bytes,              # Origin of file key packet (user / contact)
                             contact_list:  'ContactList',      # ContactList object
                             file_keys:     Dict[bytes, bytes]  # Dictionary of file identifiers and decryption keys
                             ) -> str:
    """Process received file key delivery message."""
    if origin == ORIGIN_USER_HEADER:
        raise FunctionReturn("File key message from the user.", output=False)

    try:
        decoded = base64.b85decode(assembled)
    except ValueError:
        raise FunctionReturn("Error: Received an invalid file key message.")

    ct_hash, file_key = separate_header(decoded, BLAKE2_DIGEST_LENGTH)

    if len(ct_hash) != BLAKE2_DIGEST_LENGTH or len(file_key) != SYMMETRIC_KEY_LENGTH:
        raise FunctionReturn("Error: Received an invalid file key message.")

    file_keys[onion_pub_key + ct_hash] = file_key
    nick = contact_list.get_contact_by_pub_key(onion_pub_key).nick

    return nick
