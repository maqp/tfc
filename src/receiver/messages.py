#!/usr/bin/env python3.7
# -*- coding: utf-8 -*-

"""
TFC - Onion-routed, endpoint secure messaging system
Copyright (C) 2013-2020  Markus Ottela

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
from src.common.exceptions import SoftError
from src.common.misc       import separate_header, separate_headers
from src.common.statics    import (ASSEMBLY_PACKET_HEADER_LENGTH, BLAKE2_DIGEST_LENGTH, FILE, FILE_KEY_HEADER,
                                   GROUP_ID_LENGTH, GROUP_MESSAGE_HEADER, GROUP_MSG_ID_LENGTH, LOCAL_PUBKEY, MESSAGE,
                                   MESSAGE_HEADER_LENGTH, ONION_SERVICE_PUBLIC_KEY_LENGTH, ORIGIN_CONTACT_HEADER,
                                   ORIGIN_HEADER_LENGTH, ORIGIN_USER_HEADER, PLACEHOLDER_DATA, PRIVATE_MESSAGE_HEADER,
                                   SYMMETRIC_KEY_LENGTH, WHISPER_FIELD_LENGTH)

from src.receiver.packet import decrypt_assembly_packet

if typing.TYPE_CHECKING:
    from datetime               import datetime
    from src.common.database    import MessageLog
    from src.common.db_contacts import ContactList
    from src.common.db_groups   import GroupList
    from src.common.db_keys     import KeyList
    from src.common.db_settings import Settings
    from src.receiver.packet    import Packet, PacketList
    from src.receiver.windows   import WindowList


def log_masking_packets(onion_pub_key: bytes,         # Onion address of associated contact
                        origin:        bytes,         # Origin of packet (user / contact)
                        logging:       bool,          # When True, message will be logged
                        settings:      'Settings',    # Settings object
                        packet:        'Packet',      # Packet object
                        message_log:   'MessageLog',  # MessageLog object
                        completed:     bool = False,  # When True, logs placeholder data for completed message
                        ) -> None:
    """Add masking packets to log file.

    If logging and log file masking are enabled, this function will
    in case of erroneous transmissions, store the correct number of
    placeholder data packets to log file to hide the quantity of
    communication that log file observation would otherwise reveal.
    """
    if logging and settings.log_file_masking and (packet.log_masking_ctr or completed):
        no_masking_packets = len(packet.assembly_pt_list) if completed else packet.log_masking_ctr
        for _ in range(no_masking_packets):
            write_log_entry(PLACEHOLDER_DATA, onion_pub_key, message_log, origin)
    packet.log_masking_ctr = 0


def process_message_packet(ts:                 'datetime',          # Timestamp of received message packet
                           assembly_packet_ct: bytes,               # Encrypted assembly packet
                           window_list:        'WindowList',        # WindowList object
                           packet_list:        'PacketList',        # PacketList object
                           contact_list:       'ContactList',       # ContactList object
                           key_list:           'KeyList',           # KeyList object
                           group_list:         'GroupList',         # GroupList object
                           settings:           'Settings',          # Settings object
                           file_keys:          Dict[bytes, bytes],  # Dictionary of file decryption keys
                           message_log:        'MessageLog',        # MessageLog object
                           ) -> None:
    """Process received message packet."""
    command_window = window_list.get_command_window()

    onion_pub_key, origin, assembly_packet_ct = separate_headers(
        assembly_packet_ct, [ONION_SERVICE_PUBLIC_KEY_LENGTH, ORIGIN_HEADER_LENGTH])

    if onion_pub_key == LOCAL_PUBKEY:
        raise SoftError("Warning! Received packet masqueraded as a command.",   window=command_window)

    if origin not in [ORIGIN_USER_HEADER, ORIGIN_CONTACT_HEADER]:
        raise SoftError("Error: Received packet had an invalid origin-header.", window=command_window)

    assembly_packet = decrypt_assembly_packet(assembly_packet_ct, onion_pub_key, origin,
                                              window_list, contact_list, key_list)

    p_type  = (FILE if assembly_packet[:ASSEMBLY_PACKET_HEADER_LENGTH].isupper() else MESSAGE)
    packet  = packet_list.get_packet(onion_pub_key, origin, p_type)
    logging = contact_list.get_contact_by_pub_key(onion_pub_key).log_messages

    try:
        packet.add_packet(assembly_packet)
    except SoftError:
        log_masking_packets(onion_pub_key, origin, logging, settings, packet, message_log)
        raise
    log_masking_packets(onion_pub_key, origin, logging, settings, packet, message_log)

    if packet.is_complete:
        process_complete_message_packet(ts, onion_pub_key, p_type, origin, logging, packet, window_list,
                                        contact_list, group_list, settings, message_log, file_keys)


def process_complete_message_packet(ts:            'datetime',         # Timestamp of received message packet
                                    onion_pub_key: bytes,              # Onion address of associated contact
                                    p_type:        str,                # Packet type (file, message)
                                    origin:        bytes,              # Origin of packet (user / contact)
                                    logging:       bool,               # When True, message will be logged
                                    packet:        'Packet',           # Packet object
                                    window_list:   'WindowList',       # WindowList object
                                    contact_list:  'ContactList',      # ContactList object
                                    group_list:    'GroupList',        # GroupList object
                                    settings:      'Settings',         # Settings object
                                    message_log:   'MessageLog',       # MessageLog object
                                    file_keys:     Dict[bytes, bytes]  # Dictionary of file decryption keys
                                    ) -> None:
    """Process complete message packet.

    The assembled message packet might contain a file if the sender
    has traffic masking enabled, or it might contain other data.
    """
    try:
        if p_type == FILE:
            packet.assemble_and_store_file(ts, onion_pub_key, window_list)
            raise SoftError("File storage complete.", output=False)  # Raising allows calling log_masking_packets

        if p_type == MESSAGE:
            process_message(ts, onion_pub_key, origin, logging, packet, window_list,
                            contact_list, group_list, message_log, file_keys)

    except (SoftError, UnicodeError):
        log_masking_packets(onion_pub_key, origin, logging, settings, packet, message_log, completed=True)
        raise

    finally:
        packet.clear_assembly_packets()


def process_message(ts:            'datetime',         # Timestamp of received message packet
                    onion_pub_key: bytes,              # Onion address of associated contact
                    origin:        bytes,              # Origin of message (user / contact)
                    logging:       bool,               # When True, message will be logged
                    packet:        'Packet',           # Packet object
                    window_list:   'WindowList',       # WindowList object
                    contact_list:  'ContactList',      # ContactList object
                    group_list:    'GroupList',        # GroupList object
                    message_log:   'MessageLog',       # MessageLog object
                    file_keys:     Dict[bytes, bytes]  # Dictionary of file decryption keys
                    ) -> None:
    """Process message packet.

    The received message might be a private or group message, or it
    might contain decryption key for file received earlier.

    Each received message contains a whisper header that allows the
    sender to request the message to not be logged. This request will
    be obeyed as long as the recipient does not edit the source code
    below. Thus, the sender should not trust a whisper message is
    never logged.
    """
    whisper_byte, header, assembled = separate_headers(packet.assemble_message_packet(),
                                                       [WHISPER_FIELD_LENGTH, MESSAGE_HEADER_LENGTH])
    if len(whisper_byte) != WHISPER_FIELD_LENGTH:
        raise SoftError("Error: Message from contact had an invalid whisper header.")

    whisper = bytes_to_bool(whisper_byte)

    if header == GROUP_MESSAGE_HEADER:
        logging = process_group_message(ts, assembled, onion_pub_key, origin, whisper, group_list, window_list)

    elif header == PRIVATE_MESSAGE_HEADER:
        window = window_list.get_window(onion_pub_key)
        window.add_new(ts, assembled.decode(), onion_pub_key, origin, output=True, whisper=whisper)

    elif header == FILE_KEY_HEADER:
        nick = process_file_key_message(assembled, onion_pub_key, origin, contact_list, file_keys)
        raise SoftError(f"Received file decryption key from {nick}", window=window_list.get_command_window())

    else:
        raise SoftError("Error: Message from contact had an invalid header.")

    # Logging
    if whisper:
        raise SoftError("Whisper message complete.", output=False)

    if logging:
        for p in packet.assembly_pt_list:
            write_log_entry(p, onion_pub_key, message_log, origin)


def process_group_message(ts:            'datetime',   # Timestamp of group message
                          assembled:     bytes,        # Group message and its headers
                          onion_pub_key: bytes,        # Onion address of associated contact
                          origin:        bytes,        # Origin of group message (user / contact)
                          whisper:       bool,         # When True, message is not logged.
                          group_list:    'GroupList',  # GroupList object
                          window_list:   'WindowList'  # WindowList object
                          ) -> bool:
    """Process a group message."""
    group_id, assembled = separate_header(assembled, GROUP_ID_LENGTH)
    if not group_list.has_group_id(group_id):
        raise SoftError("Error: Received message to an unknown group.", output=False)

    group = group_list.get_group_by_id(group_id)
    if not group.has_member(onion_pub_key):
        raise SoftError("Error: Account is not a member of the group.", output=False)

    group_msg_id, group_message = separate_header(assembled, GROUP_MSG_ID_LENGTH)

    try:
        group_message_str = group_message.decode()
    except UnicodeError:
        raise SoftError("Error: Received an invalid group message.")

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

    # Return the group's logging setting because it might be different
    # from the logging setting of the contact who sent group message.
    return group.log_messages


def process_file_key_message(assembled:     bytes,              # File decryption key
                             onion_pub_key: bytes,              # Onion address of associated contact
                             origin:        bytes,              # Origin of file key packet (user / contact)
                             contact_list:  'ContactList',      # ContactList object
                             file_keys:     Dict[bytes, bytes]  # Dictionary of file identifiers and decryption keys
                             ) -> str:
    """Process received file key delivery message."""
    if origin == ORIGIN_USER_HEADER:
        raise SoftError("File key message from the user.", output=False)

    try:
        decoded = base64.b85decode(assembled)
    except ValueError:
        raise SoftError("Error: Received an invalid file key message.")

    ct_hash, file_key = separate_header(decoded, BLAKE2_DIGEST_LENGTH)

    if len(ct_hash) != BLAKE2_DIGEST_LENGTH or len(file_key) != SYMMETRIC_KEY_LENGTH:
        raise SoftError("Error: Received an invalid file key message.")

    file_keys[onion_pub_key + ct_hash] = file_key
    nick = contact_list.get_nick_by_pub_key(onion_pub_key)

    return nick
