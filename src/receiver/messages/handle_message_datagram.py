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

from src.common.entities.assembly_packet import (AssemblyPacket, MessageAssemblyPacketUser, MessageAssemblyPacketContact,
                                                 FileAssemblyPacketUser, FileAssemblyPacketContact)
from src.common.entities.payload import FilePayload
from src.common.entities.payload import MessagePayload
from src.common.entities.window_uid import WindowUID
from src.common.exceptions import SoftError
from src.common.statics import Origin, TrafficMaskingData, FieldLength, MessageHeader
from src.common.types_compound import FileKeyDict
from src.common.types_custom import BoolDatagramDompleted, BoolIsWhisperedMessage, BytesAssembledMessage
from src.common.utils.encoding import bytes_to_bool
from src.common.utils.strings import separate_headers
from src.database.db_logs import MessageLog
from src.receiver.messages.file_key_message import process_file_key_message
from src.receiver.messages.group_message import process_group_message
from src.receiver.messages.decrypt_message_datagram import decrypt_message_datagram

if TYPE_CHECKING:
    from src.common.entities.contact import Contact
    from src.common.entities.payload_buffer import PayloadBuffer
    from src.common.types_custom import BoolLogMessages
    from src.database.db_contacts import ContactList
    from src.database.db_groups import GroupList
    from src.database.db_keys import KeyStore
    from src.database.db_settings import Settings
    from src.datagrams.receiver.message import DatagramIncomingMessage, DatagramOutgoingMessage
    from src.ui.receiver.window_rx import WindowList


def handle_message_datagram(datagram     : 'DatagramIncomingMessage|DatagramOutgoingMessage',
                            window_list  : 'WindowList',
                            payload_buf  : 'PayloadBuffer',
                            contact_list : 'ContactList',
                            key_store    : 'KeyStore',
                            group_list   : 'GroupList',
                            settings     : 'Settings',
                            file_keys    : 'FileKeyDict',
                            message_log  : MessageLog,
                            ) -> None:
    """Process received message packet."""
    onion_pub_key   = datagram.pub_key_contact
    contact         = contact_list.get_contact_by_pub_key(onion_pub_key)
    assembly_packet = decrypt_message_datagram(datagram, window_list, key_store, contact)
    logging         = contact.log_messages
    origin          = assembly_packet.origin

    payload: MessagePayload | FilePayload
    if   isinstance(assembly_packet, MessageAssemblyPacketUser):    payload = payload_buf.get_message_payload_from_user   (onion_pub_key)
    elif isinstance(assembly_packet, MessageAssemblyPacketContact): payload = payload_buf.get_message_payload_from_contact(onion_pub_key)
    elif isinstance(assembly_packet, FileAssemblyPacketUser):       payload = payload_buf.get_file_payload_from_user      (onion_pub_key)
    elif isinstance(assembly_packet, FileAssemblyPacketContact):    payload = payload_buf.get_file_payload_from_contact   (onion_pub_key)
    else: raise SoftError('Could not determine assembly packet payload type.', output=False)

    try:
        payload.add_assembly_packet(assembly_packet)
    except SoftError:
        log_masking_packets(contact, origin, logging, settings, payload, message_log)
        if assembly_packet.is_cancel_of_payload:
            process_cancelled_payload(datagram.ts, contact, origin, payload, window_list)
            return
        raise
    log_masking_packets(contact, origin, logging, settings, payload, message_log)

    # The payload timestamp is the timestamp of the last assembly packet.
    ts = datagram.ts

    if payload.is_complete:
        process_complete_message_payload(ts, contact, origin, logging, payload, window_list,
                                         contact_list, group_list, settings, message_log, file_keys)


def process_complete_message_payload(ts           : 'datetime',
                                     contact      : 'Contact',
                                     origin       : Origin,
                                     logging      : 'BoolLogMessages',
                                     payload      : FilePayload | MessagePayload,
                                     window_list  : 'WindowList',
                                     contact_list : 'ContactList',
                                     group_list   : 'GroupList',
                                     settings     : 'Settings',
                                     message_log  : MessageLog,
                                     file_keys    : 'FileKeyDict'
                                     ) -> None:
    """Process complete message payload.

    The assembled message payload might contain
        * a 1:1 message
        * a group message
        * a multi-cast file decryption key
        * a file if the sender has traffic masking enabled
    """
    try:
        if isinstance(payload, FilePayload):
            payload.assemble_and_store_file(ts, contact, window_list)
            raise SoftError('File storage complete.', output=False)  # Raising allows calling log_masking_packets

        if isinstance(payload, MessagePayload):
            process_message(ts, contact, origin, logging, payload, window_list,
                            contact_list, group_list, message_log, file_keys)

    except (SoftError, UnicodeError):
        log_masking_packets(contact, origin, logging, settings, payload, message_log, completed=BoolDatagramDompleted(True))
        raise

    finally:
        payload.clear_assembly_packets()


def process_message(ts           : datetime,
                    contact      : 'Contact',
                    origin       : Origin,
                    logging      : 'BoolLogMessages',
                    payload      : MessagePayload,
                    window_list  : 'WindowList',
                    contact_list : 'ContactList',
                    group_list   : 'GroupList',
                    message_log  : MessageLog,
                    file_keys    : 'FileKeyDict'
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
    whisper_byte, header, assembled_bytes = separate_headers(payload.assemble_message_packet(),
                                                             [FieldLength.MESSAGE_HEADER, FieldLength.MESSAGE_HEADER])

    assembled = BytesAssembledMessage(assembled_bytes)

    if len(whisper_byte) != FieldLength.MESSAGE_HEADER:
        raise SoftError('Error: Message from contact had an invalid whisper header.')
    whisper = BoolIsWhisperedMessage(bytes_to_bool(whisper_byte))

    if header == MessageHeader.GROUP_MESSAGE:
        logging = process_group_message(ts, assembled, contact, origin, whisper, group_list, window_list)

    elif header == MessageHeader.PRIVATE_MESSAGE:
        window = window_list.get_or_create_window(WindowUID.for_contact(contact))
        window.add_new_message(ts, contact, origin, assembled.decode(), output=True, whisper=whisper)

    elif header == MessageHeader.FILE_KEY:
        nick = process_file_key_message(assembled, contact, origin, contact_list, file_keys)
        raise SoftError(f'Received file decryption key from {nick}', window=window_list.sys_msg_win)

    else:
        raise SoftError('Error: Message from contact had an invalid header.')

    # Logging
    if whisper:
        raise SoftError('Whisper message complete.', output=False)

    if logging:
        for assembly_packet in payload:
            MessageLog.write_log_entry(assembly_packet, contact.onion_pub_key, message_log, origin)


def process_cancelled_payload(ts          : 'datetime',
                              contact     : 'Contact',
                              origin      : Origin,
                              payload     : MessagePayload | FilePayload,
                              window_list : 'WindowList',
                              ) -> None:
    """Display a user-facing notice for a cancelled message or file payload."""
    window = window_list.get_or_create_window(WindowUID.for_contact(contact))

    if origin == Origin.USER:
        message = f'Cancelled {payload.payload_type_hr} transmission to {contact.nick.value}.'
    else:
        message = f'Contact cancelled {payload.payload_type_hr} transmission.'

    window.add_new_message(ts, contact, origin, message, output=True, event_msg=True)


def log_masking_packets(contact     : 'Contact',
                        origin      : Origin,
                        logging     : 'BoolLogMessages',
                        settings    : 'Settings',
                        payload     : MessagePayload | FilePayload,
                        message_log : MessageLog,
                        completed   : BoolDatagramDompleted = BoolDatagramDompleted(False),  # When True, logs placeholder data for completed message
                        ) -> None:
    """Add masking packets to log file.

    If logging and log file masking are enabled, this function will
    in case of erroneous transmissions, store the correct number of
    placeholder data packets to log file to hide the quantity of
    communication that log file observation would otherwise reveal.
    """
    if logging and settings.log_file_masking and (payload.log_masking_ctr or completed):
        no_masking_packets = len(payload) if completed else payload.log_masking_ctr
        for _ in range(no_masking_packets):
            MessageLog.write_log_entry(AssemblyPacket.from_bytes(TrafficMaskingData.PLACEHOLDER_DATA),
                                       contact.onion_pub_key,
                                       message_log,
                                       origin)
    payload.log_masking_ctr = 0
