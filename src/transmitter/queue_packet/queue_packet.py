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

import os

from typing import TYPE_CHECKING, Optional as O

from src.common.entities.payload import MessagePayload, FilePayload, CommandPayload
from src.common.exceptions import SoftError
from src.common.statics import MessageHeader, FieldLength, TFCDatabaseFileName
from src.common.types_custom import BoolLogAsPlaceHolder, BytesMessage
from src.ui.common.input.get_yes import get_yes
from src.ui.common.input.path.get_path import get_path
from src.transmitter.files.file_normal import queue_normal_file
from src.transmitter.files.file_traffic_masking import TrafficMaskedFile

if TYPE_CHECKING:
    from src.common.entities.payload import Payload
    from src.common.entities.serialized_command import SerializedCommand
    from src.common.queues import TxQueue
    from src.database.db_settings import Settings
    from src.ui.transmitter.user_input import UserInput
    from src.ui.transmitter.window_tx import TxWindow, MockWindow


def queue_message(settings   : 'Settings',
                  queues     : 'TxQueue',
                  window     : 'TxWindow|MockWindow',
                  user_input : 'UserInput',
                  msg_header : O[MessageHeader]     = None,
                  log_as_ph  : BoolLogAsPlaceHolder = BoolLogAsPlaceHolder(False),
                  ) -> None:
    """\
    Prepend header to message, construct the MessagePayload object and
    queue its assembly packets.

    In this function the Transmitter Program adds the headers that allow
    the recipient's Receiver Program to redirect the received message to
    the correct window.

    Each message packet starts with a 1 byte whisper-header that
    determines whether the packet should be logged by the recipient. For
    private messages no additional information aside the
    PRIVATE_MESSAGE -- that informs the Receiver Program to use
    sender's window -- is required.

    For group messages, the GROUP_MESSAGE tells the Receiver
    Program that the header is followed by two additional headers:

        1) 4-byte Group ID that tells to what group the message was
           intended to. If the Receiver Program has not whitelisted the
           group ID, the group message will be ignored. The group ID
           space was chosen so that the birthday bound is at 65536
           because it's unlikely a user will ever have that many groups.

        2) 16-byte group message ID. This random ID is not important for
           the recipient. Instead, it is used by the sender's Receiver
           Program to detect what group messages are copies sent to other
           members of the group (these will be ignored from ephemeral and
           persistent message log). The message ID space was chosen so
           that the birthday bound is 2^64 (the same as the hash ratchet
           counter space).
    """
    if msg_header is None:
        if window.is_group_window and window.group is not None:
            header = bytes(MessageHeader.GROUP_MESSAGE.value) + window.group.group_id.raw_bytes + os.urandom(FieldLength.GROUP_MSG_ID.value)
        else:
            header = bytes(MessageHeader.PRIVATE_MESSAGE.value)
    else:
        header = bytes(msg_header)

    payload_bytes   = BytesMessage(user_input.whisper_bytes + header + user_input.plaintext_bytes)
    message_payload = MessagePayload.from_bytes(payload_bytes)

    queue_payload(message_payload, settings, queues, window, log_as_ph)


def queue_file(settings : 'Settings',
               queues   : 'TxQueue',
               window   : 'TxWindow',
               ) -> None:
    """Ask file path and load file data.

    In TFC there are two ways to send a file.

    For traffic masking, the file is loaded and sent inside normal
    messages using assembly packet headers dedicated for file
    transmission. This transmission is much slower, so the File object
    will determine metadata about the transmission's estimated transfer
    time, number of packets and the name and size of file. This
    information is inserted to the first assembly packet so that the
    recipient can observe the transmission progress from file transfer
    window.

    When traffic masking is disabled, file transmission is much faster
    as the file is only encrypted and transferred over serial once
    before the Relay Program multicasts the ciphertext to each
    specified recipient. See the send_file docstring (below) for more
    details.
    """
    path_to_file = get_path('Select file to send...', settings, get_file=True)

    if path_to_file.name in TFCDatabaseFileName:
        raise SoftError("Error: Can't send TFC database.", clear_before=True)

    if not settings.traffic_masking:
        queue_normal_file(path_to_file, settings, queues, window)
        return

    file    = TrafficMaskedFile(path_to_file, window, settings)
    payload = file.to_payload()

    if settings.confirm_tm_files:
        try:
            if not get_yes(f'Send {file.file_name} ({file.file_size_hr})'
                       f' to {window.window_type_hr} {window.window_name}'
                       f' ({len(payload)} packets, time: {file.time_hr})?'):
                raise SoftError('File selection aborted.', clear_before=True)
        except (EOFError, KeyboardInterrupt):
            raise SoftError('File selection aborted.', clear_before=True)

    queue_payload(payload, settings, queues, window, BoolLogAsPlaceHolder(True))


def queue_command(settings : 'Settings',
                  queues   : 'TxQueue',
                  command  : 'SerializedCommand',
                  ) -> None:
    """Split a command into assembly packets and queue them for sender processes."""
    payload = CommandPayload.from_bytes(command)
    queue_payload(payload, settings, queues)


def queue_payload(payload   : 'Payload',
                  settings  : 'Settings',
                  queues    : 'TxQueue',
                  window    : O['TxWindow|MockWindow'] = None,
                  log_as_ph : BoolLogAsPlaceHolder     = BoolLogAsPlaceHolder(False)
                  ) -> None:
    """Queue payload assembly packets to sender processes.

    This function is the last function on Transmitter Program's
    `input_process` process. It feeds the assembly packets to
    multiprocessing queues along with metadata required for transmission
    and message logging. The data put into these queues is read by the
    sender-side code in `process_sender()`, `normal_sender()`,
    and `traffic_masking_sender()`.
    """
    if isinstance(payload, CommandPayload):
        queue = queues.tm_command_packet if settings.traffic_masking else queues.command_packet
        for cmd_assembly_packet in payload:
            queue.put(cmd_assembly_packet)
        return

    if window is None:
        raise SoftError('Error: Window is required for message and file payloads.', clear_before=True)

    if isinstance(payload, MessagePayload):
        if settings.traffic_masking:
            for assembly_packet in payload:
                queues.tm_message_packet.put((assembly_packet, window.log_messages_tbytes, log_as_ph))
        else:
            for contact in window:
                for assembly_packet in payload:
                    queues.message_packet.put((assembly_packet,
                                              contact.onion_pub_key,
                                              window.log_messages_tbytes,
                                              log_as_ph,
                                              window.uid_tbytes))
        return

    if isinstance(payload, FilePayload):
        if settings.traffic_masking:
            for assembly_packet in payload:
                queues.tm_file_packet.put((assembly_packet, window.log_messages_tbytes, log_as_ph))
        else:
            for contact in window:
                for assembly_packet in payload:
                    queues.message_packet.put((assembly_packet,
                                              contact.onion_pub_key,
                                              window.log_messages_tbytes,
                                              log_as_ph,
                                              window.uid_tbytes))
        return

    raise SoftError('Error: Unsupported payload type.', clear_before=True)
