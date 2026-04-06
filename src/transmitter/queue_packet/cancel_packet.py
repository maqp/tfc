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

from src.common.exceptions import SoftError
from src.common.entities.assembly_packet import FileAssemblyPacketUser, MessageAssemblyPacket
from src.common.statics import PayloadType, AsmPacket, CryptoVarLength
from src.common.types_custom import BoolLogAsPlaceHolder, BoolLogMessages, BytesWindowUID
from src.ui.common.output.print_message import print_message

if TYPE_CHECKING:
    from src.common.queues import TxQueue
    from src.common.types_compound import StandardPacketQueueData
    from src.database.db_settings import Settings
    from src.ui.transmitter.window_tx import TxWindow


def cancel_message(settings : 'Settings',
                   queues   : 'TxQueue',
                   window   : 'TxWindow',
                   ) -> None:
    """Cancel sent message to contact/group."""
    cancel_packet(window, settings, queues, PayloadType.MESSAGE)


def cancel_file(settings : 'Settings',
                queues   : 'TxQueue',
                window   : 'TxWindow',
                ) -> None:
    """Cancel sent file to contact/group."""
    cancel_packet(window, settings, queues, PayloadType.FILE)


def cancel_packet(window   : 'TxWindow',
                  settings : 'Settings',
                  queues   : 'TxQueue',
                  p_type   : PayloadType
                  ) -> None:
    """Cancel sent message/file to contact/group.

    In cases where the assembly packets have not yet been encrypted or
    output to Networked Computer, the queued messages or files to active
    window can be cancelled. Any single-packet message and file this
    function removes from the queue/transfer buffer are unavailable to
    recipient. However, in the case of multi-packet transmissions, if
    only the last assembly packet is cancelled, the recipient might
    obtain large enough section of the key that protects the inner
    encryption layer to allow them to brute force the rest of the key,
    and thus, decryption of the packet. There is simply no way to
    prevent this kind of attack without making TFC proprietary and
    re-writing it in a compiled language (which is very bad for users'
    rights).
    """
    if not settings.traffic_masking and p_type == PayloadType.FILE:
        raise SoftError('Files are only queued during traffic masking.', clear_before=True)

    if settings.traffic_masking:
        cancel_traffic_masking_packet(p_type, queues)
    else:
        cancel_standard_packet(p_type, queues, window)


def cancel_standard_packet(p_type : PayloadType,
                           queues : 'TxQueue',
                           window : 'TxWindow'
                           ) -> None:
    """Cancel standard packet."""
    queue  = queues.message_packet

    found_queued_packets_to_window = False

    packet_buffer : list['StandardPacketQueueData'] = []
    while queue.qsize():
        assembly_packet, onion_pub_key_bytes, log_messages, log_as_ph, window_uid_bytes = queue.get()

        # Put messages unrelated to the active window into the buffer
        if window_uid_bytes != window.uid_bytes:
            packet_buffer.append((assembly_packet, onion_pub_key_bytes, log_messages, log_as_ph, window_uid_bytes))
        else:
            found_queued_packets_to_window = True

    # Insert cancel packets to the queue
    if found_queued_packets_to_window:
        for contact in window:
            queue.put((_build_cancel_packet(p_type),
                       contact.onion_pub_key,
                       BoolLogMessages       (window.log_messages),
                       BoolLogAsPlaceHolder  (True),
                       BytesWindowUID        (window.uid_bytes)))

    # Put unrelated packets back to queue
    for packet in packet_buffer:
        queue.put(packet)

    # ---

    if found_queued_packets_to_window:
        message = f'Cancelled queued {p_type}s to {window.window_type_hr} {window.window_name}.'
    else:
        message = f'No {p_type}s queued for {window.window_type_hr} {window.window_name}.'
    raise SoftError(message, clear_before=True)


def cancel_traffic_masking_packet(p_type : PayloadType,
                                  queues : 'TxQueue',
                                  ) -> None:
    """Cancel traffic masking packet."""
    is_msg = p_type == PayloadType.MESSAGE
    queue  = queues.tm_message_packet if is_msg else queues.tm_file_packet

    # Initial values
    log_messages = BoolLogMessages(False)
    message      = f'No {p_type}s to cancel.'

    if queue.qsize():
        message = f'Cancelled {p_type}s for active window.'

        # Consume the message or file queue for the window
        while queue.qsize():
            log_messages = queue.get()[1] # Consuming gives access to most up-to-date log messages setting on input-process side.

        # Put only the cancel packet into the queue
        queue.put((_build_cancel_packet(p_type),
                   log_messages,
                   BoolLogAsPlaceHolder(True)))

    print_message(message, padding_top=1, padding_bottom=1)


def _build_cancel_packet(p_type: PayloadType) -> MessageAssemblyPacket | FileAssemblyPacketUser:
    """Create a cancel packet for the payload type."""
    if p_type == PayloadType.FILE:
        return FileAssemblyPacketUser(AsmPacket.F_C_HEADER + bytes(CryptoVarLength.PADDING))
    return MessageAssemblyPacket(AsmPacket.M_C_HEADER + bytes(CryptoVarLength.PADDING))
