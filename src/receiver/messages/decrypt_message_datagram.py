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

import nacl.exceptions

from src.common.crypto.pt_ct import (MessageAssemblyPacketContactCT, MessageAssemblyPacketUserCT, MessageHeaderContactCT,
                                     MessageHeaderUserCT)
from src.common.entities.assembly_packet import (FileAssemblyPacketContact, FileAssemblyPacketUser,
                                                 MessageAssemblyPacketContact, MessageAssemblyPacketUser)
from src.common.exceptions import SoftError
from src.common.statics import Origin
from src.datagrams.receiver.message import DatagramOutgoingMessage
from src.ui.receiver.get_process_ratchet_offset import process_offset

if TYPE_CHECKING:
    from src.common.entities.contact import Contact
    from src.database.db_keys import KeyStore
    from src.datagrams.receiver.message import DatagramIncomingMessage
    from src.ui.receiver.window_rx import WindowList


def decrypt_message_datagram(datagram    : 'DatagramIncomingMessage|DatagramOutgoingMessage',
                             window_list : 'WindowList',
                             key_store   : 'KeyStore',
                             contact     : 'Contact'
                             ) -> MessageAssemblyPacketUser | MessageAssemblyPacketContact | FileAssemblyPacketUser | FileAssemblyPacketContact:
    """Decrypt message datagram from contact/local Transmitter."""
    if isinstance(datagram, DatagramOutgoingMessage):
        return decrypt_assembly_packet_from_user(window_list, key_store, contact, datagram.ct_header, datagram.ct_packet)
    else:
        return decrypt_assembly_packet_from_contact(window_list, key_store, contact, datagram.ct_header, datagram.ct_packet)


def decrypt_assembly_packet_from_user(window_list        : 'WindowList',
                                      key_store          : 'KeyStore',
                                      contact            : 'Contact',
                                      ct_header          : MessageHeaderUserCT,
                                      ct_assembly_packet : MessageAssemblyPacketUserCT,
                                      ) -> MessageAssemblyPacketUser | FileAssemblyPacketUser:
    """Decrypt assembly packet from user."""
    sys_msg_win = window_list.sys_msg_win

    try:
        offset = key_store.auth_and_decrypt_sent_packet_header(contact.onion_pub_key, ct_header)
    except nacl.exceptions.CryptoError:
        raise SoftError(f'Warning! Received packet sent to {str(contact.nick)} had an invalid header MAC.', window=sys_msg_win)

    process_offset(offset, Origin.USER, contact.nick, sys_msg_win, p_type='packet')

    try:
        assembly_packet_pt = key_store.auth_and_decrypt_sent_assembly_packet(contact.onion_pub_key, ct_assembly_packet, offset=offset)
    except nacl.exceptions.CryptoError:
        raise SoftError(f'Warning! Received packet sent to {str(contact.nick)} had an invalid MAC.', window=sys_msg_win)

    return MessageAssemblyPacketUser.from_bytes(assembly_packet_pt.pt_bytes)


def decrypt_assembly_packet_from_contact(window_list        : 'WindowList',
                                         key_store          : 'KeyStore',
                                         contact            : 'Contact',
                                         ct_header          : MessageHeaderContactCT,
                                         ct_assembly_packet : MessageAssemblyPacketContactCT,
                                         ) -> MessageAssemblyPacketContact | FileAssemblyPacketContact:
    """Decrypt assembly packet from contact."""
    sys_msg_win = window_list.sys_msg_win

    try:
        offset = key_store.auth_and_decrypt_received_packet_header(contact.onion_pub_key, ct_header)
    except nacl.exceptions.CryptoError:
        raise SoftError(f'Warning! Received packet from {str(contact.nick)} had an invalid header MAC.', window=sys_msg_win)

    process_offset(offset, Origin.CONTACT, contact.nick, window=sys_msg_win, p_type='packet')

    try:
        assembly_packet = key_store.auth_and_decrypt_received_assembly_packet(contact.onion_pub_key, ct_assembly_packet, offset=offset)
    except nacl.exceptions.CryptoError:
        raise SoftError(f'Warning! Received packet from {str(contact.nick)} had an invalid MAC.', window=sys_msg_win)

    return MessageAssemblyPacketContact.from_bytes(assembly_packet.pt_bytes)
