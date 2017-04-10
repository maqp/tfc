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
import zlib

from typing import List, Tuple

import nacl.exceptions

from src.common.crypto   import auth_and_decrypt, hash_chain, rm_padding_bytes
from src.common.encoding import bytes_to_int
from src.common.errors   import FunctionReturn
from src.common.input    import yes
from src.common.output   import box_print, c_print
from src.common.statics  import *
from src.rx.files        import process_received_file

if typing.TYPE_CHECKING:
    from src.common.db_contacts import Contact, ContactList
    from src.common.db_keys     import KeyList
    from src.common.db_settings import Settings
    from src.rx.windows         import WindowList


def decrypt_assembly_packet(packet:       bytes,  # Received packet
                            window_list:  'WindowList',
                            contact_list: 'ContactList',
                            key_list:     'KeyList') -> Tuple[bytes, str, bytes]:
    """Decrypt assembly packet from contact/local TxM."""
    message   = packet[:1] == MESSAGE_PACKET_HEADER
    enc_harac = packet[1:49]
    enc_msg   = packet[49:345]

    # Set packet-related variables

    if message:
        origin  = packet[345:346]
        account = packet[346:].decode()

        if origin not in [ORIGIN_CONTACT_HEADER, ORIGIN_USER_HEADER]:
            raise FunctionReturn("Received packet had an invalid origin-header.")

        direction, key_dir = {ORIGIN_USER_HEADER: ("sent to", 'tx'), ORIGIN_CONTACT_HEADER: ("from", 'rx')}[origin]
        p_type             = "packet"
        nick               = contact_list.get_contact(account).nick

    else:
        origin    = ORIGIN_USER_HEADER
        account   = 'local'
        direction = "from"
        key_dir   = 'tx'
        p_type    = 'command'
        nick      = "local TxM"

    window = window_list.get_local_window()
    keyset = key_list.get_keyset(account)

    if keyset.rx_hek == bytes(32) and origin == ORIGIN_CONTACT_HEADER:
        raise FunctionReturn(f"Warning! Received {p_type} from {nick} but no PSK exists.", window=window)

    # Decrypt hash ratchet counter

    try:
        header_key  = getattr(keyset, f'{key_dir}_hek')
        harac_bytes = auth_and_decrypt(enc_harac, header_key, soft_e=True)
    except nacl.exceptions.CryptoError:
        raise FunctionReturn(f"Warning! Received {p_type} {direction} {nick} had an invalid hash ratchet MAC.", window=window)

    # Catch up with hash ratchet offset

    purp_harac   = bytes_to_int(harac_bytes)
    stored_harac = getattr(keyset, f'{key_dir}_harac')

    if stored_harac > purp_harac:
        raise FunctionReturn(f"Warning! Received {p_type} {direction} {nick} had an expired hash ratchet counter.", window=window)

    key_candidate = getattr(keyset, f'{key_dir}_key')
    offset        = purp_harac - stored_harac

    if offset:
        box_print(f"Warning! {offset} {p_type}(s) {direction} {nick} were not received.")

    if offset > 1000 and origin == ORIGIN_CONTACT_HEADER:
        box_print([f"This might indicate that {offset} packets have been lost since last received ",
                   f"message, or that the contact is attempting a denial of service attack.",
                   f"You can catch up with key offset but this might take a long time or forever."])
        if not yes("Proceed with the key catchup?", tail=1):
            raise FunctionReturn(f"Dropped packet from {nick}.", window=window)

    for _ in range(offset):
        key_candidate = hash_chain(key_candidate)

    # Decrypt packet

    try:
        assembly_packet = auth_and_decrypt(enc_msg, key_candidate, soft_e=True)
    except nacl.exceptions.CryptoError:
        raise FunctionReturn(f"Warning! Received {p_type} {direction} {nick} had an invalid MAC.", window=window)

    # Update keys in database
    keyset.update_key(key_dir, hash_chain(key_candidate), offset + 1)

    return assembly_packet, account, origin


class Packet(object):
    """Packet objects collect and keep track of received, related assembly packets."""

    def __init__(self,
                 account:  str,
                 contact:  'Contact',
                 origin:   bytes,
                 type_:    str,
                 settings: 'Settings') -> None:
        """Create new packet."""
        self.account  = account
        self.contact  = contact
        self.origin   = origin
        self.type     = type_
        self.settings = settings

        # File information
        self.f_name    = None  # type: str
        self.f_size    = None  # type: str
        self.f_packets = None  # type: int
        self.f_eta     = None  # type: str

        self.sh = dict(message=M_S_HEADER, file=F_S_HEADER, command=C_S_HEADER)[self.type]
        self.lh = dict(message=M_L_HEADER, file=F_L_HEADER, command=C_L_HEADER)[self.type]
        self.ah = dict(message=M_A_HEADER, file=F_A_HEADER, command=C_A_HEADER)[self.type]
        self.eh = dict(message=M_E_HEADER, file=F_E_HEADER, command=C_E_HEADER)[self.type]
        self.ch = dict(message=M_C_HEADER, file=F_C_HEADER, command=C_C_HEADER)[self.type]
        self.nh = dict(message=P_N_HEADER, file=P_N_HEADER, command=C_N_HEADER)[self.type]

        self.assembly_pt_list = []  # type: List[bytes]
        self.lt_active        = False
        self.is_complete      = False

    def add_packet(self, packet: bytes) -> None:
        """Add new assembly packet to the object"""
        header = packet[:1]

        if header == self.sh:
            if self.type == 'file':
                if self.origin == ORIGIN_USER_HEADER:
                    raise FunctionReturn("Ignored short file from user.", output=False)
                if not self.contact.file_reception:
                    c_print("{} sent a file but file reception was disabled!".format(self.contact.nick), head=1, tail=1)
                    raise FunctionReturn("Unauthorized short file from contact.", output=False)
            self.assembly_pt_list = [packet]
            self.lt_active        = False
            self.is_complete      = True

        if header == self.lh:
            if self.type == 'file':
                if self.origin == ORIGIN_USER_HEADER:
                    raise FunctionReturn("Ignored long file from user.", output=False)
                if not self.contact.file_reception:
                    c_print("{} is sending file but file reception is disabled!".format(self.contact.nick), head=1, tail=1)
                    raise FunctionReturn("Unauthorized long file from contact.", output=False)

                try:
                    self.f_packets                          = bytes_to_int(packet[1:9])
                    self.f_name, self.f_size, self.f_eta, _ = [f.decode() for f in packet[9:].split(US_BYTE)]
                except (struct.error, ValueError, UnicodeError):
                    self.assembly_pt_list = []
                    self.lt_active        = False
                    self.is_complete      = False
                    raise FunctionReturn("Received packet had an invalid header.")

                box_print(['Receiving file from {}:'.format(self.contact.nick),
                           '{} ({})'.format(self.f_name, self.f_size),
                           'ETA {} ({} packets)'.format(self.f_eta, self.f_packets)])
                packet = self.lh + packet[9:]

            self.assembly_pt_list = [packet]
            self.lt_active        = True
            self.is_complete      = False

        if header == self.ah:
            if not self.lt_active:
                raise FunctionReturn("Missing start packet.", output=False)
            self.assembly_pt_list.append(packet)

        if header == self.eh:
            if not self.lt_active:
                raise FunctionReturn("Missing start packet.", output=False)
            self.assembly_pt_list.append(packet)
            self.lt_active   = False
            self.is_complete = True

        if header in [self.ch, self.nh]:
            if self.type == 'file':
                c_print("{} cancelled file.".format(self.contact.nick), head=1, tail=1)
            self.assembly_pt_list = []
            self.lt_active        = False
            self.is_complete      = False

    def assemble_message_packet(self) -> bytes:
        """Assemble message packet."""
        padded  = b''.join([p[1:] for p in self.assembly_pt_list])
        payload = rm_padding_bytes(padded)

        if len(self.assembly_pt_list) > 1:

            if len(payload) < (24 + 1 + 16 + 32):
                raise FunctionReturn("Received invalid packet.")

            msg_ct  = payload[:-32]
            msg_key = payload[-32:]

            try:
                payload = auth_and_decrypt(msg_ct, msg_key, soft_e=True)
            except (nacl.exceptions.CryptoError, nacl.exceptions.ValueError):
                raise FunctionReturn("Decryption of long message failed.")

        try:
            payload = zlib.decompress(payload)
        except zlib.error:
            raise FunctionReturn("Decompression of long message failed.")

        return payload

    def assemble_and_store_file(self) -> None:
        """Assemble file packet and store it to file."""
        padded  = b''.join([p[1:] for p in self.assembly_pt_list])
        payload = rm_padding_bytes(padded)
        process_received_file(payload, self.contact.nick)


    def assemble_command_packet(self) -> bytes:
        """Assemble command packet."""
        padded  = b''.join([p[1:] for p in self.assembly_pt_list])
        payload = rm_padding_bytes(padded)

        if len(self.assembly_pt_list) > 1:
            cmd_hash = payload[-32:]
            payload  = payload[:-32]
            if hash_chain(payload) != cmd_hash:
                raise FunctionReturn("Received an invalid command.")

        return zlib.decompress(payload)


class PacketList(object):
    """PacketList manages all file, message, and command packets."""

    def __init__(self, contact_list: 'ContactList', settings: 'Settings') -> None:
        """Create a new packet list object."""
        self.contact_list = contact_list
        self.settings     = settings
        self.packet_l     = []  # type: List[Packet]

    def __iter__(self):
        """Iterate over packet list."""
        for p in self.packet_l:
            yield p

    def __len__(self):
        """Return number of packets in packet list."""
        return len(self.packet_l)

    def has_packet(self, account: str, origin: bytes, type_: str) -> bool:
        """Return True if packet object for account exists, else False."""
        return any(p for p in self.packet_l if (p.account == account
                                                and p.origin == origin
                                                and p.type == type_))

    def get_packet(self, account: str, origin: bytes, type_: str) -> Packet:
        """Get packet based on account, origin and type.

        If packet does not exist, create it.
        """
        if not self.has_packet(account, origin, type_):
            contact = self.contact_list.get_contact(account)
            self.packet_l.append(Packet(account, contact, origin, type_, self.settings))

        return next(p for p in self.packet_l if (p.account == account
                                                 and p.origin == origin
                                                 and p.type == type_))
