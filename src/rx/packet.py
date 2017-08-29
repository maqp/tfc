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

import datetime
import struct
import typing
import zlib

from typing import Callable, Dict, Generator, Iterable, List, Sized, Tuple

import nacl.exceptions

from src.common.crypto     import auth_and_decrypt, hash_chain, rm_padding_bytes
from src.common.encoding   import bytes_to_int
from src.common.exceptions import FunctionReturn
from src.common.input      import yes
from src.common.misc       import readable_size
from src.common.output     import box_print, c_print
from src.common.statics    import *

from src.rx.files import process_received_file

if typing.TYPE_CHECKING:
    from src.common.db_contacts import Contact, ContactList
    from src.common.db_keys     import KeyList
    from src.common.db_settings import Settings
    from src.rx.windows         import RxWindow, WindowList


def get_packet_values(packet:       bytes,
                      window:       'RxWindow',
                      contact_list: 'ContactList') -> Tuple[bytes, str, str, str, str, str]:
    """Load packet-related variables."""
    if packet[:1] == COMMAND_PACKET_HEADER:
        origin    = ORIGIN_USER_HEADER
        direction = "from"
        key_dir   = TX
        p_type    = "command"
        account   = LOCAL_ID
        nick      = "local TxM"
    else:
        origin = packet[345:346]
        if origin not in [ORIGIN_USER_HEADER, ORIGIN_CONTACT_HEADER]:
            raise FunctionReturn("Error: Received packet had an invalid origin-header.", window=window)

        direction, key_dir = ("sent to", TX) if origin == ORIGIN_USER_HEADER else ("from", RX)
        p_type  = "packet"
        account = packet[346:].decode()
        nick    = contact_list.get_contact(account).nick

        if account == LOCAL_ID:
            raise FunctionReturn("Warning! Received packet masqueraded as command.", window=window)

    return origin, direction, key_dir, p_type, account, nick


def process_offset(offset:    int,
                   origin:    bytes,
                   direction: str,
                   nick:      str,
                   window:    'RxWindow') -> None:
    """Display warnings about increased offsets.

    If offset has increased over threshold, ask
    the user to confirm hash ratchet catch up.
    """
    if offset > HARAC_WARN_THRESHOLD and origin == ORIGIN_CONTACT_HEADER:
        box_print([f"Warning! {offset} packets from {nick} were not received.",
                   f"This might indicate that {offset} most recent packets were ",
                   f"lost during transmission, or that the contact is attempting ",
                   f"a DoS attack. You can wait for TFC to attempt to decrypt the ",
                   "packet, but it might take a very long time or even forever."])
        if not yes("Proceed with the decryption?", tail=1):
            raise FunctionReturn(f"Dropped packet from {nick}.", window=window)
    elif offset:
        box_print(f"Warning! {offset} packet{'s' if offset > 1 else ''} {direction} {nick} were not received.")


def decrypt_assembly_packet(packet:       bytes,
                            window_list:  'WindowList',
                            contact_list: 'ContactList',
                            key_list:     'KeyList') -> Tuple[bytes, str, bytes]:
    """Decrypt assembly packet from contact/local TxM."""
    enc_harac = packet[1:49]
    enc_msg   = packet[49:345]
    window    = window_list.get_local_window()

    origin, direction, key_dir, p_type, account, nick = get_packet_values(packet, window, contact_list)

    # Load keys
    keyset      = key_list.get_keyset(account)
    header_key  = getattr(keyset, f'{key_dir}_hek')
    message_key = getattr(keyset, f'{key_dir}_key')

    if any(k == bytes(KEY_LENGTH) for k in [header_key, message_key]):
        raise FunctionReturn("Warning! Loaded zero-key for packet decryption.")

    # Decrypt hash ratchet counter
    try:
        harac_bytes = auth_and_decrypt(enc_harac, header_key, soft_e=True)
    except nacl.exceptions.CryptoError:
        raise FunctionReturn(f"Warning! Received {p_type} {direction} {nick} had an invalid hash ratchet MAC.", window=window)

    # Catch up with hash ratchet offset
    purp_harac   = bytes_to_int(harac_bytes)
    stored_harac = getattr(keyset, f'{key_dir}_harac')
    offset       = purp_harac - stored_harac
    if offset < 0:
        raise FunctionReturn(f"Warning! Received {p_type} {direction} {nick} had an expired hash ratchet counter.", window=window)

    process_offset(offset, origin, direction, nick, window)
    for _ in range(offset):
        message_key = hash_chain(message_key)

    # Decrypt packet
    try:
        assembly_packet = auth_and_decrypt(enc_msg, message_key, soft_e=True)
    except nacl.exceptions.CryptoError:
        raise FunctionReturn(f"Warning! Received {p_type} {direction} {nick} had an invalid MAC.", window=window)

    # Update keys in database
    keyset.update_key(key_dir, hash_chain(message_key), offset + 1)

    return assembly_packet, account, origin


class Packet(object):
    """Packet objects collect and keep track of received assembly packets."""

    def __init__(self,
                 account:  str,
                 contact:  'Contact',
                 origin:   bytes,
                 p_type:   str,
                 settings: 'Settings') -> None:
        """Create a new Packet object."""
        self.account  = account
        self.contact  = contact
        self.origin   = origin
        self.type     = p_type
        self.settings = settings

        # File transmission metadata
        self.packets = None  # type: int
        self.time    = None  # type: str
        self.size    = None  # type: str
        self.name    = None  # type: str

        self.sh = dict(message=M_S_HEADER, file=F_S_HEADER, command=C_S_HEADER)[self.type]
        self.lh = dict(message=M_L_HEADER, file=F_L_HEADER, command=C_L_HEADER)[self.type]
        self.ah = dict(message=M_A_HEADER, file=F_A_HEADER, command=C_A_HEADER)[self.type]
        self.eh = dict(message=M_E_HEADER, file=F_E_HEADER, command=C_E_HEADER)[self.type]
        self.ch = dict(message=M_C_HEADER, file=F_C_HEADER, command=C_C_HEADER)[self.type]
        self.nh = dict(message=P_N_HEADER, file=P_N_HEADER, command=C_N_HEADER)[self.type]

        self.assembly_pt_list = []  # type: List[bytes]
        self.log_masking_ctr  = 0   # type: int
        self.long_active      = False
        self.is_complete      = False

    def add_masking_packet_to_logfile(self, increase: int = 1) -> None:
        """Increase log_masking_ctr for message and file packets."""
        if self.type in [MESSAGE, FILE]:
            self.log_masking_ctr += increase

    def clear_file_metadata(self) -> None:
        """Clear file metadata."""
        self.packets = None
        self.time    = None
        self.size    = None
        self.name    = None

    def clear_assembly_packets(self) -> None:
        """Clear packet state."""
        self.assembly_pt_list = []
        self.long_active      = False
        self.is_complete      = False

    def new_file_packet(self) -> None:
        """New file transmission handling logic."""
        name       = self.name
        was_active = self.long_active
        self.clear_file_metadata()
        self.clear_assembly_packets()

        if self.origin == ORIGIN_USER_HEADER:
            self.add_masking_packet_to_logfile()
            raise FunctionReturn("Ignored file from user.", output=False)

        if not self.contact.file_reception:
            self.add_masking_packet_to_logfile()
            raise FunctionReturn(f"Alert! File transmission from {self.contact.nick} but reception is disabled.")

        if was_active:
            c_print(f"Alert! File '{name}' from {self.contact.nick} never completed.", head=1, tail=1)

    def check_long_packet(self):
        """Check if long packet has permission to be extended."""
        if not self.long_active:
            self.add_masking_packet_to_logfile()
            raise FunctionReturn("Missing start packet.", output=False)

        if self.type == FILE and not self.contact.file_reception:
            self.add_masking_packet_to_logfile(increase=len(self.assembly_pt_list) + 1)
            self.clear_assembly_packets()
            raise FunctionReturn("Alert! File reception disabled mid-transfer.")

    def process_short_header(self, packet: bytes) -> None:
        """Process short packet."""
        if self.long_active:
            self.add_masking_packet_to_logfile(increase=len(self.assembly_pt_list))

        if self.type == FILE:
            self.new_file_packet()
            packet = self.sh + packet[17:]

        self.assembly_pt_list = [packet]
        self.long_active      = False
        self.is_complete      = True

    def process_long_header(self, packet: bytes) -> None:
        """Process first packet of long transmission."""
        if self.long_active:
            self.add_masking_packet_to_logfile(increase=len(self.assembly_pt_list))

        if self.type == FILE:
            self.new_file_packet()
            try:
                self.packets = bytes_to_int(packet[1:9])
                self.time    = str(datetime.timedelta(seconds=bytes_to_int(packet[9:17])))
                self.size    = readable_size(bytes_to_int(packet[17:25]))
                self.name    = packet[25:].split(US_BYTE)[0].decode()
                packet       = self.lh + packet[25:]

                box_print([f'Receiving file from {self.contact.nick}:',
                           f'{self.name} ({self.size})',
                           f'ETA {self.time} ({self.packets} packets)'])

            except (struct.error, UnicodeError, ValueError):
                self.add_masking_packet_to_logfile()
                raise FunctionReturn("Error: Received file packet had an invalid header.")

        self.assembly_pt_list = [packet]
        self.long_active      = True
        self.is_complete      = False

    def process_append_header(self, packet: bytes) -> None:
        """Process consecutive packet(s) of long transmission."""
        self.check_long_packet()
        self.assembly_pt_list.append(packet)

    def process_end_header(self, packet: bytes) -> None:
        """Process last packet of long transmission."""
        self.check_long_packet()
        self.assembly_pt_list.append(packet)
        self.long_active = False
        self.is_complete = True

    def abort_packet(self, message: str) -> None:
        """Process cancel/noise packet."""
        if self.type == FILE and self.origin == ORIGIN_CONTACT_HEADER and self.long_active:
            c_print(message, head=1, tail=1)
            self.clear_file_metadata()
        self.add_masking_packet_to_logfile(increase=len(self.assembly_pt_list) + 1)
        self.clear_assembly_packets()

    def process_cancel_header(self, _: bytes) -> None:
        """Process cancel packet for long transmission."""
        self.abort_packet(f"{self.contact.nick} cancelled file.")

    def process_noise_header(self, _: bytes) -> None:
        """Process traffic masking noise packet."""
        self.abort_packet(f"Alert! File '{self.name}' from {self.contact.nick} never completed.")

    def add_packet(self, packet: bytes) -> None:
        """Add a new assembly packet to the object."""
        try:
            func_d = {self.sh: self.process_short_header,
                      self.lh: self.process_long_header,
                      self.ah: self.process_append_header,
                      self.eh: self.process_end_header,
                      self.ch: self.process_cancel_header,
                      self.nh: self.process_noise_header}  # type: Dict[bytes, Callable]
            func = func_d[packet[:1]]
        except KeyError:
            # Erroneous headers are ignored, but stored as placeholder data.
            self.add_masking_packet_to_logfile()
            raise FunctionReturn("Error: Received packet had an invalid assembly packet header.")
        func(packet)

    def assemble_message_packet(self) -> bytes:
        """Assemble message packet."""
        padded  = b''.join([p[1:] for p in self.assembly_pt_list])
        payload = rm_padding_bytes(padded)

        if len(self.assembly_pt_list) > 1:
            msg_ct  = payload[:-KEY_LENGTH]
            msg_key = payload[-KEY_LENGTH:]

            try:
                payload = auth_and_decrypt(msg_ct, msg_key, soft_e=True)
            except (nacl.exceptions.CryptoError, nacl.exceptions.ValueError):
                raise FunctionReturn("Error: Decryption of message failed.")

        try:
            return zlib.decompress(payload)
        except zlib.error:
            raise FunctionReturn("Error: Decompression of message failed.")

    def assemble_and_store_file(self) -> None:
        """Assemble file packet and store it."""
        padded  = b''.join([p[1:] for p in self.assembly_pt_list])
        payload = rm_padding_bytes(padded)

        process_received_file(payload, self.contact.nick)

    def assemble_command_packet(self) -> bytes:
        """Assemble command packet."""
        padded  = b''.join([p[1:] for p in self.assembly_pt_list])
        payload = rm_padding_bytes(padded)

        if len(self.assembly_pt_list) > 1:
            cmd_hash = payload[-KEY_LENGTH:]
            payload  = payload[:-KEY_LENGTH]
            if hash_chain(payload) != cmd_hash:
                raise FunctionReturn("Error: Received an invalid command.")

        try:
            return zlib.decompress(payload)
        except zlib.error:
            raise FunctionReturn("Error: Decompression of command failed.")


class PacketList(Iterable, Sized):
    """PacketList manages all file, message, and command packets."""

    def __init__(self, settings: 'Settings', contact_list: 'ContactList') -> None:
        """Create a new PacketList object."""
        self.settings     = settings
        self.contact_list = contact_list
        self.packets      = []  # type: List[Packet]

    def __iter__(self) -> Generator:
        """Iterate over packet list."""
        yield from self.packets

    def __len__(self) -> int:
        """Return number of packets in packet list."""
        return len(self.packets)

    def has_packet(self, account: str, origin: bytes, p_type: str) -> bool:
        """Return True if packet with matching selectors exists, else False."""
        return any(p for p in self.packets if (p.account == account
                                               and p.origin == origin
                                               and p.type == p_type))

    def get_packet(self, account: str, origin: bytes, p_type: str) -> Packet:
        """Get packet based on account, origin and type.

        If packet does not exist, create it.
        """
        if not self.has_packet(account, origin, p_type):
            contact = self.contact_list.get_contact(account)
            self.packets.append(Packet(account, contact, origin, p_type, self.settings))

        return next(p for p in self.packets if (p.account == account
                                                and p.origin == origin
                                                and p.type == p_type))
