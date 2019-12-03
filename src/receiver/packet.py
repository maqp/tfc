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

import struct
import typing
import zlib

from datetime import datetime, timedelta
from typing import Any, Callable, Dict, Iterable, Iterator, List, Optional, Sized

import nacl.exceptions

from src.common.crypto import auth_and_decrypt, blake2b, rm_padding_bytes
from src.common.encoding import bytes_to_int, int_to_bytes
from src.common.exceptions import SoftError
from src.common.input import yes
from src.common.misc import (
    decompress,
    readable_size,
    separate_header,
    separate_headers,
    separate_trailer,
)
from src.common.output import m_print
from src.common.statics import (
    ASSEMBLY_PACKET_HEADER_LENGTH,
    BLAKE2_DIGEST_LENGTH,
    COMMAND,
    C_A_HEADER,
    C_C_HEADER,
    C_E_HEADER,
    C_L_HEADER,
    C_N_HEADER,
    C_S_HEADER,
    ENCODED_INTEGER_LENGTH,
    FILE,
    F_A_HEADER,
    F_C_HEADER,
    F_E_HEADER,
    F_L_HEADER,
    F_S_HEADER,
    HARAC_CT_LENGTH,
    HARAC_WARN_THRESHOLD,
    LOCAL_PUBKEY,
    MAX_MESSAGE_SIZE,
    MESSAGE,
    M_A_HEADER,
    M_C_HEADER,
    M_E_HEADER,
    M_L_HEADER,
    M_S_HEADER,
    ORIGIN_CONTACT_HEADER,
    ORIGIN_USER_HEADER,
    P_N_HEADER,
    RX,
    SYMMETRIC_KEY_LENGTH,
    TX,
    US_BYTE,
)

from src.receiver.files import process_assembled_file

if typing.TYPE_CHECKING:
    from src.common.db_contacts import Contact, ContactList
    from src.common.db_keys import KeyList
    from src.common.db_settings import Settings
    from src.receiver.windows import RxWindow, WindowList


def process_offset(
    offset: int,  # Number of dropped packets
    origin: bytes,  # "to/from" preposition
    direction: str,  # Direction of packet
    nick: str,  # Nickname of associated contact
    window: "RxWindow",  # RxWindow object
) -> None:
    """Display warnings about increased offsets.

    If the offset has increased over the threshold, ask the user to
    confirm hash ratchet catch up.
    """
    if offset > HARAC_WARN_THRESHOLD and origin == ORIGIN_CONTACT_HEADER:
        m_print(
            [
                f"Warning! {offset} packets from {nick} were not received.",
                f"This might indicate that {offset} most recent packets were ",
                f"lost during transmission, or that the contact is attempting ",
                f"a DoS attack. You can wait for TFC to attempt to decrypt the ",
                "packet, but it might take a very long time or even forever.",
            ]
        )

        if not yes("Proceed with the decryption?", abort=False, tail=1):
            raise SoftError(f"Dropped packet from {nick}.", window=window)

    elif offset:
        m_print(
            f"Warning! {offset} packet{'s' if offset > 1 else ''} {direction} {nick} were not received."
        )


def decrypt_assembly_packet(
    packet: bytes,  # Assembly packet ciphertext
    onion_pub_key: bytes,  # Onion Service pubkey of associated contact
    origin: bytes,  # Direction of packet
    window_list: "WindowList",  # WindowList object
    contact_list: "ContactList",  # ContactList object
    key_list: "KeyList",  # Keylist object
) -> bytes:  # Decrypted assembly packet
    """Decrypt assembly packet from contact/local Transmitter.

    This function authenticates and decrypts incoming message and
    command datagrams. This function does not authenticate/decrypt
    incoming file and/or local key datagrams.

    While all message datagrams have been implicitly assumed to have
    originated from some contact until this point, to prevent the
    possibility of existential forgeries, the origin of message will be
    validated at this point with the cryptographic Poly1305-tag.

    As per the cryptographic doom principle, the message will not be
    even decrypted unless the Poly1305 tag of the ciphertext is valid.

    This function also authentication of packets that handle control
    flow of the Receiver program. Like messages, command datagrams have
    been implicitly assumed to be commands until this point. However,
    unless the Poly1305-tag of the purported command is found to be valid
    with the forward secret local key, it will not be even decrypted,
    let alone processed.
    """
    ct_harac, ct_assemby_packet = separate_header(packet, header_length=HARAC_CT_LENGTH)
    cmd_win = window_list.get_command_window()
    command = onion_pub_key == LOCAL_PUBKEY

    p_type = "command" if command else "packet"
    direction = "from" if command or (origin == ORIGIN_CONTACT_HEADER) else "sent to"
    nick = contact_list.get_nick_by_pub_key(onion_pub_key)

    # Load keys
    keyset = key_list.get_keyset(onion_pub_key)
    key_dir = TX if origin == ORIGIN_USER_HEADER else RX

    header_key = getattr(keyset, f"{key_dir}_hk")  # type: bytes
    message_key = getattr(keyset, f"{key_dir}_mk")  # type: bytes

    if any(k == bytes(SYMMETRIC_KEY_LENGTH) for k in [header_key, message_key]):
        raise SoftError("Warning! Loaded zero-key for packet decryption.")

    # Decrypt hash ratchet counter
    try:
        harac_bytes = auth_and_decrypt(ct_harac, header_key)
    except nacl.exceptions.CryptoError:
        raise SoftError(
            f"Warning! Received {p_type} {direction} {nick} had an invalid hash ratchet MAC.",
            window=cmd_win,
        )

    # Catch up with hash ratchet offset
    purp_harac = bytes_to_int(harac_bytes)
    stored_harac = getattr(keyset, f"{key_dir}_harac")
    offset = purp_harac - stored_harac
    if offset < 0:
        raise SoftError(
            f"Warning! Received {p_type} {direction} {nick} had an expired hash ratchet counter.",
            window=cmd_win,
        )

    process_offset(offset, origin, direction, nick, cmd_win)
    for harac in range(stored_harac, stored_harac + offset):
        message_key = blake2b(
            message_key + int_to_bytes(harac), digest_size=SYMMETRIC_KEY_LENGTH
        )

    # Decrypt packet
    try:
        assembly_packet = auth_and_decrypt(ct_assemby_packet, message_key)
    except nacl.exceptions.CryptoError:
        raise SoftError(
            f"Warning! Received {p_type} {direction} {nick} had an invalid MAC.",
            window=cmd_win,
        )

    # Update message key and harac
    new_key = blake2b(
        message_key + int_to_bytes(stored_harac + offset),
        digest_size=SYMMETRIC_KEY_LENGTH,
    )
    keyset.update_mk(key_dir, new_key, offset + 1)

    return assembly_packet


class Packet(object):
    """Packet objects collect and keep track of received assembly packets."""

    def __init__(
        self,
        onion_pub_key: bytes,  # Public key of the contact associated with the packet <─┐
        origin: bytes,  # Origin of packet (user, contact)                     <─┼─ Form packet UID
        p_type: str,  # Packet type (message, file, command)                 <─┘
        contact: "Contact",  # Contact object of contact associated with the packet
        settings: "Settings",  # Settings object
    ) -> None:
        """Create a new Packet object."""
        self.onion_pub_key = onion_pub_key
        self.contact = contact
        self.origin = origin
        self.type = p_type
        self.settings = settings

        # File transmission metadata
        self.packets = None  # type: Optional[int]
        self.time = None  # type: Optional[str]
        self.size = None  # type: Optional[str]
        self.name = None  # type: Optional[str]

        self.sh = {MESSAGE: M_S_HEADER, FILE: F_S_HEADER, COMMAND: C_S_HEADER}[
            self.type
        ]
        self.lh = {MESSAGE: M_L_HEADER, FILE: F_L_HEADER, COMMAND: C_L_HEADER}[
            self.type
        ]
        self.ah = {MESSAGE: M_A_HEADER, FILE: F_A_HEADER, COMMAND: C_A_HEADER}[
            self.type
        ]
        self.eh = {MESSAGE: M_E_HEADER, FILE: F_E_HEADER, COMMAND: C_E_HEADER}[
            self.type
        ]
        self.ch = {MESSAGE: M_C_HEADER, FILE: F_C_HEADER, COMMAND: C_C_HEADER}[
            self.type
        ]
        self.nh = {MESSAGE: P_N_HEADER, FILE: P_N_HEADER, COMMAND: C_N_HEADER}[
            self.type
        ]

        self.log_masking_ctr = 0  # type: int
        self.assembly_pt_list = []  # type: List[bytes]
        self.log_ct_list = []  # type: List[bytes]
        self.long_active = False
        self.is_complete = False

    def add_masking_packet_to_log_file(self, increase: int = 1) -> None:
        """Increase `log_masking_ctr` for message and file packets."""
        if self.type in [MESSAGE, FILE]:
            self.log_masking_ctr += increase

    def clear_file_metadata(self) -> None:
        """Clear file metadata."""
        self.packets = None
        self.time = None
        self.size = None
        self.name = None

    def clear_assembly_packets(self) -> None:
        """Clear packet state."""
        self.assembly_pt_list = []
        self.log_ct_list = []
        self.long_active = False
        self.is_complete = False

    def new_file_packet(self) -> None:
        """New file transmission handling logic."""
        name = self.name
        was_active = self.long_active
        self.clear_file_metadata()
        self.clear_assembly_packets()

        if self.origin == ORIGIN_USER_HEADER:
            self.add_masking_packet_to_log_file()
            raise SoftError("Ignored file from the user.", output=False)

        if not self.contact.file_reception:
            self.add_masking_packet_to_log_file()
            raise SoftError(
                f"Alert! File transmission from {self.contact.nick} but reception is disabled."
            )

        if was_active:
            m_print(
                f"Alert! File '{name}' from {self.contact.nick} never completed.",
                head=1,
                tail=1,
            )

    def check_long_packet(self) -> None:
        """Check if the long packet has permission to be extended."""
        if not self.long_active:
            self.add_masking_packet_to_log_file()
            raise SoftError("Missing start packet.", output=False)

        if self.type == FILE and not self.contact.file_reception:
            self.add_masking_packet_to_log_file(increase=len(self.assembly_pt_list) + 1)
            self.clear_assembly_packets()
            raise SoftError("Alert! File reception disabled mid-transfer.")

    def process_short_header(
        self, packet: bytes, packet_ct: Optional[bytes] = None
    ) -> None:
        """Process short packet."""
        if self.long_active:
            self.add_masking_packet_to_log_file(increase=len(self.assembly_pt_list))

        if self.type == FILE:
            self.new_file_packet()

        self.assembly_pt_list = [packet]
        self.long_active = False
        self.is_complete = True

        if packet_ct is not None:
            self.log_ct_list = [packet_ct]

    def process_long_header(
        self, packet: bytes, packet_ct: Optional[bytes] = None
    ) -> None:
        """Process first packet of long transmission."""
        if self.long_active:
            self.add_masking_packet_to_log_file(increase=len(self.assembly_pt_list))

        if self.type == FILE:
            self.new_file_packet()
            try:
                _, no_p_bytes, time_bytes, size_bytes, name_us_data = separate_headers(
                    packet,
                    [ASSEMBLY_PACKET_HEADER_LENGTH] + 3 * [ENCODED_INTEGER_LENGTH],
                )

                self.packets = bytes_to_int(
                    no_p_bytes
                )  # added by transmitter.packet.split_to_assembly_packets
                self.time = str(timedelta(seconds=bytes_to_int(time_bytes)))
                self.size = readable_size(bytes_to_int(size_bytes))
                self.name = name_us_data.split(US_BYTE, 1)[0].decode()

                m_print(
                    [
                        f"Receiving file from {self.contact.nick}:",
                        f"{self.name} ({self.size})",
                        f"ETA {self.time} ({self.packets} packets)",
                    ],
                    bold=True,
                    head=1,
                    tail=1,
                )

            except (struct.error, UnicodeError, ValueError):
                self.add_masking_packet_to_log_file()
                raise SoftError("Error: Received file packet had an invalid header.")

        self.assembly_pt_list = [packet]
        self.long_active = True
        self.is_complete = False

        if packet_ct is not None:
            self.log_ct_list = [packet_ct]

    def process_append_header(
        self, packet: bytes, packet_ct: Optional[bytes] = None
    ) -> None:
        """Process consecutive packet(s) of long transmission."""
        self.check_long_packet()
        self.assembly_pt_list.append(packet)

        if packet_ct is not None:
            self.log_ct_list.append(packet_ct)

    def process_end_header(
        self, packet: bytes, packet_ct: Optional[bytes] = None
    ) -> None:
        """Process last packet of long transmission."""
        self.check_long_packet()
        self.assembly_pt_list.append(packet)
        self.long_active = False
        self.is_complete = True

        if packet_ct is not None:
            self.log_ct_list.append(packet_ct)

    def abort_packet(self, cancel: bool = False) -> None:
        """Process cancel/noise packet."""
        if (
            self.type == FILE
            and self.origin == ORIGIN_CONTACT_HEADER
            and self.long_active
        ):
            if cancel:
                message = f"{self.contact.nick} cancelled file."
            else:
                message = f"Alert! File '{self.name}' from {self.contact.nick} never completed."
            m_print(message, head=1, tail=1)
            self.clear_file_metadata()
        self.add_masking_packet_to_log_file(increase=len(self.assembly_pt_list) + 1)
        self.clear_assembly_packets()

    def process_cancel_header(self, *_: Any) -> None:
        """Process cancel packet for long transmission."""
        self.abort_packet(cancel=True)

    def process_noise_header(self, *_: Any) -> None:
        """Process traffic masking noise packet."""
        self.abort_packet()

    def add_packet(self, packet: bytes, packet_ct: Optional[bytes] = None) -> None:
        """Add a new assembly packet to the object."""
        try:
            func_d = {
                self.sh: self.process_short_header,
                self.lh: self.process_long_header,
                self.ah: self.process_append_header,
                self.eh: self.process_end_header,
                self.ch: self.process_cancel_header,
                self.nh: self.process_noise_header,
            }  # type: Dict[bytes, Callable[[bytes, Optional[bytes]], None]]
            func = func_d[packet[:ASSEMBLY_PACKET_HEADER_LENGTH]]
        except KeyError:
            # Erroneous headers are ignored but stored as placeholder data.
            self.add_masking_packet_to_log_file()
            raise SoftError(
                "Error: Received packet had an invalid assembly packet header."
            )
        func(packet, packet_ct)

    def assemble_message_packet(self) -> bytes:
        """Assemble message packet."""
        padded = b"".join(
            [p[ASSEMBLY_PACKET_HEADER_LENGTH:] for p in self.assembly_pt_list]
        )
        payload = rm_padding_bytes(padded)

        if len(self.assembly_pt_list) > 1:
            msg_ct, msg_key = separate_trailer(payload, SYMMETRIC_KEY_LENGTH)
            try:
                payload = auth_and_decrypt(msg_ct, msg_key)
            except nacl.exceptions.CryptoError:
                raise SoftError("Error: Decryption of message failed.")

        try:
            return decompress(payload, MAX_MESSAGE_SIZE)
        except zlib.error:
            raise SoftError("Error: Decompression of message failed.")

    def assemble_and_store_file(
        self, ts: "datetime", onion_pub_key: bytes, window_list: "WindowList"
    ) -> None:
        """Assemble file packet and store it."""
        padded = b"".join(
            [p[ASSEMBLY_PACKET_HEADER_LENGTH:] for p in self.assembly_pt_list]
        )
        payload = rm_padding_bytes(padded)

        no_fields = 3 if len(self.assembly_pt_list) > 1 else 2
        *_, payload = separate_headers(payload, no_fields * [ENCODED_INTEGER_LENGTH])

        process_assembled_file(
            ts, payload, onion_pub_key, self.contact.nick, self.settings, window_list
        )

    def assemble_command_packet(self) -> bytes:
        """Assemble command packet."""
        padded = b"".join(
            [p[ASSEMBLY_PACKET_HEADER_LENGTH:] for p in self.assembly_pt_list]
        )
        payload = rm_padding_bytes(padded)

        if len(self.assembly_pt_list) > 1:
            payload, cmd_hash = separate_trailer(payload, BLAKE2_DIGEST_LENGTH)
            if blake2b(payload) != cmd_hash:
                raise SoftError("Error: Received an invalid command.")

        try:
            return decompress(payload, self.settings.max_decompress_size)
        except zlib.error:
            raise SoftError("Error: Decompression of command failed.")


class PacketList(Iterable[Packet], Sized):
    """PacketList manages all file, message, and command packets."""

    def __init__(self, settings: "Settings", contact_list: "ContactList") -> None:
        """Create a new PacketList object."""
        self.settings = settings
        self.contact_list = contact_list
        self.packets = []  # type: List[Packet]

    def __iter__(self) -> Iterator[Packet]:
        """Iterate over packet list."""
        yield from self.packets

    def __len__(self) -> int:
        """Return number of packets in the packet list."""
        return len(self.packets)

    def has_packet(self, onion_pub_key: bytes, origin: bytes, p_type: str) -> bool:
        """Return True if a packet with matching selectors exists, else False."""
        return any(
            p
            for p in self.packets
            if (
                p.onion_pub_key == onion_pub_key
                and p.origin == origin
                and p.type == p_type
            )
        )

    def get_packet(
        self, onion_pub_key: bytes, origin: bytes, p_type: str, log_access: bool = False
    ) -> Packet:
        """Get packet based on Onion Service public key, origin, and type.

        If the packet does not exist, create it.
        """
        if not self.has_packet(onion_pub_key, origin, p_type):
            if log_access:
                contact = self.contact_list.generate_dummy_contact()
            else:
                contact = self.contact_list.get_contact_by_pub_key(onion_pub_key)

            self.packets.append(
                Packet(onion_pub_key, origin, p_type, contact, self.settings)
            )

        return next(
            p
            for p in self.packets
            if (
                p.onion_pub_key == onion_pub_key
                and p.origin == origin
                and p.type == p_type
            )
        )
