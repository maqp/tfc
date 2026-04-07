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

import zlib

from datetime import datetime, timedelta
from typing import TYPE_CHECKING, Iterator, Optional as O, Sequence

import nacl.exceptions

from src.common.entities.assembly_packet import (AssemblyPacket, CommandAssemblyPacket, FileAssemblyPacketUser,
                                                 MessageAssemblyPacket)
from src.common.entities.assembly_packet_headers import COMMAND_PAYLOAD_HEADERS, FILE_PAYLOAD_HEADERS, MESSAGE_PAYLOAD_HEADERS
from src.common.entities.serialized_command import SerializedCommand
from src.common.exceptions import SoftError
from src.common.crypto.algorithms.blake2b import blake2b
from src.common.crypto.algorithms.padding import byte_padding, rm_padding_bytes
from src.common.crypto.algorithms.aead import auth_and_decrypt
from src.common.crypto.pt_ct import MsgInnerPT
from src.common.crypto.keys.symmetric_key import LongMessageKey
from src.common.statics import (PayloadType, CryptoVarLength, AsmPacket, FieldLength,
                                CompressionLiterals, KeyLength, RxCommand, Separator)
from src.common.utils.encoding import int_to_bytes, bytes_to_int, decompress
from src.common.utils.conversion import human_readable_size
from src.common.utils.strings import split_byte_string, separate_header, separate_headers, separate_trailer
from src.common.types_custom import BytesAssembledFile

if TYPE_CHECKING:
    from src.common.entities.contact import Contact
    from src.common.types_custom import BytesFile, BytesMessage
    from src.ui.receiver.window_rx import WindowList


class Payload:
    """Payload is a complete message that can be split into assembly packets for delivery."""

    PAYLOAD_TYPE : PayloadType
    PACKET_TYPE  = AssemblyPacket
    VALID_HEADERS: frozenset[AsmPacket] = frozenset()

    def __init__(self, assembly_packets : O[Sequence[AssemblyPacket]] = None) -> None:
        """Create a new Payload object."""
        self._assembly_packets : list[AssemblyPacket] = []
        self.log_masking_ctr   : int = 0

        if assembly_packets is not None:
            for packet in assembly_packets:
                self.add_assembly_packet(packet)

    def __len__(self) -> int:
        """Get the number of AssemblyPacket objects."""
        return len(self._assembly_packets)

    def __iter__(self) -> Iterator[AssemblyPacket]:
        yield from self._assembly_packets

    def add_assembly_packet(self, packet: AssemblyPacket) -> None:
        """Add a new AssemblyPacket object to this payload."""
        if not isinstance(packet, self.PACKET_TYPE) or packet.header not in self.VALID_HEADERS:
            raise SoftError(f"Can't add invalid packet to {self.payload_type_hr} payload.")

        if packet.is_cancel_of_payload:
            # Cancel packets intentionally terminate an in-progress payload.
            self.log_masking_ctr += len(self._assembly_packets) + 1
            self.clear_payload_packets()
            raise SoftError(f'{self.payload_type_hr} payload transmission was cancelled.', output=False)

        if packet.is_noise_packet:
            # Noise packets are not part of any user payload. Count them for
            # optional log-file masking, then clear any stale partial payload.
            self.log_masking_ctr += len(self._assembly_packets) + 1
            self.clear_payload_packets()
            raise SoftError(f'{self.payload_type_hr} payload construction received a noise packet.', output=False)

        if self.packet_indicates_packet_drop(packet):
            self.log_masking_ctr += len(self._assembly_packets)
            self.clear_payload_packets()
            raise SoftError(f'{self.payload_type_hr} payload construction failed due to dropped packet.')

        self._assembly_packets.append(packet)

    def clear_payload_packets(self) -> None:
        """Clear all AssemblyPacket objects from this payload."""
        self._assembly_packets = []

    # ┌──────────────┐
    # │ Payload Type │
    # └──────────────┘
    @property
    def payload_type_hr(self) -> str:
        """Return the type of the payload."""
        return self.PAYLOAD_TYPE.value

    # ┌────────────────┐
    # │ Payload Status │
    # └────────────────┘

    @property
    def has_packets(self) -> bool:
        """Return True if the payload contains at least one AssemblyPacket object."""
        return len(self._assembly_packets) > 0

    @property
    def is_complete(self) -> bool:
        """Return True if the payload contains all required assembly packets."""
        most_recent_packet = self._assembly_packets[-1]
        return (   most_recent_packet.is_short_payload
                or most_recent_packet.is_noise_packet
                or most_recent_packet.is_end_of_long_payload)

    # ┌─────────────────┐
    # │ Payload Parsing │
    # └─────────────────┘

    @property
    def most_recent_packet(self) -> O[AssemblyPacket]:
        """Get the most recent AssemblyPacket object."""
        return self._assembly_packets[-1] if self._assembly_packets else None

    def packet_indicates_packet_drop(self, packet: AssemblyPacket) -> bool:
        """Return True if the packet received is incompatible and indicates packets have been dropped."""
        if not self.has_packets:
            return packet.is_append_of_long_payload or packet.is_end_of_long_payload

        previous_packet = self.most_recent_packet
        if previous_packet is None:
            return False

        if previous_packet.is_first_of_long_payload or previous_packet.is_append_of_long_payload:
            return packet.is_short_payload or packet.is_first_of_long_payload

        return packet.is_append_of_long_payload or packet.is_end_of_long_payload

    def clear_assembly_packets(self) -> None:
        """Clear all AssemblyPacket objects from this payload."""
        self._assembly_packets = []


# ┌─────────────────────┐
# │ Payload Subclassing │
# └─────────────────────┘

class MessagePayload(Payload):
    PAYLOAD_TYPE = PayloadType.MESSAGE
    PACKET_TYPE  = MessageAssemblyPacket
    VALID_HEADERS: frozenset[AsmPacket] = MESSAGE_PAYLOAD_HEADERS

    def __iter__(self) -> Iterator[MessageAssemblyPacket]:
        """Iterate over message assembly packets."""
        for packet in self._assembly_packets:
            if isinstance(packet, MessageAssemblyPacket):
                yield packet

    def assemble_message_packet(self) -> bytes:
        """Assemble the message payload."""
        padded  = b''.join(packet.raw_bytes[FieldLength.ASSEMBLY_PACKET_HEADER.value:] for packet in self)
        payload = rm_padding_bytes(padded)

        if len(self) > 1:
            msg_ct, msg_key = separate_trailer(payload, KeyLength.SYMMETRIC_KEY.value)
            try:
                payload = auth_and_decrypt(msg_ct, msg_key)
            except nacl.exceptions.CryptoError as exc:
                raise SoftError('Error: Decryption of message failed.') from exc

        try:
            return decompress(payload, CompressionLiterals.MAX_MESSAGE_SIZE_MB)
        except zlib.error as exc:
            raise SoftError('Error: Decompression of message failed.') from exc

    @staticmethod
    def from_bytes(message_bytes: 'BytesMessage') -> 'MessagePayload':
        """Convert message_bytes to a MessagePayload object."""
        inner_plaintext = MsgInnerPT(zlib.compress(bytes(message_bytes), level=CompressionLiterals.COMPRESSION_LEVEL.value))

        if len(inner_plaintext) < CryptoVarLength.PADDING.value:
            padded             = inner_plaintext.apply_adding()
            payload_bytes_list = [padded.prepend_asm_header(AsmPacket.M_S_HEADER).pt_bytes]
        else:
            long_msg_key     = LongMessageKey()
            inner_ciphertext = long_msg_key.encrypt_and_sign(inner_plaintext)
            inner_ciphertext = inner_ciphertext.add_sender_based_control_key(long_msg_key)

            padded_ct          = inner_ciphertext.apply_adding()
            payload_bytes_list = split_byte_string(padded_ct.ct_bytes, item_len=CryptoVarLength.PADDING.value)

            first_packet   = payload_bytes_list[0]
            append_packets = [p for p in payload_bytes_list[1:-1]]
            end_packet     = payload_bytes_list[-1]

            payload_bytes_list = (  [AsmPacket.M_L_HEADER.value + first_packet]
                                  + [AsmPacket.M_A_HEADER.value + append_packet for append_packet in append_packets]
                                  + [AsmPacket.M_E_HEADER.value + end_packet])

        assembly_packets = [MessageAssemblyPacket(payload_bytes) for payload_bytes in payload_bytes_list]

        return MessagePayload(assembly_packets)


class FilePayload(Payload):
    PAYLOAD_TYPE = PayloadType.FILE
    PACKET_TYPE  = MessageAssemblyPacket
    VALID_HEADERS: frozenset[AsmPacket] = FILE_PAYLOAD_HEADERS

    def __iter__(self) -> Iterator[MessageAssemblyPacket]:
        """Iterate over file assembly packets."""
        for packet in self._assembly_packets:
            if isinstance(packet, MessageAssemblyPacket):
                yield packet

    @property
    def transfer_metadata(self) -> O[tuple[str, str, int]]:
        """Return display metadata for an in-progress long file payload."""
        if not self.has_packets:
            return None

        first_packet = self._assembly_packets[0]
        if not first_packet.is_first_of_long_payload:
            return None

        try:
            _, packet_total_bytes, eta_bytes, size_bytes, name_data = separate_headers(
                first_packet.raw_bytes,
                [FieldLength.ASSEMBLY_PACKET_HEADER.value] + 3 * [FieldLength.ENCODED_INTEGER.value],
            )
            file_name = name_data.split(Separator.US_BYTE, 1)[0].decode()
        except (UnicodeError, ValueError):
            return None

        packet_total = bytes_to_int(packet_total_bytes)
        if packet_total <= 0:
            return None

        _ = str(timedelta(seconds=bytes_to_int(eta_bytes)))
        return file_name, human_readable_size(bytes_to_int(size_bytes)), packet_total


    def assemble_and_store_file(self, ts: datetime, contact: 'Contact', window_list: 'WindowList') -> None:
        """Assemble and store the file payload."""
        from src.receiver.files.file_traffic_masking import process_assembled_file

        padded        = b''.join(packet.raw_bytes[FieldLength.ASSEMBLY_PACKET_HEADER.value:] for packet in self)
        payload_bytes = rm_padding_bytes(padded)

        no_fields         = 3 if len(self) > 1 else 2
        *_, payload_bytes = separate_headers(payload_bytes, no_fields * [FieldLength.ENCODED_INTEGER.value])

        payload = BytesAssembledFile(payload_bytes)

        process_assembled_file(ts, payload, contact, contact.nick, window_list.settings, window_list)

    @staticmethod
    def from_bytes(bytes_file: 'BytesFile') -> 'FilePayload':
        """Convert file bytes to a FilePayload object."""
        file_data = bytes(bytes_file)

        if len(file_data) < CryptoVarLength.PADDING.value:
            padded             = byte_padding(file_data)
            payload_bytes_list = [AsmPacket.F_S_HEADER + padded]

        else:
            payload_bytes = bytes(FieldLength.FILE_PACKET_CTR.value) + file_data  # Reserve space for packet counter
            padded        = byte_padding(payload_bytes)
            payload_list  = split_byte_string(padded, item_len=CryptoVarLength.PADDING.value)

            first_packet     = payload_list[0]
            packet_ctr_bytes = int_to_bytes(len(payload_list))
            first_packet     = packet_ctr_bytes + first_packet[FieldLength.FILE_PACKET_CTR:]

            append_packets  = [p for p in payload_list[1:-1]]
            end_packet      = payload_list[-1]

            payload_bytes_list = (  [AsmPacket.F_L_HEADER + first_packet]
                                  + [AsmPacket.F_A_HEADER + append_packet for append_packet in append_packets]
                                  + [AsmPacket.F_E_HEADER + end_packet])

        assembly_packets = [FileAssemblyPacketUser(payload_bytes) for payload_bytes in payload_bytes_list]

        return FilePayload(assembly_packets)


class CommandPayload(Payload):
    PAYLOAD_TYPE = PayloadType.COMMAND
    PACKET_TYPE  = CommandAssemblyPacket
    VALID_HEADERS: frozenset[AsmPacket] = COMMAND_PAYLOAD_HEADERS

    def __iter__(self) -> Iterator[CommandAssemblyPacket]:
        """Iterate over command assembly packets."""
        for packet in self._assembly_packets:
            if isinstance(packet, CommandAssemblyPacket):
                yield packet

    def assemble_command(self, max_decompress_size_mb: int) -> tuple[RxCommand, SerializedCommand]:
        """\
        Construct the command header and serialized data
        from complete collection of assembly packets.
        """
        padded  = b''.join(packet.raw_bytes[FieldLength.ASSEMBLY_PACKET_HEADER.value:] for packet in self)
        payload = rm_padding_bytes(padded)

        if len(self) > 1:
            payload, cmd_hash = separate_trailer(payload, CryptoVarLength.BLAKE2_DIGEST.value)
            if blake2b(payload) != cmd_hash:
                raise SoftError('Error: Received an invalid command.')

        try:
            command = decompress(payload, max_decompress_size_mb)
        except zlib.error as exc:
            raise SoftError('Error: Decompression of command failed.') from exc

        header_bytes, command_bytes = separate_header(command, FieldLength.RELAY_COMMAND_HEADER.value)

        try:
            header = RxCommand(header_bytes)
        except ValueError as exc:
            raise SoftError('Error: Received command had an invalid header.') from exc

        return header, SerializedCommand(header, command_bytes or None)

    @staticmethod
    def from_bytes(serialized_command: SerializedCommand) -> 'CommandPayload':
        """Convert command bytes to a CommandPayload object."""
        payload_bytes = zlib.compress(serialized_command.raw_bytes, level=CompressionLiterals.COMPRESSION_LEVEL.value)

        if len(payload_bytes) < CryptoVarLength.PADDING.value:
            padded             = byte_padding(payload_bytes)
            payload_bytes_list = [AsmPacket.C_S_HEADER + padded]

        else:
            payload_bytes     += blake2b(payload_bytes)
            padded             = byte_padding(payload_bytes)
            payload_bytes_list = split_byte_string(padded, item_len=CryptoVarLength.PADDING.value)

            first_packet   = payload_bytes_list[0]
            append_packets = [p for p in payload_bytes_list[1:-1]]
            end_packet     = payload_bytes_list[-1]

            payload_bytes_list = (  [AsmPacket.C_L_HEADER + first_packet]
                                  + [AsmPacket.C_A_HEADER + append_packet for append_packet in append_packets]
                                  + [AsmPacket.C_E_HEADER + end_packet])

        assembly_packets = [CommandAssemblyPacket(payload_bytes) for payload_bytes in payload_bytes_list]

        return CommandPayload(assembly_packets)
