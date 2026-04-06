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

from typing import Any, ClassVar

from src.common.entities.assembly_packet_headers import (COMMAND_PAYLOAD_HEADERS, CONTACT_ASSEMBLY_PACKET_HEADERS,
                                                         SHORT_PAYLOAD_HEADERS, FIRST_OF_LONG_HEADERS,
                                                         APPEND_OF_LONG_HEADERS, END_OF_LONG_HEADERS, CANCEL_HEADERS,
                                                         NOISE_HEADERS, MESSAGE_PAYLOAD_HEADERS, FILE_PAYLOAD_HEADERS)
from src.common.exceptions import CriticalError
from src.common.statics import AsmPacket, CompoundFieldLength, FieldLength, Origin
from src.common.utils.strings import separate_header
from src.common.utils.validators import validate_bytes


class AssemblyPacket:
    """Type-safe immutable wrapper for validated assembly packets."""

    VALID_HEADERS: ClassVar[frozenset[AsmPacket]] = frozenset()

    def __init__(self, assembly_packet: bytes) -> None:
        """Create new AssemblyPacket object."""
        header = self._parse_header(assembly_packet)
        if header not in self.VALID_HEADERS:
            raise CriticalError(f'Invalid {self.__class__.__name__} header: {header.value.decode()}')

        self.__header = header
        self.__bytes  = assembly_packet

    @staticmethod
    def _parse_header(assembly_packet: bytes) -> AsmPacket:
        """Validate assembly packet and return its header enum."""
        validate_bytes(assembly_packet, is_length=CompoundFieldLength.ASSEMBLY_PACKET_PT.value)
        header_bytes, _ = separate_header(assembly_packet, header_length=FieldLength.ASSEMBLY_PACKET_HEADER.value)
        try:
            return AsmPacket(header_bytes)
        except ValueError:
            raise CriticalError(f'Invalid AssemblyPacket header: {header_bytes.decode()}')

    @classmethod
    def from_bytes(cls, assembly_packet: bytes) -> 'AssemblyPacket':
        """Create the correct concrete packet subclass for `assembly_packet`."""
        header      = cls._parse_header(assembly_packet)
        packet_type: type[AssemblyPacket]
        if header in FILE_PAYLOAD_HEADERS:
            packet_type = FileAssemblyPacket
        elif header in CONTACT_ASSEMBLY_PACKET_HEADERS:
            packet_type = MessageAssemblyPacket
        else:
            packet_type = CommandAssemblyPacket
        return packet_type(assembly_packet)

    def __str__(self) -> str:
        """Get a print-friendly version of the AssemblyPacket object."""
        return self.__bytes.hex()

    def __eq__(self, other: Any) -> bool:
        """Return True if two AssemblyPacket objects are equal."""
        if not isinstance(other, AssemblyPacket):
            return False
        return self.__bytes == other.raw_bytes

    def __ne__(self, other: Any) -> bool:
        """Return True if two AssemblyPacket objects are not equal."""
        return not (self == other)

    @property
    def header(self) -> AsmPacket:
        """Return the assembly packet header."""
        return self.__header

    @property
    def raw_bytes(self) -> bytes:
        """Return the raw bytes for the assembly packet object."""
        return self.__bytes

    @property
    def is_short_payload(self) -> bool:
        """Return True if the assembly packet is a short packet."""
        return self.__header in SHORT_PAYLOAD_HEADERS

    @property
    def is_first_of_long_payload(self) -> bool:
        """Return True if the assembly packet is the first packet."""
        return self.__header in FIRST_OF_LONG_HEADERS

    @property
    def is_append_of_long_payload(self) -> bool:
        """Return True if the assembly packet is an append packet."""
        return self.__header in APPEND_OF_LONG_HEADERS

    @property
    def is_end_of_long_payload(self) -> bool:
        """Return True if the assembly packet is the last packet."""
        return self.__header in END_OF_LONG_HEADERS

    @property
    def is_cancel_of_payload(self) -> bool:
        """Return True if the assembly packet cancels a long payload."""
        return self.__header in CANCEL_HEADERS

    @property
    def is_noise_packet(self) -> bool:
        """Return True if the assembly packet is a noise packet."""
        return self.__header in NOISE_HEADERS



class MessageAssemblyPacket(AssemblyPacket):
    """Message assembly packet."""
    VALID_HEADERS = MESSAGE_PAYLOAD_HEADERS
    ORIGIN : Origin

    @property
    def origin(self) -> Origin:
        """Get the origin of the assembly packet."""
        return self.ORIGIN

    @property
    def is_from_user(self) -> bool:
        """Return True if the assembly packet is from a user."""
        return self.ORIGIN == Origin.USER

    @property
    def is_from_contact(self) -> bool:
        """Return True if the assembly packet is form a contact."""
        return self.ORIGIN == Origin.CONTACT


class MessageAssemblyPacketUser(MessageAssemblyPacket):
    ORIGIN = Origin.USER

    @classmethod
    def from_bytes(cls, assembly_packet: bytes) -> 'MessageAssemblyPacketUser | FileAssemblyPacketUser':
        """Create the correct user-origin assembly packet wrapper."""
        header = cls._parse_header(assembly_packet)
        if header in FILE_PAYLOAD_HEADERS:
            return FileAssemblyPacketUser(assembly_packet)
        return cls(assembly_packet)

class MessageAssemblyPacketContact(MessageAssemblyPacket):
    ORIGIN = Origin.CONTACT

    @classmethod
    def from_bytes(cls, assembly_packet: bytes) -> 'MessageAssemblyPacketContact | FileAssemblyPacketContact':
        """Create the correct contact-origin assembly packet wrapper."""
        header = cls._parse_header(assembly_packet)
        if header in FILE_PAYLOAD_HEADERS:
            return FileAssemblyPacketContact(assembly_packet)
        return cls(assembly_packet)


class FileAssemblyPacket(AssemblyPacket):
    """File assembly packet."""
    VALID_HEADERS = FILE_PAYLOAD_HEADERS
    ORIGIN : Origin

    @property
    def origin(self) -> Origin:
        """Get the origin of the assembly packet."""
        return self.ORIGIN

    @property
    def is_from_user(self) -> bool:
        """Return True if the assembly packet is from a user."""
        return self.ORIGIN == Origin.USER

    @property
    def is_from_contact(self) -> bool:
        """Return True if the assembly packet is form a contact."""
        return self.ORIGIN == Origin.CONTACT


class FileAssemblyPacketUser(FileAssemblyPacket, MessageAssemblyPacket):
    ORIGIN = Origin.USER

class FileAssemblyPacketContact(FileAssemblyPacket, MessageAssemblyPacket):
    ORIGIN = Origin.CONTACT


class CommandAssemblyPacket(AssemblyPacket):
    """Assembly packet sent with the local command key."""
    VALID_HEADERS = COMMAND_PAYLOAD_HEADERS
