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
from typing import Optional as O, Any

from src.common.exceptions import CriticalError, SoftError
from src.common.crypto.pt_ct import CommandHeaderCT, CommandAssemblyPacketCT
from src.common.statics import DatagramHeader, CompoundFieldLength, DatagramTypeHR
from src.common.utils.encoding import ts_to_bytes
from src.common.utils.strings import separate_header
from src.common.utils.validators import validate_bytes
from src.datagrams.datagram import DatagramLocal


class DatagramReceiverCommand(DatagramLocal):

    DATAGRAM_TYPE_HR = DatagramTypeHR.COMMAND

    def __init__(self,
                 ct_header : CommandHeaderCT,
                 ct_packet : CommandAssemblyPacketCT,
                 timestamp : O[datetime] = None
                 ) -> None:
        """Encode data fields into datagram bytes."""
        if not isinstance(ct_header, CommandHeaderCT):
            raise CriticalError('Received packet was not CommandHeaderCT')
        if not isinstance(ct_packet, CommandAssemblyPacketCT):
            raise CriticalError('Received packet was not CommandAssemblyPacketCT')

        self.__ct_header = ct_header
        self.__ct_packet = ct_packet
        self._timestamp  = timestamp

    @property
    def ct_header(self) -> CommandHeaderCT:
        """Return the CommandHeaderCT object."""
        return self.__ct_header

    @property
    def ct_assembly_packet(self) -> CommandAssemblyPacketCT:
        """Return the CommandAssemblyPacketCT object."""
        return self.__ct_packet

    # ┌───────────────────────────────┐
    # │ Serialization/Deserialization │
    # └───────────────────────────────┘

    def to_txp_rep_bytes(self) -> bytes:
        """Serializes the datagram for transport from Transmitter Program to Relay Program."""
        return (DatagramHeader.COMMAND
                + self.__ct_header.ct_bytes
                + self.__ct_packet.ct_bytes)

    @classmethod
    def from_txp_rep_bytes(cls, timestamp: datetime, datagram_bytes: bytes) -> Any:
        """Deserializes the datagram from `Transmitter Program to Relay Program` bytes."""
        validate_bytes(datagram_bytes, min_length=CompoundFieldLength.COMMAND_DATAGRAM_PAYLOAD)

        encrypted_header, encrypted_assembly_packet = separate_header(datagram_bytes, header_length=CompoundFieldLength.CT_HEADER.value)

        validate_bytes(encrypted_header,         is_length=CompoundFieldLength.CT_HEADER          .value)
        validate_bytes(encrypted_assembly_packet, is_length=CompoundFieldLength.CT_ASSEMBLY_PACKET.value)

        return DatagramReceiverCommand(ct_header = CommandHeaderCT(encrypted_header),
                                       ct_packet = CommandAssemblyPacketCT(encrypted_assembly_packet),
                                       timestamp = timestamp)

    def to_rep_rxp_bytes(self) -> bytes:
        """Serializes the datagram for transport from Relay Program to Receiver Program."""
        if self._timestamp is None:
            raise SoftError('Timestamp field is not set.')

        return (DatagramHeader.COMMAND
                + ts_to_bytes(self._timestamp)
                + self.__ct_header.ct_bytes
                + self.__ct_packet.ct_bytes)

    @classmethod
    def from_rep_rxp_bytes(cls, timestamp: datetime, datagram_bytes: bytes) -> Any:
        """Deserializes the datagram from `Relay Program to Receiver Program` bytes."""
        validate_bytes(datagram_bytes, min_length=CompoundFieldLength.COMMAND_DATAGRAM_PAYLOAD)

        encrypted_header, encrypted_assembly_packet = separate_header(datagram_bytes, header_length=CompoundFieldLength.CT_HEADER.value)

        validate_bytes(encrypted_header,          is_length=CompoundFieldLength.CT_HEADER.value)
        validate_bytes(encrypted_assembly_packet, is_length=CompoundFieldLength.CT_ASSEMBLY_PACKET.value)

        return DatagramReceiverCommand(ct_header = CommandHeaderCT        (encrypted_header),
                                       ct_packet = CommandAssemblyPacketCT(encrypted_assembly_packet),
                                       timestamp = timestamp)
