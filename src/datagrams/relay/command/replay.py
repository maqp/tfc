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

from src.common.statics import DatagramHeader, FieldLength, RelayCommand
from src.common.utils.encoding import bytes_to_int, int_to_bytes
from src.common.utils.strings import split_byte_string
from src.common.utils.validators import validate_bytes, validate_int
from src.datagrams.datagram import DatagramRelayCommand


class DatagramRelayResendPackets(DatagramRelayCommand):
    """Relay command that requests replay of cached packet numbers."""

    def __init__(self,
                 packet_numbers : list[int],
                 relay_command  : RelayCommand = RelayCommand.RESEND_TO_RECEIVER,
                 ) -> None:
        """Create new DatagramRelayResendPackets object."""
        self.packet_numbers = packet_numbers
        self.relay_command  = relay_command

    def to_txp_rep_bytes(self) -> bytes:
        """Serializes the datagram for transport from Transmitter Program to Relay Program."""
        for packet_number in self.packet_numbers:
            validate_int(packet_number, key='packet_number', min_value=1)

        payload = b''.join(int_to_bytes(packet_number) for packet_number in self.packet_numbers)
        return DatagramHeader.RELAY_COMMAND.value + self.relay_command.value + payload

    @classmethod
    def from_txp_rep_bytes(cls, timestamp: datetime, datagram_bytes: bytes) -> 'DatagramRelayResendPackets':
        """Deserializes the datagram from `Transmitter Program to Relay Program` bytes."""
        validate_bytes(datagram_bytes, min_length=FieldLength.ENCODED_INTEGER.value, len_is_mul_of=FieldLength.ENCODED_INTEGER.value)

        enc_packet_numbers = split_byte_string(datagram_bytes, FieldLength.ENCODED_INTEGER.value)
        packet_numbers     = [bytes_to_int(enc_number) for enc_number in enc_packet_numbers]
        return cls(packet_numbers)


class DatagramRelayResendFile(DatagramRelayCommand):
    """Relay command that requests replay of a cached file by base26 id."""

    def __init__(self, file_id: str) -> None:
        """Create new DatagramRelayResendFile object."""
        self.file_id = file_id.lower()

    def to_txp_rep_bytes(self) -> bytes:
        """Serializes the datagram for transport from Transmitter Program to Relay Program."""
        validate_bytes(self.file_id.encode(), min_length=1)
        return (DatagramHeader.RELAY_COMMAND.value
                + RelayCommand.RESEND_FILE_TO_RECEIVER.value
                + self.file_id.encode())

    @classmethod
    def from_txp_rep_bytes(cls, timestamp: datetime, datagram_bytes: bytes) -> 'DatagramRelayResendFile':
        """Deserializes the datagram from `Transmitter Program to Relay Program` bytes."""
        validate_bytes(datagram_bytes, min_length=1)
        return cls(datagram_bytes.decode())
