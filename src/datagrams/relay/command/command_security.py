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

from src.common.statics import DatagramHeader, RelayCommand
from src.common.utils.validators import validate_bytes
from src.datagrams.datagram import DatagramRelayCommand


class DatagramRelayCommandScreenClear(DatagramRelayCommand):

    def __init__(self) -> None:
        """Create new DatagramRelayCommandScreenClear object."""

    def to_txp_rep_bytes(self) -> bytes:
        """Serializes the datagram for transport from Transmitter Program to Relay Program."""
        return DatagramHeader.RELAY_COMMAND.value + RelayCommand.CLEAR_SCREEN.value

    @classmethod
    def from_txp_rep_bytes(cls, timestamp: datetime, datagram_bytes: bytes) -> 'DatagramRelayCommandScreenClear':
        """Deserializes the datagram from `Transmitter Program to Relay Program` bytes."""
        return DatagramRelayCommandScreenClear()


class DatagramRelayCommandClearCiphertextCache(DatagramRelayCommand):

    def __init__(self) -> None:
        """Create new DatagramRelayCommandClearCiphertextCache object."""

    def to_txp_rep_bytes(self) -> bytes:
        """Serialize the datagram for transport from Transmitter Program to Relay Program."""
        return DatagramHeader.RELAY_COMMAND.value + RelayCommand.CLEAR_CIPHERTEXT_CACHE.value

    @classmethod
    def from_txp_rep_bytes(cls, timestamp: datetime, datagram_bytes: bytes) -> 'DatagramRelayCommandClearCiphertextCache':
        """Deserialize the datagram from `Transmitter Program to Relay Program` bytes."""
        validate_bytes(datagram_bytes, is_length=0, empty_allowed=True)
        return DatagramRelayCommandClearCiphertextCache()


class DatagramRelayCommandScreenReset(DatagramRelayCommand):

    def __init__(self) -> None:
        """Create new DatagramRelayCommandScreenReset object."""

    def to_txp_rep_bytes(self) -> bytes:
        """Serializes the datagram for transport from Transmitter Program to Relay Program."""
        return DatagramHeader.RELAY_COMMAND.value + RelayCommand.RESET_SCREEN.value

    @classmethod
    def from_txp_rep_bytes(cls, timestamp: datetime, datagram_bytes: bytes) -> 'DatagramRelayCommandScreenReset':
        """Deserializes the datagram from `Transmitter Program to Relay Program` bytes."""
        validate_bytes(datagram_bytes, is_length=0, empty_allowed=True)
        return DatagramRelayCommandScreenReset()


class DatagramRelayCommandExitTFC(DatagramRelayCommand):

    def __init__(self) -> None:
        """Create new DatagramRelayCommandExitTFC object."""

    def to_txp_rep_bytes(self) -> bytes:
        """Serializes the datagram for transport from Transmitter Program to Relay Program."""
        return DatagramHeader.RELAY_COMMAND.value + RelayCommand.EXIT_TFC.value

    @classmethod
    def from_txp_rep_bytes(cls, timestamp: datetime, datagram_bytes: bytes) -> 'DatagramRelayCommandExitTFC':
        """Deserializes the datagram from `Transmitter Program to Relay Program` bytes."""
        validate_bytes(datagram_bytes, is_length=0, empty_allowed=True)
        return DatagramRelayCommandExitTFC()


class DatagramRelayCommandWipeSystem(DatagramRelayCommand):

    def __init__(self) -> None:
        """Create new DatagramRelayCommandWipeSystem object."""

    def to_txp_rep_bytes(self) -> bytes:
        """Serializes the datagram for transport from Transmitter Program to Relay Program."""
        return DatagramHeader.RELAY_COMMAND.value + RelayCommand.WIPE_SYSTEM.value

    @classmethod
    def from_txp_rep_bytes(cls, timestamp: datetime, datagram_bytes: bytes) -> 'DatagramRelayCommandWipeSystem':
        """Deserializes the datagram from `Transmitter Program to Relay Program` bytes."""
        validate_bytes(datagram_bytes, is_length=0, empty_allowed=True)
        return DatagramRelayCommandWipeSystem()
