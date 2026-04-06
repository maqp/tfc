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

from src.common.utils.validators import validate_bytes
from src.common.statics import DatagramHeader, RelayCommand

from src.datagrams.datagram import DatagramRelayCommand


class DatagramRelayDiffComparisonAccount(DatagramRelayCommand):

    def __init__(self, invalid_onion_address : str) -> None:
        """Create new OnionServiceSetupDatagram object."""
        self.__invalid_onion_address = invalid_onion_address

    @property
    def invalid_onion_address(self) -> str:
        """Return the invalid onion address string."""
        return self.__invalid_onion_address

    def to_txp_rep_bytes(self) -> bytes:
        """Serializes the datagram for transport from Transmitter Program to Relay Program."""
        return (DatagramHeader.RELAY_COMMAND.value
                + RelayCommand.CHECK_ACCOUNT_INPUT.value
                + self.__invalid_onion_address.encode())

    @classmethod
    def from_txp_rep_bytes(cls, timestamp: datetime, datagram_bytes: bytes) -> 'DatagramRelayDiffComparisonAccount':
        """Deserializes the datagram from `Transmitter Program to Relay Program` bytes."""
        validate_bytes(datagram_bytes, min_length=1)
        return DatagramRelayDiffComparisonAccount(datagram_bytes.decode())
