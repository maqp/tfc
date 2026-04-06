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
from typing import Optional as O

from src.common.exceptions import SoftError
from src.common.crypto.algorithms.blake2b import blake2b
from src.common.crypto.pt_ct import LocalKeySetCT
from src.common.statics import DatagramHeader, CompoundFieldLength, DatagramTypeHR
from src.common.utils.encoding import ts_to_bytes
from src.common.utils.validators import validate_bytes
from src.datagrams.datagram import DatagramLocal


class DatagramReceiverLocalKey(DatagramLocal):

    DATAGRAM_TYPE_HR = DatagramTypeHR.LOCAL_KEY

    def __init__(self, local_key_ct : LocalKeySetCT, timestamp: O[datetime] = None) -> None:
        """Encode data fields into datagram bytes."""
        validate_bytes(local_key_ct.ct_bytes, key='local_key_ct', is_length=CompoundFieldLength.LOCAL_KEY_CT.value)

        self.__local_key_ct = local_key_ct
        self._timestamp     = timestamp

    @property
    def local_key_ct(self) -> LocalKeySetCT:
        """Return the LocalKeySetCT object."""
        return self.__local_key_ct

    @property
    def datagram_hash(self) -> bytes:
        """Return the datagram hash.

        This is used to detect datagram duplicates.
        """
        return blake2b(self.__local_key_ct.ct_bytes)

    # ┌───────────────────────────────┐
    # │ Serialization/Deserialization │
    # └───────────────────────────────┘

    def to_txp_rep_bytes(self) -> bytes:
        """Serializes the datagram for transport from Transmitter Program to Relay Program."""
        return DatagramHeader.LOCAL_KEY.value + self.__local_key_ct.ct_bytes

    @classmethod
    def from_txp_rep_bytes(cls, ts: datetime, datagram_bytes: bytes) -> 'DatagramReceiverLocalKey':
        """Deserializes the datagram from `Transmitter Program to Relay Program` bytes."""
        validate_bytes(datagram_bytes, key='datagram_bytess', is_length=CompoundFieldLength.LOCAL_KEY_CT.value)
        return cls(LocalKeySetCT(datagram_bytes), ts)

    def to_rep_rxp_bytes(self) -> bytes:
        """Serializes the datagram for transport from Relay Program to Receiver Program."""
        if self._timestamp is None:
            raise SoftError('Timestamp field is not set.')

        return DatagramHeader.LOCAL_KEY.value + ts_to_bytes(self._timestamp) + self.__local_key_ct.ct_bytes

    @classmethod
    def from_rep_rxp_bytes(cls, timestamp: datetime, datagram_bytes: bytes) -> 'DatagramReceiverLocalKey':
        """Deserializes the datagram from `Relay Program to Receiver Program` bytes."""
        validate_bytes(datagram_bytes, key='datagram_bytess', is_length=CompoundFieldLength.LOCAL_KEY_CT.value)
        return cls(LocalKeySetCT(datagram_bytes), timestamp)
