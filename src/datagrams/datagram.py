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
from typing import Any, Optional as O, Self, TYPE_CHECKING

from src.common.exceptions import CriticalError
from src.common.statics import Origin, DatagramTypeHR

if TYPE_CHECKING:
    from src.common.crypto.keys.onion_service_keys import OnionPublicKeyContact


# ┌───────────────────────────────────────────────────────────────────────────┐
# │                                 Baseclass                                 │
# └───────────────────────────────────────────────────────────────────────────┘

class Datagram:
    """Datagram baseclass.

    Datagram is an object that represents data being transferred between the programs.
    A Datagram object encapsulates the fields and the necessary validators, getters and
    serialization / deserialization functions for transport over serial interfaces, and
    from server to client.
    """

    DATAGRAM_TYPE_HR : 'DatagramTypeHR'
    ORIGIN_HEADER    : 'Origin'
    _timestamp       : O[datetime]

    # ┌───────────┐
    # │ Timestamp │
    # └───────────┘

    @property
    def ts(self) -> datetime:
        """Return the timestamp carried with the datagram."""
        if self._timestamp is None:
            raise CriticalError('Datagram timestamp is missing.')
        return self._timestamp

    # ┌───────────────────────────────┐
    # │ Serialization/Deserialization │
    # └───────────────────────────────┘

    def to_txp_rep_bytes(self) -> bytes:
        """Serializes the datagram for transport from Transmitter Program to Relay Program."""
        raise NotImplementedError

    @classmethod
    def from_txp_rep_bytes(cls, timestamp: datetime, datagram_bytes: bytes) -> Any:
        """Deserializes the datagram from `Transmitter Program to Relay Program` bytes."""
        raise NotImplementedError

    def to_rep_rxp_bytes(self) -> bytes:
        """Serializes the datagram for transport from Relay Program to Receiver Program."""
        raise NotImplementedError

    @classmethod
    def from_rep_rxp_bytes(cls, timestamp: datetime, datagram_bytes: bytes) -> Any:
        """Deserializes the datagram from `Relay Program to Receiver Program` bytes."""
        raise NotImplementedError

# ┌───────────────────────────────────────────────────────────────────────────┐
# │                              Shared Datagrams                             │
# └───────────────────────────────────────────────────────────────────────────┘

class DatagramShared(Datagram):
    """Datagrams that are shared with contacts."""

    __recipient : 'OnionPublicKeyContact'
    __sender    : 'OnionPublicKeyContact'

    # ┌─────────┐
    # │ Contact │
    # └─────────┘

    @property
    def pub_key_contact(self) -> 'OnionPublicKeyContact':
        """Get the recipient's Onion Service public key."""
        return self.__recipient

    @property
    def sender(self) -> 'OnionPublicKeyContact':
        """Get the sender's Onion Service public key."""
        return self.__recipient

    # ┌────────┐
    # │ Origin │
    # └────────┘

    @property
    def origin_header(self) -> Origin:
        """Get the datagram's origin header."""
        return self.ORIGIN_HEADER

    @property
    def is_from_contact(self) -> bool:
        """Return true if datagram's origin is from contact."""
        return self.origin_header == Origin.CONTACT

    @property
    def is_from_user(self) -> bool:
        """Return true if datagram's origin is from user."""
        return self.origin_header == Origin.USER

    @property
    def preposition(self) -> str:
        """Return the preposition header of the datagram, if any."""
        return 'to' if self.is_from_user else 'from'

    # ┌───────────────────────────────┐
    # │ Serialization/Deserialization │
    # └───────────────────────────────┘

    def to_server_b85(self) -> bytes:
        """Serializes the datagram for transport from Flask server to Requests client."""
        raise NotImplementedError

    @classmethod
    def from_server_b85(cls, timestamp: datetime, b85_data: bytes) -> Self:
        """Deserializes the datagram from `Flask server to Requests client` bytes."""
        raise NotImplementedError


# ---

class DatagramUser(DatagramShared):
    """Datagrams from user to contact (and loop-back to user's Receiver Program)."""
    ORIGIN_HEADER = Origin.USER


class DatagramContact(DatagramShared):
    """Datagrams from contact to user."""
    ORIGIN_HEADER = Origin.CONTACT


# ┌───────────────────────────────────────────────────────────────────────────┐
# │                              Local Datagrams                              │
# └───────────────────────────────────────────────────────────────────────────┘

class DatagramLocal(Datagram):
    """Datagrams that aren't shared with contacts."""
    pass

class DatagramRelayCommand(DatagramLocal):
    """Super-class for relay command datagrams."""
    pass
