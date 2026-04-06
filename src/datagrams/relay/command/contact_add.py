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

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from src.common.crypto.keys.onion_service_keys import OnionPublicKeyContact
from src.common.statics import DatagramHeader, RelayCommand, CryptoVarLength
from src.common.utils.validators import validate_bytes
from src.datagrams.datagram import DatagramRelayCommand


class DatagramRelayAddContact(DatagramRelayCommand):

    def __init__(self, onion_pub_key: 'OnionPublicKeyContact') -> None:
        """Create new AddContactDatagram object."""
        self.__onion_pub_key = onion_pub_key

    @property
    def onion_pub_key(self) -> 'OnionPublicKeyContact':
        """Return the contact public key."""
        return self.__onion_pub_key

    def to_txp_rep_bytes(self) -> bytes:
        """Serializes the datagram for transport from Transmitter Program to Relay Program."""
        return (DatagramHeader.RELAY_COMMAND.value
                + RelayCommand.ADD_NEW_CONTACT.value
                + self.__onion_pub_key.public_bytes_raw)

    @classmethod
    def from_txp_rep_bytes(cls, timestamp: datetime, datagram_bytes: bytes) -> 'DatagramRelayAddContact':
        """Deserializes the datagram from `Transmitter Program to Relay Program` bytes."""
        validate_bytes(datagram_bytes, is_length=CryptoVarLength.ONION_SERVICE_PUBLIC_KEY.value)
        public_key = Ed25519PublicKey.from_public_bytes(datagram_bytes)
        return DatagramRelayAddContact(OnionPublicKeyContact(public_key))
