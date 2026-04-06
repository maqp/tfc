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

from src.common.crypto.keys.onion_service_keys import OnionPublicKeyContact
from src.common.statics import DatagramHeader, RelayCommand, FieldLength
from src.common.utils.validators import validate_bytes
from src.datagrams.datagram import DatagramRelayCommand


class DatagramRelayRemoveContact(DatagramRelayCommand):

    def __init__(self, onion_pub_key: 'OnionPublicKeyContact') -> None:
        """Create new RemoveContactDatagram object."""
        self.__onion_pub_key = onion_pub_key

    @property
    def onion_pub_key(self) -> 'OnionPublicKeyContact':
        """Return the contact public key."""
        return self.__onion_pub_key

    def to_txp_rep_bytes(self) -> bytes:
        """Serializes the datagram for transport from Transmitter Program to Relay Program."""
        return DatagramHeader.RELAY_COMMAND.value + RelayCommand.REMOVE_CONTACT + self.__onion_pub_key.serialize()

    @classmethod
    def from_txp_rep_bytes(cls, timestamp: datetime, datagram_bytes: bytes) -> 'DatagramRelayRemoveContact':
        """Deserializes the datagram from `Transmitter Program to Relay Program` bytes."""
        validate_bytes(datagram_bytes, is_length=FieldLength.ONION_ADDRESS.value)
        return DatagramRelayRemoveContact(OnionPublicKeyContact.from_onion_address_bytes(datagram_bytes))
