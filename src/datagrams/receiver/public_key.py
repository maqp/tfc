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

import base64

from datetime import datetime
from typing import Optional as O, Self

from cryptography.hazmat.primitives.asymmetric.x448 import X448PublicKey

from src.common.exceptions import SoftError
from src.common.crypto.keys.onion_service_keys import OnionPublicKeyContact
from src.common.crypto.keys.x448_keys import X448PubKey
from src.common.statics import DatagramHeader, CompoundFieldLength, DatagramTypeHR, FieldLength
from src.common.utils.encoding import ts_to_bytes
from src.common.utils.strings import separate_header
from src.common.utils.validators import validate_bytes
from src.datagrams.datagram import DatagramUser


class DatagramPublicKey(DatagramUser):

    DATAGRAM_TYPE_HR = DatagramTypeHR.PUBLIC_KEY

    def __init__(self,
                 onion_pub_key_contact : 'OnionPublicKeyContact',
                 x448_public_key_user  : X448PubKey,
                 timestamp             : O[datetime] = None
                 ) -> None:
        """Create new PublicKeyDatagram object."""
        self.__onion_pub_key_contact = onion_pub_key_contact
        self.__x448_public_key_user  = x448_public_key_user
        self._timestamp              = timestamp

    @property
    def pub_key_contact(self) -> 'OnionPublicKeyContact':
        """Return the Onion Service public key of the contact."""
        return self.__onion_pub_key_contact

    @property
    def x448_public_key(self) -> X448PubKey:
        """Return the X448 public key."""
        return self.__x448_public_key_user

    # ┌───────────────────────────────┐
    # │ Serialization/Deserialization │
    # └───────────────────────────────┘

    def to_txp_rep_bytes(self) -> bytes:
        """Serializes the datagram for transport from Transmitter Program to Relay Program."""
        return (DatagramHeader.PUBLIC_KEY.value
                + self.__onion_pub_key_contact.serialize()
                + self.__x448_public_key_user.x448_public_key.public_bytes_raw())

    @classmethod
    def from_txp_rep_bytes(cls, timestamp: datetime, datagram_bytes: bytes) -> Self:
        """Deserializes the datagram from `Transmitter Program to Relay Program` bytes."""
        validate_bytes(datagram_bytes, is_length=CompoundFieldLength.PUBLIC_KEY_DATAGRAM)

        enc_contact_address, x448_public_key_contact_bytes \
            = separate_header(datagram_bytes, header_length=FieldLength.ONION_ADDRESS.value)

        onion_pub_key = OnionPublicKeyContact.from_onion_address_bytes(enc_contact_address)
        x448_pub_key  = X448PubKey(X448PublicKey.from_public_bytes(x448_public_key_contact_bytes))
        return cls(onion_pub_key, x448_pub_key, timestamp)


    def to_server_b85(self) -> bytes:
        """Serializes the datagram for transport from Flask server to Requests client."""
        payload_enc = base64.b85encode(self.__onion_pub_key_contact.serialize()
                                       + self.__x448_public_key_user.x448_public_key.public_bytes_raw())

        return DatagramHeader.PUBLIC_KEY.value + payload_enc

    @classmethod
    def from_server_b85(cls, timestamp: datetime, b85_data: bytes) -> Self:
        """Deserializes the datagram from `Flask server to Requests client` bytes."""
        return cls.from_txp_rep_bytes(timestamp, base64.b85decode(b85_data))


    def to_rep_rxp_bytes(self) -> bytes:
        """Serializes the datagram for transport from Relay Program to Receiver Program."""
        if self._timestamp is None:
            raise SoftError('Timestamp field is not set.')

        return (DatagramHeader.PUBLIC_KEY.value
                + ts_to_bytes(self._timestamp)
                + self.__onion_pub_key_contact.serialize()
                + self.__x448_public_key_user.x448_public_key.public_bytes_raw())

    @classmethod
    def from_rep_rxp_bytes(cls, timestamp: datetime, datagram_bytes: bytes) -> Self:
        """Deserializes the datagram from `Relay Program to Receiver Program` bytes."""
        return cls.from_txp_rep_bytes(timestamp, datagram_bytes)
