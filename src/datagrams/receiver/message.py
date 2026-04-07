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
from typing import Optional as O

from src.common.exceptions import CriticalError, ValidationError
from src.common.crypto.keys.onion_service_keys import OnionPublicKeyContact
from src.common.crypto.pt_ct import (MessageAssemblyPacketUserCT, MessageHeaderUserCT, MessageAssemblyPacketContactCT,
                                     MessageHeaderContactCT)
from src.common.statics import DatagramHeader, CompoundFieldLength, FieldLength, DatagramTypeHR, Origin
from src.common.utils.encoding import ts_to_bytes
from src.common.utils.strings import separate_headers
from src.common.utils.validators import validate_bytes
from src.datagrams.datagram import DatagramUser, DatagramContact


class DatagramOutgoingMessage(DatagramUser):

    DATAGRAM_TYPE_HR = DatagramTypeHR.MESSAGE

    def __init__(self,
                 pub_key   : OnionPublicKeyContact,
                 ct_header : MessageHeaderUserCT,
                 ct_packet : MessageAssemblyPacketUserCT,
                 timestamp : O[datetime] = None
                 ) -> None:
        """Create new DatagramOutgoingMessage object.

        The constructor validation is done only on outbound datagrams as we
        want to guard Transmitter Program's output as much as possible.
        """
        if not isinstance(pub_key, OnionPublicKeyContact):
            raise CriticalError('Received public key was not OnionPublicKeyContact')
        if not isinstance(ct_header, MessageHeaderUserCT):
            raise CriticalError('Received header CT was not MessageHeaderUserCT')
        if not isinstance(ct_packet, MessageAssemblyPacketUserCT):
            raise CriticalError('Received assembly packet CT was not MessageAssemblyPacketUserCT')
        if timestamp is not None and timestamp and not isinstance(timestamp, datetime):
            raise CriticalError('Received timestamp was not datetime')

        self.__pub_key   = pub_key
        self.__ct_header = ct_header
        self.__ct_packet = ct_packet
        self._timestamp  = timestamp

    @property
    def pub_key_contact(self) -> OnionPublicKeyContact:
        """Return the public key"""
        return self.__pub_key

    @property
    def ct_header(self) -> MessageHeaderUserCT:
        """Return the encrypted message header."""
        return self.__ct_header

    @property
    def ct_packet(self) -> MessageAssemblyPacketUserCT:
        """Return the encrypted assembly packet."""
        return self.__ct_packet

    # ┌───────────────────────────────┐
    # │ Serialization/Deserialization │
    # └───────────────────────────────┘

    def to_txp_rep_bytes(self) -> bytes:
        """Serializes the datagram for transport from Transmitter Program to Relay Program."""
        return (DatagramHeader.MESSAGE
                + self.__pub_key.serialize()
                + self.__ct_header.ct_bytes
                + self.__ct_packet.ct_bytes)

    @classmethod
    def from_txp_rep_bytes(cls, timestamp: datetime, datagram_bytes: bytes) -> 'DatagramOutgoingMessage':
        """Parse datagram bytes into field values.

        Note that DatagramHeader has been stripped by
        the time data is redirected to this function.
        """
        validate_bytes(datagram_bytes, key='datagram_bytes', min_length=CompoundFieldLength.MESSAGE_DATAGRAM_PAYLOAD)

        enc_onion_address, encrypted_header, encrypted_assembly_packet \
            = separate_headers(datagram_bytes, header_length_list=[FieldLength.ONION_ADDRESS.value,
                                                                   CompoundFieldLength.CT_HEADER.value])

        validate_bytes(enc_onion_address,         key='enc_onion_address',         is_length=FieldLength.ONION_ADDRESS.value)
        validate_bytes(encrypted_header,          key='encrypted_header',          is_length=CompoundFieldLength.CT_HEADER.value)
        validate_bytes(encrypted_assembly_packet, key='encrypted_assembly_packet', is_length=CompoundFieldLength.CT_ASSEMBLY_PACKET.value)

        return DatagramOutgoingMessage(OnionPublicKeyContact.from_onion_address_bytes(enc_onion_address),
                                       MessageHeaderUserCT        (encrypted_header),
                                       MessageAssemblyPacketUserCT(encrypted_assembly_packet),
                                       timestamp)

    def to_rep_rxp_bytes(self) -> bytes:
        """Serializes the datagram for transport from Relay Program to Receiver Program."""
        if self._timestamp is None:
            raise ValueError('Message datagram was missing timestamp.')

        return (DatagramHeader.MESSAGE.value
                 + ts_to_bytes(self._timestamp)
                 + self.__pub_key.serialize()
                 + self.origin_header.value
                 + self.__ct_header.ct_bytes
                 + self.__ct_packet.ct_bytes)

    @classmethod
    def from_rep_rxp_bytes(cls, timestamp: datetime, datagram_bytes: bytes) -> 'DatagramOutgoingMessage':
        """Deserializes the datagram from `Relay Program to Receiver Program` bytes."""
        return cls.from_txp_rep_bytes(timestamp, datagram_bytes)

    def to_server_b85(self) -> bytes:
        """Serialize the message for contact delivery over the server buffer."""
        payload = self.__pub_key.serialize() + self.__ct_header.ct_bytes + self.__ct_packet.ct_bytes
        return DatagramHeader.MESSAGE.value + base64.b85encode(payload)



class DatagramIncomingMessage(DatagramContact):
    DATAGRAM_TYPE_HR = DatagramTypeHR.MESSAGE

    def __init__(self,
                 pub_key   : OnionPublicKeyContact,
                 ct_header : MessageHeaderContactCT,
                 ct_packet : MessageAssemblyPacketContactCT,
                 timestamp : O[datetime] = None,
                 ) -> None:
        """Create new DatagramIncomingMessage object."""
        self.__pub_key   = pub_key
        self.__ct_header = ct_header
        self.__ct_packet = ct_packet
        self._timestamp  = timestamp

    @property
    def pub_key_contact(self) -> OnionPublicKeyContact:
        """Return the public key."""
        return self.__pub_key

    @property
    def ct_header(self) -> MessageHeaderContactCT:
        """Return the encrypted message header."""
        return self.__ct_header

    @property
    def ct_packet(self) -> MessageAssemblyPacketContactCT:
        """Return the encrypted assembly packet."""
        return self.__ct_packet

    # ┌───────────────────────────────┐
    # │ Serialization/Deserialization │
    # └───────────────────────────────┘

    def to_txp_rep_bytes(self) -> bytes:
        """Serializes the datagram for transport from Transmitter Program to Relay Program."""
        return (DatagramHeader.MESSAGE
                + self.__pub_key.serialize()
                + self.__ct_header.ct_bytes
                + self.__ct_packet.ct_bytes)

    @classmethod
    def from_txp_rep_bytes(cls, timestamp: datetime, datagram_bytes: bytes) -> 'DatagramIncomingMessage':
        """Parse datagram bytes into field values.

        Note that DatagramHeader has been stripped by
        the time data is redirected to this function.
        """
        validate_bytes(datagram_bytes, key='datagram_bytes', min_length=CompoundFieldLength.MESSAGE_DATAGRAM_PAYLOAD)

        enc_onion_address, encrypted_header, encrypted_assembly_packet \
            = separate_headers(datagram_bytes, header_length_list=[FieldLength.ONION_ADDRESS.value,
                                                                   CompoundFieldLength.CT_HEADER.value])

        validate_bytes(enc_onion_address,         key='enc_onion_address',         is_length=FieldLength.ONION_ADDRESS.value)
        validate_bytes(encrypted_header,          key='encrypted_header',          is_length=CompoundFieldLength.CT_HEADER.value)
        validate_bytes(encrypted_assembly_packet, key='encrypted_assembly_packet', is_length=CompoundFieldLength.CT_ASSEMBLY_PACKET.value)

        return DatagramIncomingMessage(OnionPublicKeyContact.from_onion_address_bytes(enc_onion_address),
                                       MessageHeaderContactCT        (encrypted_header),
                                       MessageAssemblyPacketContactCT(encrypted_assembly_packet),
                                       timestamp)

    def to_rep_rxp_bytes(self) -> bytes:
        """Serializes the datagram for transport from Relay Program to Receiver Program."""
        if self._timestamp is None:
            raise ValueError('Message datagram was missing timestamp.')

        return (DatagramHeader.MESSAGE.value
                 + ts_to_bytes(self._timestamp)
                 + self.__pub_key.serialize()
                 + self.origin_header.value
                 + self.__ct_header.ct_bytes
                 + self.__ct_packet.ct_bytes)

    @classmethod
    def from_rep_rxp_bytes(cls, timestamp: datetime, datagram_bytes: bytes) -> 'DatagramIncomingMessage|DatagramOutgoingMessage':
        """Deserializes the datagram from `Relay Program to Receiver Program` bytes."""
        validate_bytes(datagram_bytes, key='datagram_bytes', min_length=CompoundFieldLength.MESSAGE_RECEIVER_PAYLOAD)

        enc_onion_address, origin_bytes, encrypted_header, encrypted_assembly_packet \
            = separate_headers(datagram_bytes, header_length_list=[FieldLength.ONION_ADDRESS.value,
                                                                   FieldLength.ORIGIN_HEADER.value,
                                                                   CompoundFieldLength.CT_HEADER.value])

        validate_bytes(enc_onion_address,         key='enc_onion_address',         is_length=FieldLength.ONION_ADDRESS.value)
        validate_bytes(origin_bytes,              key='origin_bytes',              is_length=FieldLength.ORIGIN_HEADER.value)
        validate_bytes(encrypted_header,          key='encrypted_header',          is_length=CompoundFieldLength.CT_HEADER.value)
        validate_bytes(encrypted_assembly_packet, key='encrypted_assembly_packet', is_length=CompoundFieldLength.CT_ASSEMBLY_PACKET.value)

        if not origin_bytes in Origin:
            raise ValidationError(f'Received message had invalid origin header {origin_bytes.decode()}.')

        origin = Origin(origin_bytes)

        if origin == Origin.USER:  # Not ideal place for this but it works.
            return DatagramOutgoingMessage(OnionPublicKeyContact.from_onion_address_bytes(enc_onion_address),
                                           MessageHeaderUserCT(encrypted_header),
                                           MessageAssemblyPacketUserCT(encrypted_assembly_packet),
                                           timestamp)
        else:
            return DatagramIncomingMessage(OnionPublicKeyContact.from_onion_address_bytes(enc_onion_address),
                                           MessageHeaderContactCT        (encrypted_header),
                                           MessageAssemblyPacketContactCT(encrypted_assembly_packet),
                                           timestamp)

    @classmethod
    def from_server_b85(cls, timestamp: datetime, b85_data: bytes) -> 'DatagramIncomingMessage':
        """Deserialize a message delivered over the server buffer."""
        return cls.from_txp_rep_bytes(timestamp, base64.b85decode(b85_data))


class DatagramIncomingNoiseMessage(DatagramIncomingMessage):
    pass