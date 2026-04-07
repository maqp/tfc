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

from src.common.crypto.keys.symmetric_key import BufferKey
from src.common.types_custom import BoolAllowContactRequests, BytesActiveSetup
from src.common.entities.confirm_code import ConfirmationCode
from src.common.crypto.keys.onion_service_keys import OnionServicePrivateKey, OnionPublicKeyContact
from src.common.statics import DatagramHeader, RelayCommand, FieldLength, CompoundFieldLength, KeyLength
from src.common.utils.encoding import int_to_bytes, bool_to_bytes, bytes_to_bool, bytes_to_int
from src.common.utils.strings import separate_headers, split_byte_string, separate_header
from src.common.utils.validators import validate_bytes
from src.datagrams.datagram import DatagramRelayCommand


class DatagramRelaySetupOnionService(DatagramRelayCommand):

    def __init__(self,
                 onion_service_private_key : OnionServicePrivateKey,
                 buffer_key                : BufferKey,
                 confirmation_code         : ConfirmationCode,
                 pending_pub_keys          : list[OnionPublicKeyContact],
                 existing_pub_keys         : list[OnionPublicKeyContact],
                 allow_contact_requests    : BoolAllowContactRequests,
                 timestamp                 : O[datetime] = None
                 ) -> None:
        """Create new OnionServiceSetupDatagram object."""
        self.__onion_service_private_key = onion_service_private_key
        self.__buffer_key                = buffer_key
        self.__confirmation_code         = confirmation_code
        self.__existing_pub_keys         = existing_pub_keys
        self.__pending_pub_keys          = pending_pub_keys
        self.__allow_contact_requests    = allow_contact_requests
        self._timestamp                  = timestamp

    @property
    def onion_service_private_key(self) -> OnionServicePrivateKey:
        """Return the onion_service_private_key value."""
        return self.__onion_service_private_key

    @property
    def buffer_key(self) -> BufferKey:
        """Return the buffer_key value."""
        return self.__buffer_key

    @property
    def confirmation_code(self) -> ConfirmationCode:
        """Return the confirmation_code value."""
        return self.__confirmation_code

    @property
    def existing_pub_keys(self) -> list[OnionPublicKeyContact]:
        """Return the existing_pub_keys value."""
        return self.__existing_pub_keys

    @property
    def pending_pub_keys(self) -> list[OnionPublicKeyContact]:
        """Return the pending_pub_keys value."""
        return self.__pending_pub_keys

    @property
    def allow_contact_requests(self) -> BoolAllowContactRequests:
        """Return the allow_contact_requests value."""
        return self.__allow_contact_requests

    @property
    def timestamp(self) -> O[datetime]:
        """Return the timestamp value."""
        return self._timestamp

    # ┌───────────────────────────────┐
    # │ Serialization/Deserialization │
    # └───────────────────────────────┘

    def to_txp_rep_bytes(self) -> BytesActiveSetup:
        """Serializes the datagram for transport from Transmitter Program to Relay Program."""
        pending_contacts  = b''.join([pub_key.serialize() for pub_key in self.__pending_pub_keys])
        existing_contacts = b''.join([pub_key.serialize() for pub_key in self.__existing_pub_keys])

        no_pending   = int_to_bytes(len(self.__pending_pub_keys))
        contact_data = no_pending + pending_contacts + existing_contacts

        datagram_bytes = (DatagramHeader.RELAY_COMMAND.value
                          + RelayCommand.ONION_SERVICE_SETUP_DATA.value
                          + self.__buffer_key.raw_bytes
                          + self.__onion_service_private_key.raw_private_bytes
                          + self.__confirmation_code.raw_bytes
                          + bool_to_bytes(self.__allow_contact_requests)
                          + contact_data)

        return BytesActiveSetup(datagram_bytes)

    @classmethod
    def from_txp_rep_bytes(cls, timestamp: datetime, datagram_bytes: bytes) -> 'DatagramRelaySetupOnionService':
        """Deserializes the datagram from `Transmitter Program to Relay Program` bytes."""
        validate_bytes(datagram_bytes, min_length=CompoundFieldLength.ONION_SERVICE_SETUP_DATA_MIN.value)

        buffer_key_bytes, onion_private_bytes, conf_code_bytes, allow_contact_requests_bytes, no_pending_bytes, all_pub_keys \
            = separate_headers(datagram_bytes, header_length_list=[KeyLength.SYMMETRIC_KEY.value,
                                                                   KeyLength.ONION_SERVICE_PRIVATE_KEY.value,
                                                                   FieldLength.CONFIRM_CODE.value,
                                                                   FieldLength.ENCODED_BOOLEAN.value,
                                                                   FieldLength.ENCODED_INTEGER.value])

        validate_bytes(buffer_key_bytes, is_length=KeyLength.SYMMETRIC_KEY)
        buffer_key = BufferKey(buffer_key_bytes)

        validate_bytes(onion_private_bytes, is_length=KeyLength.ONION_SERVICE_PRIVATE_KEY.value, not_all_zeros=True)
        onion_service_private_key = OnionServicePrivateKey(onion_private_bytes)

        validate_bytes(conf_code_bytes, is_length=FieldLength.CONFIRM_CODE.value)
        confirmation_code = ConfirmationCode(conf_code_bytes)

        validate_bytes(allow_contact_requests_bytes, is_length=FieldLength.ENCODED_BOOLEAN.value)
        allow_contact_requests = BoolAllowContactRequests(bytes_to_bool(allow_contact_requests_bytes))

        validate_bytes(no_pending_bytes, is_length=FieldLength.ENCODED_INTEGER.value)
        number_of_pending_contacts = bytes_to_int(no_pending_bytes)

        validate_bytes(all_pub_keys, empty_allowed=True, len_is_mul_of=FieldLength.ONION_ADDRESS.value)

        pending_data_len = number_of_pending_contacts * FieldLength.ONION_ADDRESS.value
        if pending_data_len > len(all_pub_keys):
            raise ValueError('Pending contact count exceeds encoded address data.')

        enc_addr_pending, enc_addr_all = separate_header(all_pub_keys, header_length=number_of_pending_contacts * FieldLength.ONION_ADDRESS.value)

        pending_enc_addr_list = split_byte_string(enc_addr_pending, item_len=FieldLength.ONION_ADDRESS.value)
        contact_enc_addr_list = split_byte_string(enc_addr_all,     item_len=FieldLength.ONION_ADDRESS.value)

        pending_pub_keys  = [OnionPublicKeyContact.from_onion_address_bytes(addr) for addr in pending_enc_addr_list]
        existing_pub_keys = [OnionPublicKeyContact.from_onion_address_bytes(addr) for addr in contact_enc_addr_list]

        return DatagramRelaySetupOnionService(onion_service_private_key,
                                              buffer_key,
                                              confirmation_code,
                                              pending_pub_keys,
                                              existing_pub_keys,
                                              allow_contact_requests,
                                              timestamp)
