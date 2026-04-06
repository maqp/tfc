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
from typing import Optional as O, Self, TYPE_CHECKING

from src.common.crypto.algorithms.blake2b import blake2b
from src.common.exceptions import CriticalError, ValidationError
from src.common.crypto.keys.onion_service_keys import OnionPublicKeyContact
from src.common.statics import DatagramHeader, CryptoVarLength, DatagramTypeHR, FieldLength, KeyLength, RelayLimits
from src.common.utils.encoding import bytes_to_int, int_to_bytes, ts_to_bytes
from src.common.utils.strings import separate_header, separate_headers, separate_trailer, split_byte_string
from src.common.utils.validators import validate_bytes, validate_int
from src.datagrams.datagram import DatagramContact, DatagramUser

if TYPE_CHECKING:
    from src.common.crypto.pt_ct import MulticastFileCT


class DatagramFileMulticastFragment(DatagramContact):

    DATAGRAM_TYPE_HR = DatagramTypeHR.FILE

    def __init__(self,
                 pub_key_contact  : OnionPublicKeyContact,
                 packet_number    : int,
                 packet_total     : int,
                 payload_fragment : bytes,
                 payload_checksum : O[bytes]    = None,
                 timestamp        : O[datetime] = None,
                 ) -> None:
        """Create a Relay-to-Receiver file fragment datagram."""
        if not isinstance(pub_key_contact, OnionPublicKeyContact):
            raise CriticalError('Received public key was not OnionPublicKeyContact.')

        validate_int  (packet_number,    key='packet_number', min_value=1)
        validate_int  (packet_total,     key='packet_total',  min_value=1)
        validate_bytes(payload_fragment, key='payload_fragment')

        if packet_number > packet_total:
            raise ValidationError('Packet number exceeded packet count.')

        if packet_number == packet_total:
            if payload_checksum is None:
                raise ValidationError('Final file fragment was missing payload checksum.')
            validate_bytes(payload_checksum, key='payload_checksum', is_length=CryptoVarLength.BLAKE2_DIGEST.value)
        elif payload_checksum is not None:
            raise ValidationError('Only the final file fragment may contain payload checksum.')

        self.__pub_key_contact  = pub_key_contact
        self.__packet_number    = packet_number
        self.__packet_total     = packet_total
        self.__payload_fragment = payload_fragment
        self.__payload_checksum = payload_checksum
        self._timestamp         = timestamp

    @property
    def pub_key_contact(self) -> OnionPublicKeyContact:
        """Return the sender's public key."""
        return self.__pub_key_contact

    @property
    def packet_number(self) -> int:
        """Return the 1-based fragment number."""
        return self.__packet_number

    @property
    def packet_total(self) -> int:
        """Return the total number of fragments in the file datagram."""
        return self.__packet_total

    @property
    def payload_fragment(self) -> bytes:
        """Return this fragment's ciphertext slice."""
        return self.__payload_fragment

    @property
    def payload_checksum(self) -> O[bytes]:
        """Return the reassembly checksum carried by the final fragment."""
        return self.__payload_checksum

    def to_rep_rxp_bytes(self) -> bytes:
        """Serialize the fragment for Relay-to-Receiver delivery."""
        if self._timestamp is None:
            raise ValueError('File fragment datagram was missing timestamp.')

        packet = (DatagramHeader.FILE.value
                  + ts_to_bytes(self._timestamp)
                  + self.__pub_key_contact.serialize()
                  + int_to_bytes(self.__packet_number)
                  + int_to_bytes(self.__packet_total)
                  + self.__payload_fragment)

        if self.__payload_checksum is not None:
            packet += self.__payload_checksum

        return packet

    @classmethod
    def from_rep_rxp_bytes(cls, timestamp: datetime, datagram_bytes: bytes) -> Self:
        """Deserialize a Relay-to-Receiver multicast file fragment datagram."""
        min_payload_length = (FieldLength.ONION_ADDRESS.value
                              + 2 * FieldLength.ENCODED_INTEGER.value
                              + 1)

        validate_bytes(datagram_bytes, key='datagram_bytes', min_length=min_payload_length)

        enc_contact_address, packet_number_bytes, packet_total_bytes, payload \
            = separate_headers(datagram_bytes, [FieldLength.ONION_ADDRESS.value,
                                                FieldLength.ENCODED_INTEGER.value,
                                                FieldLength.ENCODED_INTEGER.value])

        validate_bytes(enc_contact_address, key='enc_contact_address', is_length=FieldLength.ONION_ADDRESS.value)
        validate_bytes(packet_number_bytes, key='packet_number_bytes', is_length=FieldLength.ENCODED_INTEGER.value)
        validate_bytes(packet_total_bytes,  key='packet_total_bytes',  is_length=FieldLength.ENCODED_INTEGER.value)

        packet_number = bytes_to_int(packet_number_bytes)
        packet_total  = bytes_to_int(packet_total_bytes)

        payload_checksum = None
        if packet_number == packet_total:
            if len(payload) <= CryptoVarLength.BLAKE2_DIGEST.value:
                raise ValidationError('Final file fragment payload was too short.')
            payload, payload_checksum = separate_trailer(payload, CryptoVarLength.BLAKE2_DIGEST.value)

        return cls(OnionPublicKeyContact.from_onion_address_bytes(enc_contact_address),
                   packet_number,
                   packet_total,
                   payload,
                   payload_checksum,
                   timestamp)


class DatagramFileMulticast(DatagramUser):
    DATAGRAM_TYPE_HR = DatagramTypeHR.FILE

    def __init__(self,
                 file_ct         : 'MulticastFileCT',
                 recipient_list  : O[list[OnionPublicKeyContact]] = None,
                 pub_key_contact : O[OnionPublicKeyContact]       = None,
                 timestamp       : O[datetime]                    = None,
                 ) -> None:
        """Create a Source-to-Relay file multicast datagram."""
        from src.common.crypto.pt_ct import MulticastFileCT

        if not isinstance(file_ct, MulticastFileCT):
            raise CriticalError('Received ciphertext was not of type MulticastFileCT.')

        validate_bytes(file_ct.ct_bytes)

        self.__recipient_list  = recipient_list
        self.__file_ct         = file_ct
        self._timestamp        = timestamp
        self.__pub_key_contact = pub_key_contact

    @property
    def recipient_pub_keys(self) -> list[OnionPublicKeyContact]:
        """Return the intended recipient public keys."""
        if self.__recipient_list is None:
            raise CriticalError('Recipient list is empty.')
        return self.__recipient_list

    @property
    def pub_key_contact(self) -> OnionPublicKeyContact:
        """Get the contact's Onion Service public key."""
        if self.__pub_key_contact is None:
            raise CriticalError('File datagram contact public key is not set.')
        return self.__pub_key_contact

    @property
    def file_ct(self) -> 'MulticastFileCT':
        """Return the encrypted multicast file payload."""
        return self.__file_ct

    def to_fragments(self,
                     fragment_size: int = RelayLimits.FILE_FRAGMENT_SIZE.value,
                     ) -> list[DatagramFileMulticastFragment]:
        """Split a Relay-to-Receiver multicast file datagram into fragments."""
        validate_int(fragment_size, key='fragment_size', min_value=1)

        if self._timestamp is None:
            raise ValueError('File datagram was missing timestamp.')
        if self.__pub_key_contact is None:
            raise CriticalError('File datagram contact public key is not set.')

        fragments         = split_byte_string(self.__file_ct.ct_bytes, fragment_size)
        packet_total      = len(fragments)
        payload_checksum  = blake2b(self.__pub_key_contact.serialize() + self.__file_ct.ct_bytes)

        return [DatagramFileMulticastFragment(self.__pub_key_contact,
                                              index,
                                              packet_total,
                                              payload_fragment,
                                              payload_checksum if index == packet_total else None,
                                              self._timestamp)
                for index, payload_fragment in enumerate(fragments, start=1)]

    @classmethod
    def from_fragments(cls, fragments: list[DatagramFileMulticastFragment]) -> Self:
        """Reassemble a complete Relay-to-Receiver multicast file datagram."""
        from src.common.crypto.pt_ct import MulticastFileCT

        if not fragments:
            raise ValidationError('File datagram fragment list was empty.')

        first = fragments[0]

        if first.payload_checksum is not None and first.packet_total > 1:
            raise ValidationError('Non-final file fragment carried payload checksum.')

        indexed_fragments: dict[int, DatagramFileMulticastFragment] = {}
        for fragment in fragments:
            if fragment.pub_key_contact != first.pub_key_contact:  raise ValidationError('File datagram fragments had mixed senders.')
            if fragment.packet_total    != first.packet_total:     raise ValidationError('File datagram fragments had mismatched packet counts.')
            if fragment.ts              != first.ts:               raise ValidationError('File datagram fragments had mismatched timestamps.')
            if fragment.packet_number in indexed_fragments:        raise ValidationError('File datagram fragments contained duplicates.')
            indexed_fragments[fragment.packet_number] = fragment

        if len(indexed_fragments) != first.packet_total:
            raise ValidationError('File datagram fragments were incomplete.')

        try:
            ordered_fragments = [indexed_fragments[index] for index in range(1, first.packet_total + 1)]
        except KeyError as e:
            raise ValidationError(f'File datagram fragments were missing packet {e.args[0]}.')

        final_fragment = ordered_fragments[-1]
        if final_fragment.payload_checksum is None:
            raise ValidationError('Final file fragment was missing payload checksum.')

        file_ct = b''.join(fragment.payload_fragment for fragment in ordered_fragments)

        if blake2b(first.pub_key_contact.serialize() + file_ct) != final_fragment.payload_checksum:
            raise ValidationError('File datagram fragment checksum mismatch.')

        return cls(MulticastFileCT(file_ct), pub_key_contact=first.pub_key_contact, timestamp=first.ts)

    # ┌───────────────────────────────┐
    # │ Serialization/Deserialization │
    # └───────────────────────────────┘

    def to_txp_rep_bytes(self) -> bytes:
        """Return the multicasting datagram serialized to bytes."""
        if not self.__recipient_list:
            raise ValueError('Outgoing file datagram was missing recipients.')

        no_contacts  = int_to_bytes(len(self.__recipient_list))
        ser_contacts = b''.join([contact.serialize() for contact in self.__recipient_list])

        return (DatagramHeader.FILE.value
                + no_contacts
                + ser_contacts
                + self.__file_ct.ct_bytes)

    @classmethod
    def from_txp_rep_bytes(cls, ts: datetime, datagram_bytes: bytes) -> 'DatagramFileMulticast':
        """\
        Parse the group message datagram from Transmitter Program's multi-
        casted bytes into a list of Datagram objects for each recipient.
        """
        from src.common.crypto.pt_ct import MulticastFileCT

        no_contacts_bytes, remaining_bytes = separate_header(datagram_bytes, FieldLength.ENCODED_INTEGER.value)
        no_contacts                        = bytes_to_int(no_contacts_bytes)
        contact_bytes_length               = no_contacts * FieldLength.ONION_ADDRESS.value

        if no_contacts <= 0:
            raise ValidationError('Outgoing file datagram had an invalid recipient list.')
        if contact_bytes_length > len(remaining_bytes):
            raise ValidationError('Outgoing file datagram had an invalid recipient list.')
        if len(remaining_bytes) < (KeyLength.XCHACHA20_NONCE.value
                                   + FieldLength.PADDED_UTF32_STR.value
                                   + FieldLength.ENCODED_BOOLEAN.value  # Minimum payload is 1 byte.
                                   + CryptoVarLength.POLY1305_TAG.value):
            raise ValidationError('Outgoing file datagram was too short.')

        enc_contact_addresses, file_ct = separate_header(remaining_bytes, contact_bytes_length)

        validate_bytes(enc_contact_addresses, len_is_mul_of=FieldLength.ONION_ADDRESS.value)

        addresses          = split_byte_string(enc_contact_addresses, FieldLength.ONION_ADDRESS.value)
        recipient_pub_keys = [OnionPublicKeyContact.from_onion_address_bytes(address) for address in addresses]

        return cls(MulticastFileCT(file_ct), recipient_pub_keys, timestamp=ts)

    def to_server_b85(self) -> bytes:
        """Return the single-cast, i.e. per-recipient datagram serialized to bytes."""
        if self.__pub_key_contact is None:
            raise CriticalError('File datagram contact public key is not set.')

        return DatagramHeader.FILE.value + base64.b85encode(self.__pub_key_contact.serialize() + self.__file_ct.ct_bytes)

    @classmethod
    def from_server_b85(cls, ts: datetime, b85_bytes: bytes) -> Self:
        """Parse the group message data from server message bytes."""
        from src.common.crypto.pt_ct import MulticastFileCT

        datagram_bytes                 = base64.b85decode(b85_bytes)
        enc_contact_addresses, file_ct = separate_header(datagram_bytes, header_length=FieldLength.ONION_ADDRESS.value)
        pub_key_contact                = OnionPublicKeyContact.from_onion_address_bytes(enc_contact_addresses)

        return cls(MulticastFileCT(file_ct), pub_key_contact=pub_key_contact, timestamp=ts)

    def to_rep_rxp_bytes(self) -> bytes:
        """Serialize a fetched contact file for Relay-to-Receiver delivery."""
        if self._timestamp is None:
            raise ValueError('File datagram was missing timestamp.')

        return (DatagramHeader.FILE.value
                + ts_to_bytes(self._timestamp)
                + self.pub_key_contact.serialize()
                + self.__file_ct.ct_bytes)

    @classmethod
    def from_rep_rxp_bytes(cls, timestamp: datetime, datagram_bytes: bytes) -> Self:
        """Deserialize a Relay-to-Receiver multicast file datagram."""
        from src.common.crypto.pt_ct import MulticastFileCT

        min_payload_length = (FieldLength.ONION_ADDRESS.value
                              + KeyLength.XCHACHA20_NONCE.value
                              + FieldLength.PADDED_UTF32_STR.value
                              + FieldLength.ENCODED_BOOLEAN.value
                              + CryptoVarLength.POLY1305_TAG.value)

        validate_bytes(datagram_bytes, key='datagram_bytes', min_length=min_payload_length)

        enc_contact_address, file_ct = separate_headers(datagram_bytes, [FieldLength.ONION_ADDRESS.value])

        validate_bytes(enc_contact_address, key='enc_contact_address', is_length=FieldLength.ONION_ADDRESS.value)
        validate_bytes(file_ct,             key='file_ct',             min_length=min_payload_length - FieldLength.ONION_ADDRESS.value)

        return cls(MulticastFileCT(file_ct),
                   pub_key_contact = OnionPublicKeyContact.from_onion_address_bytes(enc_contact_address),
                   timestamp       = timestamp)
