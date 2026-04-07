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

from src.common.crypto.keys.onion_service_keys import OnionPublicKeyContact
from src.common.statics import DatagramHeader, CryptoVarLength, FieldLength, Origin, DatagramTypeHR
from src.common.utils.encoding import ts_to_bytes
from src.common.utils.strings import separate_headers
from src.common.utils.validators import validate_bytes
from src.datagrams.datagram import DatagramContact


class DatagramIncomingFile(DatagramContact):

    DATAGRAM_TYPE_HR = DatagramTypeHR.FILE

    def __init__(self,
                 sender_pub_key : OnionPublicKeyContact,
                 file_ct        : bytes,
                 timestamp      : O[datetime] = None,
                 origin         : Origin      = Origin.CONTACT,
                 file_path      : O[str]      = None,
                 file_size      : O[int]      = None,
                 ) -> None:
        """Create a Relay-to-Receiver file datagram."""
        if file_path is None:
            validate_bytes(file_ct)
        elif file_size is None or file_size <= 0:
            raise ValueError('Incoming file datagram was missing file size.')

        self.__sender_pub_key = sender_pub_key
        self.__file_ct        = file_ct
        self._timestamp       = timestamp
        self.__origin         = origin
        self.__file_path      = file_path
        self.__file_size      = file_size

    @property
    def sender_pub_key(self) -> OnionPublicKeyContact:
        """Return the contact public key bundled with the file datagram."""
        return self.__sender_pub_key

    @property
    def file_ct(self) -> bytes:
        """Return the encrypted file payload."""
        if self.__file_path is not None:
            with open(self.__file_path, 'rb') as f:
                return f.read()
        return self.__file_ct

    @property
    def packet(self) -> bytes:
        """Return the Receiver payload containing sender key, origin, and file ciphertext."""
        return self.__assemble_payload(self.__sender_pub_key.public_bytes_raw + self.__origin.value)

    def to_bytes(self) -> bytes:
        """Serialize the datagram bytes."""
        return DatagramHeader.FILE.value + self.packet

    def to_receiver_packet(self) -> bytes:
        """Serialize the datagram to the timestamped packet format Receiver expects."""
        return self.__assemble_payload(DatagramHeader.FILE.value
                                       + ts_to_bytes(self.ts)
                                       + self.__sender_pub_key.public_bytes_raw
                                       + self.__origin.value)

    @classmethod
    def from_contact_file(cls,
                          timestamp      : datetime,
                          sender_pub_key : OnionPublicKeyContact,
                          file_ct        : bytes  = b'',
                          file_path      : O[str] = None,
                          file_size      : O[int] = None,
                          ) -> 'DatagramIncomingFile':
        """Create an incoming file datagram from a fetched contact file."""
        return cls(sender_pub_key = sender_pub_key,
                   file_ct        = file_ct,
                   timestamp      = timestamp,
                   file_path      = file_path,
                   file_size      = file_size)

    @classmethod
    def from_bytes(cls, timestamp: datetime, datagram_bytes: bytes) -> 'DatagramIncomingFile':
        """Parse Receiver-side file payload into a useful datagram object."""
        validate_bytes(datagram_bytes,
                       min_length=CryptoVarLength.ONION_SERVICE_PUBLIC_KEY.value + FieldLength.ORIGIN_HEADER.value + 1)

        onion_pub_key_raw, origin_bytes, file_ct = separate_headers(datagram_bytes,
                                                                    [CryptoVarLength.ONION_SERVICE_PUBLIC_KEY.value,
                                                                     FieldLength.ORIGIN_HEADER.value])

        try:
            origin = Origin(origin_bytes)
        except ValueError as exc:
            raise ValueError('Received file datagram had an invalid origin header.') from exc

        return cls(sender_pub_key = OnionPublicKeyContact(onion_pub_key_raw),
                   file_ct        = file_ct,
                   timestamp      = timestamp,
                   origin         = origin)

    def __assemble_payload(self, prefix: bytes) -> bytes:
        """Build payload bytes, reading ciphertext lazily from disk when needed."""
        if self.__file_path is None:
            return prefix + self.__file_ct

        if self.__file_size is None:
            raise ValueError('Incoming file datagram was missing file size.')

        payload = bytearray(len(prefix) + self.__file_size)
        payload[:len(prefix)] = prefix

        with open(self.__file_path, 'rb') as f:
            bytes_read = f.readinto(memoryview(payload)[len(prefix):])

        if bytes_read != self.__file_size:
            raise ValueError('Incoming file datagram was truncated on disk.')

        return bytes(payload)
