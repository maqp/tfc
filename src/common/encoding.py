#!/usr/bin/env python3.6
# -*- coding: utf-8 -*-

"""
TFC - Onion-routed, endpoint secure messaging system
Copyright (C) 2013-2019  Markus Ottela

This file is part of TFC.

TFC is free software: you can redistribute it and/or modify it under the terms
of the GNU General Public License as published by the Free Software Foundation,
either version 3 of the License, or (at your option) any later version.

TFC is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with TFC. If not, see <https://www.gnu.org/licenses/>.
"""

import base64
import hashlib
import struct

from datetime import datetime
from typing   import List, Union

from src.common.statics import *


def sha256d(message: bytes) -> bytes:
    """Chain SHA256 twice for Bitcoin WIF format."""
    return hashlib.sha256(
        hashlib.sha256(message).digest()
    ).digest()


def b58encode(byte_string: bytes, public_key: bool = False) -> str:
    """Encode byte string to check-summed Base58 string.

    This format is exactly the same as Bitcoin's Wallet Import Format
    (WIF) for mainnet and testnet addresses.
        https://en.bitcoin.it/wiki/Wallet_import_format
    """
    b58_alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

    mainnet_header = b'\x80'
    testnet_header = b'\xef'
    net_id         = testnet_header if public_key else mainnet_header

    byte_string  = net_id + byte_string
    byte_string += sha256d(byte_string)[:B58_CHECKSUM_LENGTH]

    original_len = len(byte_string)
    byte_string  = byte_string.lstrip(b'\x00')
    new_len      = len(byte_string)

    p, acc = 1, 0
    for byte in bytearray(byte_string[::-1]):
        acc += p * byte
        p   *= 256

    encoded = ''
    while acc > 0:
        acc, mod = divmod(acc, 58)
        encoded += b58_alphabet[mod]

    return (encoded + (original_len - new_len) * b58_alphabet[0])[::-1]


def b58decode(string: str, public_key: bool = False) -> bytes:
    """Decode a Base58-encoded string and verify the checksum."""
    b58_alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

    mainnet_header = b'\x80'
    testnet_header = b'\xef'
    net_id         = testnet_header if public_key else mainnet_header

    orig_len = len(string)
    string   = string.lstrip(b58_alphabet[0])
    new_len  = len(string)

    p, acc = 1, 0
    for c in string[::-1]:
        acc += p * b58_alphabet.index(c)
        p   *= 58

    decoded = []
    while acc > 0:
        acc, mod = divmod(acc, 256)
        decoded.append(mod)

    decoded_ = (bytes(decoded) + (orig_len - new_len) * b'\x00')[::-1]  # type: Union[bytes, List[int]]

    if sha256d(bytes(decoded_[:-B58_CHECKSUM_LENGTH]))[:B58_CHECKSUM_LENGTH] != decoded_[-B58_CHECKSUM_LENGTH:]:
        raise ValueError

    if decoded_[:len(net_id)] != net_id:
        raise ValueError

    return bytes(decoded_[len(net_id):-B58_CHECKSUM_LENGTH])


def b85encode(data: bytes) -> str:
    """Encode byte string with base85.

    The encoding is slightly more inefficient, but allows variable
    length transmissions when used together with a delimiter char.
    """
    return base64.b85encode(data).decode()


def b10encode(fingerprint: bytes) -> str:
    """Encode bytestring in base10.

    Base10 encoding is used in fingerprint comparison to allow distinct
    communication:

    Base64 has 75% efficiency, but encoding is bad as the user might
           confuse uppercase I with lower case l, 0 with O, etc.

    Base58 has 73% efficiency and removes the problem of Base64
           explained above, but works only when manually typing
           strings because the user has to take time to explain which
           letters were capitalized etc.

    Base16 has 50% efficiency and removes the capitalization problem
           with Base58 but the choice is bad as '3', 'b', 'c', 'd'
           and 'e' are hard to distinguish in the English language
           (fingerprints are usually read aloud over off band call).

    Base10 has 41% efficiency but natural languages have evolved in a
    way that makes a clear distinction between the way different numbers
    are pronounced: reading them is faster and less error-prone.
    Compliments to Signal/WA developers for discovering this.
        https://signal.org/blog/safety-number-updates/
    """
    return str(int(fingerprint.hex(), base=16))


# Database unicode string padding

def unicode_padding(string: str) -> str:
    """Pad Unicode string to 255 chars.

    Database fields are padded with Unicode chars and then encoded
    with UTF-32 to hide the metadata about plaintext field length.
    """
    from src.common.exceptions import CriticalError

    if len(string) >= PADDING_LENGTH:
        raise CriticalError("Invalid input size.")

    length  = PADDING_LENGTH - (len(string) % PADDING_LENGTH)
    string += length * chr(length)

    if len(string) != PADDING_LENGTH:  # pragma: no cover
        raise CriticalError("Invalid padded string size.")

    return string


def rm_padding_str(string: str) -> str:
    """Remove padding from plaintext."""
    return string[:-ord(string[-1:])]


# Database constant length encoding

def onion_address_to_pub_key(account: str) -> bytes:
    """Encode TFC account to a public key byte string.

    The public key is the most compact possible representation of a TFC
    account, so it is useful when storing the address into databases.
    """
    return base64.b32decode(account.upper())[:-(ONION_ADDRESS_CHECKSUM_LENGTH + ONION_SERVICE_VERSION_LENGTH)]


def bool_to_bytes(boolean: bool) -> bytes:
    """Convert boolean value to a 1-byte byte string."""
    return bytes([boolean])


def int_to_bytes(integer: int) -> bytes:
    """Convert integer to an 8-byte byte string."""
    return struct.pack('!Q', integer)


def double_to_bytes(double_: float) -> bytes:
    """Convert double to an 8-byte byte string."""
    return struct.pack('d', double_)


def str_to_bytes(string: str) -> bytes:
    """Pad string with Unicode chars and encode it with UTF-32.

    Length of padded string is 255 * 4 + 4 (BOM) = 1024 bytes.
    """
    return unicode_padding(string).encode('utf-32')


# Decoding

def pub_key_to_onion_address(public_key: bytes) -> str:
    """Decode public key byte string to TFC account.

    This decoding is exactly the same process as conversion of Ed25519
    public key of v3 Onion Service into service ID:
        https://gitweb.torproject.org/torspec.git/tree/rend-spec-v3.txt#n2019
    """
    checksum = hashlib.sha3_256(ONION_ADDRESS_CHECKSUM_ID
                                + public_key
                                + ONION_SERVICE_VERSION
                                ).digest()[:ONION_ADDRESS_CHECKSUM_LENGTH]

    return base64.b32encode(public_key + checksum + ONION_SERVICE_VERSION).lower().decode()


def pub_key_to_short_address(public_key: bytes) -> str:
    """Decode public key to TFC account and truncate it."""
    return pub_key_to_onion_address(public_key)[:TRUNC_ADDRESS_LENGTH]


def bytes_to_bool(byte_string: Union[bytes, int]) -> bool:
    """Convert 1-byte byte string to a boolean value."""
    if isinstance(byte_string, bytes):
        byte_string = byte_string[0]
    return bool(byte_string)


def bytes_to_int(byte_string: bytes) -> int:
    """Convert 8-byte byte string to an integer."""
    int_format = struct.unpack('!Q', byte_string)[0]  # type: int
    return int_format


def bytes_to_double(byte_string: bytes) -> float:
    """Convert 8-byte byte string to double."""
    float_format = struct.unpack('d', byte_string)[0]  # type: float
    return float_format


def bytes_to_str(byte_string: bytes) -> str:
    """Convert 1024-byte byte string to Unicode string.

    Decode byte string with UTF-32 and remove Unicode padding.
    """
    return rm_padding_str(byte_string.decode('utf-32'))


def bytes_to_timestamp(byte_string: bytes) -> datetime:
    """Covert 4-byte byte string to datetime object."""
    return datetime.fromtimestamp(struct.unpack('<L', byte_string)[0])
