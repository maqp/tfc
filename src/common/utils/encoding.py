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
import hashlib
import struct
import zlib

from datetime import datetime
from typing import TYPE_CHECKING

from src.common.statics import B58Literals, CryptoVarLength, FieldLength, B58Alphabet
from src.common.utils.validators import validate_bytes

if TYPE_CHECKING:
    from src.common.crypto.fingerprint import Fingerprint


# ┌───────────────────────────────────────────────────────────────────────────┐
# │                                   Base10                                  │
# └───────────────────────────────────────────────────────────────────────────┘

def b10encode(fingerprint: 'Fingerprint') -> str:
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
           way that makes a clear distinction between the way different
           numbers are pronounced: reading them is faster and less
           error-prone. Compliments to Signal/WA developers for
           discovering this: https://signal.org/blog/safety-number-updates/
    """
    return str(int((fingerprint.to_bytes().hex()), base=16))


# ┌───────────────────────────────────────────────────────────────────────────┐
# │                                   Base26                                  │
# └───────────────────────────────────────────────────────────────────────────┘

def encode_base26(index: int) -> str:
    """Encode a zero-based integer using lowercase base26 letters."""
    if index < 0:
        raise ValueError('Base26 index must be non-negative.')

    result = ''
    value  = index
    while True:
        value, remainder = divmod(value, 26)
        result = chr(ord('a') + remainder) + result
        if value == 0:
            return result
        value -= 1


def decode_base26(token: str) -> int:
    """Decode a lowercase base26 token into a zero-based integer."""
    if not token or any(char < 'a' or char > 'z' for char in token):
        raise ValueError('Invalid base26 token.')

    value = 0
    for char in token:
        value = value * 26 + (ord(char) - ord('a') + 1)
    return value - 1


# ┌───────────────────────────────────────────────────────────────────────────┐
# │                                Base58 / WIF                               │
# └───────────────────────────────────────────────────────────────────────────┘

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
    net_id       = B58Literals.TESTNET_HEADER.value if public_key else B58Literals.MAINNET_HEADER.value
    byte_string  = net_id + byte_string
    byte_string += sha256d(byte_string)[:FieldLength.B58_CHECKSUM]

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
        encoded += B58Alphabet.B58_ALPHABET[mod]

    return (encoded + (original_len - new_len) * B58Alphabet.B58_ALPHABET[0])[::-1]


def b58decode(string: str, public_key: bool = False) -> bytes:
    """Decode a Base58-encoded string and verify the checksum."""
    net_id       = B58Literals.TESTNET_HEADER.value if public_key else B58Literals.MAINNET_HEADER.value
    checksum_len = FieldLength.B58_CHECKSUM.value
    orig_len     = len(string)
    string       = string.lstrip(B58Alphabet.B58_ALPHABET.value[0])
    new_len      = len(string)

    p, acc = 1, 0
    for c in string[::-1]:
        acc += p * B58Alphabet.B58_ALPHABET.B58_ALPHABET.value.index(c)
        p   *= 58

    decoded = []
    while acc > 0:
        acc, mod = divmod(acc, 256)
        decoded.append(mod)

    decoded_ = (bytes(decoded) + (orig_len - new_len) * b'\x00')[::-1]  # type: bytes|list[int]

    if sha256d(bytes(decoded_[:-checksum_len]))[:checksum_len] != decoded_[-checksum_len:]:
        raise ValueError

    if decoded_[:len(net_id)] != net_id:
        raise ValueError

    return bytes(decoded_[len(net_id):-checksum_len])


# ┌───────────────────────────────────────────────────────────────────────────┐
# │                                   Base85                                  │
# └───────────────────────────────────────────────────────────────────────────┘

def b85encode(data: bytes) -> str:
    """Encode byte string with base85.

    The encoding is slightly more inefficient, but allows variable
    length transmissions when used together with a delimiter char.
    """
    return base64.b85encode(data).decode()


# ┌───────────────────────────────────────────────────────────────────────────┐
# │                     Basic data type (de)serialization                     │
# └───────────────────────────────────────────────────────────────────────────┘

# ┌─────────┐
# │ Boolean │
# └─────────┘

def bool_to_bytes(boolean: bool) -> bytes:
    """Convert boolean value to a 1-byte byte string."""
    return bytes([boolean])

def bytes_to_bool(byte_string: bytes|int) -> bool:
    """Convert 1-byte byte string to a boolean value."""
    if isinstance(byte_string, bytes):
        byte_string = byte_string[0]
    return bool(byte_string)


# ┌──────────┐
# │ Integers │
# └──────────┘

def int_to_bytes(integer: int) -> bytes:
    """Convert integer to an 8-byte byte string."""
    return struct.pack('!Q', integer)

def bytes_to_int(byte_string: bytes) -> int:
    """Convert 8-byte byte string to an integer."""
    int_format = struct.unpack('!Q', byte_string)[0]  # type: int
    return int_format

# ┌────────┐
# │ Floats │
# └────────┘

def double_to_bytes(double_: float) -> bytes:
    """Convert double to an 8-byte byte string."""
    return struct.pack('d', double_)

def bytes_to_double(byte_string: bytes) -> float:
    """Convert 8-byte byte string to double."""
    float_format = struct.unpack('d', byte_string)[0]  # type: float
    return float_format

# ┌─────────┐
# │ Strings │
# └─────────┘

def unicode_padding(string: str) -> str:
    """Pad Unicode string to 255 chars using PKCS #7 padding.

    Database fields are padded with Unicode chars and then encoded
    with UTF-32 to hide the metadata about plaintext field length.
    """
    from src.common.exceptions import CriticalError

    if len(string) >= CryptoVarLength.PADDING:
        raise CriticalError('Invalid input size.')

    length  = CryptoVarLength.PADDING - (len(string) % CryptoVarLength.PADDING)
    string += length * chr(length)

    if len(string) != CryptoVarLength.PADDING:  # pragma: no cover
        raise CriticalError('Invalid padded string size.')

    return string

def rm_padding_str(string: str) -> str:
    """Remove padding from plaintext."""
    return string[:-ord(string[-1:])]


def str_to_padded_bytes(string: str) -> bytes:
    """Pad string with Unicode chars and encode it with UTF-32.

    Length of padded string is 255 * 4 + 4 (BOM) = 1024 bytes.
    """
    padded = unicode_padding(string).encode('utf-32')
    validate_bytes(padded, is_length=1024)
    return padded

def padded_bytes_to_str(byte_string: bytes) -> str:
    """Convert 1024-byte byte string to Unicode string.

    Decode byte string with UTF-32 and remove Unicode padding.
    """
    return rm_padding_str(byte_string.decode('utf-32'))


# ┌────────────┐
# │ Timestamps │
# └────────────┘

def ts_to_bytes(ts: datetime) -> bytes:
    """Convert datetime object to a 8-byte byte string."""
    return int_to_bytes(int(ts.strftime('%Y%m%d%H%M%S%f')[:-4]))


def bytes_to_timestamp(byte_string: bytes) -> datetime:
    """Covert 4-byte byte string to datetime object."""
    return datetime.fromtimestamp(struct.unpack('<L', byte_string)[0])


# ┌───────────────────────────────────────────────────────────────────────────┐
# │                            Data (de)compression                           │
# └───────────────────────────────────────────────────────────────────────────┘

def decompress(data        : bytes,  # Data to be decompressed
               max_size_mb : int     # The maximum size of decompressed data.
               ) -> bytes:           # Decompressed data
    """Decompress received data.

    The decompressed data has a maximum size, designed to prevent zip
    bombs from filling the drive of an unsuspecting user.
    """
    from src.common.exceptions import SoftError  # Avoid circular import

    max_size = max_size_mb * 1_000_000

    dec = zlib.decompressobj()

    try:
        # Allow one extra byte so oversize output can be detected reliably.
        data = dec.decompress(data, max_size + 1)
        if len(data) > max_size:
            raise SoftError('Error: Decompression aborted due to possible zip bomb.')

        data += dec.flush(max_size + 1 - len(data))

        if len(data) > max_size:
            raise SoftError('Error: Decompression aborted due to possible zip bomb.')

        if dec.unconsumed_tail:
            raise SoftError('Error: Decompression aborted due to possible zip bomb.')

        if dec.unused_data or not dec.eof:
            raise SoftError('Error: Decompression failed.')

        return data

    except zlib.error:
        raise SoftError('Error: Decompression failed.')
