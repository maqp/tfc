#!/usr/bin/env python3.6
# -*- coding: utf-8 -*-

"""
Copyright (C) 2013-2017  Markus Ottela

This file is part of TFC.

TFC is free software: you can redistribute it and/or modify it under the terms
of the GNU General Public License as published by the Free Software Foundation,
either version 3 of the License, or (at your option) any later version.

TFC is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with TFC. If not, see <http://www.gnu.org/licenses/>.
"""

import hashlib
import struct

from typing import List, Union

from src.common.statics import *


def sha256d(message: bytes) -> bytes:
    """Chain SHA256 twice for Bitcoin WIF format."""
    return hashlib.sha256(hashlib.sha256(message).digest()).digest()


def b58encode(byte_string: bytes, file_key: bool = False) -> str:
    """Encode byte string to checksummed Base58 string.

    This format is exactly the same as Bitcoin's Wallet
    Import Format for mainnet/testnet addresses.
        https://en.bitcoin.it/wiki/Wallet_import_format
    """
    b58_alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    net_id       = b'\xef' if file_key else b'\x80'

    byte_string  = net_id + byte_string
    byte_string += sha256d(byte_string)[:B58_CHKSUM_LEN]

    orig_len     = len(byte_string)
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

    return (encoded + (orig_len - new_len) * '1')[::-1]


def b58decode(string: str, file_key: bool = False) -> bytes:
    """Decode a Base58-encoded string and verify checksum."""
    b58_alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

    orig_len = len(string)
    string   = string.lstrip('1')
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

    if sha256d(bytes(decoded_[:-B58_CHKSUM_LEN]))[:B58_CHKSUM_LEN] != decoded_[-B58_CHKSUM_LEN:]:
        raise ValueError

    net_id = b'\xef' if file_key else b'\x80'
    if decoded_[:1] != net_id:
        raise ValueError

    return bytes(decoded_[1:-B58_CHKSUM_LEN])


# Database unicode string padding

def unicode_padding(string: str) -> str:
    """Pad unicode string to 255 chars.

    Database fields are padded with unicode chars and then encoded
    with UTF-32 to hide the metadata about plaintext field length.

    :param string: String to be padded
    :return:       Padded string
    """
    assert len(string) < PADDING_LEN

    length  = PADDING_LEN - (len(string) % PADDING_LEN)
    string += length * chr(length)

    assert len(string) == PADDING_LEN

    return string


def rm_padding_str(string: str) -> str:
    """Remove padding from plaintext.

    :param string: String from which padding is removed
    :return:       String without padding
    """
    return string[:-ord(string[-1:])]


# Database constant length encoding

def bool_to_bytes(boolean: bool) -> bytes:
    """Convert boolean value to 1-byte byte string."""
    return bytes([boolean])


def int_to_bytes(integer: int) -> bytes:
    """Convert integer to 8-byte byte string."""
    return struct.pack('!Q', integer)


def double_to_bytes(double_: float) -> bytes:
    """Convert double to 8-byte byte string."""
    return struct.pack('d', double_)


def str_to_bytes(string: str) -> bytes:
    """Pad string with unicode chars and encode it with UTF-32.

    Length of padded string is 255 * 4 + 4 (BOM) = 1024 bytes.
    """
    return unicode_padding(string).encode('utf-32')


# Decoding

def bytes_to_bool(byte_string: Union[bytes, int]) -> bool:
    """Convert 1-byte byte string to boolean value."""
    if isinstance(byte_string, bytes):
        byte_string = byte_string[0]
    return bool(byte_string)


def bytes_to_int(byte_string: bytes) -> int:
    """Convert 8-byte byte string to integer."""
    return struct.unpack('!Q', byte_string)[0]


def bytes_to_double(byte_string: bytes) -> float:
    """Convert 8-byte byte string to double."""
    return struct.unpack('d', byte_string)[0]


def bytes_to_str(byte_string: bytes) -> str:
    """Convert 1024-byte byte string to unicode string.

    Decode byte string with UTF-32 and remove unicode padding.
    """
    return rm_padding_str(byte_string.decode('utf-32'))
