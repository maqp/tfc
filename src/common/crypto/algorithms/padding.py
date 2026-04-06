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

from cryptography.hazmat.primitives import padding

from src.common.exceptions import CriticalError
from src.common.statics import CryptoVarLength, EncodingLiteral


def byte_padding(bytestring: bytes  # Bytestring to be padded
                 ) -> bytes:        # Padded bytestring
    """Pad bytestring to next 255 bytes.

    TFC adds padding to messages it outputs. The padding ensures each
    assembly packet has a constant length. When traffic masking is
    disabled, because of padding the packet length reveals only the
    maximum length of the compressed message.

    When traffic masking is enabled, the padding contributes to traffic
    flow confidentiality: During traffic masking, TFC will output a
    constant stream of padded packets at constant intervals that hides
    metadata about message length (i.e., the adversary won't be able to
    distinguish when transmission of packet or series of packets begins
    and ends), as well as the type (message/file) of transferred data.

    TFC uses the PKCS #7 padding scheme described in RFC 2315 and RFC 5652:
        https://tools.ietf.org/html/rfc2315#section-10.3
        https://tools.ietf.org/html/rfc5652#section-6.3

    For a better explanation, see
        https://en.wikipedia.org/wiki/Padding_(cryptography)#PKCS#5_and_PKCS#7
    """
    padder  = padding.PKCS7(CryptoVarLength.PADDING.value * EncodingLiteral.BITS_PER_BYTE.value).padder()
    padded  = padder.update(bytestring)  # type: bytes
    padded += padder.finalize()

    if not isinstance(padded, bytes):
        raise CriticalError(f'Padded message had invalid type ({type(padded)}).')

    if len(padded) % CryptoVarLength.PADDING.value != 0:
        raise CriticalError(f'Padded message had an invalid length ({len(padded)}).')

    return padded


def rm_padding_bytes(bytestring: bytes  # Padded bytestring
                     ) -> bytes:        # Bytestring without padding
    """Remove padding from plaintext.

    The length of padding is determined by the ord-value of the last
    byte that is always part of the padding.
    """
    unpadder  = padding.PKCS7(CryptoVarLength.PADDING.value * EncodingLiteral.BITS_PER_BYTE.value).unpadder()
    unpadded  = unpadder.update(bytestring)  # type: bytes
    unpadded += unpadder.finalize()

    return unpadded
