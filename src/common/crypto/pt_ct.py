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

from typing import TYPE_CHECKING

from src.common.exceptions import CriticalError
from src.common.crypto.algorithms.blake2b import blake2b
from src.common.crypto.algorithms.padding import byte_padding

from src.common.statics import AsmPacket

if TYPE_CHECKING:
    from src.common.crypto.keys.symmetric_key import LongFileKey, LongMessageKey


class Plaintext:
    """Plaintext baseclass.

    Plaintext is a type-safe immutable wrapper for plaintext bytestrings.
    They're used to ensure encryption keys can only encrypt specific types
    of plaintexts into their counterpart Ciphertext objects.
    """

    def __init__(self, plaintext_bytes: bytes) -> None:
        self.__plaintext_bytes = plaintext_bytes

    def __len__(self) -> int:
        return len(self.__plaintext_bytes)

    def __add__(self, other: 'Plaintext') -> 'Plaintext':
        return Plaintext(self.__plaintext_bytes + other.pt_bytes)

    @property
    def pt_bytes(self) -> bytes:
        """Get the raw bytes of the Plaintext object."""
        return self.__plaintext_bytes

    def apply_adding(self) -> 'Plaintext':
        """Apply padding to the current Plaintext object."""
        return Plaintext(byte_padding(self.__plaintext_bytes))

    def prepend_asm_header(self, header: AsmPacket) -> 'Plaintext':
        """Prepend an AsmPacket object to the current Plaintext object."""
        if not isinstance(header, AsmPacket):
            raise CriticalError('Received unintended header for the ciphertext')
        return Plaintext(header.value + self.__plaintext_bytes)


class Ciphertext:
    """Ciphertext baseclass.

    Ciphertext is a type-safe immutable wrapper for ciphertext bytestrings.
    They're used to ensure decryption keys can only decrypt specific types
    of ciphertexts into their Plaintext counterpart objects.
    """
    def __init__(self, ciphertext_bytes: bytes) -> None:
        self.__ciphertext_bytes = ciphertext_bytes

    def __add__(self, other: 'Ciphertext') -> 'Ciphertext':
        return Ciphertext(self.__ciphertext_bytes + other.ct_bytes)

    def apply_adding(self) -> 'Ciphertext':
        """Apply padding to the current Ciphertext object."""
        return Ciphertext(byte_padding(self.__ciphertext_bytes))

    @property
    def ct_bytes(self) -> bytes:
        """Get the raw ciphertext bytes."""
        return self.__ciphertext_bytes


# ┌───────────────┐
# │ Key Exchanges │
# └───────────────┘
class LocalKeySetPT(Plaintext):  pass
class LocalKeySetCT(Ciphertext): pass
class PSKPT        (Plaintext):  pass
class PSKCT        (Ciphertext): pass

# ┌───────────────┐
# │ Communication │
# └───────────────┘
class MessageHeaderUserPT           (Plaintext):  pass
class MessageHeaderUserCT           (Ciphertext): pass
class MessageHeaderContactPT        (Plaintext):  pass
class MessageHeaderContactCT        (Ciphertext): pass
class MessageAssemblyPacketUserPT   (Plaintext):  pass
class MessageAssemblyPacketUserCT   (Ciphertext): pass
class MessageAssemblyPacketContactPT(Plaintext):  pass
class MessageAssemblyPacketContactCT(Ciphertext): pass

# ┌───────┐
# │ Files │
# └───────┘
class MulticastFilePT(Plaintext): pass

class MulticastFileCT(Ciphertext):
    @property
    def ct_hash(self) -> bytes:
        """Return the BLAKE2b hash of the ciphertext bytes.

        Used to validate received ciphertext integrity and
        to find the correct decryption key.
        """
        return blake2b(self.ct_bytes)


# ┌──────────┐
# │ Commands │
# └──────────┘
class CommandHeaderPT        (Plaintext):  pass
class CommandHeaderCT        (Ciphertext): pass
class CommandAssemblyPacketPT(Plaintext):  pass
class CommandAssemblyPacketCT(Ciphertext): pass

# ┌──────────────────────┐
# │ Sender-Based Control │
# └──────────────────────┘

class MsgInnerPT (Plaintext):  pass
class FileInnerPT(Plaintext):  pass

class MsgInnerCT(Ciphertext):

    def add_sender_based_control_key(self, key: 'LongMessageKey') -> 'MsgInnerCT':
        """Add sender-based control key to this ciphertext."""
        from src.common.crypto.keys.symmetric_key import LongMessageKey

        if not isinstance(key, LongMessageKey):
            raise CriticalError('Received unintended sender-based-control key for the ciphertext')
        return MsgInnerCT(self.ct_bytes + key.raw_bytes)


class FileInnerCT(Ciphertext):

    def add_sender_based_control_key(self, key: 'LongFileKey') -> 'FileInnerCT':
        """Add sender-based control key to this ciphertext."""
        from src.common.crypto.keys.symmetric_key import LongFileKey

        if not isinstance(key, LongFileKey):
            raise CriticalError('Received unintended sender-based-control key for the ciphertext')
        return FileInnerCT(self.ct_bytes + key.raw_bytes)
