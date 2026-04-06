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

from src.common.crypto.algorithms.blake2b import blake2b

if TYPE_CHECKING:
    from src.common.crypto.keys.symmetric_key import LocalKeyEncryptionKey


class KEKHash:
    """The local key's key encryption key hash.

    This value is used to scan outgoing packets for the key encryption key.
    """

    def __init__(self, kek_hash: bytes) -> None:
        """Create new Fingerprint object."""
        self.__kek_hash = kek_hash

    def __eq__(self, other: object) -> bool:
        """Return true if two objects are equal."""
        if not isinstance(other, KEKHash):
            return False
        return self.__kek_hash == other.__kek_hash

    def __ne__(self, other: object) -> bool:
        """Return true if two objects are not equal."""
        return not (self == other)

    def __hash__(self) -> int:
        """Get the hashed version of the object."""
        return hash((self.__kek_hash,))

    @staticmethod
    def from_kek(kek: 'LocalKeyEncryptionKey') -> 'KEKHash':
        """Create new KEKHash from the KeyEncryptionKey object."""
        return KEKHash(blake2b(kek.raw_bytes))

    @property
    def kek_bytes(self) -> bytes:
        """Return the fingerprint bytes."""
        return self.__kek_hash
