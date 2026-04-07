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

from typing import Self

from src.common.statics import CryptoVarLength


class Fingerprint:
    """The public key fingerprint."""

    def __init__(self, fingerprint_bytes: bytes) -> None:
        """Create new Fingerprint object."""
        self.__fingerprint_bytes = fingerprint_bytes

    def to_bytes(self) -> bytes:
        """Return the fingerprint bytes."""
        return self.__fingerprint_bytes

    @classmethod
    def generate_zero_fp(cls) -> Self:
        """Generate empty fingerprint.

        This is used on for PSKs and for Receiver Program
        where displayed fingerprints can not be trusted.
        """
        return cls(bytes(CryptoVarLength.FINGERPRINT))


class FingerprintUser(Fingerprint):
    """The fingerprint read by the user."""
    pass


class FingerprintContact(Fingerprint):
    """The fingerprint read by the contact."""
    pass
