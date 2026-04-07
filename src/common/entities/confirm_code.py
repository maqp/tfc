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

import os

from typing import Any, Optional as O

from src.common.crypto.algorithms.blake2b import blake2b
from src.common.statics import FieldLength
from src.common.utils.validators import validate_onion_addr


class ConfirmationCode:
    """Confirmation code.

    This class provides type-safety,immutability, and encoding
    """

    def __init__(self, conf_code_bytes: O[bytes]) -> None:
        """Create new OnionServicePrivateKey object from bytes."""
        self.__conf_code_bytes = conf_code_bytes

    def __str__(self) -> str:
        """Printable representation of OnionServicePrivateKey."""
        if self.__conf_code_bytes is None:
            return ''
        return self.__conf_code_bytes.hex()

    def __eq__(self, other: Any) -> bool:
        """Return True if other ConfirmationCode is equal to this object."""
        if not isinstance(other, ConfirmationCode):
            return False
        return self.__conf_code_bytes == other.__conf_code_bytes

    def __ne__(self, other: Any) -> bool:
        """Return True if other ConfirmationCode is not equal to this object."""
        return not (self == other)

    @property
    def is_resend_request(self) -> bool:
        """Return True if this ConfirmationCode is a resend request."""
        return self.__conf_code_bytes is None

    @property
    def hr_code(self) -> str:
        """Return the human readable representation of this ConfirmationCode."""
        return str(self)

    @property
    def raw_bytes(self) -> bytes:
        """Export the confirmation code as bytes."""
        if self.__conf_code_bytes is None:
            raise ValueError('ConfirmationCode is not initialized.')
        return self.__conf_code_bytes

    @staticmethod
    def generate() -> 'ConfirmationCode':
        """Generate a new ConfirmationCode object."""
        return ConfirmationCode(os.getrandom(FieldLength.CONFIRM_CODE.value))

    @staticmethod
    def from_onion_address(onion_address: str) -> 'ConfirmationCode':
        """Generate a new ConfirmationCode object from a public key."""
        validate_onion_addr(onion_address)
        return ConfirmationCode(blake2b(onion_address.encode(), digest_size=FieldLength.CONFIRM_CODE))

    @staticmethod
    def from_hex(hex_code: str) -> 'ConfirmationCode':
        """Create a new OnionServicePrivateKey object from hex string."""
        normalized = ''.join(hex_code.split())

        if normalized == '':
            return ConfirmationCode(conf_code_bytes=None)

        conf_code_bytes = bytes.fromhex(normalized)

        if len(conf_code_bytes) != FieldLength.CONFIRM_CODE.value:
            raise ValueError('Invalid confirmation code length.')

        return ConfirmationCode(conf_code_bytes)
