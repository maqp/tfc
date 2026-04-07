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

from src.common.exceptions import SoftError, ValidationError
from src.common.statics import HashRatchet, EncodingLiteral, FieldLength
from src.common.utils.encoding import bytes_to_int, int_to_bytes
from src.common.utils.validators import validate_int, validate_bytes


class RatchetState:

    """RatchetState is a type-safe integer that can only increment.

    It is used by the forward-secret ratchet keys.
    """

    def __init__(self, value: int = HashRatchet.INITIAL_RATCHET_VALUE) -> None:
        """Create a new RatchetState object."""
        self.validate_value(value)
        self.__value = value

    @staticmethod
    def validate_value(value: int) -> None:
        """Validate the RatchetState value."""
        try:
            validate_int(value,
                         key       = 'ratchet state',
                         min_value = HashRatchet.INITIAL_RATCHET_VALUE,
                         max_value = EncodingLiteral.MAX_INT)
        except ValidationError as e:
            raise SoftError(e.args[0])

    @staticmethod
    def from_bytes(ratchet_state_bytes: bytes) -> 'RatchetState':
        """Create a new RatchetState object from bytes."""
        validate_bytes(ratchet_state_bytes, is_length=FieldLength.ENCODED_INTEGER.value)
        return RatchetState(bytes_to_int(ratchet_state_bytes))

    @property
    def value(self) -> int:
        """Return the current RatchetState value."""
        return self.__value

    def serialize(self) -> bytes:
        """Return the current RatchetState value."""
        return int_to_bytes(self.__value)

    def increment(self) -> None:
        """Increment the RatchetState by 1."""
        self.__value += 1
