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

from typing import Any, Optional as O

from src.common.statics import RxCommand, FieldLength
from src.common.utils.validators import validate_bytes, validate_type


class SerializedCommand:
    """SerializedCommand is a type-safe immutable wrapper for serialized commands."""

    def __init__(self, header: 'RxCommand', command_bytes: O[bytes]=None) -> None:
        """Create new SerializedCommand Object"""
        validate_type('header', header, RxCommand)
        validate_bytes(header.value, is_length=FieldLength.RELAY_COMMAND_HEADER)

        self.__header        = header
        self.__command_bytes = command_bytes

    def __eq__(self, other: Any) -> bool:
        """Return True if two SerializedCommand objects are equal."""
        if not isinstance(other, SerializedCommand):
            return False
        return self.raw_bytes == other.raw_bytes

    def __ne__(self, other: Any) -> bool:
        """Return True if two SerializedCommand objects are not equal."""
        return not (self == other)

    @property
    def raw_bytes(self) -> bytes:
        """Get the SerializedCommand Object bytes."""
        raw_bytes = self.__header.value

        if self.__command_bytes is not None:
            raw_bytes += self.__command_bytes

        return raw_bytes

    @property
    def command_bytes(self) -> bytes:
        """Get the serialized command payload without the command header."""
        return self.__command_bytes if self.__command_bytes is not None else b''
