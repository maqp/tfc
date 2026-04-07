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

from typing import Any

from src.common.entities.window_uid import WindowUID
from src.common.exceptions import CriticalError
from src.common.statics import FieldLength
from src.common.utils.encoding import b58encode, b58decode
from src.common.utils.validators import validate_bytes


class GroupID:
    """GroupID is a type-safe immutable wrapper for group IDs.

    Group IDs are short random identifiers for groups
    """

    def __init__(self, group_id: bytes) -> None:
        """Create new GroupID Object"""
        validate_bytes(group_id, is_length=FieldLength.GROUP_ID.value)

        self.__group_id = group_id

    def __str__(self) -> str:
        """Get the print-friendly version of the GroupID Object."""
        return b58encode(self.__group_id)

    def __eq__(self, other: Any) -> bool:
        """Return True if two GroupID objects are equal."""
        if not isinstance(other, GroupID):
            return False
        return self.__group_id == other.raw_bytes

    def __ne__(self, other: Any) -> bool:
        """Return True if two GroupID objects are not equal."""
        return not (self == other)

    def __hash__(self) -> int:
        """Hash by raw group-id bytes to allow dict/set usage."""
        return hash(self.__group_id)

    @staticmethod
    def from_string(group_id_str: str) -> 'GroupID':
        """Generate GroupID from string representation of ID."""
        return GroupID(b58decode(group_id_str))

    @property
    def hr_value(self) -> str:
        """Get human readable version of the group ID."""
        return b58encode(self.__group_id)

    @property
    def raw_bytes(self) -> bytes:
        """Get the group name via property."""
        if self.__group_id is None:
            raise CriticalError('GroupID is not set.')

        return self.__group_id

    @property
    def win_uid(self) -> WindowUID:
        """Get the Window UID of the group ID."""
        return WindowUID(self.__group_id)
