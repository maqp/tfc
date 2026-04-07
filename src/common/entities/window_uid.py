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

from typing import TYPE_CHECKING, Any

from src.common.statics import WinSelectHeader

if TYPE_CHECKING:
    from src.common.entities.contact import Contact
    from src.common.entities.group import Group


class WindowUID:
    """WindowUID is a type-safe immutable wrapper for unique window identifiers."""

    def __init__(self, window_uid_bytes: bytes) -> None:
        """Create new WindowUID Object"""
        self.__window_uid_bytes = window_uid_bytes

    def __str__(self) -> str:
        """Get the print-friendly version of the WindowUID Object."""
        return self.__window_uid_bytes.hex()

    def __eq__(self, other: Any) -> bool:
        """Return True if two WindowUID objects are equal."""
        if not isinstance(other, WindowUID):
            return False
        return self.__window_uid_bytes == other.raw_bytes

    def __ne__(self, other: Any) -> bool:
        """Return True if two WindowUID objects are not equal."""
        return not (self == other)

    @property
    def raw_bytes(self) -> bytes:
        """Get the bytes for the WindowUID object."""
        return self.__window_uid_bytes

    @staticmethod
    def system_messages() -> 'WindowUID':
        """Return the WindowUID object for system messages."""
        return WindowUID(WinSelectHeader.SYSTEM_MESSAGES)

    @staticmethod
    def file_transfers() -> 'WindowUID':
        """Return the WindowUID object for file transfers."""
        return WindowUID(WinSelectHeader.FILE_TRANSFERS)

    @staticmethod
    def for_group(group: 'Group') -> 'WindowUID':
        """Return the WindowUID object for a specific group."""
        return WindowUID(group.group_id.raw_bytes)

    @staticmethod
    def for_contact(contact: 'Contact') -> 'WindowUID':
        """Return the WindowUID object for a contact."""
        return WindowUID(contact.onion_pub_key.public_bytes_raw)
