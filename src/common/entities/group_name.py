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


class GroupName:
    """GroupName is a type-safe immutable wrapper for group names."""

    def __init__(self, group_name: str) -> None:
        """Create new GroupName Object"""
        self.__group_name = group_name

    def __str__(self) -> str:
        """Get the print-friendly version of the GroupName Object."""
        return self.__group_name

    def __eq__(self, other: Any) -> bool:
        """Return True if two GroupName objects are equal."""
        if not isinstance(other, GroupName):
            return False
        return self.__group_name == other.value

    def __ne__(self, other: Any) -> bool:
        """Return True if two GroupName objects are not equal."""
        return not (self == other)

    @property
    def value(self) -> str:
        """Get the group name via property."""
        return self.__group_name
