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


class WindowName:
    """WindowName is a type-safe immutable wrapper for window names."""

    def __init__(self, window_name: str) -> None:
        """Create new Nick Object"""
        self.__window_name = window_name

    def __str__(self) -> str:
        """Get the print-friendly version of the Nick Object."""
        return self.__window_name

    def __eq__(self, other: Any) -> bool:
        """Return True if two GroupName objects are equal."""
        if not isinstance(other, WindowName):
            return False
        return self.__window_name == other.value

    def __ne__(self, other: Any) -> bool:
        """Return True if two GroupName objects are not equal."""
        return not (self == other)

    @property
    def value(self) -> str:
        """Get the nickname for the Nick Object."""
        return self.__window_name
