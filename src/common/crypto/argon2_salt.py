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

from typing import Optional as O

from src.common.exceptions import CriticalError
from src.common.crypto.algorithms.csprng import csprng
from src.common.statics import KeyLength
from src.common.utils.validators import validate_bytes


class Argon2Salt:
    """The Argon2 salt object."""

    def __init__(self, salt_bytes: O[bytes]=None) -> None:
        """Create new Argon2Salt object."""
        if salt_bytes is None:
            salt_bytes = csprng(KeyLength.ARGON2_SALT)
        else:
            validate_bytes(salt_bytes, is_length=KeyLength.ARGON2_SALT)

        self.__salt_bytes = salt_bytes

    @property
    def salt_bytes(self) -> bytes:
        """Return the salt bytes."""
        if self.__salt_bytes is None:
            raise CriticalError('Salt bytes not set.')

        return self.__salt_bytes
