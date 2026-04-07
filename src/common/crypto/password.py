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

import math
import random

from typing import Optional as O

from src.common.exceptions import CriticalError
from src.common.statics import Argon2Literals
from src.database.word_list import eff_wordlist


class Password:
    """Type-safe immutable object for passwords."""

    def __init__(self,
                 password     : str,
                 bit_strength : O[int] = None
                 ) -> None:
        """Create new Password object."""
        self.__password     = password
        self.__bit_strength = bit_strength

    @property
    def password(self) -> str:
        """Get the password."""
        return self.__password

    def to_bytes(self) -> bytes:
        """Return the encoded password."""
        return self.__password.encode()

    @property
    def bit_strength(self) -> int:
        """Get the password strength in bits."""
        if self.__bit_strength is None:
            raise CriticalError('Password was not generated.')

        return self.__bit_strength

    @classmethod
    def generate(cls) -> 'Password':
        """Generate a strong password using the EFF wordlist.

        Note: random.SystemRandom is GETRANDOM equivalent.
              rng.choice does uniform sampling.
        """
        word_space = len(eff_wordlist)
        pwd_length = math.ceil(math.log(2 ** Argon2Literals.PASSWORD_MIN_BIT_STRENGTH.value, word_space))

        pwd_bit_strength = math.floor(math.log2(word_space ** pwd_length))

        rng      = random.SystemRandom()
        password = ' '.join(rng.choice(eff_wordlist) for _ in range(pwd_length))

        return cls(password, pwd_bit_strength)
