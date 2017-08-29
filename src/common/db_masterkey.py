#!/usr/bin/env python3.6
# -*- coding: utf-8 -*-

"""
Copyright (C) 2013-2017  Markus Ottela

This file is part of TFC.

TFC is free software: you can redistribute it and/or modify it under the terms
of the GNU General Public License as published by the Free Software Foundation,
either version 3 of the License, or (at your option) any later version.

TFC is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with TFC. If not, see <http://www.gnu.org/licenses/>.
"""

import os.path
import time

from src.common.crypto     import argon2_kdf, csprng, hash_chain
from src.common.encoding   import int_to_bytes, bytes_to_int
from src.common.exceptions import graceful_exit
from src.common.input      import pwd_prompt
from src.common.misc       import ensure_dir
from src.common.output     import c_print, clear_screen, phase, print_on_previous_line
from src.common.statics    import *


class MasterKey(object):
    """\
    MasterKey object manages the 32-byte
    master key and methods related to it.
    """

    def __init__(self, operation: str, local_test: bool) -> None:
        """Create a new MasterKey object."""
        self.master_key = None  # type: bytes
        self.file_name  = f'{DIR_USER_DATA}{operation}_login_data'
        self.local_test = local_test

        try:
            if os.path.isfile(self.file_name):
                self.load_master_key()
            else:
                self.new_master_key()
        except KeyboardInterrupt:
            graceful_exit()

    def new_master_key(self) -> None:
        """Create a new master key from salt and password."""
        password = MasterKey.new_password()
        salt     = csprng()
        rounds   = ARGON2_ROUNDS
        memory   = ARGON2_MIN_MEMORY

        phase("Deriving master key", head=2)
        while True:
            time_start = time.monotonic()
            master_key, parallellism = argon2_kdf(password, salt, rounds, memory=memory, local_test=self.local_test)
            time_final = time.monotonic() - time_start

            if time_final > 3.0:
                self.master_key = master_key
                ensure_dir(f'{DIR_USER_DATA}/')
                with open(self.file_name, 'wb+') as f:
                    f.write(salt
                            + hash_chain(self.master_key)
                            + int_to_bytes(rounds)
                            + int_to_bytes(memory)
                            + int_to_bytes(parallellism))
                phase(DONE)
                break
            else:
                memory *= 2

    def load_master_key(self) -> None:
        """Derive master key from password and salt."""
        with open(self.file_name, 'rb') as f:
            data = f.read()
        salt        = data[0:32]
        key_hash    = data[32:64]
        rounds      = bytes_to_int(data[64:72])
        memory      = bytes_to_int(data[72:80])
        parallelism = bytes_to_int(data[80:88])

        while True:
            password = MasterKey.get_password()
            phase("Deriving master key", head=2, offset=16)
            purp_key, _ = argon2_kdf(password, salt, rounds, memory, parallelism)

            if hash_chain(purp_key) == key_hash:
                self.master_key = purp_key
                phase("Password correct", done=True)
                clear_screen(delay=0.5)
                break
            else:
                phase("Invalid password", done=True)
                print_on_previous_line(reps=5, delay=1)

    @classmethod
    def new_password(cls, purpose: str = "master password") -> str:
        """Prompt user to enter and confirm a new password."""
        password_1 = pwd_prompt(f"Enter a new {purpose}: ")
        password_2 = pwd_prompt(f"Confirm the {purpose}: ", second=True)

        if password_1 == password_2:
            return password_1
        else:
            c_print("Error: Passwords did not match. Try again.", head=1, tail=1)
            time.sleep(1)
            print_on_previous_line(reps=7)
            return cls.new_password(purpose)

    @classmethod
    def get_password(cls, purpose: str = "master password") -> str:
        """Prompt user to enter a password."""
        return pwd_prompt(f"Enter {purpose}: ")
