#!/usr/bin/env python3.6
# -*- coding: utf-8 -*-

"""
TFC - Onion-routed, endpoint secure messaging system
Copyright (C) 2013-2019  Markus Ottela

This file is part of TFC.

TFC is free software: you can redistribute it and/or modify it under the terms
of the GNU General Public License as published by the Free Software Foundation,
either version 3 of the License, or (at your option) any later version.

TFC is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with TFC. If not, see <https://www.gnu.org/licenses/>.
"""

import multiprocessing
import os.path
import time

from src.common.crypto     import argon2_kdf, blake2b, csprng
from src.common.encoding   import bytes_to_int, int_to_bytes
from src.common.exceptions import CriticalError, graceful_exit
from src.common.input      import pwd_prompt
from src.common.misc       import ensure_dir, separate_headers
from src.common.output     import clear_screen, m_print, phase, print_on_previous_line
from src.common.statics    import *


class MasterKey(object):
    """\
    MasterKey object manages the 32-byte master key and methods related
    to it. Master key is the key that protects all data written on disk.
    """

    def __init__(self, operation: str, local_test: bool) -> None:
        """Create a new MasterKey object."""
        self.file_name  = f'{DIR_USER_DATA}{operation}_login_data'
        self.local_test = local_test

        ensure_dir(DIR_USER_DATA)
        try:
            if os.path.isfile(self.file_name):
                self.master_key = self.load_master_key()
            else:
                self.master_key = self.new_master_key()
        except (EOFError, KeyboardInterrupt):
            graceful_exit()

    def new_master_key(self) -> bytes:
        """Create a new master key from password and salt.

        The generated master key depends on a 256-bit salt and the
        password entered by the user. Additional computational strength
        is added by the slow hash function (Argon2d). This method
        automatically tweaks the Argon2 memory parameter so that key
        derivation on used hardware takes at least three seconds. The
        more cores and the faster each core is, the more security a
        given password provides.

        The preimage resistance of BLAKE2b prevents derivation of master
        key from the stored hash, and Argon2d ensures brute force and
        dictionary attacks against the master password are painfully
        slow even with GPUs/ASICs/FPGAs, as long as the password is
        sufficiently strong.

        The salt does not need additional protection as the security it
        provides depends on the salt space in relation to the number of
        attacked targets (i.e. if two or more physically compromised
        systems happen to share the same salt, the attacker can speed up
        the attack against those systems with time-memory-trade-off
        attack).

        A 256-bit salt ensures that even in a group of 4.8*10^29 users,
        the probability that two users share the same salt is just
        10^(-18).*
            * https://en.wikipedia.org/wiki/Birthday_attack
        """
        password = MasterKey.new_password()
        salt     = csprng(ARGON2_SALT_LENGTH)
        memory   = ARGON2_MIN_MEMORY

        parallelism = multiprocessing.cpu_count()
        if self.local_test:
            parallelism = max(1, parallelism // 2)

        phase("Deriving master key", head=2)
        while True:
            time_start = time.monotonic()
            master_key = argon2_kdf(password, salt, ARGON2_ROUNDS, memory, parallelism)
            kd_time    = time.monotonic() - time_start

            if kd_time < MIN_KEY_DERIVATION_TIME:
                memory *= 2
            else:
                ensure_dir(DIR_USER_DATA)
                with open(self.file_name, 'wb+') as f:
                    f.write(salt
                            + blake2b(master_key)
                            + int_to_bytes(memory)
                            + int_to_bytes(parallelism))
                phase(DONE)
                return master_key

    def load_master_key(self) -> bytes:
        """Derive the master key from password and salt.

        Load the salt, hash, and key derivation settings from the login
        database. Derive the purported master key from the salt and
        entered password. If the BLAKE2b hash of derived master key
        matches the hash in the login database, accept the derived
        master key.
        """
        with open(self.file_name, 'rb') as f:
            data = f.read()

        if len(data) != MASTERKEY_DB_SIZE:
            raise CriticalError(f"Invalid {self.file_name} database size.")

        salt, key_hash, memory_bytes, parallelism_bytes \
            = separate_headers(data, [ARGON2_SALT_LENGTH, BLAKE2_DIGEST_LENGTH, ENCODED_INTEGER_LENGTH])

        memory      = bytes_to_int(memory_bytes)
        parallelism = bytes_to_int(parallelism_bytes)

        while True:
            password = MasterKey.get_password()
            phase("Deriving master key", head=2, offset=len("Password correct"))
            purp_key = argon2_kdf(password, salt, ARGON2_ROUNDS, memory, parallelism)

            if blake2b(purp_key) == key_hash:
                phase("Password correct", done=True, delay=1)
                clear_screen()
                return purp_key
            else:
                phase("Invalid password", done=True, delay=1)
                print_on_previous_line(reps=5)

    @classmethod
    def new_password(cls, purpose: str = "master password") -> str:
        """Prompt the user to enter and confirm a new password."""
        password_1 = pwd_prompt(f"Enter a new {purpose}: ")
        password_2 = pwd_prompt(f"Confirm the {purpose}: ", repeat=True)

        if password_1 == password_2:
            return password_1
        else:
            m_print("Error: Passwords did not match. Try again.", head=1, tail=1)
            print_on_previous_line(delay=1, reps=7)
            return cls.new_password(purpose)

    @classmethod
    def get_password(cls, purpose: str = "master password") -> str:
        """Prompt the user to enter a password."""
        return pwd_prompt(f"Enter {purpose}: ")
