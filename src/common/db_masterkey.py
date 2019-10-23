#!/usr/bin/env python3.7
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

import math
import multiprocessing
import os.path
import random
import time

from typing import List, Tuple

from src.common.crypto     import argon2_kdf, blake2b, csprng
from src.common.encoding   import bytes_to_int, int_to_bytes
from src.common.exceptions import CriticalError, graceful_exit
from src.common.input      import pwd_prompt
from src.common.misc       import ensure_dir, separate_headers
from src.common.output     import clear_screen, m_print, phase, print_on_previous_line
from src.common.word_list  import eff_wordlist
from src.common.statics    import (ARGON2_MIN_MEMORY_COST, ARGON2_MIN_PARALLELISM, ARGON2_MIN_TIME_COST,
                                   ARGON2_SALT_LENGTH, BLAKE2_DIGEST_LENGTH, DIR_USER_DATA, DONE,
                                   ENCODED_INTEGER_LENGTH, GENERATE, MASTERKEY_DB_SIZE, MAX_KEY_DERIVATION_TIME,
                                   MIN_KEY_DERIVATION_TIME, PASSWORD_MIN_BIT_STRENGTH, RESET)


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

    @staticmethod
    def timed_key_derivation(password:    str,
                             salt:        bytes,
                             time_cost:   int,
                             memory_cost: int,
                             parallelism: int
                             ) -> Tuple[bytes, float]:
        """Derive key and measure its derivation time."""
        time_start = time.monotonic()
        master_key = argon2_kdf(password, salt, time_cost, memory_cost, parallelism)
        kd_time    = time.monotonic() - time_start

        return master_key, kd_time

    @staticmethod
    def get_available_memory() -> int:
        """Return the amount of available memory in the system."""
        fields    = os.popen("cat /proc/meminfo").read().splitlines()
        field     = [f for f in fields if f.startswith('MemAvailable')][0]
        mem_avail = int(field.split()[1])

        return mem_avail

    @staticmethod
    def generate_master_password() -> Tuple[int, str]:
        """Generate a strong password using the EFF wordlist."""
        word_space = len(eff_wordlist)
        sys_rand   = random.SystemRandom()

        pwd_bit_strength = 0.0
        password_words   = []  # type: List[str]

        while pwd_bit_strength < PASSWORD_MIN_BIT_STRENGTH:
            password_words.append(sys_rand.choice(eff_wordlist))
            pwd_bit_strength = math.log2(word_space ** len(password_words))

        password = ' '.join(password_words)

        return int(pwd_bit_strength), password

    def new_master_key(self) -> bytes:
        """Create a new master key from password and salt.

        The generated master key depends on a 256-bit salt and the
        password entered by the user. Additional computational strength
        is added by the slow hash function (Argon2id). The more cores and
        the faster each core is, and the more memory the system has, the
        more secure TFC data is under the same password.

        This method automatically tweaks the Argon2 time and memory cost
        parameters according to best practices as determined in

            https://tools.ietf.org/html/draft-irtf-cfrg-argon2-04#section-4

        1) For Argon2 type (y), Argon2id was selected because the
           adversary might be able to run arbitrary code on Destination
           Computer and thus perform a side-channel attack against the
           function.

        2) The maximum number of threads (h) is determined by the number
           available in the system. However, during local testing this
           number is reduced to half to allow simultaneous login to
           Transmitter and Receiver Program.

        3) The maximum amount of memory (m) is what the system has to
           offer. For hard-drive encryption purposes, the recommendation
           is 6GiB. TFC will use that amount (or even more) if available.
           However, on less powerful systems, it will settle for less.

        4) For key derivation time (x), the value is set to at least 3
           seconds, with the maximum being 4 seconds. The minimum value
           is the same as the recommendation for hard-drive encryption.

        5) The salt length is set to 256-bits which is double the
           recommended length. The salt size ensures that even in a
           group of 4.8*10^29 users, the probability that two users
           share the same salt is just 10^(-18).*
            * https://en.wikipedia.org/wiki/Birthday_attack

           The salt does not need additional protection as the security it
           provides depends on the salt space in relation to the number of
           attacked targets (i.e. if two or more physically compromised
           systems happen to share the same salt, the attacker can speed up
           the attack against those systems with time-memory-trade-off
           attack).

        6) The tag length isn't utilized. The result of the key derivation is
           the master encryption key itself, which is set to 32 bytes for
           use in XChaCha20-Poly1305.

        7) Memory wiping feature is not provided.

        To recognize the password is correct, the BLAKE2b hash of the master
        key is stored together with key derivation parameters into the
        login database.
            The preimage resistance of BLAKE2b prevents derivation of master
        key from the stored hash, and Argon2id ensures brute force and
        dictionary attacks against the master password are painfully
        slow even with GPUs/ASICs/FPGAs, as long as the password is
        sufficiently strong.
        """
        password  = MasterKey.new_password()
        salt      = csprng(ARGON2_SALT_LENGTH)
        time_cost = ARGON2_MIN_TIME_COST

        # Determine the amount of memory used from the amount of free RAM in the system.
        memory_cost = self.get_available_memory()
        if self.local_test:
            memory_cost //= 2

        # Determine the amount of threads to use
        parallelism = multiprocessing.cpu_count()
        if self.local_test:
            parallelism = max(ARGON2_MIN_PARALLELISM, parallelism // 2)

        phase("Deriving master key", head=2)

        # Initial key derivation
        master_key, kd_time = self.timed_key_derivation(password, salt, time_cost, memory_cost, parallelism)

        # If derivation was too fast, increase time_cost
        while kd_time < MIN_KEY_DERIVATION_TIME:
            time_cost += 1
            master_key, kd_time = self.timed_key_derivation(password, salt, time_cost, memory_cost, parallelism)

        # At this point time_cost may have value of 1 or it may have increased to e.g. 3, which might make it take
        # longer than MAX_KEY_DERIVATION_TIME. If that's the case, it makes no sense to lower it back to 2 because even
        # with all memory, time_cost=2 will still be too fast. We therefore accept the time_cost whatever it is.

        # If the key derivation time is too long, we do a binary search on the amount
        # of memory to use until we hit the desired key derivation time range.
        middle = None

        if kd_time > MAX_KEY_DERIVATION_TIME:

            lower_bound = ARGON2_MIN_MEMORY_COST
            upper_bound = memory_cost

            while kd_time < MIN_KEY_DERIVATION_TIME or kd_time > MAX_KEY_DERIVATION_TIME:

                middle              = (lower_bound + upper_bound) // 2
                master_key, kd_time = self.timed_key_derivation(password, salt, time_cost, middle, parallelism)

                # The search might fail e.g. if external CPU load causes delay in key derivation, which causes the
                # search to continue into wrong branch. In such a situation the search is restarted. The binary search
                # is problematic with tight key derivation time target ranges, so if the search keeps restarting,
                # increasing MAX_KEY_DERIVATION_TIME (and thus expanding the range) will help finding suitable
                # memory_cost value faster. Increasing MAX_KEY_DERIVATION_TIME slightly affects security (positively)
                # and user experience (negatively).
                if middle == lower_bound or middle == upper_bound:
                    lower_bound = ARGON2_MIN_MEMORY_COST
                    upper_bound = memory_cost
                    continue

                if kd_time < MIN_KEY_DERIVATION_TIME:
                    lower_bound = middle

                elif kd_time > MAX_KEY_DERIVATION_TIME:
                    upper_bound = middle

        memory_cost = middle if middle is not None else memory_cost

        # Store values to database
        ensure_dir(DIR_USER_DATA)
        with open(self.file_name, 'wb+') as f:
            f.write(salt
                    + blake2b(master_key)
                    + int_to_bytes(time_cost)
                    + int_to_bytes(memory_cost)
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

        salt, key_hash, time_bytes, memory_bytes, parallelism_bytes \
            = separate_headers(data, [ARGON2_SALT_LENGTH, BLAKE2_DIGEST_LENGTH,
                                      ENCODED_INTEGER_LENGTH, ENCODED_INTEGER_LENGTH])

        time_cost   = bytes_to_int(time_bytes)
        memory_cost = bytes_to_int(memory_bytes)
        parallelism = bytes_to_int(parallelism_bytes)

        while True:
            password = MasterKey.get_password()
            phase("Deriving master key", head=2, offset=len("Password correct"))
            purp_key = argon2_kdf(password, salt, time_cost, memory_cost, parallelism)

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

        if password_1 == GENERATE:
            pwd_bit_strength, password_1 = MasterKey.generate_master_password()

            m_print([f"Generated a {pwd_bit_strength}-bit password:",
                     '', password_1, '',
                     "Write down this password and dispose of the copy once you remember it.",
                     "Press <Enter> to continue."], manual_proceed=True, box=True, head=1, tail=1)
            os.system(RESET)

            password_2 = password_1
        else:
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
