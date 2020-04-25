#!/usr/bin/env python3.7
# -*- coding: utf-8 -*-

"""
TFC - Onion-routed, endpoint secure messaging system
Copyright (C) 2013-2020  Markus Ottela

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

from typing import List, Optional, Tuple

from src.common.crypto     import argon2_kdf, blake2b, csprng
from src.common.database   import TFCUnencryptedDatabase
from src.common.encoding   import bytes_to_int, int_to_bytes
from src.common.exceptions import CriticalError, graceful_exit, SoftError
from src.common.input      import pwd_prompt
from src.common.misc       import ensure_dir, reset_terminal, separate_headers
from src.common.output     import clear_screen, m_print, phase, print_on_previous_line
from src.common.word_list  import eff_wordlist
from src.common.statics    import (ARGON2_MIN_MEMORY_COST, ARGON2_MIN_PARALLELISM, ARGON2_MIN_TIME_COST,
                                   ARGON2_SALT_LENGTH, BLAKE2_DIGEST_LENGTH, DIR_USER_DATA, DONE,
                                   ENCODED_INTEGER_LENGTH, GENERATE, MASTERKEY_DB_SIZE, MAX_KEY_DERIVATION_TIME,
                                   MIN_KEY_DERIVATION_TIME, PASSWORD_MIN_BIT_STRENGTH)


class MasterKey(object):
    """\
    MasterKey object manages the 32-byte master key and methods related
    to it. Master key is the key that protects all data written on disk.
    """

    def __init__(self, operation: str, local_test: bool) -> None:
        """Create a new MasterKey object."""
        self.operation     = operation
        self.file_name     = f'{DIR_USER_DATA}{operation}_login_data'
        self.database      = TFCUnencryptedDatabase(self.file_name)
        self.local_test    = local_test
        self.database_data = None  # type: Optional[bytes]

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

    def get_available_memory(self) -> int:
        """Return the amount of available memory in the system."""
        fields = os.popen("/bin/cat /proc/meminfo").read().splitlines()
        field  = [f for f in fields if f.startswith("MemAvailable")][0]
        mem_avail = int(field.split()[1])

        if self.local_test:
            mem_avail //= 2

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

    def new_master_key(self, replace: bool = True) -> bytes:
        """Create a new master key from password and salt.

        The generated master key depends on a 256-bit salt and the
        password entered by the user. Additional computational strength
        is added by the slow hash function (Argon2id). The more cores
        and the faster each core is, and the more memory the system has,
        the more secure TFC data is under the same password.

        This method automatically tweaks the Argon2 time and memory cost
        parameters according to best practices as determined in

            https://tools.ietf.org/html/draft-irtf-cfrg-argon2-09#section-4

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

           The salt does not need additional protection as the security
           it provides depends on the salt space in relation to the
           number of attacked targets (i.e. if two or more physically
           compromised systems happen to share the same salt, the
           attacker can speed up the attack against those systems with
           time-memory-trade-off attack).

        6) The tag length isn't utilized. The result of the key
           derivation is the master encryption key itself, which is set
           to 32 bytes for use in XChaCha20-Poly1305.

        7) Memory wiping feature is not provided.

        To recognize the password is correct, the BLAKE2b hash of the
        master key is stored together with key derivation parameters
        into the login database.
            The preimage resistance of BLAKE2b prevents derivation of
        master key from the stored hash, and Argon2id ensures brute
        force and dictionary attacks against the master password are
        painfully slow even with GPUs/ASICs/FPGAs, as long as the
        password is sufficiently strong.
        """
        password = MasterKey.new_password()
        salt     = csprng(ARGON2_SALT_LENGTH)

        # Determine the amount of memory used from the amount of free RAM in the system.
        memory_cost = self.get_available_memory()

        # Determine the number of threads to use
        parallelism = multiprocessing.cpu_count()
        if self.local_test:
            parallelism = max(ARGON2_MIN_PARALLELISM, parallelism // 2)

        # Determine time cost
        time_cost, kd_time, master_key = self.determine_time_cost(password, salt, memory_cost, parallelism)

        # Determine memory cost
        if kd_time > MAX_KEY_DERIVATION_TIME:
            memory_cost, master_key = self.determine_memory_cost(password, salt, time_cost, memory_cost, parallelism)

        # Store values to database
        database_data = (salt
                         + blake2b(master_key)
                         + int_to_bytes(time_cost)
                         + int_to_bytes(memory_cost)
                         + int_to_bytes(parallelism))

        if replace:
            self.database.store_unencrypted_database(database_data)
        else:
            # When replacing the master key, the new master key needs to be generated before
            # databases are encrypted. However, storing the new master key shouldn't be done
            # before all new databases have been successfully written. We therefore just cache
            # the database data.
            self.database_data = database_data

        print_on_previous_line()
        phase("Deriving master key")
        phase(DONE, delay=1)

        return master_key

    def determine_time_cost(self,
                            password:    str,
                            salt:        bytes,
                            memory_cost: int,
                            parallelism: int
                            ) -> Tuple[int, float, bytes]:
        """Find suitable time_cost value for Argon2id.

        There are two acceptable time_cost values.

        1. A time_cost value that together with all available memory
           sets the key derivation time between MIN_KEY_DERIVATION_TIME
           and MAX_KEY_DERIVATION_TIME. If during the search we find
           such suitable time_cost value, we accept it as such.

        2. In a situation where no time_cost value is suitable alone,
           there will exist some time_cost value `t` that makes key
           derivation too fast, and another time_cost value `t+1` that
           makes key derivation too slow. In this case we are interested
           in the latter value, as unlike `t`, the value `t+1` can be
           fine-tuned to suitable key derivation time range by adjusting
           the memory_cost parameter.

        As time_cost has no upper limit, and as the amount of available
        memory has tremendous effect on how long one round takes, it's
        difficult to determine the upper bound for a time_cost binary
        search. We therefore start with a single round, and by
        benchmarking it, estimate how many rounds are needed to reach
        the target zone. After every try, we update our time_cost
        candidate based on new average time per round estimate, a value
        that gets more accurate as the search progresses. If this
        method isn't able to suggest a value larger than 1, we increase
        time_cost by 1 anyway to prevent an Alderson loop.

        Every time the time_cost value is increased, we update the lower
        bound to narrow the search space of the binary search we can
        switch to immediately, once the MAX_KEY_DERIVATION_TIME is
        exceeded (i.e. once an upper bound is found). At that point, the
        time_cost `t+1` can be found in log(n) time.
        """
        lower_bound = ARGON2_MIN_TIME_COST  # type: int
        upper_bound = None                  # type: Optional[int]
        time_cost   = lower_bound

        print(2*'\n')

        while True:
            print_on_previous_line()
            phase(f"Trying time cost {time_cost}")
            master_key, kd_time = self.timed_key_derivation(password, salt, time_cost, memory_cost, parallelism)
            phase(f"{kd_time:.1f}s", done=True)

            # Sentinel that checks if the binary search has ended, and that restarts
            # the search if kd_time repeats. This prevents an Alderson loop.
            if upper_bound is not None and time_cost in [lower_bound, upper_bound]:  # pragma: no cover
                lower_bound = ARGON2_MIN_TIME_COST
                upper_bound = None
                continue

            if MIN_KEY_DERIVATION_TIME <= kd_time <= MAX_KEY_DERIVATION_TIME:
                break

            if kd_time < MIN_KEY_DERIVATION_TIME:
                lower_bound = time_cost

                if upper_bound is None:
                    avg_time_per_round  = kd_time / time_cost
                    time_cost_candidate = math.floor(MAX_KEY_DERIVATION_TIME / avg_time_per_round)
                    time_cost           = max(time_cost+1, time_cost_candidate)

                else:
                    if time_cost + 1 == upper_bound:
                        time_cost += 1
                        break

                    time_cost = math.floor((lower_bound + upper_bound) / 2)

            elif kd_time > MAX_KEY_DERIVATION_TIME:
                upper_bound = time_cost

                # Sentinel: If even a single round takes too long, it's the `t+1` we're looking for.
                if time_cost == 1:
                    break

                # Sentinel: If the current time_cost value (that was too large) is one
                # greater than the lower_bound, we know current time_cost is at `t+1`.
                if time_cost == lower_bound + 1:
                    break

                # Otherwise we know the current time_cost is at least two integers greater
                # than `t`. Our best candidate for `t` is lower_bound, but for all we know,
                # `t` might be a much greater value. So we continue binary search for `t+1`
                time_cost = math.floor((lower_bound + upper_bound) / 2)

        return time_cost, kd_time, master_key

    def determine_memory_cost(self,
                              password:    str,
                              salt:        bytes,
                              time_cost:   int,
                              memory_cost: int,
                              parallelism: int,
                              ) -> Tuple[int, bytes]:
        """Determine suitable memory_cost value for Argon2id.

        If we reached this function, it means we found a `t+1` value for
        time_cost (explained in the `determine_time_cost` function). We
        therefore do a binary search on the amount of memory to use
        until we hit the desired key derivation time range.
        """
        lower_bound = ARGON2_MIN_MEMORY_COST
        upper_bound = memory_cost

        while True:
            memory_cost = int(round((lower_bound + upper_bound) // 2, -3))

            print_on_previous_line()
            phase(f"Trying memory cost {memory_cost} KiB")
            master_key, kd_time = self.timed_key_derivation(password, salt, time_cost, memory_cost, parallelism)
            phase(f"{kd_time:.1f}s", done=True)

            # If we found a suitable memory_cost value, we accept the key and the memory_cost.
            if MIN_KEY_DERIVATION_TIME <= kd_time <= MAX_KEY_DERIVATION_TIME:
                return memory_cost, master_key

            # The search might fail e.g. if external CPU load causes delay in key
            # derivation, which causes the search to continue into wrong branch. In
            # such a situation the search is restarted. The binary search is problematic
            # with tight key derivation time target ranges, so if the search keeps
            # restarting, increasing MAX_KEY_DERIVATION_TIME (and thus expanding the
            # range) will help finding suitable memory_cost value faster. Increasing
            # MAX_KEY_DERIVATION_TIME slightly affects security (positively) and user
            # experience (negatively).
            if memory_cost == lower_bound or memory_cost == upper_bound:
                lower_bound = ARGON2_MIN_MEMORY_COST
                upper_bound = self.get_available_memory()
                continue

            if kd_time < MIN_KEY_DERIVATION_TIME:
                lower_bound = memory_cost

            elif kd_time > MAX_KEY_DERIVATION_TIME:
                upper_bound = memory_cost

    def replace_database_data(self) -> None:
        """Store cached database data into database."""
        if self.database_data is not None:
            self.database.store_unencrypted_database(self.database_data)
        self.database_data = None

    def load_master_key(self) -> bytes:
        """Derive the master key from password and salt.

        Load the salt, hash, and key derivation settings from the login
        database. Derive the purported master key from the salt and
        entered password. If the BLAKE2b hash of derived master key
        matches the hash in the login database, accept the derived
        master key.
        """
        database_data = self.database.load_database()

        if len(database_data) != MASTERKEY_DB_SIZE:
            raise CriticalError(f"Invalid {self.file_name} database size.")

        salt, key_hash, time_bytes, memory_bytes, parallelism_bytes \
            = separate_headers(database_data, [ARGON2_SALT_LENGTH, BLAKE2_DIGEST_LENGTH,
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
            reset_terminal()

            password_2 = password_1
        else:
            password_2 = pwd_prompt(f"Confirm the {purpose}: ", repeat=True)

        if password_1 == password_2:
            return password_1

        m_print("Error: Passwords did not match. Try again.", head=1, tail=1)
        print_on_previous_line(delay=1, reps=7)
        return cls.new_password(purpose)

    @classmethod
    def get_password(cls, purpose: str = "master password") -> str:
        """Prompt the user to enter a password."""
        return pwd_prompt(f"Enter {purpose}: ")

    def authenticate_action(self) -> bool:
        """Return True if user entered correct master password to authenticate an action."""
        try:
            authenticated = self.load_master_key() == self.master_key
        except (EOFError, KeyboardInterrupt):
            raise SoftError("Authentication aborted.", tail_clear=True, head=2, delay=1)

        return authenticated
