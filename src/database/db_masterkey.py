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
import multiprocessing
import os.path
import time

from statistics import median
from typing import Optional as O, TYPE_CHECKING

from src.common.crypto.argon2_salt import Argon2Salt
from src.common.crypto.algorithms.blake2b import blake2b
from src.common.crypto.algorithms.argon2 import argon2_kdf
from src.common.crypto.password import Password
from src.common.types_custom import (IntArgon2TimeCost, IntArgon2Parallelism, IntArgon2MemoryCost, BoolReplaceDB,
                                     BoolRekeyDB, BoolAuthenticate, BytesRawMasterKey)
from src.database.database import TFCUnencryptedDatabase
from src.common.crypto.keys.symmetric_key import SymmetricKey, MasterKeyRekeying
from src.common.utils.encoding import bytes_to_int, int_to_bytes
from src.common.exceptions import CriticalError, graceful_exit, SoftError, InvalidPassword
from src.ui.common.input.get_password import get_password
from src.ui.common.output.print_message import print_message
from src.ui.common.output.vt100_utils import clear_screen, clear_previous_lines, reset_terminal
from src.ui.common.output.phase import phase
from src.common.utils.strings import separate_headers
from src.common.statics import (Argon2Literals, CryptoVarLength, StatusMsg, FieldLength, CompoundFieldLength,
                                Argon2KDTime, KeyLength, DBName, LocalKeyDBMgmt, KeyDBMgmt, LogWriterMgmt)

if TYPE_CHECKING:
    from src.common.launch_args import LaunchArgumentsTCB
    from src.common.queues import TxQueue


class MasterKey:
    """\
    MasterKey object manages the 32-byte master key and methods related
    to it. Master key is the key that protects all data written on disk.
    """

    def __init__(self, launch_arguments: 'LaunchArgumentsTCB') -> None:
        """Create a new MasterKey object."""
        self.__program_id   = launch_arguments.program_id

        self.__database    = TFCUnencryptedDatabase(DBName.LOGIN_DATA, launch_arguments.program_id)
        self.__local_test  = launch_arguments.local_test
        self.__cached_data = None  # type: O[bytes]

        self.__master_key : O[SymmetricKey] = None
        self.__cached_key : O[SymmetricKey] = None

        try:
            if os.path.isfile(self.__database.path_to_db):
                self.__master_key = self.load_master_key()
                clear_screen()
            else:
                self.new_master_key()
        except (EOFError, KeyboardInterrupt):
            graceful_exit()

    def _get_key(self, rekey: BoolRekeyDB = BoolRekeyDB(False)) -> SymmetricKey:
        """Return the active symmetric key."""
        key = self.__cached_key if rekey else self.__master_key
        if key is None:
            raise CriticalError('Master key is not available.')
        return key

    def replace_active_key(self, master_key: bytes) -> None:
        """Replace the active master key from serialized key bytes."""
        self.__master_key = SymmetricKey(master_key)
        self.__cached_key = None

    def encrypt_and_sign(self,
                         plaintext : bytes,
                         rekey     : BoolRekeyDB = BoolRekeyDB(False)
                         ) -> bytes:
        """Encrypt and sign plaintext data to be stored on disk."""
        key = self._get_key(rekey=rekey)
        return key.encrypt_and_sign(plaintext)

    def auth_and_decrypt(self,
                         nonce_ct_tag : bytes,                             # Nonce + ciphertext + tag
                         database     : str   =  '',                       # When provided, gracefully exits TFC when the tag is invalid
                         ad           : bytes = b'',                       # Associated data
                         rekey        : BoolRekeyDB  = BoolRekeyDB(False)  # When True, use key for re-keying databases
                         ) -> bytes:                                       # Plaintext
        """Authenticate and decrypt data stored on disk."""
        key = self._get_key(rekey=rekey)
        return key.auth_and_decrypt(nonce_ct_tag, database, ad)

    @staticmethod
    def timed_key_derivation(password    : Password,
                             salt        : Argon2Salt,
                             time_cost   : IntArgon2TimeCost,
                             memory_cost : IntArgon2MemoryCost,
                             parallelism : IntArgon2Parallelism
                             ) -> tuple[BytesRawMasterKey, float]:
        """Derive key and measure its derivation time."""
        time_start = time.monotonic()
        master_key = argon2_kdf(password, salt, time_cost, memory_cost, parallelism)
        kd_time    = time.monotonic() - time_start

        return BytesRawMasterKey(master_key), kd_time

    def median_timed_key_derivation(self,
                                    password    : Password,
                                    salt        : Argon2Salt,
                                    time_cost   : IntArgon2TimeCost,
                                    memory_cost : IntArgon2MemoryCost,
                                    parallelism : IntArgon2Parallelism,
                                    ) -> tuple[BytesRawMasterKey, float]:
        """Derive the key multiple times and return the median timing sample."""
        kd_times   = []
        master_key = BytesRawMasterKey(b'')

        for _ in range(Argon2Literals.ITERATIONS_PER_CONFIG):
            master_key, kd_time = self.timed_key_derivation(password, salt, time_cost, memory_cost, parallelism)
            kd_times.append(kd_time)

        return master_key, median(kd_times)

    @staticmethod
    def round_memory_cost(*, midpoint: int, step: int) -> IntArgon2MemoryCost:
        """Round memory cost to the nearest search step in KiB."""
        return IntArgon2MemoryCost(step * ((midpoint + step // 2) // step))

    def get_available_memory(self) -> IntArgon2MemoryCost:
        """Return the amount of available memory in the system."""
        with open('/proc/meminfo') as f:
            fields = f.read().splitlines()

        field     = [f for f in fields if f.startswith('MemAvailable')][0]
        mem_avail = int(field.split()[1])

        if self.__local_test:
            mem_avail //= 2

        return IntArgon2MemoryCost(mem_avail)

    def new_master_key(self, replace : BoolReplaceDB = BoolReplaceDB(True)) -> None:
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
        salt     = Argon2Salt()

        # Determine the amount of memory used from the amount of free RAM in the system.
        memory_cost = self.get_available_memory()

        # Determine the number of threads to use
        parallelism = IntArgon2Parallelism(multiprocessing.cpu_count())
        if self.__local_test:
            parallelism = IntArgon2Parallelism(max(Argon2Literals.ARGON2_MIN_PARALLELISM.value, parallelism // 2))

        # Determine time cost
        time_cost, kd_time, master_key_bytes = self.determine_time_cost(password, salt, memory_cost, parallelism)

        # Determine memory cost
        if kd_time > Argon2KDTime.MAX_KEY_DERIVATION_TIME.value:
            memory_cost, master_key_bytes = self.determine_memory_cost(password, salt, time_cost, memory_cost, parallelism)

        # Store values to database
        database_data = (salt.salt_bytes
                         + blake2b(master_key_bytes)
                         + int_to_bytes(time_cost)
                         + int_to_bytes(memory_cost)
                         + int_to_bytes(parallelism))

        if replace:
            self.__database.store_database(database_data)
            self.__master_key = SymmetricKey(master_key_bytes)

        else:
            # When replacing the master key, the new master key needs to be generated before
            # databases are encrypted. However, storing the new master key shouldn't be done
            # before all new databases have been successfully written. We therefore just cache
            # the database data.
            self.__cached_data = database_data
            self.__cached_key  = SymmetricKey(master_key_bytes)

        clear_previous_lines(no_lines=1)
        phase('Deriving master key')
        phase(StatusMsg.DONE.value, delay=1)
        return None

    def determine_time_cost(self,
                            password    : Password,
                            salt        : Argon2Salt,
                            memory_cost : IntArgon2MemoryCost,
                            parallelism : IntArgon2Parallelism
                            ) -> tuple[IntArgon2TimeCost, float, bytes]:
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
        lower_bound :   int  = Argon2Literals.ARGON2_MIN_TIME_COST.value
        upper_bound : O[int] = None
        time_cost   = IntArgon2TimeCost(lower_bound)

        min_time = Argon2KDTime.MIN_KEY_DERIVATION_TIME.value
        max_time = Argon2KDTime.MAX_KEY_DERIVATION_TIME.value

        print(2*'\n')

        while True:
            clear_previous_lines(no_lines=1)

            with phase(f'Trying time cost {time_cost}') as set_done_message:
                master_key, kd_time = self.median_timed_key_derivation(password, salt, time_cost, memory_cost, parallelism)
                # noinspection PyTypeChecker
                set_done_message(f'{kd_time:.1f}s')

            # Sentinel that checks if the binary search has ended, and that restarts
            # the search if kd_time repeats. This prevents an Alderson loop.
            if upper_bound is not None and time_cost in [lower_bound, upper_bound]:  # pragma: no cover
                lower_bound = Argon2Literals.ARGON2_MIN_TIME_COST.value
                upper_bound = None
                continue

            if min_time <= kd_time <= max_time:
                break

            if kd_time < min_time:
                lower_bound = time_cost

                if upper_bound is None:
                    avg_time_per_round  = kd_time / time_cost
                    time_cost_candidate = math.floor(max_time / avg_time_per_round)
                    time_cost           = IntArgon2TimeCost(max(time_cost+1, time_cost_candidate))

                else:
                    if time_cost + 1 == upper_bound:
                        time_cost = IntArgon2TimeCost(time_cost+1)
                        break

                    time_cost = IntArgon2TimeCost(math.floor((lower_bound + upper_bound) / 2))

            elif kd_time > max_time:
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
                time_cost = IntArgon2TimeCost(math.floor((lower_bound + upper_bound) / 2))

        return IntArgon2TimeCost(time_cost), kd_time, master_key

    def determine_memory_cost(self,
                              password    : Password,
                              salt        : Argon2Salt,
                              time_cost   : IntArgon2TimeCost,
                              memory_cost : IntArgon2MemoryCost,
                              parallelism : IntArgon2Parallelism,
                              ) -> tuple[IntArgon2MemoryCost, BytesRawMasterKey]:
        """Determine suitable memory_cost value for Argon2id.

        If we reached this function, it means we found a `t+1` value for
        time_cost (explained in the `determine_time_cost` function). We
        therefore do a binary search on the amount of memory to use
        until we hit the desired key derivation time range.
        """
        step        = Argon2Literals.ARGON2_MEMORY_COST_STEP.value
        lower_bound = Argon2Literals.ARGON2_MIN_MEMORY_COST.value
        upper_bound = memory_cost

        previous_memory_cost : O[int] = None

        min_time = Argon2KDTime.MIN_KEY_DERIVATION_TIME.value
        max_time = Argon2KDTime.MAX_KEY_DERIVATION_TIME.value

        while True:
            midpoint    = (lower_bound + upper_bound) // 2
            memory_cost = self.round_memory_cost(midpoint=midpoint, step=step)

            if previous_memory_cost is not None:
                delta = abs(memory_cost - previous_memory_cost)
                if delta <= Argon2Literals.ARGON2_MEMORY_RESTART_MIN.value:
                    lower_bound = Argon2Literals.ARGON2_MIN_MEMORY_COST.value
                    upper_bound = self.get_available_memory()
                    previous_memory_cost = None
                    continue

            clear_previous_lines(no_lines=1)
            with phase(f'Trying memory cost {memory_cost}') as set_done_message:
                master_key, kd_time = self.median_timed_key_derivation(password, salt, time_cost, memory_cost, parallelism)
                # noinspection PyTypeChecker
                set_done_message(f'{kd_time:.1f}s')

            previous_memory_cost = memory_cost

            # If we found a suitable memory_cost value, we accept the key and the memory_cost.
            if min_time <= kd_time <= max_time:
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
                lower_bound = Argon2Literals.ARGON2_MIN_MEMORY_COST.value
                upper_bound = self.get_available_memory()

                previous_memory_cost = None
                continue

            if kd_time < min_time:
                lower_bound = memory_cost

            elif kd_time > max_time:
                upper_bound = memory_cost

        raise RuntimeError('Broke out of loop')

    def replace_database_data(self) -> None:
        """Store cached database data into database."""
        if self.__cached_data is not None:
            self.__database.store_database(self.__cached_data)
            self.__master_key = self._get_key(rekey=BoolRekeyDB(True))
            self.__cached_key = None

        self.__cached_data = None

    def update_sender_key(self, queues: 'TxQueue') -> None:
        """Send the master key to sender-side processes."""
        key = self.__cached_key if self.__cached_key is not None else self._get_key()
        queues.key_store_mgmt .put( (KeyDBMgmt     .UPDATE_MASTER_KEY, MasterKeyRekeying(key.raw_bytes)) )
        queues.local_key_mgmt .put( (LocalKeyDBMgmt.UPDATE_MASTER_KEY, MasterKeyRekeying(key.raw_bytes)) )
        queues.log_writer_mgmt.put( (LogWriterMgmt .UPDATE_MASTER_KEY, MasterKeyRekeying(key.raw_bytes)) )

    def load_master_key(self, authenticate: BoolAuthenticate = BoolAuthenticate(False)) -> SymmetricKey:
        """Derive the master key from password and salt.

        Load the salt, hash, and key derivation settings from the login
        database. Derive the purported master key from the salt and
        entered password. If the BLAKE2b hash of derived master key
        matches the hash in the login database, accept the derived
        master key.
        """
        database_data = self.__database.load_database()

        if len(database_data) != CompoundFieldLength.MASTERKEY_DB_SIZE:
            raise CriticalError(f'Invalid {self.__database.database_name} database size.')

        salt_bytes, key_hash, time_bytes, memory_bytes, parallelism_bytes \
            = separate_headers(database_data, [KeyLength.ARGON2_SALT.value, CryptoVarLength.BLAKE2_DIGEST.value,
                                               FieldLength.ENCODED_INTEGER.value, FieldLength.ENCODED_INTEGER.value])

        salt        = Argon2Salt(salt_bytes)
        time_cost   = IntArgon2TimeCost(bytes_to_int(time_bytes))
        memory_cost = bytes_to_int(memory_bytes)
        parallelism = bytes_to_int(parallelism_bytes)

        while True:
            password = MasterKey.get_password()

            with phase('Deriving master key', padding_top=2) as set_done_message:
                purp_key = argon2_kdf(password, salt, time_cost, memory_cost, parallelism)

                if blake2b(purp_key) == key_hash:
                    # noinspection PyTypeChecker
                    set_done_message('Password correct')
                    return SymmetricKey(purp_key)
                else:
                    if authenticate:
                        raise InvalidPassword('Authentication failed.')

                    # noinspection PyTypeChecker
                    set_done_message('Invalid password')
                    # Clear the phase line, its spacer line, and the three-line password box.
                    clear_previous_lines(no_lines=5)

    @classmethod
    def new_password(cls, purpose: str = 'master password') -> Password:
        """Prompt the user to enter and confirm a new password."""
        password_str_1 = get_password(f'Enter a new {purpose}: ')

        if password_str_1.lower() == 'generate':
            password = Password.generate()

            print_message([f'Generated a {password.bit_strength}-bit password:',
                     '', password.password, '',
                     'Write down this password and dispose of the copy once you remember it.',
                     'Press <Enter> to continue.'], manual_proceed=True, box=True, padding_top=1, padding_bottom=1)
            reset_terminal()
            return password

        password_str_2 = get_password(f'Confirm the {purpose}: ', repeat=True)

        if password_str_1 == password_str_2:
            return Password(password_str_1)

        print_message('Error: Passwords did not match. Try again.', padding_top=1, padding_bottom=1)
        clear_previous_lines(delay=1, no_lines=7)
        return cls.new_password(purpose)

    @classmethod
    def get_password(cls, purpose: str = 'master password') -> Password:
        """Prompt the user to enter a password."""
        return Password(get_password(f'Enter {purpose}: '))

    def authenticate_action(self) -> bool:
        """Return True if user entered correct master password to authenticate an action."""
        try:
            self.load_master_key(authenticate=BoolAuthenticate(True))
            return True
        except InvalidPassword:
            print_message('Invalid master password.', padding_top=1, padding_bottom=1)
            return False
        except (EOFError, KeyboardInterrupt):
            raise SoftError('Authentication aborted.', clear_after=True, padding_top=2, clear_delay=1)
