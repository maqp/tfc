import hashlib
import multiprocessing
import os
import random
import subprocess
import unittest
from string import ascii_letters, digits
from unittest import mock
from unittest.mock import MagicMock

import argon2

from src.common.crypto_phf import argon2_kdf
from src.common.statics import ARGON2_SALT_LENGTH, ARGON2_MIN_TIME_COST, ARGON2_MIN_MEMORY_COST, ARGON2_MIN_PARALLELISM, \
    SYMMETRIC_KEY_LENGTH

from tests.utils import cd_unit_test, cleanup


class TestArgon2KDF(unittest.TestCase):
    """\
    Similar to normal cryptographic hash functions, a password hashing
    function such as the Argon2 also generates unpredictable values
    (secret keys in this case). The IETF test vectors[1] require
    parameters (e.g. the "Secret" and the "Associated data" fields) that
    the argon2_cffi library does not provide. The only available option
    is to generate the test vectors dynamically.
        To do that, this test downloads and compiles the command-line
    utility[2] for the reference implementation of Argon2. Next, the
    test compiles and runs the command-line utility's tests. It then
    generates random (but valid) input parameters, and compares the
    output of the argon2_cffi library to the output of the command-line
    utility under those input parameters.

     [1] https://tools.ietf.org/html/draft-irtf-cfrg-argon2-09#section-5.3
     [2] https://github.com/P-H-C/phc-winner-argon2#command-line-utility
    """

    def setUp(self) -> None:
        """Pre-test actions."""
        self.unit_test_dir   = cd_unit_test()
        self.number_of_tests = 256

        file_url  = 'https://github.com/P-H-C/phc-winner-argon2/archive/master.zip'
        file_name = 'phc-winner-argon2-master.zip'

        # Download the Argon2 command-line utility.
        subprocess.Popen(f'wget {file_url} -O {file_name}', shell=True).wait()

        # Verify the SHA256 hash of the zip-file containing the command-line utility.
        with open(file_name, 'rb') as f:
            file_data = f.read()
        self.assertEqual('c13017dcbc3239fbcd35ef3cf8949f4c052817ad5ce8195b59110f401479ad14',
                         hashlib.sha256(file_data).hexdigest())

        # Unzip, compile, and test the command-line utility.
        subprocess.Popen(f'unzip {file_name}', shell=True).wait()
        os.chdir('phc-winner-argon2-master/')
        subprocess.Popen(f'/usr/bin/make',      shell=True).wait()
        subprocess.Popen('/usr/bin/make test', shell=True).wait()

    def tearDown(self) -> None:
        """Post-test actions."""
        os.chdir('..')
        cleanup(self.unit_test_dir)

    def test_argon2_cffi_using_the_official_command_line_utility(self) -> None:

        # Command-line utility's parameter limits.
        min_password_length = 1
        max_password_length = 127
        min_salt_length     = 8
        min_parallelism     = 1
        max_parallelism     = multiprocessing.cpu_count()
        min_time_cost       = 1
        min_memory_cost     = 7
        min_key_length      = 4

        # Arbitrary limits set for the test.
        max_salt_length = 128
        max_time_cost   = 3
        max_memory_cost = 15
        max_key_length  = 64

        sys_rand = random.SystemRandom()

        for _ in range(self.number_of_tests):

            # Generate random parameters for the test.
            len_password = sys_rand.randint(min_password_length, max_password_length)
            len_salt     = sys_rand.randint(min_salt_length,     max_salt_length)
            parallelism  = sys_rand.randint(min_parallelism,     max_parallelism)
            time_cost    = sys_rand.randint(min_time_cost,       max_time_cost)
            memory_cost  = sys_rand.randint(min_memory_cost,     max_memory_cost)
            key_length   = sys_rand.randint(min_key_length,      max_key_length)

            password = ''.join([sys_rand.choice(ascii_letters + digits) for _ in range(len_password)])
            salt     = ''.join([sys_rand.choice(ascii_letters + digits) for _ in range(len_salt)])

            # Generate a key test vector using the command-line utility.
            output = subprocess.check_output(
                f'echo -n "{password}" | ./argon2 {salt} '
                f'-t {time_cost} '
                f'-m {memory_cost} '
                f'-p {parallelism} '
                f'-l {key_length} '
                f'-id',
                shell=True).decode()  # type: str

            key_test_vector = output.split('\n')[4].split('\t')[-1]

            # Generate a key using the argon2_cffi library.
            purported_key = argon2.low_level.hash_secret_raw(secret=password.encode(),
                                                             salt=salt.encode(),
                                                             time_cost=time_cost,
                                                             memory_cost=2**memory_cost,
                                                             parallelism=parallelism,
                                                             hash_len=key_length,
                                                             type=argon2.Type.ID).hex()

            self.assertEqual(purported_key, key_test_vector)


class TestArgon2Wrapper(unittest.TestCase):

    def setUp(self) -> None:
        """Pre-test actions."""
        self.salt     = os.urandom(ARGON2_SALT_LENGTH)
        self.password = 'password'

    def test_invalid_length_salt_raises_critical_error(self) -> None:
        invalid_salts = [salt_length * b'a' for salt_length in [0, ARGON2_SALT_LENGTH-1,
                                                                   ARGON2_SALT_LENGTH+1, 1000]]
        for invalid_salt in invalid_salts:
            with self.assertRaises(SystemExit):
                argon2_kdf(self.password, invalid_salt,
                           ARGON2_MIN_TIME_COST, ARGON2_MIN_MEMORY_COST, ARGON2_MIN_PARALLELISM)

    @mock.patch("argon2.low_level.hash_secret_raw", MagicMock(side_effect=[SYMMETRIC_KEY_LENGTH*'a']))
    def test_invalid_type_key_from_argon2_raises_critical_error(self) -> None:
        with self.assertRaises(SystemExit):
            argon2_kdf(self.password, self.salt, ARGON2_MIN_TIME_COST, ARGON2_MIN_MEMORY_COST, ARGON2_MIN_PARALLELISM)

    @mock.patch("argon2.low_level.hash_secret_raw", MagicMock(side_effect=[(SYMMETRIC_KEY_LENGTH-1)*b'a',
                                                                           (SYMMETRIC_KEY_LENGTH+1)*b'a']))
    def test_invalid_size_key_from_argon2_raises_critical_error(self) -> None:
        with self.assertRaises(SystemExit):
            argon2_kdf(self.password, self.salt, ARGON2_MIN_TIME_COST, ARGON2_MIN_MEMORY_COST, ARGON2_MIN_PARALLELISM)
        with self.assertRaises(SystemExit):
            argon2_kdf(self.password, self.salt, ARGON2_MIN_TIME_COST, ARGON2_MIN_MEMORY_COST, ARGON2_MIN_PARALLELISM)

    def test_too_small_time_cost_raises_critical_error(self) -> None:
        with self.assertRaises(SystemExit):
            argon2_kdf(self.password, self.salt, ARGON2_MIN_TIME_COST-1, ARGON2_MIN_MEMORY_COST, ARGON2_MIN_PARALLELISM)

    def test_too_small_memory_cost_raises_critical_error(self) -> None:
        with self.assertRaises(SystemExit):
            argon2_kdf(self.password, self.salt, ARGON2_MIN_TIME_COST, ARGON2_MIN_MEMORY_COST-1, ARGON2_MIN_PARALLELISM)

    def test_too_small_parallelism_raises_critical_error(self) -> None:
        with self.assertRaises(SystemExit):
            argon2_kdf(self.password, self.salt, ARGON2_MIN_TIME_COST, ARGON2_MIN_MEMORY_COST, ARGON2_MIN_PARALLELISM-1)

    def test_argon2_kdf_key_type_and_length(self) -> None:
        key = argon2_kdf(self.password, self.salt, ARGON2_MIN_TIME_COST, ARGON2_MIN_MEMORY_COST, ARGON2_MIN_PARALLELISM)
        self.assertIsInstance(key, bytes)
        self.assertEqual(len(key), SYMMETRIC_KEY_LENGTH)
