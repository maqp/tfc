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

import os
import os.path
import unittest

from unittest      import mock
from unittest.mock import MagicMock
from typing        import Any

from src.common.crypto       import blake2b
from src.common.db_masterkey import MasterKey
from src.common.misc         import ensure_dir
from src.common.statics      import (BLAKE2_DIGEST_LENGTH, DIR_USER_DATA, MASTERKEY_DB_SIZE, PASSWORD_MIN_BIT_STRENGTH,
                                     SYMMETRIC_KEY_LENGTH, TX)

from tests.utils import cd_unit_test, cleanup, TFCTestCase


KL = SYMMETRIC_KEY_LENGTH


class TestMasterKey(TFCTestCase):
    input_list = ['password', 'different_password',  # Invalid new password pair
                  'password', 'password',            # Valid   new password pair
                  'invalid_password',                # Invalid login password
                  'password']                        # Valid   login password

    def setUp(self) -> None:
        """Pre-test actions."""
        self.unit_test_dir = cd_unit_test()
        self.operation     = TX
        self.file_name     = f"{DIR_USER_DATA}{self.operation}_login_data"

    def tearDown(self) -> None:
        """Post-test actions."""
        cleanup(self.unit_test_dir)

    def test_password_generation(self) -> None:
        bit_strength, password = MasterKey.generate_master_password()
        self.assertIsInstance(bit_strength, int)
        self.assertIsInstance(password,     str)
        self.assertGreaterEqual(bit_strength, PASSWORD_MIN_BIT_STRENGTH)
        self.assertEqual(len(password.split(' ')), 10)

    @mock.patch('time.sleep', return_value=None)
    def test_invalid_data_in_db_raises_critical_error(self, _: Any) -> None:
        for delta in [-1, 1]:
            # Setup
            ensure_dir(DIR_USER_DATA)
            data = os.urandom(MASTERKEY_DB_SIZE + delta)
            data += blake2b(data)
            with open(self.file_name, 'wb+') as f:
                f.write(data)

            # Test
            with self.assertRaises(SystemExit):
                _ = MasterKey(self.operation, local_test=False)

    @mock.patch('time.sleep', return_value=None)
    def test_load_master_key_with_invalid_data_raises_critical_error(self, _: Any) -> None:
        # Setup
        ensure_dir(DIR_USER_DATA)
        data = os.urandom(MASTERKEY_DB_SIZE + BLAKE2_DIGEST_LENGTH)
        with open(self.file_name, 'wb+') as f:
            f.write(data)

        # Test
        with self.assertRaises(SystemExit):
            _ = MasterKey(self.operation, local_test=False)

    @mock.patch('src.common.db_masterkey.MIN_KEY_DERIVATION_TIME', 0.01)
    @mock.patch('src.common.db_masterkey.MAX_KEY_DERIVATION_TIME', 0.1)
    @mock.patch('os.popen',        return_value=MagicMock(
        read=MagicMock(return_value=MagicMock(splitlines=MagicMock(return_value=["MemAvailable 10240"])))))
    @mock.patch('os.path.isfile',  side_effect=[KeyboardInterrupt, False, True, False])
    @mock.patch('getpass.getpass', side_effect=input_list)
    @mock.patch('time.sleep',      return_value=None)
    def test_master_key_generation_and_load(self, *_: Any) -> None:
        with self.assertRaises(SystemExit):
            MasterKey(self.operation, local_test=True)

        master_key = MasterKey(self.operation, local_test=True)
        self.assertIsInstance(master_key.master_key, bytes)
        self.assertEqual(os.path.getsize(self.file_name), MASTERKEY_DB_SIZE + BLAKE2_DIGEST_LENGTH)

        master_key2 = MasterKey(self.operation, local_test=True)
        self.assertIsInstance(master_key2.master_key, bytes)
        self.assertEqual(master_key.master_key, master_key2.master_key)

    @mock.patch('src.common.db_masterkey.MIN_KEY_DERIVATION_TIME', 0.01)
    @mock.patch('src.common.db_masterkey.MAX_KEY_DERIVATION_TIME', 0.1)
    @mock.patch('os.popen',        return_value=MagicMock(
        read=MagicMock(return_value=MagicMock(splitlines=MagicMock(return_value=["MemAvailable 10240"])))))
    @mock.patch('os.path.isfile',  side_effect=[False, True, False])
    @mock.patch('getpass.getpass', side_effect=4*['password'])
    @mock.patch('time.sleep',      return_value=None)
    def test_database_data_caching_and_storage_on_command(self, *_: Any):
        master_key = MasterKey(self.operation, local_test=True)
        master_key.new_master_key(replace=False)
        self.assertEqual(len(master_key.database_data), MASTERKEY_DB_SIZE)
        master_key.replace_database_data()
        self.assertIsNone(master_key.database_data)
        self.assertTrue(os.path.isfile(self.file_name))

    @mock.patch('src.common.db_masterkey.MIN_KEY_DERIVATION_TIME', 0.01)
    @mock.patch('src.common.db_masterkey.MAX_KEY_DERIVATION_TIME', 0.1)
    @mock.patch('os.popen',        return_value=MagicMock(
        read=MagicMock(return_value=MagicMock(splitlines=MagicMock(return_value=["MemAvailable 10240"])))))
    @mock.patch('getpass.getpass', side_effect=['generate'])
    @mock.patch('builtins.input',  side_effect=[''])
    @mock.patch('os.system',       return_value=None)
    @mock.patch('time.sleep',      return_value=None)
    def test_password_generation(self, *_: Any) -> None:
        master_key = MasterKey(self.operation, local_test=True)
        self.assertIsInstance(master_key.master_key, bytes)

    @mock.patch('src.common.db_masterkey.MasterKey.timed_key_derivation',
                MagicMock(side_effect=        [(KL*b'a',  0.01)]
                                      + 100 * [(KL*b'b',  5.0)]
                                      +   2 * [(KL*b'a',  2.5)]
                                      +       [(KL*b'a',  3.0)]))
    @mock.patch('os.path.isfile',  side_effect=[False, True])
    @mock.patch('getpass.getpass', side_effect=input_list)
    @mock.patch('time.sleep',      return_value=None)
    def test_kd_binary_search(self, *_: Any) -> None:
        MasterKey(self.operation, local_test=True)

    @mock.patch('src.common.db_masterkey.MIN_KEY_DERIVATION_TIME', 0.01)
    @mock.patch('src.common.db_masterkey.MAX_KEY_DERIVATION_TIME', 0.1)
    @mock.patch('os.popen',        return_value=MagicMock(
        read=MagicMock(return_value=MagicMock(splitlines=MagicMock(return_value=["MemAvailable 10240"])))))
    @mock.patch('getpass.getpass', side_effect=['password', 'password', KeyboardInterrupt, 'password', 'invalid_pwd'])
    @mock.patch('time.sleep',      return_value=None)
    def test_authenticate_action(self, *_: Any) -> None:
        master_key = MasterKey(self.operation, local_test=True)
        self.assert_se("Authentication aborted.", master_key.authenticate_action)
        self.assertTrue(master_key.authenticate_action())


if __name__ == '__main__':
    unittest.main(exit=False)
