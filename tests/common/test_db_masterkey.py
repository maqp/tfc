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

import os
import os.path
import unittest

from unittest import mock

from src.common.db_masterkey import MasterKey
from src.common.misc         import ensure_dir
from src.common.statics      import *

from tests.utils import cd_unittest, cleanup


class TestMasterKey(unittest.TestCase):
    input_list = ['password', 'different_password',  # Invalid new password pair
                  'password', 'password',            # Valid   new password pair
                  'invalid_password',                # Invalid login password
                  'password']                        # Valid   login password

    def setUp(self):
        self.unittest_dir = cd_unittest()
        self.operation    = TX
        self.file_name    = f"{DIR_USER_DATA}{self.operation}_login_data"

    def tearDown(self):
        cleanup(self.unittest_dir)

    @mock.patch('time.sleep', return_value=None)
    def test_invalid_data_in_db_raises_critical_error(self, _):
        for delta in [-1, 1]:
            ensure_dir(DIR_USER_DATA)
            with open(self.file_name, 'wb+') as f:
                f.write(os.urandom(MASTERKEY_DB_SIZE + delta))

            with self.assertRaises(SystemExit):
                _ = MasterKey(self.operation, local_test=False)

    @mock.patch('src.common.db_masterkey.ARGON2_MIN_MEMORY',       100)
    @mock.patch('src.common.db_masterkey.ARGON2_ROUNDS',           1)
    @mock.patch('src.common.db_masterkey.MIN_KEY_DERIVATION_TIME', 0.1)
    @mock.patch('os.path.isfile',  side_effect=[KeyboardInterrupt, False, True])
    @mock.patch('getpass.getpass', side_effect=input_list)
    @mock.patch('time.sleep',      return_value=None)
    def test_master_key_generation_and_load(self, *_):
        with self.assertRaises(SystemExit):
            MasterKey(self.operation, local_test=True)

        master_key = MasterKey(self.operation, local_test=True)
        self.assertIsInstance(master_key.master_key, bytes)
        self.assertEqual(os.path.getsize(self.file_name), MASTERKEY_DB_SIZE)

        master_key2 = MasterKey(self.operation, local_test=True)
        self.assertIsInstance(master_key2.master_key, bytes)
        self.assertEqual(master_key.master_key, master_key2.master_key)


if __name__ == '__main__':
    unittest.main(exit=False)
