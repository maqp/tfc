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

import getpass
import os.path
import unittest

from src.common.db_masterkey import MasterKey
from src.common.statics      import *

from tests.utils import cleanup


class TestMasterKey(unittest.TestCase):

    def setUp(self):
        self.o_get_password = getpass.getpass

        input_list      = ['invalid_password', 'test_password',  # Invalid new password pair
                           'test_password',    'test_password',  # Valid new password pair
                           'invalid_password',                   # Invalid login password
                           'test_password']                      # Valid login password
        gen             = iter(input_list)
        getpass.getpass = lambda _: str(next(gen))

    def tearDown(self):
        getpass.getpass = self.o_get_password
        cleanup()

    def test_master_key_generation_and_load(self):
        masterkey = MasterKey('ut', local_test=False)
        self.assertIsInstance(masterkey.master_key, bytes)

        os.path.isfile(f"{DIR_USER_DATA}ut_login_data")
        self.assertEqual(os.path.getsize(f"{DIR_USER_DATA}ut_login_data"), ARGON2_SALT_LEN + KEY_LENGTH + 3*INTEGER_SETTING_LEN)

        masterkey = MasterKey('ut', local_test=False)
        self.assertIsInstance(masterkey.master_key, bytes)


if __name__ == '__main__':
    unittest.main(exit=False)
