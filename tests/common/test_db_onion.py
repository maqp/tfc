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

import os
import unittest

from unittest import mock

from src.common.crypto   import encrypt_and_sign
from src.common.db_onion import OnionService
from src.common.misc     import ensure_dir, validate_onion_addr
from src.common.statics  import *

from tests.mock_classes import MasterKey
from tests.utils        import cd_unit_test, cleanup, tamper_file


class TestOnionService(unittest.TestCase):

    def setUp(self):
        self.unit_test_dir = cd_unit_test()
        self.master_key    = MasterKey()
        self.file_name     = f"{DIR_USER_DATA}{TX}_onion_db"

    def tearDown(self):
        cleanup(self.unit_test_dir)

    @mock.patch('time.sleep', return_value=None)
    def test_onion_service_key_generation_and_load(self, _):
        onion_service = OnionService(self.master_key)

        # Test new OnionService has valid attributes
        self.assertIsInstance(onion_service.master_key,         MasterKey)
        self.assertIsInstance(onion_service.onion_private_key,  bytes)
        self.assertIsInstance(onion_service.user_onion_address, str)
        self.assertFalse(onion_service.is_delivered)
        self.assertEqual(validate_onion_addr(onion_service.user_onion_address), '')

        # Test data is stored to a database
        self.assertTrue(os.path.isfile(self.file_name))
        self.assertEqual(os.path.getsize(self.file_name),
                         XCHACHA20_NONCE_LENGTH + ONION_SERVICE_PRIVATE_KEY_LENGTH + POLY1305_TAG_LENGTH)

        # Test data can be loaded from the database
        onion_service2 = OnionService(self.master_key)
        self.assertIsInstance(onion_service2.onion_private_key, bytes)
        self.assertEqual(onion_service.onion_private_key, onion_service2.onion_private_key)

    @mock.patch('time.sleep', return_value=None)
    def test_loading_invalid_onion_key_raises_critical_error(self, _):
        # Setup
        ct_bytes = encrypt_and_sign((ONION_SERVICE_PRIVATE_KEY_LENGTH +1) * b'a', self.master_key.master_key)

        ensure_dir(DIR_USER_DATA)
        with open(f'{DIR_USER_DATA}{TX}_onion_db', 'wb+') as f:
            f.write(ct_bytes)

        # Test
        with self.assertRaises(SystemExit):
            OnionService(self.master_key)

    @mock.patch('time.sleep', return_value=None)
    def test_load_of_modified_database_raises_critical_error(self, _):
        # Write data to file
        OnionService(self.master_key)

        # Test reading works normally
        self.assertIsInstance(OnionService(self.master_key), OnionService)

        # Test loading of the tampered database raises CriticalError
        tamper_file(self.file_name, tamper_size=1)
        with self.assertRaises(SystemExit):
            OnionService(self.master_key)

    @mock.patch('os.getrandom', side_effect=[ 1 * b'a',   # Initial confirmation code
                                             32 * b'a',   # ed25519 key
                                             24 * b'a',   # Nonce
                                              1 * b'b'])  # New confirmation code (different)
    @mock.patch('time.sleep', return_value=None)
    def test_confirmation_code_generation(self, *_):
        onion_service = OnionService(self.master_key)
        conf_code     = onion_service.conf_code
        onion_service.new_confirmation_code()
        self.assertNotEqual(conf_code, onion_service.conf_code)


if __name__ == '__main__':
    unittest.main(exit=False)
