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

import base64
import binascii
import builtins
import datetime
import os
import shutil
import unittest
import zlib

from src.common.crypto   import encrypt_and_sign
from src.common.encoding import b58encode, str_to_bytes
from src.common.statics  import *

from src.rx.files import process_imported_file, process_received_file, store_unique

from tests.mock_classes import Settings, WindowList
from tests.utils        import ignored, TFCTestCase


class TestStoreUnique(unittest.TestCase):

    def setUp(self):
        self.f_data = os.urandom(100)
        self.f_dir  = 'test_dir/'
        self.f_name = 'test_file'

    def tearDown(self):
        with ignored(FileNotFoundError):
            shutil.rmtree('test_dir/')

    def test_each_file_is_store_with_unique_name(self):
        self.assertEqual(store_unique(self.f_data, self.f_dir, self.f_name), 'test_file')
        self.assertEqual(store_unique(self.f_data, self.f_dir, self.f_name), 'test_file.1')
        self.assertEqual(store_unique(self.f_data, self.f_dir, self.f_name), 'test_file.2')


class TestProcessReceivedFile(TFCTestCase):

    def setUp(self):
        self.nick = 'Alice'
        self.key  = os.urandom(KEY_LENGTH)

    def tearDown(self):
        with ignored(FileNotFoundError):
            shutil.rmtree(DIR_RX_FILES)

    def test_invalid_structure_raises_fr(self):
        self.assertFR("Error: Received file had invalid structure.", process_received_file, b'testfile.txt', self.nick)

    def test_invalid_encoding_raises_fr(self):
        # Setup
        payload = binascii.unhexlify('3f264d4189d7a091') + US_BYTE + base64.b85encode(b'filedata')

        # Test
        self.assertFR("Error: Received file name had invalid encoding.", process_received_file, payload, self.nick)

    def test_invalid_name_raises_fr(self):
        # Setup
        payload = b'\x01filename' + US_BYTE + base64.b85encode(b'filedata')

        # Test
        self.assertFR("Error: Received file had an invalid name.", process_received_file, payload, self.nick)

    def test_invalid_data_raises_fr(self):
        # Setup
        payload = b'testfile.txt' + US_BYTE + base64.b85encode(b'filedata') + b'\x01'

        # Test
        self.assertFR("Error: Received file had invalid encoding.", process_received_file, payload, self.nick)

    def test_invalid_key_raises_fr(self):
        # Setup
        payload = b'testfile.txt' + US_BYTE + base64.b85encode(b'filedata')

        # Test
        self.assertFR("Error: Received file had an invalid key.", process_received_file, payload, self.nick)

    def test_decryption_fail_raises_fr(self):
        # Setup
        f_data  = encrypt_and_sign(b'filedata', self.key)[::-1]
        payload = b'testfile.txt' + US_BYTE + base64.b85encode(f_data)

        # Test
        self.assertFR("Error: Decryption of file data failed.", process_received_file, payload, self.nick)

    def test_invalid_compression_raises_fr(self):
        # Setup
        compressed = zlib.compress(b'filedata', level=COMPRESSION_LEVEL)[::-1]
        f_data     = encrypt_and_sign(compressed, self.key) + self.key
        payload    = b'testfile.txt' + US_BYTE + base64.b85encode(f_data)

        # Test
        self.assertFR("Error: Decompression of file data failed.", process_received_file, payload, self.nick)

    def test_successful_reception(self):
        # Setup
        compressed = zlib.compress(b'filedata', level=COMPRESSION_LEVEL)
        f_data     = encrypt_and_sign(compressed, self.key) + self.key
        payload    = b'testfile.txt' + US_BYTE + base64.b85encode(f_data)

        # Test
        self.assertIsNone(process_received_file(payload, self.nick))
        self.assertTrue(os.path.isfile(f'{DIR_RX_FILES}Alice/testfile.txt'))


class TestProcessImportedFile(TFCTestCase):

    def setUp(self):
        self.o_input     = builtins.input
        self.settings    = Settings()
        self.ts          = datetime.datetime.now()
        self.window_list = WindowList(nicks=[LOCAL_ID])
        self.key         = os.urandom(KEY_LENGTH)
        self.key_b58     = b58encode(self.key, file_key=True)

        input_list     = ['91avARGdfge8E4tZfYLoxeJ5sGBdNJQH4kvjJoQFacbgwi1C2GD', self.key_b58]
        gen            = iter(input_list)
        builtins.input = lambda _: str(next(gen))

    def tearDown(self):
        builtins.input = self.o_input

        with ignored(FileNotFoundError):
            shutil.rmtree(DIR_IMPORTED)

    def test_invalid_compression_raises_fr(self):
        # Setup
        data           = os.urandom(1000)
        compressed     = zlib.compress(data, level=COMPRESSION_LEVEL)
        compressed     = compressed[:-2] + b'aa'
        packet         = IMPORTED_FILE_HEADER + encrypt_and_sign(compressed, self.key)
        input_list     = ['bad', self.key_b58]
        gen            = iter(input_list)
        builtins.input = lambda _: str(next(gen))

        # Test
        self.assertFR("Error: Decompression of file data failed.",
                      process_imported_file, self.ts, packet, self.window_list, self.settings)

    def test_invalid_name_encoding_raises_fr(self):
        # Setup
        file_name  = binascii.unhexlify('8095b2f59d650ab7')
        data       = file_name + os.urandom(1000)
        compressed = zlib.compress(data, level=COMPRESSION_LEVEL)
        packet     = IMPORTED_FILE_HEADER + encrypt_and_sign(compressed, self.key)

        # Test
        self.assertFR("Error: Received file name had invalid encoding.",
                      process_imported_file, self.ts, packet, self.window_list, self.settings)

    def test_invalid_name_raises_fr(self):
        # Setup
        file_name  = str_to_bytes('\x01testfile.txt')
        data       = file_name + os.urandom(1000)
        compressed = zlib.compress(data, level=COMPRESSION_LEVEL)
        packet     = IMPORTED_FILE_HEADER + encrypt_and_sign(compressed, self.key)

        # Test
        self.assertFR("Error: Received file had an invalid name.",
                      process_imported_file, self.ts, packet, self.window_list, self.settings)

    def test_valid_import(self):
        # Setup
        file_name  = str_to_bytes('testfile.txt')
        data       = file_name + os.urandom(1000)
        compressed = zlib.compress(data, level=COMPRESSION_LEVEL)
        packet     = IMPORTED_FILE_HEADER + encrypt_and_sign(compressed, self.key)

        # Test
        self.assertIsNone(process_imported_file(self.ts, packet, self.window_list, self.settings))
        self.assertTrue(os.path.isfile(f"{DIR_IMPORTED}testfile.txt"))


if __name__ == '__main__':
    unittest.main(exit=False)
