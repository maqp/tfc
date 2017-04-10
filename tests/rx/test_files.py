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
import builtins
import datetime
import os
import shutil
import unittest
import zlib

from src.common.crypto   import encrypt_and_sign
from src.common.encoding import b58encode, str_to_bytes
from src.common.statics  import *
from src.rx.files        import store_unique, process_imported_file, process_received_file
from tests.mock_classes  import WindowList
from tests.utils         import TFCTestCase


class TestStoreUnique(unittest.TestCase):

    def test_function(self):
        # Setup
        f_data = os.urandom(100)
        f_dir  = 'test_dir'
        f_name = 'test_file'

        # Test
        self.assertEqual(store_unique(f_data, f_dir, f_name), 'test_file')
        self.assertEqual(store_unique(f_data, f_dir, f_name), 'test_file.1')
        self.assertEqual(store_unique(f_data, f_dir, f_name), 'test_file.2')

        # Teardown
        shutil.rmtree('test_dir/')


class TestProcessImportedFile(TFCTestCase):

    def test_invalid_compression_raises_fr(self):
        # Setup
        data        = os.urandom(1000)
        compressed  = zlib.compress(data, level=9)
        compressed  = compressed[:-2] + b'aa'
        key         = os.urandom(32)
        key_b58     = b58encode(key)
        packet      = IMPORTED_FILE_CT_HEADER + encrypt_and_sign(compressed, key)
        ts          = datetime.datetime.now()
        window_list = WindowList()

        o_input     = builtins.input
        input_list  = ['bad', key_b58]
        gen         = iter(input_list)

        def mock_input(_):
            return str(next(gen))

        builtins.input = mock_input

        # Test
        self.assertFR("Decompression of file data failed.", process_imported_file, ts, packet, window_list)

        # Teardown
        builtins.input = o_input


    def test_invalid_name_raises_fr(self):
        # Setup
        file_name   = str_to_bytes('\x01testfile.txt')
        data        = file_name + os.urandom(1000)
        compressed  = zlib.compress(data, level=9)
        key         = os.urandom(32)
        key_b58     = b58encode(key)
        packet      = IMPORTED_FILE_CT_HEADER + encrypt_and_sign(compressed, key)
        ts          = datetime.datetime.now()
        window_list = WindowList(nicks=['local'])
        o_input     = builtins.input
        input_list  = ['2QJL5gVSPEjMTaxWPfYkzG9UJxzZDNSx6PPeVWdzS5CFN7knZy', key_b58]
        gen         = iter(input_list)

        def mock_input(_):
            return str(next(gen))

        builtins.input = mock_input

        # Test
        self.assertFR("Received file had an invalid name.", process_imported_file, ts, packet, window_list)

        # Teardown
        builtins.input = o_input

    def test_valid_import(self):
        file_name   = str_to_bytes('testfile.txt')
        data        = file_name + os.urandom(1000)
        compressed  = zlib.compress(data, level=9)
        key         = os.urandom(32)
        key_b58     = b58encode(key)
        packet      = IMPORTED_FILE_CT_HEADER + encrypt_and_sign(compressed, key)
        ts          = datetime.datetime.now()
        window_list = WindowList(nicks=['local'])
        o_input     = builtins.input
        input_list  = ['2QJL5gVSPEjMTaxWPfYkzG9UJxzZDNSx6PPeVWdzS5CFN7knZy', key_b58]
        gen         = iter(input_list)

        def mock_input(_):
            return str(next(gen))

        builtins.input = mock_input

        # Setup
        self.assertIsNone(process_imported_file(ts, packet, window_list))
        self.assertTrue(os.path.isfile(f"{DIR_IMPORTED}/testfile.txt"))

        # Teardown
        builtins.input = o_input
        shutil.rmtree(f'{DIR_IMPORTED}/')


class TestProcessReceivedFile(TFCTestCase):

    def test_invalid_structure_raises_fr(self):
        # Setup
        payload = US_BYTE.join([b'filename', b'unused', b'next is missing'])
        nick    = 'Alice'

        # Test
        self.assertFR("Received file had invalid structure.", process_received_file, payload, nick)

    def test_invalid_name_raises_fr(self):
        # Setup
        payload = US_BYTE.join([b'\x01filename', b'unused', b'unused', b'filedata'])
        nick    = 'Alice'

        # Test
        self.assertFR("Received file had an invalid name.", process_received_file, payload, nick)

    def test_invalid_encoding_raises_fr(self):
        # Setup
        f_data  = b'\x01filedata'
        payload = US_BYTE.join([b'filename', b'unused', b'unused', f_data])
        nick    = 'Alice'

        # Test
        self.assertFR("Received file had invalid encoding.", process_received_file, payload, nick)

    def test_invalid_key_raises_fr(self):
        # Setup
        f_data  = base64.b85encode(b'filedata')
        payload = US_BYTE.join([b'filename', b'unused', b'unused', f_data])
        nick    = 'Alice'

        # Test
        self.assertFR("Received file had an invalid key.", process_received_file, payload, nick)

    def test_decryption_fail_raises_fr(self):
        # Setup
        key     = os.urandom(32)
        f_data  = encrypt_and_sign(b'filedata', key)
        f_data  += key[1:] + b''
        f_data  = base64.b85encode(f_data)
        payload = US_BYTE.join([b'filename', b'unused', b'unused', f_data])
        nick    = 'Alice'

        # Test
        self.assertFR("Decryption of file data failed.", process_received_file, payload, nick)

    def test_invalid_compression_raises_fr(self):
        # Setup
        key        = os.urandom(32)
        compressed = zlib.compress(b'filedata', level=9)
        compressed = compressed[:-1] + b'a'
        f_data     = encrypt_and_sign(compressed, key)
        f_data    += key
        f_data     = base64.b85encode(f_data)
        payload    = US_BYTE.join([b'filename', b'unused', b'unused', f_data])
        nick       = 'Alice'

        # Test
        self.assertFR("Decompression of file data failed.", process_received_file, payload, nick)

    def test_missing_file_data_raises_fr(self):
        # Setup
        key        = os.urandom(32)
        compressed = zlib.compress(b'', level=9)
        f_data     = encrypt_and_sign(compressed, key)
        f_data    += key
        f_data     = base64.b85encode(f_data)
        payload    = US_BYTE.join([b'filename', b'unused', b'unused', f_data])
        nick       = 'Alice'

        # Test
        self.assertFR("Received file did not contain data.", process_received_file, payload, nick)

    def test_successful_reception(self):
        # Setup
        key        = os.urandom(32)
        compressed = zlib.compress(b'filedata', level=9)
        f_data     = encrypt_and_sign(compressed, key)
        f_data    += key
        f_data     = base64.b85encode(f_data)
        payload    = US_BYTE.join([b'filename', b'unused', b'unused', f_data])
        nick       = 'Alice'

        # Test
        self.assertIsNone(process_received_file(payload, nick))
        self.assertTrue(os.path.isfile(f'{DIR_RX_FILES}/Alice/filename'))

        # Teardown
        shutil.rmtree(f'{DIR_RX_FILES}/')


if __name__ == '__main__':
    unittest.main(exit=False)
