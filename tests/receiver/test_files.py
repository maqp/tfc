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
import unittest
import zlib

from datetime import datetime
from unittest import mock
from typing   import Any

from src.common.crypto   import blake2b, encrypt_and_sign
from src.common.encoding import str_to_bytes
from src.common.statics  import COMPRESSION_LEVEL, DIR_RECV_FILES, ORIGIN_CONTACT_HEADER, SYMMETRIC_KEY_LENGTH, US_BYTE

from src.receiver.files import new_file, process_assembled_file, process_file, store_unique

from tests.mock_classes import ContactList, Settings, WindowList
from tests.utils        import cd_unit_test, cleanup, nick_to_pub_key, TFCTestCase, UNDECODABLE_UNICODE


class TestStoreUnique(unittest.TestCase):

    def setUp(self) -> None:
        """Pre-test actions."""
        self.unit_test_dir = cd_unit_test()
        self.file_data     = os.urandom(100)
        self.file_dir      = 'test_dir/'
        self.file_name     = 'test_file'

    def tearDown(self) -> None:
        """Post-test actions."""
        cleanup(self.unit_test_dir)

    def test_each_file_is_store_with_unique_name(self) -> None:
        self.assertEqual(store_unique(self.file_data, self.file_dir, self.file_name), 'test_file')
        self.assertEqual(store_unique(self.file_data, self.file_dir, self.file_name), 'test_file.1')
        self.assertEqual(store_unique(self.file_data, self.file_dir, self.file_name), 'test_file.2')


class ProcessAssembledFile(TFCTestCase):

    def setUp(self) -> None:
        """Pre-test actions."""
        self.unit_test_dir = cd_unit_test()
        self.ts            = datetime.now()
        self.onion_pub_key = nick_to_pub_key('Alice')
        self.nick          = 'Alice'
        self.settings      = Settings()
        self.window_list   = WindowList(nick=['Alice', 'Bob'])
        self.key           = os.urandom(SYMMETRIC_KEY_LENGTH)
        self.args          = self.onion_pub_key, self.nick, self.settings, self.window_list

    def tearDown(self) -> None:
        """Post-test actions."""
        cleanup(self.unit_test_dir)

    def test_invalid_structure_raises_se(self) -> None:
        # Setup
        payload = b'testfile.txt'

        # Test
        self.assert_se("Error: Received file had an invalid structure.",
                       process_assembled_file, self.ts, payload, *self.args)

    def test_invalid_encoding_raises_se(self) -> None:
        # Setup
        payload = UNDECODABLE_UNICODE + US_BYTE + b'file_data'

        # Test
        self.assert_se("Error: Received file name had an invalid encoding.",
                       process_assembled_file, self.ts, payload, *self.args)

    def test_invalid_name_raises_se(self) -> None:
        # Setup
        payload = b'\x01filename' + US_BYTE + b'file_data'

        # Test
        self.assert_se("Error: Received file had an invalid name.",
                       process_assembled_file, self.ts, payload, *self.args)

    def test_slash_in_file_name_raises_se(self) -> None:
        # Setup
        payload = b'file/name' + US_BYTE + b'file_data'

        # Test
        self.assert_se("Error: Received file had an invalid name.",
                       process_assembled_file, self.ts, payload, *self.args)

    def test_invalid_key_raises_se(self) -> None:
        # Setup
        payload = b'testfile.txt' + US_BYTE + b'file_data'

        # Test
        self.assert_se("Error: Received file had an invalid key.",
                       process_assembled_file, self.ts, payload, *self.args)

    def test_decryption_fail_raises_se(self) -> None:
        # Setup
        file_data = encrypt_and_sign(b'file_data', self.key)[::-1]
        payload   = b'testfile.txt' + US_BYTE + file_data

        # Test
        self.assert_se("Error: Decryption of file data failed.",
                       process_assembled_file, self.ts, payload, *self.args)

    def test_invalid_compression_raises_se(self) -> None:
        # Setup
        compressed = zlib.compress(b'file_data', level=COMPRESSION_LEVEL)[::-1]
        file_data  = encrypt_and_sign(compressed, self.key) + self.key
        payload    = b'testfile.txt' + US_BYTE + file_data

        # Test
        self.assert_se("Error: Decompression of file data failed.",
                       process_assembled_file, self.ts, payload, *self.args)

    def test_successful_reception(self) -> None:
        # Setup
        compressed = zlib.compress(b'file_data', level=COMPRESSION_LEVEL)
        file_data  = encrypt_and_sign(compressed, self.key) + self.key
        payload    = b'testfile.txt' + US_BYTE + file_data

        # Test
        self.assertIsNone(process_assembled_file(self.ts, payload, *self.args))
        self.assertTrue(os.path.isfile(f'{DIR_RECV_FILES}Alice/testfile.txt'))

    def test_successful_reception_during_traffic_masking(self) -> None:
        # Setup
        self.settings.traffic_masking = True
        self.window_list.active_win   = self.window_list.get_window(nick_to_pub_key('Bob'))

        compressed = zlib.compress(b'file_data', level=COMPRESSION_LEVEL)
        file_data  = encrypt_and_sign(compressed, self.key) + self.key
        payload    = b'testfile.txt' + US_BYTE + file_data

        # Test
        self.assertIsNone(process_assembled_file(self.ts, payload, *self.args))
        self.assertEqual(self.window_list.get_window(nick_to_pub_key('Bob')).message_log[0][1],
                         "Stored file from Alice as 'testfile.txt'.")
        self.assertTrue(os.path.isfile(f'{DIR_RECV_FILES}Alice/testfile.txt'))


class TestNewFile(TFCTestCase):

    def setUp(self) -> None:
        """Pre-test actions."""
        self.unit_test_dir = cd_unit_test()
        self.ts            = datetime.now()
        self.packet        = b''
        self.file_keys     = dict()
        self.file_buf      = dict()
        self.contact_list  = ContactList(nicks=['Alice'])
        self.window_list   = WindowList()
        self.file_key      = SYMMETRIC_KEY_LENGTH*b'a'
        self.settings      = Settings()
        self.compressed    = zlib.compress(str_to_bytes("test_file.txt") + b'file_data', level=COMPRESSION_LEVEL)
        self.args          = self.file_keys, self.file_buf, self.contact_list, self.window_list, self.settings

    def tearDown(self) -> None:
        """Post-test actions."""
        cleanup(self.unit_test_dir)

    def test_unknown_account_raises_se(self) -> None:
        # Setup
        file_ct = encrypt_and_sign(self.compressed, self.file_key)
        packet  = nick_to_pub_key('Bob') + ORIGIN_CONTACT_HEADER + file_ct

        # Test
        self.assert_se("File from an unknown account.", new_file, self.ts, packet, *self.args)

    def test_disabled_file_reception_raises_se(self) -> None:
        # Setup
        file_ct = encrypt_and_sign(self.compressed, self.file_key)
        packet  = nick_to_pub_key('Alice') + ORIGIN_CONTACT_HEADER + file_ct
        self.contact_list.get_contact_by_address_or_nick('Alice').file_reception = False

        # Test
        self.assert_se("Alert! Discarded file from Alice as file reception for them is disabled.",
                       new_file, self.ts, packet, *self.args)

    def test_valid_file_without_key_is_cached(self) -> None:
        # Setup
        file_ct   = encrypt_and_sign(self.compressed, self.file_key)
        file_hash = blake2b(file_ct)
        packet    = nick_to_pub_key('Alice') + ORIGIN_CONTACT_HEADER + file_ct

        # Test
        self.assertIsNone(new_file(self.ts, packet, *self.args))
        self.assertEqual(self.file_buf[nick_to_pub_key('Alice') + file_hash], (self.ts, file_ct))

    @mock.patch('time.sleep', return_value=None)
    def test_valid_file_with_key_is_processed(self, _: Any) -> None:
        # Setup
        file_ct        = encrypt_and_sign(self.compressed, self.file_key)
        file_hash      = blake2b(file_ct)
        packet         = nick_to_pub_key('Alice') + ORIGIN_CONTACT_HEADER + file_ct
        self.file_keys = {(nick_to_pub_key('Alice') + file_hash): self.file_key}
        self.args      = self.file_keys, self.file_buf, self.contact_list, self.window_list, self.settings

        # Test
        self.assertIsNone(new_file(self.ts, packet, *self.args))


class TestProcessFile(TFCTestCase):

    def setUp(self) -> None:
        """Pre-test actions."""
        self.unit_test_dir = cd_unit_test()
        self.ts            = datetime.now()
        self.account       = nick_to_pub_key('Alice')
        self.file_key      = SYMMETRIC_KEY_LENGTH*b'a'
        self.file_ct       = encrypt_and_sign(50 * b'a', key=self.file_key)
        self.contact_list  = ContactList(nicks=['Alice'])
        self.window_list   = WindowList()
        self.settings      = Settings()
        self.args          = self.file_key, self.contact_list, self.window_list, self.settings

    def tearDown(self) -> None:
        """Post-test actions."""
        cleanup(self.unit_test_dir)

    def test_invalid_key_raises_se(self) -> None:
        self.file_key = SYMMETRIC_KEY_LENGTH * b'f'
        self.args     = self.file_key, self.contact_list, self.window_list, self.settings
        self.assert_se("Error: Decryption key for file from Alice was invalid.",
                       process_file, self.ts, self.account, self.file_ct, *self.args)

    def test_invalid_compression_raises_se(self) -> None:
        compressed = zlib.compress(b'file_data', level=COMPRESSION_LEVEL)[::-1]
        file_data  = encrypt_and_sign(compressed, self.file_key)

        self.assert_se("Error: Failed to decompress file from Alice.",
                       process_file, self.ts, self.account, file_data, *self.args)

    @mock.patch('time.sleep', return_value=None)
    def test_invalid_file_name_raises_se(self, _: Any) -> None:
        compressed = zlib.compress(UNDECODABLE_UNICODE + b'file_data', level=COMPRESSION_LEVEL)
        file_data  = encrypt_and_sign(compressed, self.file_key)

        self.assert_se("Error: Name of file from Alice had an invalid encoding.",
                       process_file, self.ts, self.account, file_data, *self.args)

    @mock.patch('time.sleep', return_value=None)
    def test_non_printable_name_raises_se(self, _: Any) -> None:
        compressed = zlib.compress(str_to_bytes("file\x01") + b'file_data', level=COMPRESSION_LEVEL)
        file_data  = encrypt_and_sign(compressed, self.file_key)

        self.assert_se("Error: Name of file from Alice was invalid.",
                       process_file, self.ts, self.account, file_data, *self.args)

    @mock.patch('time.sleep', return_value=None)
    def test_slash_in_name_raises_se(self, _: Any) -> None:
        compressed = zlib.compress(str_to_bytes("Alice/file.txt") + b'file_data', level=COMPRESSION_LEVEL)
        file_data  = encrypt_and_sign(compressed, self.file_key)

        self.assert_se("Error: Name of file from Alice was invalid.",
                       process_file, self.ts, self.account, file_data, *self.args)

    @mock.patch('time.sleep', return_value=None)
    def test_successful_storage_of_file(self, _: Any) -> None:
        compressed = zlib.compress(str_to_bytes("test_file.txt") + b'file_data', level=COMPRESSION_LEVEL)
        file_data  = encrypt_and_sign(compressed, self.file_key)

        self.assertIsNone(process_file(self.ts, self.account, file_data, *self.args))

    @mock.patch('time.sleep', return_value=None)
    def test_successful_storage_during_traffic_masking(self, _: Any) -> None:
        # Setup
        self.settings.traffic_masking = True
        self.window_list.active_win   = self.window_list.get_window(nick_to_pub_key('Bob'))

        compressed = zlib.compress(str_to_bytes("testfile.txt") + b'file_data', level=COMPRESSION_LEVEL)
        file_data  = encrypt_and_sign(compressed, self.file_key)

        self.assertIsNone(process_file(self.ts, self.account, file_data, *self.args))

        self.assertEqual(self.window_list.get_window(nick_to_pub_key('Bob')).message_log[0][1],
                         "Stored file from Alice as 'testfile.txt'.")

        self.assertTrue(os.path.isfile(f'{DIR_RECV_FILES}Alice/testfile.txt'))


if __name__ == '__main__':
    unittest.main(exit=False)
