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

import binascii
import os
import unittest

from src.common.encoding import b58encode, bool_to_bytes, double_to_bytes, str_to_bytes, int_to_bytes, unicode_padding
from src.common.encoding import b58decode, bytes_to_bool, bytes_to_double, bytes_to_str, bytes_to_int, rm_padding_str
from src.common.statics  import *


class TestBase58EncodeAndDecode(unittest.TestCase):

    def test_encoding_and_decoding_of_random_keys(self):
        for _ in range(1000):
            key     = os.urandom(KEY_LENGTH)
            encoded = b58encode(key)
            decoded = b58decode(encoded)
            self.assertEqual(key, decoded)

    def test_encoding_and_decoding_of_random_file_keys(self):
        for _ in range(1000):
            key     = os.urandom(KEY_LENGTH)
            encoded = b58encode(key, file_key=True)
            decoded = b58decode(encoded, file_key=True)
            self.assertEqual(key, decoded)

    def test_invalid_decoding(self):
        key     = KEY_LENGTH * b'\x01'
        encoded = b58encode(key)  # 5HpjE2Hs7vjU4SN3YyPQCdhzCu92WoEeuE6PWNuiPyTu3ESGnzn
        changed = encoded[:-1] + 'a'
        with self.assertRaises(ValueError):
            b58decode(changed)

    def test_public_keys_raise_value_error_when_expecting_file_key(self):
        public_key  = KEY_LENGTH * b'\x01'
        b58_pub_key = b58encode(public_key)

        with self.assertRaises(ValueError):
            b58decode(b58_pub_key, file_key=True)

    def test_file_keys_raise_value_error_when_expecting_public_key(self):
        file_key    = KEY_LENGTH * b'\x01'
        b58_file_key = b58encode(file_key, file_key=True)

        with self.assertRaises(ValueError):
            b58decode(b58_file_key)

    def test_Bitcoin_WIF_test_vectors(self):
        """Test vectors are available at
            https://en.bitcoin.it/wiki/Wallet_import_format
        """
        byte_key = binascii.unhexlify("0C28FCA386C7A227600B2FE50B7CAE11"
                                      "EC86D3BF1FBE471BE89827E19D72AA1D")

        b58_key  = "5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ"

        self.assertEqual(b58encode(byte_key), b58_key)
        self.assertEqual(b58decode(b58_key), byte_key)


class TestUnicodePadding(unittest.TestCase):

    def test_padding(self):
        for s in range(0, PADDING_LEN):
            string = s * 'm'
            padded = unicode_padding(string)
            self.assertEqual(len(padded), PADDING_LEN)

            # Verify removal of padding doesn't alter the string
            self.assertEqual(string, padded[:-ord(padded[-1:])])

    def test_oversize_msg_raises_assertion_error(self):
        for s in range(PADDING_LEN, 260):
            with self.assertRaises(AssertionError):
                unicode_padding(s * 'm')


class TestRmPaddingStr(unittest.TestCase):

    def test_padding_removal(self):
        for i in range(0, 1000):
            string = i * 'm'
            length = PADDING_LEN - (len(string) % PADDING_LEN)
            padded = string + length * chr(length)
            self.assertEqual(rm_padding_str(padded), string)


class TestConversions(unittest.TestCase):

    def test_bool_to_bytes(self):
        self.assertEqual(bool_to_bytes(False), b'\x00')
        self.assertEqual(bool_to_bytes(True),  b'\x01')
        self.assertEqual(len(bool_to_bytes(True)), BOOLEAN_SETTING_LEN)

    def test_bytes_to_bool(self):
        self.assertEqual(bytes_to_bool(b'\x00'), False)
        self.assertEqual(bytes_to_bool(b'\x01'), True)

    def test_int_to_bytes(self):
        self.assertEqual(int_to_bytes(1), b'\x00\x00\x00\x00\x00\x00\x00\x01')
        self.assertEqual(len(int_to_bytes(1)), INTEGER_SETTING_LEN)

    def test_bytes_to_int(self):
        self.assertEqual(bytes_to_int(b'\x00\x00\x00\x00\x00\x00\x00\x01'), 1)

    def test_double_to_bytes(self):
        self.assertEqual(double_to_bytes(1.0), binascii.unhexlify('000000000000f03f'))
        self.assertEqual(double_to_bytes(1.1), binascii.unhexlify('9a9999999999f13f'))
        self.assertEqual(len(double_to_bytes(1.1)), FLOAT_SETTING_LEN)

    def test_bytes_to_double(self):
        self.assertEqual(bytes_to_double(binascii.unhexlify('000000000000f03f')), 1.0)
        self.assertEqual(bytes_to_double(binascii.unhexlify('9a9999999999f13f')), 1.1)

    def test_str_to_bytes(self):
        encoded = str_to_bytes('test')
        self.assertIsInstance(encoded, bytes)
        self.assertEqual(len(encoded), PADDED_UTF32_STR_LEN)

    def test_bytes_to_str(self):
        encoded = str_to_bytes('test')
        self.assertEqual(bytes_to_str(encoded), 'test')


if __name__ == '__main__':
    unittest.main(exit=False)
