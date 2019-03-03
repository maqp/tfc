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

import base64
import os
import unittest

from datetime import datetime

from src.common.encoding import b58encode, bool_to_bytes, double_to_bytes, str_to_bytes, int_to_bytes
from src.common.encoding import b58decode, bytes_to_bool, bytes_to_double, bytes_to_str, bytes_to_int
from src.common.encoding import onion_address_to_pub_key, unicode_padding, pub_key_to_short_address, b85encode
from src.common.encoding import pub_key_to_onion_address, rm_padding_str, bytes_to_timestamp, b10encode
from src.common.statics  import *


class TestBase58EncodeAndDecode(unittest.TestCase):

    def setUp(self):
        self.key = SYMMETRIC_KEY_LENGTH * b'\x01'

    def test_encoding_and_decoding_of_random_local_keys(self):
        for _ in range(100):
            key     = os.urandom(SYMMETRIC_KEY_LENGTH)
            encoded = b58encode(key)
            decoded = b58decode(encoded)
            self.assertEqual(key, decoded)

    def test_encoding_and_decoding_of_random_public_keys(self):
        for _ in range(100):
            key     = os.urandom(TFC_PUBLIC_KEY_LENGTH)
            encoded = b58encode(key,     public_key=True)
            decoded = b58decode(encoded, public_key=True)
            self.assertEqual(key, decoded)

    def test_invalid_decoding(self):
        encoded = b58encode(self.key)  # 5HpjE2Hs7vjU4SN3YyPQCdhzCu92WoEeuE6PWNuiPyTu3ESGnzn
        changed = encoded[:-1] + 'a'
        with self.assertRaises(ValueError):
            b58decode(changed)

    def test_public_keys_raise_value_error_when_expecting_local_key(self):
        b58_pub_key = b58encode(self.key)
        with self.assertRaises(ValueError):
            b58decode(b58_pub_key, public_key=True)

    def test_local_keys_raise_value_error_when_expecting_public_key(self):
        b58_file_key = b58encode(self.key, public_key=True)
        with self.assertRaises(ValueError):
            b58decode(b58_file_key)

    def test_bitcoin_wif_test_vectors(self):
        """Test vectors are available at
            https://en.bitcoin.it/wiki/Wallet_import_format
        """
        byte_key = bytes.fromhex("0C28FCA386C7A227600B2FE50B7CAE11"
                                 "EC86D3BF1FBE471BE89827E19D72AA1D")

        b58_key  = "5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ"

        self.assertEqual(b58encode(byte_key), b58_key)
        self.assertEqual(b58decode(b58_key), byte_key)


class TestBase85Encode(unittest.TestCase):

    def test_b85encode(self):
        message = os.urandom(100)
        self.assertEqual(b85encode(message),
                         base64.b85encode(message).decode())


class TestBase10Encode(unittest.TestCase):

    def test_b10encode(self):
        self.assertEqual(b10encode(FINGERPRINT_LENGTH * b'a'),
                         '44046402572626160612103472728795008085361523578694645928734845681441465000289')


class TestUnicodePadding(unittest.TestCase):

    def test_padding(self):
        for s in range(0, PADDING_LENGTH):
            string = s * 'm'
            padded = unicode_padding(string)
            self.assertEqual(len(padded), PADDING_LENGTH)

            # Verify removal of padding doesn't alter the string
            self.assertEqual(string, padded[:-ord(padded[-1:])])

    def test_oversize_msg_raises_critical_error(self):
        for s in range(PADDING_LENGTH, 500):
            with self.assertRaises(SystemExit):
                unicode_padding(s * 'm')


class TestRmPaddingStr(unittest.TestCase):

    def test_padding_removal(self):
        for i in range(0, 1000):
            string = i * 'm'
            length = PADDING_LENGTH - (len(string) % PADDING_LENGTH)
            padded = string + length * chr(length)
            self.assertEqual(rm_padding_str(padded), string)


class TestConversions(unittest.TestCase):

    def test_conversion_back_and_forth(self):
        pub_key = os.urandom(SYMMETRIC_KEY_LENGTH)
        self.assertEqual(onion_address_to_pub_key(pub_key_to_onion_address(pub_key)), pub_key)

    def test_pub_key_to_short_addr(self):
        self.assertEqual(len(pub_key_to_short_address(bytes(ONION_SERVICE_PUBLIC_KEY_LENGTH))),
                         TRUNC_ADDRESS_LENGTH)

        self.assertIsInstance(pub_key_to_short_address(bytes(ONION_SERVICE_PUBLIC_KEY_LENGTH)), str)

    def test_bool_to_bytes(self):
        self.assertEqual(    bool_to_bytes(False), b'\x00')
        self.assertEqual(    bool_to_bytes(True),  b'\x01')
        self.assertEqual(len(bool_to_bytes(True)), ENCODED_BOOLEAN_LENGTH)

    def test_bytes_to_bool(self):
        self.assertEqual(bytes_to_bool(b'\x00'), False)
        self.assertEqual(bytes_to_bool(b'\x01'), True)

    def test_int_to_bytes(self):
        self.assertEqual(    int_to_bytes(1),  b'\x00\x00\x00\x00\x00\x00\x00\x01')
        self.assertEqual(len(int_to_bytes(1)), ENCODED_INTEGER_LENGTH)

    def test_bytes_to_int(self):
        self.assertEqual(bytes_to_int(b'\x00\x00\x00\x00\x00\x00\x00\x01'), 1)

    def test_double_to_bytes(self):
        self.assertEqual(    double_to_bytes(1.0),  bytes.fromhex('000000000000f03f'))
        self.assertEqual(    double_to_bytes(1.1),  bytes.fromhex('9a9999999999f13f'))
        self.assertEqual(len(double_to_bytes(1.1)), ENCODED_FLOAT_LENGTH)

    def test_bytes_to_double(self):
        self.assertEqual(bytes_to_double(bytes.fromhex('000000000000f03f')), 1.0)
        self.assertEqual(bytes_to_double(bytes.fromhex('9a9999999999f13f')), 1.1)

    def test_str_to_bytes(self):
        encoded = str_to_bytes('test')
        self.assertIsInstance(encoded, bytes)
        self.assertEqual(len(encoded), PADDED_UTF32_STR_LENGTH)

    def test_bytes_to_str(self):
        encoded = str_to_bytes('test')
        self.assertEqual(bytes_to_str(encoded), 'test')

    def test_bytes_to_timestamp(self):
        encoded = bytes.fromhex('00000000')
        self.assertIsInstance(bytes_to_timestamp(encoded), datetime)


if __name__ == '__main__':
    unittest.main(exit=False)
