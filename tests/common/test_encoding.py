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

from src.common.encoding import b58encode, bool_to_bytes, double_to_bytes, str_to_bytes, int_to_bytes
from src.common.encoding import b58decode, bytes_to_bool, bytes_to_double, bytes_to_str, bytes_to_int


class TestB58(unittest.TestCase):

    def test_function(self):
        for _ in range(1000):
            key     = os.urandom(32)
            encoded = b58encode(key)
            decoded = b58decode(encoded)
            self.assertEqual(key, decoded)

    def test_invalid_decoding(self):
        key     = 32 * b'\x01'
        encoded = b58encode(key)  # SeLqn3UAUoRymWmwW7axrzJK7JfNaBR2cHCryA6cFsiJ67Em
        changed = encoded[:-1] + 'a'
        with self.assertRaises(ValueError):
            b58decode(changed)


class TestConversions(unittest.TestCase):

    def test_bool_to_bytes(self):
        self.assertEqual(bool_to_bytes(False), b'\x00')
        self.assertEqual(bool_to_bytes(True),  b'\x01')

    def test_bytes_to_bool(self):
        self.assertEqual(bytes_to_bool(b'\x00'), False)
        self.assertEqual(bytes_to_bool(b'\x01'), True)

    def int_to_bytes(self):
        self.assertEqual(int_to_bytes(1), b'\x00\x00\x00\x00\x00\x00\x00\x01')

    def test_bytes_to_int(self):
        self.assertEqual(bytes_to_int(b'\x00\x00\x00\x00\x00\x00\x00\x01'), 1)

    def test_double_to_bytes(self):
        self.assertEqual(double_to_bytes(1.0), binascii.unhexlify('000000000000f03f'))
        self.assertEqual(double_to_bytes(1.1), binascii.unhexlify('9a9999999999f13f'))

    def test_bytes_to_double(self):
        self.assertEqual(bytes_to_double(binascii.unhexlify('000000000000f03f')), 1.0)
        self.assertEqual(bytes_to_double(binascii.unhexlify('9a9999999999f13f')), 1.1)

    def test_str_to_bytes(self):
        encoded = str_to_bytes('test')
        self.assertIsInstance(encoded, bytes)
        self.assertEqual(len(encoded), 1024)

    def test_bytes_to_str(self):
        encoded = str_to_bytes('test')
        self.assertEqual(bytes_to_str(encoded), 'test')


if __name__ == '__main__':
    unittest.main(exit=False)
