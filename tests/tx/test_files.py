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

import os
import unittest

from src.tx.files import File

from tests.mock_classes import create_contact, Gateway, Settings, TxWindow
from tests.utils        import ignored, TFCTestCase


class TestFile(TFCTestCase):

    def setUp(self):
        self.f_name   = 250 * 'a' + '.txt'
        self.settings = Settings()
        self.window   = TxWindow()
        self.gateway  = Gateway(txm_inter_packet_delay=0.02)

    def tearDown(self):
        for f in [self.f_name, 'testfile.txt']:
            with ignored(OSError):
                os.remove(f)

    def test_missing_file_raises_fr(self):
        self.assertFR("Error: File not found.",
                      File, './testfile.txt', self.window, self.settings, self.gateway)

    def test_empty_file_raises_fr(self):
        # Setup
        with open('testfile.txt', 'wb+') as f:
            f.write(b'')

        # Test
        self.assertFR("Error: Target file is empty.",
                      File, './testfile.txt', self.window, self.settings, self.gateway)

    def test_oversize_filename_raises_fr(self):
        # Setup
        with open(self.f_name, 'wb+') as f:
            f.write(b'a')

        # Test
        self.assertFR("Error: File name is too long.",
                      File, f'./{self.f_name}', self.window, self.settings, self.gateway)

    def test_small_file(self):
        # Setup
        input_data = os.urandom(5)
        with open('testfile.txt', 'wb+') as f:
            f.write(input_data)

        self.settings.session_traffic_masking   = True
        self.settings.multi_packet_random_delay = True

        # Test
        file = File('./testfile.txt', self.window, self.settings, self.gateway)

        self.assertEqual(file.name, b'testfile.txt')
        self.assertEqual(file.size, b'\x00\x00\x00\x00\x00\x00\x00\x05')
        self.assertEqual(file.size_print, '5.0B')
        self.assertEqual(len(file.plaintext), 136)
        self.assertIsInstance(file.plaintext, bytes)

    def test_large_file_and_local_testing(self):
        # Setup
        input_data = os.urandom(2000)
        with open('testfile.txt', 'wb+') as f:
            f.write(input_data)

        self.settings.multi_packet_random_delay = True
        self.settings.local_testing_mode        = True
        self.window.window_contacts             = [create_contact(c) for c in ['Alice', 'Bob']]

        # Test
        file = File('./testfile.txt', self.window, self.settings, self.gateway)

        self.assertEqual(file.name, b'testfile.txt')
        self.assertEqual(file.size, b'\x00\x00\x00\x00\x00\x00\x07\xd0')
        self.assertEqual(len(file.plaintext), 2633)
        self.assertEqual(file.size_print, '2.0KB')
        self.assertIsInstance(file.plaintext, bytes)
        self.assertEqual(file.time_print, '0:00:56')


if __name__ == '__main__':
    unittest.main(exit=False)
