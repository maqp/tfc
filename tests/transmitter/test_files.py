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

from src.transmitter.files import File

from tests.mock_classes import create_contact, Settings, TxWindow
from tests.utils        import cd_unittest, cleanup, TFCTestCase


class TestFile(TFCTestCase):

    def setUp(self):
        self.unittest_dir = cd_unittest()
        self.window       = TxWindow()
        self.settings     = Settings()
        self.args         = self.window, self.settings

    def tearDown(self):
        cleanup(self.unittest_dir)

    def test_missing_file_raises_fr(self):
        self.assert_fr("Error: File not found.", File, './testfile.txt', *self.args)

    def test_empty_file_raises_fr(self):
        # Setup
        with open('testfile.txt', 'wb+') as f:
            f.write(b'')

        # Test
        self.assert_fr("Error: Target file is empty.", File, './testfile.txt', *self.args)

    def test_oversize_filename_raises_fr(self):
        # Setup
        f_name = 250 * 'a' + '.txt'
        with open(f_name, 'wb+') as f:
            f.write(b'a')

        # Test
        self.assert_fr("Error: File name is too long.", File, f'./{f_name}', *self.args)

    def test_small_file(self):
        # Setup
        input_data = os.urandom(5)
        with open('testfile.txt', 'wb+') as f:
            f.write(input_data)

        self.settings.traffic_masking           = True
        self.settings.multi_packet_random_delay = True

        # Test
        file = File('./testfile.txt', *self.args)

        self.assertEqual(file.name, b'testfile.txt')
        self.assertEqual(file.size_hr, '5.0B')
        self.assertEqual(len(file.plaintext), 114)
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
        file = File('./testfile.txt', *self.args)

        self.assertEqual(file.name, b'testfile.txt')
        self.assertEqual(len(file.plaintext), 2112)
        self.assertEqual(file.size_hr, '2.0KB')
        self.assertIsInstance(file.plaintext, bytes)
        self.assertEqual(file.time_hr, '0:01:48')


if __name__ == '__main__':
    unittest.main(exit=False)
