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

import builtins
import os
import unittest

from src.common.statics import *
from src.nh.settings    import bool_to_bytes, int_to_bytes, bytes_to_bool, bytes_to_int, Settings

from tests.utils import cleanup

class TestConversions(unittest.TestCase):

    def test_bool_to_bytes(self):
        self.assertEqual(bool_to_bytes(False), b'\x00')
        self.assertEqual(bool_to_bytes(True),  b'\x01')

    def int_to_bytes(self):
        self.assertEqual(int_to_bytes(1), b'\x00\x00\x00\x00\x00\x00\x00\x01')

    def test_bytes_to_bool(self):
        self.assertEqual(bytes_to_bool(b'\x00'), False)
        self.assertEqual(bytes_to_bool(b'\x01'), True)

    def test_bytes_to_int(self):
        self.assertEqual(bytes_to_int(b'\x00\x00\x00\x00\x00\x00\x00\x01'), 1)


class TestSettings(unittest.TestCase):

    def test_class(self):
        # Setup
        o_input        = builtins.input
        builtins.input = lambda x: 'yes'
        settings       = Settings(False, False, 'ut')

        # Test store/load
        settings.disable_gui_dialog = True
        settings.store_settings()

        self.assertTrue(os.path.isfile(f"{DIR_USER_DATA}/ut_settings"))
        self.assertEqual(os.path.getsize(f"{DIR_USER_DATA}/ut_settings"), 8 + 8 + 1 + 1)

        settings2 = Settings(False, False, 'ut')
        self.assertTrue(settings2.disable_gui_dialog)

        builtins.input = o_input

    def tearDown(self):
        cleanup()


if __name__ == '__main__':
    unittest.main(exit=False)
