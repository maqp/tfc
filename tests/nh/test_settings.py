#!/usr/bin/env python3.5
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

from src.nh.settings import Settings

from tests.utils import cleanup


class TestSettings(unittest.TestCase):

    def setUp(self):
        self.o_input   = builtins.input
        builtins.input = lambda _: 'yes'

    def tearDown(self):
        cleanup()
        builtins.input = self.o_input

    def test_store_and_load_settings(self):
        # Test store
        settings = Settings(False, False, 'ut')
        settings.disable_gui_dialog = True
        settings.store_settings()
        self.assertEqual(os.path.getsize(f"{DIR_USER_DATA}ut_settings"), 2*INTEGER_SETTING_LEN + 2*BOOLEAN_SETTING_LEN)

        # Test load
        settings2 = Settings(False, False, 'ut')
        self.assertTrue(settings2.disable_gui_dialog)


if __name__ == '__main__':
    unittest.main(exit=False)
