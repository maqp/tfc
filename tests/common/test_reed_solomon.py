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

from src.common.reed_solomon import RSCodec


class TestRS(unittest.TestCase):

    def test_reed_solomon(self):
        reed_solomon = RSCodec(20)
        string       = 10 * "TestMessage"
        encoded      = reed_solomon.encode(string)
        error        = 5
        altered      = os.urandom(error) + encoded[error:]
        corrected    = reed_solomon.decode(altered).decode('latin-1')
        self.assertEqual(string, corrected)


if __name__ == '__main__':
    unittest.main(exit=False)
