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

from src.common.gateway import Gateway

from tests.mock_classes import Settings


class TestGateway(unittest.TestCase):

    @unittest.skipIf("TRAVIS" in os.environ and os.environ["TRAVIS"] == "true", "Skipping this test on Travis CI.")
    def test_class(self):
        # Setup
        settings = Settings()
        gateway  = Gateway(settings)

        # Test
        self.assertIsNone(gateway.write(b'test'))
        self.assertEqual(gateway.search_serial_interface(), '/dev/ttyS0')


if __name__ == '__main__':
    unittest.main(exit=False)
