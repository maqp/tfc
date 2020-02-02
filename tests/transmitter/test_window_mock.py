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

import unittest

from src.transmitter.window_mock import MockWindow

from tests.mock_classes import create_contact, Contact
from tests.utils        import nick_to_pub_key


class TestMockWindow(unittest.TestCase):

    def setUp(self) -> None:
        """Pre-test actions."""
        self.window = MockWindow(nick_to_pub_key("Alice"), contacts=[create_contact(n) for n in ['Alice', 'Bob']])

    def test_window_iterates_over_contacts(self) -> None:
        for c in self.window:
            self.assertIsInstance(c, Contact)
