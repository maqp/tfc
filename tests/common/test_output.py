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
import unittest

from src.common.output  import box_print, c_print, message_printer, phase
from src.common.output  import print_fingerprints, print_on_previous_line, g_mgmt_print

from tests.mock_classes import ContactList


class TestOutput(unittest.TestCase):

    def test_box_print(self):
        self.assertIsNone(box_print("Test message",                          head=1, tail=1))
        self.assertIsNone(box_print(["Test message", '', "Another message"], head=1, tail=1))

        o_input        = builtins.input
        builtins.input = lambda x: ''
        self.assertIsNone(box_print("Test message", manual_proceed=True))
        builtins.input = o_input

    def test_c_print(self):
        self.assertIsNone(c_print('Test message', head=1, tail=1))

    def test_message_printer(self):
        self.assertIsNone(message_printer('Test message', head=1, tail=1))

    def test_phase(self):
        self.assertIsNone(phase('Entering phase'))
        self.assertIsNone(phase('Done'))
        self.assertIsNone(phase('Starting phase', head=1, offset=len("Finished")))
        self.assertIsNone(phase('Finished', done=True))

    def test_print_fingerprints(self):
        self.assertIsNone(print_fingerprints(32 * b'\x01'), 'test')

    def test_print_on_previous_line(self):
        self.assertIsNone(print_on_previous_line())
        self.assertIsNone(print_on_previous_line(reps=2, flush=True))

    def test_g_mgmt_print(self):
        # Setup
        contact_list = ContactList(nicks=['Alice'])

        # Test
        self.assertIsNone(g_mgmt_print("new_g", ['alice@jabber.org', 'bob@jabber.org'], contact_list, g_name='testgroup'))
        self.assertIsNone(g_mgmt_print("add_m", ['alice@jabber.org', 'bob@jabber.org'], contact_list, g_name='testgroup'))
        self.assertIsNone(g_mgmt_print("add_a", ['alice@jabber.org', 'bob@jabber.org'], contact_list, g_name='testgroup'))
        self.assertIsNone(g_mgmt_print("rem_m", ['alice@jabber.org', 'bob@jabber.org'], contact_list, g_name='testgroup'))
        self.assertIsNone(g_mgmt_print("rem_n", ['alice@jabber.org', 'bob@jabber.org'], contact_list, g_name='testgroup'))
        self.assertIsNone(g_mgmt_print("unkwn", ['alice@jabber.org', 'bob@jabber.org'], contact_list, g_name='testgroup'))


if __name__ == '__main__':
    unittest.main(exit=False)
