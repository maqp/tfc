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

from src.common.statics import *

from src.tx.user_input import get_input, process_aliases, UserInput

from tests.mock_classes import create_contact, create_group, Settings, TxWindow


class TestProcessAliases(unittest.TestCase):

    def setUp(self):
        self.settings = Settings()
        self.window   = TxWindow(name='Alice',
                                 type=WIN_TYPE_CONTACT,
                                 type_print='contact',
                                 window_contacts=[create_contact()])

    def test_unread_shortcut(self):
        self.assertEqual(process_aliases(' ', self.settings, self.window), '/unread')

    def test_clear_shortcut(self):
        self.assertEqual(process_aliases('  ', self.settings, self.window), '/clear')

    def test_exit_shortcut(self):
        # Setup
        self.settings.double_space_exits = True

        # Test
        self.assertEqual(process_aliases('  ', self.settings, self.window), '/exit')

    def test_cmd_shortcut(self):
        self.assertEqual(process_aliases('//', self.settings, self.window), '/cmd')


class TestGetInput(unittest.TestCase):

    def setUp(self):
        self.settings = Settings()
        self.window   = TxWindow(name='Alice',
                                 type=WIN_TYPE_CONTACT,
                                 type_print='contact',
                                 window_contacts=[create_contact()])
        self.window.group = create_group('test_group')

    def test_message(self):
        # Setup
        input_list     = ['/', '', 'testmessage']
        gen            = iter(input_list)
        builtins.input = lambda _: str(next(gen))

        # Test
        user_input = get_input(self.window, self.settings)
        self.assertEqual(user_input.plaintext, 'testmessage')
        self.assertEqual(user_input.type, MESSAGE)

    def test_message_and_command_to_empty_group(self):
        # Setup
        input_list     = ['/', '', 'testmessage', '/clear']
        gen            = iter(input_list)
        builtins.input = lambda _: str(next(gen))

        self.window.type            = WIN_TYPE_GROUP
        self.window.window_contacts = []
        self.window.group.members   = []

        # Test
        user_input = get_input(self.window, self.settings)
        self.assertEqual(user_input.plaintext, 'clear')
        self.assertEqual(user_input.type, COMMAND)

    def test_file(self):
        # Setup
        builtins.input = lambda _: '/file'

        # Test
        user_input = get_input(self.window, self.settings)
        self.assertEqual(user_input.plaintext, '/file')
        self.assertEqual(user_input.type, FILE)

    def test_command(self):
        # Setup
        builtins.input = lambda _: '/clear'

        # Test
        user_input = get_input(self.window, self.settings)
        self.assertEqual(user_input.plaintext, 'clear')
        self.assertEqual(user_input.type, COMMAND)


class TestUserInput(unittest.TestCase):

    def test_user_input(self):
        # Setup
        user_input = UserInput('test_plaintext', FILE)

        # Test
        self.assertEqual(user_input.plaintext, 'test_plaintext')
        self.assertEqual(user_input.type, FILE)


if __name__ == '__main__':
    unittest.main(exit=False)
