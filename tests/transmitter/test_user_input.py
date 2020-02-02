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

from unittest import mock
from typing   import Any

from src.common.statics         import COMMAND, FILE, MESSAGE, WIN_TYPE_CONTACT, WIN_TYPE_GROUP
from src.transmitter.user_input import get_input, process_aliases, UserInput
from tests.mock_classes         import create_contact, create_group, Settings, TxWindow


class TestProcessAliases(unittest.TestCase):

    def setUp(self) -> None:
        """Pre-test actions."""
        self.settings = Settings()
        self.window   = TxWindow(name='Alice',
                                 type=WIN_TYPE_CONTACT,
                                 type_print='contact',
                                 window_contacts=[create_contact('Alice')])

    def test_unread_shortcut(self) -> None:
        self.assertEqual(process_aliases(' ', self.settings, self.window), '/unread')

    def test_clear_shortcut(self) -> None:
        self.assertEqual(process_aliases('  ', self.settings, self.window), '/clear')

    def test_exit_shortcut(self) -> None:
        # Setup
        self.settings.double_space_exits = True

        # Test
        self.assertEqual(process_aliases('  ', self.settings, self.window), '/exit')

    def test_cmd_shortcut(self) -> None:
        self.assertEqual(process_aliases('//', self.settings, self.window), '/cmd')


class TestGetInput(unittest.TestCase):

    def setUp(self) -> None:
        """Pre-test actions."""
        self.settings = Settings()
        self.window   = TxWindow(name='Alice',
                                 type=WIN_TYPE_CONTACT,
                                 type_print='contact',
                                 window_contacts=[create_contact('Alice')])
        self.window.group = create_group('test_group')

    @mock.patch('time.sleep',     return_value=None)
    @mock.patch('builtins.input', side_effect=['/', '', 'test_message'])
    def test_message(self, *_: Any) -> None:
        user_input = get_input(self.window, self.settings)
        self.assertEqual(user_input.plaintext, 'test_message')
        self.assertEqual(user_input.type, MESSAGE)

    @mock.patch('time.sleep',     return_value=None)
    @mock.patch('builtins.input', side_effect=['/', '', 'test_message', '/clear'])
    def test_message_and_command_to_empty_group(self, *_: Any) -> None:
        self.window.type            = WIN_TYPE_GROUP
        self.window.window_contacts = []
        self.window.group.members   = []
        user_input = get_input(self.window, self.settings)
        self.assertEqual(user_input.plaintext, 'clear')
        self.assertEqual(user_input.type, COMMAND)

    @mock.patch('time.sleep',     return_value=None)
    @mock.patch('builtins.input', return_value='/file')
    def test_file(self, *_: Any) -> None:
        user_input = get_input(self.window, self.settings)
        self.assertEqual(user_input.plaintext, '/file')
        self.assertEqual(user_input.type, FILE)

    @mock.patch('time.sleep',     return_value=None)
    @mock.patch('builtins.input', return_value='/clear')
    def test_command(self, *_: Any) -> None:
        user_input = get_input(self.window, self.settings)
        self.assertEqual(user_input.plaintext, 'clear')
        self.assertEqual(user_input.type, COMMAND)


class TestUserInput(unittest.TestCase):

    def test_user_input(self) -> None:
        user_input = UserInput('test_plaintext', FILE)
        self.assertEqual(user_input.plaintext, 'test_plaintext')
        self.assertEqual(user_input.type, FILE)


if __name__ == '__main__':
    unittest.main(exit=False)
