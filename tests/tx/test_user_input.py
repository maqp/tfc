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

from src.tx.user_input  import UserInput

from tests.mock_classes import create_contact, Settings, Window


class TestUserInput(unittest.TestCase):

    def test_class(self):
        # Setup
        o_input    = builtins.input
        input_list = ['/', '', 'testmessage', '/file', '/nick Alice', 'testmessage', '/nick Alice', '  ']
        gen        = iter(input_list)
        def mock_input(_):
            return str(next(gen))
        builtins.input = mock_input

        window   = Window(name='Alice', type='contact', window_contacts=[create_contact('Alice')])
        settings = Settings()

        # Test
        user_input = UserInput(window, settings)
        self.assertEqual(user_input.plaintext, 'testmessage')
        self.assertEqual(user_input.type,      'message')

        user_input = UserInput(window, settings)
        self.assertEqual(user_input.plaintext, '/file')
        self.assertEqual(user_input.type,      'file')

        user_input = UserInput(window, settings)
        self.assertEqual(user_input.plaintext, 'nick Alice')
        self.assertEqual(user_input.type,      'command')

        window = Window(name='Testgroup',
                        type='group',
                        window_contacts=[])

        user_input = UserInput(window, settings)
        self.assertEqual(user_input.plaintext, 'nick Alice')
        self.assertEqual(user_input.type,      'command')


        user_input = UserInput(window, settings)
        self.assertEqual(user_input.plaintext, 'clear')
        self.assertEqual(user_input.type,      'command')

        # Teardown
        builtins.input = o_input


if __name__ == '__main__':
    unittest.main(exit=False)
