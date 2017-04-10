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
import getpass
import unittest

from src.common.input   import box_input, get_b58_key, nh_bypass_msg, pwd_prompt, yes

from tests.mock_classes import Settings


class TestInputs(unittest.TestCase):

    o_input = builtins.input

    def tearDown(self):
        builtins.input = self.o_input

    def test_box_input(self):
        builtins.input = lambda x: 'mock_input'
        self.assertEqual(box_input('test title'), 'mock_input')
        self.assertEqual(box_input('test title', head=1, tail=1, expected_len=20), 'mock_input')

        builtins.input = lambda x: ''
        self.assertEqual(box_input('test title', head=1, tail=1, default = 'mock_input', expected_len=20), 'mock_input')

        def test_validator(string, *_):
            if string == 'ok':
                return True, ''
            else:
                print(string)
                return False, 'Error'

        input_list = ['bad', 'ok']
        gen        = iter(input_list)

        def mock_input(_):
            return str(next(gen))

        builtins.input = mock_input
        self.assertEqual(box_input('test title', validator=test_validator), 'ok')

    def test_get_b58_key(self):

        for kt in ['pubkey', 'localkey', 'imported_file']:
            input_list = ['bad',
                          "2QJL5gVSPEjMTaxWPfYkzG9UJxzZDNSx6PPeVWdzS5CFN7knZa",
                          "2QJL5gVSPEjMTaxWPfYkzG9UJxzZDNSx6PPeVWdzS5CFN7knZy"]

            gen = iter(input_list)
            def mock_input(_):
                return str(next(gen))

            builtins.input = mock_input
            key            = get_b58_key(kt)
            self.assertIsInstance(key, bytes)
            self.assertEqual(len(key), 32)

        with self.assertRaises(SystemExit):
            get_b58_key('invalid_keytype')

    def test_nh_bypass_msg(self):
        # Setup
        settings       = Settings()
        builtins.input = lambda x: ''

        # Test
        self.assertIsNone(nh_bypass_msg('start', settings))
        self.assertIsNone(nh_bypass_msg('finish', settings))

    def test_pwd_prompt(self):
        # Setup
        o_getpass       = getpass.getpass
        getpass.getpass = lambda x: 'testpwd'

        # Test
        self.assertEqual(pwd_prompt("test prompt", '┌', '┐'), 'testpwd')

        # Teardown
        getpass.getpass = o_getpass


    def test_yes(self):
        # Setup
        words      = ['BAD', '', 'bad', 'Y', 'YES', 'N', 'NO']
        input_list = words
        gen        = iter(input_list)

        def mock_input(_):
            return str(next(gen))

        builtins.input = mock_input

        # Test
        self.assertTrue(yes('test prompt', head=1, tail=1))
        self.assertTrue(yes('test prompt'))
        self.assertFalse(yes('test prompt', head=1, tail=1))
        self.assertFalse(yes('test prompt'))


if __name__ == '__main__':
    unittest.main(exit=False)
