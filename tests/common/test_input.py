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

from src.common.input   import ask_confirmation_code, box_input, get_b58_key, nh_bypass_msg, pwd_prompt, yes
from src.common.statics import *

from tests.mock_classes import Settings


class TestAskConfirmationCode(unittest.TestCase):

    def setUp(self):
        self.o_input   = builtins.input
        builtins.input = lambda _: 'ff'

    def tearDown(self):
        builtins.input = self.o_input

    def test_ask_confirmation_code(self):
        self.assertEqual(ask_confirmation_code(), 'ff')


class TestBoxInput(unittest.TestCase):

    def setUp(self):
        self.o_input        = builtins.input
        input_list          = ['mock_input', 'mock_input', '', 'bad', 'ok']
        gen                 = iter(input_list)
        builtins.input      = lambda _: str(next(gen))
        self.mock_validator = lambda string, *_: '' if string == 'ok' else 'Error'

    def tearDown(self):
        builtins.input = self.o_input

    def test_box_input(self):
        self.assertEqual(box_input('test title'), 'mock_input')
        self.assertEqual(box_input('test title', head=1,                       expected_len=20), 'mock_input')
        self.assertEqual(box_input('test title', head=1, default='mock_input', expected_len=20), 'mock_input')
        self.assertEqual(box_input('test title', validator=self.mock_validator), 'ok')


class TestGetB58Key(unittest.TestCase):

    def setUp(self):
        self.o_input  = builtins.input
        self.settings = Settings()

    def tearDown(self):
        builtins.input = self.o_input

    def test_get_b58_key(self):
        for boolean in [True, False]:
            self.settings.local_testing_mode = boolean
            for key_type in [B58_PUB_KEY, B58_LOCAL_KEY]:
                input_list    = ["bad",
                                 "5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTa",
                                 "5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ"]
                gen            = iter(input_list)
                builtins.input = lambda _: str(next(gen))
                key            = get_b58_key(key_type, self.settings)

                self.assertIsInstance(key, bytes)
                self.assertEqual(len(key), KEY_LENGTH)

            with self.assertRaises(SystemExit):
                get_b58_key('invalid_keytype', self.settings)

        for boolean in [True, False]:
            self.settings.local_testing_mode = boolean
            for key_type in [B58_FILE_KEY]:
                input_list    = ["bad",
                                 "91avARGdfge8E4tZfYLoxeJ5sGBdNJQH4kvjJoQFacbgwi1C2Ga",
                                 "91avARGdfge8E4tZfYLoxeJ5sGBdNJQH4kvjJoQFacbgwi1C2GD"]
                gen            = iter(input_list)
                builtins.input = lambda _: str(next(gen))
                key            = get_b58_key(key_type, self.settings)

                self.assertIsInstance(key, bytes)
                self.assertEqual(len(key), KEY_LENGTH)

            with self.assertRaises(SystemExit):
                get_b58_key('invalid_keytype', self.settings)


class TestNHBypassMsg(unittest.TestCase):

    def setUp(self):
        self.o_input   = builtins.input
        self.settings  = Settings()
        builtins.input = lambda _: ''

    def tearDown(self):
        builtins.input = self.o_input

    def test_nh_bypass_msg(self):
        self.assertIsNone(nh_bypass_msg(NH_BYPASS_START, self.settings))
        self.assertIsNone(nh_bypass_msg(NH_BYPASS_STOP, self.settings))


class TestPwdPrompt(unittest.TestCase):

    def setUp(self):
        self.o_input    = builtins.input
        self.o_getpass  = getpass.getpass
        getpass.getpass = lambda x: 'testpwd'

    def tearDown(self):
        builtins.input  = self.o_input
        getpass.getpass = self.o_getpass

    def test_pwd_prompt(self):
        self.assertEqual(pwd_prompt("test prompt"), 'testpwd')


class TestYes(unittest.TestCase):

    def setUp(self):
        self.o_input   = builtins.input
        self.o_getpass = getpass.getpass
        input_list     = ['BAD', '', 'bad', 'Y', 'YES', 'N', 'NO']
        gen            = iter(input_list)
        builtins.input = lambda _: str(next(gen))

    def tearDown(self):
        builtins.input  = self.o_input
        getpass.getpass = self.o_getpass

    def test_yes(self):
        self.assertTrue(yes('test prompt', head=1, tail=1))
        self.assertTrue(yes('test prompt'))
        self.assertFalse(yes('test prompt', head=1, tail=1))
        self.assertFalse(yes('test prompt'))


if __name__ == '__main__':
    unittest.main(exit=False)
