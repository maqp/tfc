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

from src.common.input   import ask_confirmation_code, box_input, get_b58_key, nc_bypass_msg, pwd_prompt, yes
from src.common.statics import (B58_LOCAL_KEY, B58_PUBLIC_KEY, NC_BYPASS_START, NC_BYPASS_STOP, SYMMETRIC_KEY_LENGTH,
                                TFC_PUBLIC_KEY_LENGTH)

from tests.mock_classes import Settings
from tests.utils        import nick_to_short_address, VALID_ECDHE_PUB_KEY, VALID_LOCAL_KEY_KDK


class TestAskConfirmationCode(unittest.TestCase):

    confirmation_code = 'ff'

    @mock.patch('builtins.input', return_value=confirmation_code)
    def test_ask_confirmation_code(self, _: Any) -> None:
        self.assertEqual(ask_confirmation_code('Receiver'), self.confirmation_code)


class TestBoxInput(unittest.TestCase):

    @mock.patch('time.sleep',     return_value=None)
    @mock.patch('builtins.input', side_effect=['mock_input', 'mock_input', '', 'invalid', 'ok'])
    def test_box_input(self, *_: Any) -> None:
        self.assertEqual(box_input('test title'), 'mock_input')
        self.assertEqual(box_input('test title', head=1,                       expected_len=20), 'mock_input')
        self.assertEqual(box_input('test title', head=1, default='mock_input', expected_len=20), 'mock_input')
        self.assertEqual(box_input('test title', validator=lambda string, *_: '' if string == 'ok' else 'Error'), 'ok')


class TestGetB58Key(unittest.TestCase):

    def setUp(self) -> None:
        """Pre-test actions."""
        self.settings = Settings()

    def test_invalid_key_type_raises_critical_error(self) -> None:
        with self.assertRaises(SystemExit):
            get_b58_key('invalid_key_type', self.settings)


    @mock.patch('time.sleep',               return_value=None)
    @mock.patch('shutil.get_terminal_size', return_value=[200, 200])
    @mock.patch('builtins.input',           side_effect=([51*'a',
                                                          VALID_LOCAL_KEY_KDK[:-1],
                                                          VALID_LOCAL_KEY_KDK+'a',
                                                          VALID_LOCAL_KEY_KDK]))
    def test_get_b58_local_key(self, *_: Any) -> None:
        key = get_b58_key(B58_LOCAL_KEY, self.settings)
        self.assertIsInstance(key, bytes)
        self.assertEqual(len(key), SYMMETRIC_KEY_LENGTH)

    @mock.patch('time.sleep',               return_value=None)
    @mock.patch('shutil.get_terminal_size', return_value=[200, 200])
    @mock.patch('builtins.input',           side_effect=(2*[VALID_ECDHE_PUB_KEY[:-1],
                                                          VALID_ECDHE_PUB_KEY+'a',
                                                          VALID_ECDHE_PUB_KEY,
                                                          84*'a']))
    def test_get_b58_pub_key(self, *_: Any) -> None:
        for local_testing in [True, False]:
            self.settings.local_testing_mode = local_testing
            key = get_b58_key(B58_PUBLIC_KEY, self.settings)
            self.assertIsInstance(key, bytes)
            self.assertEqual(len(key), TFC_PUBLIC_KEY_LENGTH)

            with self.assertRaises(ValueError):
                get_b58_key(B58_PUBLIC_KEY, self.settings, nick_to_short_address('Alice'))

    @mock.patch('builtins.input',           return_value='')
    @mock.patch('shutil.get_terminal_size', return_value=[200, 200])
    def test_empty_pub_key_returns_empty_bytes(self, *_: Any) -> None:
        key = get_b58_key(B58_PUBLIC_KEY, self.settings)
        self.assertEqual(key, b'')


class TestNCBypassMsg(unittest.TestCase):

    @mock.patch('builtins.input', return_value='')
    def test_nc_bypass_msg(self, _: Any) -> None:
        settings = Settings(nc_bypass_messages=True)
        self.assertIsNone(nc_bypass_msg(NC_BYPASS_START, settings))
        self.assertIsNone(nc_bypass_msg(NC_BYPASS_STOP,  settings))


class TestPwdPrompt(unittest.TestCase):

    @mock.patch('getpass.getpass', return_value='test_password')
    def test_pwd_prompt(self, _: Any) -> None:
        self.assertEqual(pwd_prompt("test prompt"), 'test_password')


class TestYes(unittest.TestCase):

    @mock.patch('builtins.input', side_effect=['Invalid', '', 'invalid', 'Y', 'YES', 'N', 'NO',
                                               KeyboardInterrupt, KeyboardInterrupt, EOFError,
                                               EOFError, EOFError, KeyboardInterrupt])
    def test_yes(self, _: Any) -> None:
        self.assertTrue(yes('test prompt', head=1, tail=1))
        self.assertTrue(yes('test prompt'))

        self.assertFalse(yes('test prompt', head=1, tail=1))
        self.assertFalse(yes('test prompt'))

        self.assertTrue(yes('test prompt', head=1, tail=1, abort=True))
        self.assertFalse(yes('test prompt', abort=False))

        self.assertTrue(yes('test prompt', head=1, tail=1, abort=True))
        self.assertFalse(yes('test prompt', abort=False))

        with self.assertRaises(EOFError):
            self.assertFalse(yes('test prompt'))

        with self.assertRaises(KeyboardInterrupt):
            self.assertFalse(yes('test prompt'))


if __name__ == '__main__':
    unittest.main(exit=False)
