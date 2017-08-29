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

import argparse
import os
import types
import unittest

from src.common.misc    import ensure_dir, get_tab_complete_list, get_tab_completer, get_terminal_height
from src.common.misc    import get_terminal_width, ignored, process_arguments, readable_size, round_up, split_string
from src.common.misc    import split_byte_string, validate_account, validate_key_exchange, validate_nick
from src.common.statics import *

from tests.mock_classes import ContactList, GroupList, Settings
from tests.utils        import ignored


class TestEnsureDir(unittest.TestCase):

    def tearDown(self):
        with ignored(OSError):
            os.rmdir('test_dir/')

    def test_ensure_dir(self):
        self.assertIsNone(ensure_dir('test_dir/'))
        self.assertTrue(os.path.isdir('test_dir/'))


class TestTabCompleteList(unittest.TestCase):

    def setUp(self):
        self.contact_list = ContactList(nicks=['Alice', 'Bob'])
        self.group_list   = GroupList(groups=['testgroup'])
        self.settings     = Settings(key_list=['key1', 'key2'])

    def test_get_tab_complete_list(self):
        tab_complete_list = ['about', 'add ', 'all', 'clear', 'cmd', 'create ', 'exit', 'export ', 'false', 'file',
                             'fingerprints', 'group ', 'help', 'history ', 'join ', 'localkey', 'logging ', 'msg ', 'names',
                             'nick ', 'notify ', 'passwd ', 'psk', 'reset', 'rm', 'rmlogs ', 'set ', 'settings',
                             'store ', 'true', 'unread', 'key1 ', 'key2 ', 'alice@jabber.org ', 'user@jabber.org ',
                             'Alice ', 'bob@jabber.org ', 'Bob ', 'testgroup ', 'whisper ']

        self.assertEqual(set(get_tab_complete_list(self.contact_list, self.group_list, self.settings)), set(tab_complete_list))
        self.assertIsInstance(get_tab_completer(self.contact_list, self.group_list, self.settings), types.FunctionType)

        completer = get_tab_completer(self.contact_list, self.group_list, self.settings)
        options   = completer('a', state=0)

        self.assertEqual(options, 'about')
        self.assertIsNone(completer('a', state=5))


class TestGetTerminalHeight(unittest.TestCase):

    def test_get_terminal_height(self):
        self.assertIsInstance(get_terminal_height(), int)


class TestGetTerminalWidth(unittest.TestCase):

    def test_get_terminal_width(self):
        self.assertIsInstance(get_terminal_width(), int)


class TestIgnored(unittest.TestCase):

    @staticmethod
    def func():
        raise KeyboardInterrupt

    def test_ignored_contextmanager(self):
        raised = False
        try:
            with ignored(KeyboardInterrupt):
                TestIgnored.func()
        except KeyboardInterrupt:
            raised = True
        self.assertFalse(raised)


class TestProcessArguments(unittest.TestCase):

    def setUp(self):
        class MockParser(object):
            def __init__(self, *_, **__):
                pass

            def parse_args(self):
                class Args(object):
                    def __init__(self):
                        self.operation  = True
                        self.local_test = True
                        self.dd_sockets = True
                args = Args()
                return args

            def add_argument(self, *_, **__):
                pass

        self.o_argparse         = argparse.ArgumentParser
        argparse.ArgumentParser = MockParser

    def tearDown(self):
        argparse.ArgumentParser = self.o_argparse

    def test_process_arguments(self):
        self.assertEqual(process_arguments(), (RX, True, True))


class TestReadableSize(unittest.TestCase):

    def test_readable_size(self):
        sizes = ['', 'K', 'M', 'G', 'T', 'P', 'E', 'Z', 'Y']
        for i in range(0, 9):
            size = readable_size(1024 ** i)
            self.assertEqual(size, f'1.0{sizes[i]}B')


class TestRoundUp(unittest.TestCase):

    def test_round_up(self):
        self.assertEqual(round_up(1),  10)
        self.assertEqual(round_up(5),  10)
        self.assertEqual(round_up(8),  10)
        self.assertEqual(round_up(10), 10)
        self.assertEqual(round_up(11), 20)
        self.assertEqual(round_up(15), 20)
        self.assertEqual(round_up(18), 20)
        self.assertEqual(round_up(20), 20)
        self.assertEqual(round_up(21), 30)


class TestSplitString(unittest.TestCase):

    def test_split_string(self):
        self.assertEqual(split_string('teststring', 1),  ['t', 'e', 's', 't', 's', 't', 'r', 'i', 'n', 'g'])
        self.assertEqual(split_string('teststring', 2),  ['te', 'st', 'st', 'ri', 'ng'])
        self.assertEqual(split_string('teststring', 3),  ['tes', 'tst', 'rin', 'g'])
        self.assertEqual(split_string('teststring', 5),  ['tests', 'tring'])
        self.assertEqual(split_string('teststring', 10), ['teststring'])
        self.assertEqual(split_string('teststring', 15), ['teststring'])


class TestSplitByteString(unittest.TestCase):

    def test_split_byte_string(self):
        self.assertEqual(split_byte_string(b'teststring', 1),  [b't', b'e', b's', b't', b's', b't', b'r', b'i', b'n', b'g'])
        self.assertEqual(split_byte_string(b'teststring', 2),  [b'te', b'st', b'st', b'ri', b'ng'])
        self.assertEqual(split_byte_string(b'teststring', 3),  [b'tes', b'tst', b'rin', b'g'])
        self.assertEqual(split_byte_string(b'teststring', 5),  [b'tests', b'tring'])
        self.assertEqual(split_byte_string(b'teststring', 10), [b'teststring'])
        self.assertEqual(split_byte_string(b'teststring', 15), [b'teststring'])


class TestValidateAccount(unittest.TestCase):

    def test_validate_account(self):
        self.assertEqual(validate_account(248 * 'a' + '@a.com'), '')
        self.assertEqual(validate_account(249 * 'a' + '@a.com'), "Account must be shorter than 255 chars.")
        self.assertEqual(validate_account(250 * 'a' + '@a.com'), "Account must be shorter than 255 chars.")
        self.assertEqual(validate_account('bob@jabberorg'),      "Invalid account format.")
        self.assertEqual(validate_account('bobjabber.org'),      "Invalid account format.")
        self.assertEqual(validate_account('\x1fbobjabber.org'),  "Account must be printable.")


class TestValidateKeyExchange(unittest.TestCase):

    def test_validate_key_exchange(self):
        self.assertEqual(validate_key_exchange(''),       'Invalid key exchange selection.')
        self.assertEqual(validate_key_exchange('x2'),     'Invalid key exchange selection.')
        self.assertEqual(validate_key_exchange('x'),      '')
        self.assertEqual(validate_key_exchange('X'),      '')
        self.assertEqual(validate_key_exchange('x25519'), '')
        self.assertEqual(validate_key_exchange('X25519'), '')
        self.assertEqual(validate_key_exchange('p'),      '')
        self.assertEqual(validate_key_exchange('P'),      '')
        self.assertEqual(validate_key_exchange('psk'),    '')
        self.assertEqual(validate_key_exchange('PSK'),    '')


class TestValidateNick(unittest.TestCase):

    def setUp(self):
        self.contact_list = ContactList(nicks=['Alice', 'Bob'])
        self.group_list   = GroupList(groups=['testgroup'])

    def test_validate_nick(self):
        self.assertEqual(validate_nick("Alice_",    (self.contact_list, self.group_list, 'alice@jabber.org')), '')
        self.assertEqual(validate_nick(254*"a",     (self.contact_list, self.group_list, 'alice@jabber.org')), '')
        self.assertEqual(validate_nick(255*"a",     (self.contact_list, self.group_list, 'alice@jabber.org')), 'Nick must be shorter than 255 chars.')
        self.assertEqual(validate_nick("\x01Alice", (self.contact_list, self.group_list, 'alice@jabber.org')), 'Nick must be printable.')
        self.assertEqual(validate_nick('',          (self.contact_list, self.group_list, 'alice@jabber.org')), "Nick can't be empty.")
        self.assertEqual(validate_nick('Me',        (self.contact_list, self.group_list, 'alice@jabber.org')), "'Me' is a reserved nick.")
        self.assertEqual(validate_nick('-!-',       (self.contact_list, self.group_list, 'alice@jabber.org')), "'-!-' is a reserved nick.")
        self.assertEqual(validate_nick('local',     (self.contact_list, self.group_list, 'alice@jabber.org')), "Nick can't refer to local keyfile.")
        self.assertEqual(validate_nick('a@b.org',   (self.contact_list, self.group_list, 'alice@jabber.org')), "Nick can't have format of an account.")
        self.assertEqual(validate_nick('Bob',       (self.contact_list, self.group_list, 'alice@jabber.org')), 'Nick already in use.')
        self.assertEqual(validate_nick("Alice",     (self.contact_list, self.group_list, 'alice@jabber.org')), '')
        self.assertEqual(validate_nick("testgroup", (self.contact_list, self.group_list, 'alice@jabber.org')), "Nick can't be a group name.")


if __name__ == '__main__':
    unittest.main(exit=False)
