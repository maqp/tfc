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

from src.common.misc    import clear_screen, ensure_dir, get_tab_complete_list, get_tab_completer, get_tty_w
from src.common.misc    import process_arguments, resize_terminal, round_up, split_string, split_byte_string
from src.common.misc    import validate_account, validate_key_exchange, validate_nick

from tests.mock_classes import ContactList, GroupList, Settings


class TestMisc(unittest.TestCase):

    def test_clear_screen(self):
        self.assertIsNone(clear_screen())

    def test_ensure_dir(self):
        self.assertIsNone(ensure_dir('test_dir/'))
        try:
            os.rmdir('test_dir/')
        except OSError:
            pass

    def test_get_tab_complete_list(self):
        # Setup
        contact_list = ContactList(nicks=['Alice', 'Bob'])
        group_list   = GroupList(groups=['testgroup'])
        settings     = Settings(key_list = ['key1', 'key2'])

        tclst = ['about', 'add ', 'all', 'clear', 'cmd', 'create ', 'exit', 'export ', 'false', 'file', 'fingerprints',
                 'group ', 'help', 'history ', 'localkey', 'logging ', 'msg ', 'names', 'nick ', 'notify ', 'passwd ',
                 'psk', 'reset', 'rm ', 'set ', 'settings', 'store ', 'true', 'unread', 'key1 ', 'key2 ',
                 'alice@jabber.org ', 'user@jabber.org ', 'Alice ', 'bob@jabber.org ', 'Bob ', 'testgroup ']

        # Test
        self.assertEqual(set(get_tab_complete_list(contact_list, group_list, settings)), set(tclst))
        self.assertIsInstance(get_tab_completer(contact_list, group_list, settings), types.FunctionType)

    def test_get_tty_w(self):
        self.assertIsInstance(get_tty_w(), int)

    def test_process_arguments(self):
        # Setup
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

        o_argparse              = argparse.ArgumentParser
        argparse.ArgumentParser = MockParser

        # Test
        self.assertEqual(process_arguments(), ('rx', True, True))

        # Teardown
        argparse.ArgumentParser = o_argparse

    def test_resize_terminal(self):
        self.assertIsNone(resize_terminal(24, 80))

    def test_round_up(self):
        self.assertEqual(round_up(1), 10)
        self.assertEqual(round_up(5), 10)
        self.assertEqual(round_up(8), 10)
        self.assertEqual(round_up(10), 10)
        self.assertEqual(round_up(11), 20)
        self.assertEqual(round_up(15), 20)
        self.assertEqual(round_up(18), 20)
        self.assertEqual(round_up(20), 20)
        self.assertEqual(round_up(21), 30)

    def test_split_string(self):
        self.assertEqual(split_string('teststring', 1),  ['t', 'e', 's', 't', 's', 't', 'r', 'i', 'n', 'g'])
        self.assertEqual(split_string('teststring', 2),  ['te', 'st', 'st', 'ri', 'ng'])
        self.assertEqual(split_string('teststring', 3),  ['tes', 'tst', 'rin', 'g'])
        self.assertEqual(split_string('teststring', 5),  ['tests', 'tring'])
        self.assertEqual(split_string('teststring', 10), ['teststring'])
        self.assertEqual(split_string('teststring', 15), ['teststring'])

    def test_split_byte_string(self):
        self.assertEqual(split_byte_string(b'teststring', 1),  [b't', b'e', b's', b't', b's', b't', b'r', b'i', b'n', b'g'])
        self.assertEqual(split_byte_string(b'teststring', 2),  [b'te', b'st', b'st', b'ri', b'ng'])
        self.assertEqual(split_byte_string(b'teststring', 3),  [b'tes', b'tst', b'rin', b'g'])
        self.assertEqual(split_byte_string(b'teststring', 5),  [b'tests', b'tring'])
        self.assertEqual(split_byte_string(b'teststring', 10), [b'teststring'])
        self.assertEqual(split_byte_string(b'teststring', 15), [b'teststring'])

    def test_validate_account(self):
        self.assertEqual(validate_account(248 * 'a' + '@a.com'), (True,  ''))
        self.assertEqual(validate_account(249 * 'a' + '@a.com'), (False, "Account must be shorter than 255 chars."))
        self.assertEqual(validate_account(250 * 'a' + '@a.com'), (False, "Account must be shorter than 255 chars."))
        self.assertEqual(validate_account('bob@jabberorg'),      (False, "Invalid account format."))
        self.assertEqual(validate_account('bobjabber.org'),      (False, "Invalid account format."))
        self.assertEqual(validate_account('\x1fbobjabber.org'),  (False, "Account must be printable."))

    def test_validate_key_exchange(self):
        self.assertEqual(validate_key_exchange(''),      (False, 'Invalid key exchange selection.'))
        self.assertEqual(validate_key_exchange('ec'),    (False, 'Invalid key exchange selection.'))
        self.assertEqual(validate_key_exchange('e'),     (True,  ''))
        self.assertEqual(validate_key_exchange('E'),     (True,  ''))
        self.assertEqual(validate_key_exchange('ecdhe'), (True,  ''))
        self.assertEqual(validate_key_exchange('ECDHE'), (True,  ''))
        self.assertEqual(validate_key_exchange('p'),     (True,  ''))
        self.assertEqual(validate_key_exchange('P'),     (True,  ''))
        self.assertEqual(validate_key_exchange('psk'),   (True,  ''))
        self.assertEqual(validate_key_exchange('PSK'),   (True,  ''))

    def test_validate_nick(self):
        # Setup
        contact_list = ContactList(nicks=['Alice', 'Bob'])
        group_list   = GroupList(groups=['testgroup'])

        # Test
        self.assertEqual(validate_nick("Alice_",    (contact_list, group_list, 'alice@jabber.org')), (True, ''))
        self.assertEqual(validate_nick(254*"a",     (contact_list, group_list, 'alice@jabber.org')), (True, ''))
        self.assertEqual(validate_nick(255*"a",     (contact_list, group_list, 'alice@jabber.org')), (False, 'Nick must be shorter than 255 chars.'))
        self.assertEqual(validate_nick("\x01Alice", (contact_list, group_list, 'alice@jabber.org')), (False, 'Nick must be printable.'))
        self.assertEqual(validate_nick('',          (contact_list, group_list, 'alice@jabber.org')), (False, "Nick can't be empty."))
        self.assertEqual(validate_nick('Me',        (contact_list, group_list, 'alice@jabber.org')), (False, "'Me' is a reserved nick."))
        self.assertEqual(validate_nick('-!-',       (contact_list, group_list, 'alice@jabber.org')), (False, "'-!-' is a reserved nick."))
        self.assertEqual(validate_nick('local',     (contact_list, group_list, 'alice@jabber.org')), (False, "Nick can't refer to local keyfile."))
        self.assertEqual(validate_nick('a@b.org',   (contact_list, group_list, 'alice@jabber.org')), (False, "Nick can't have format of an account."))
        self.assertEqual(validate_nick('Bob',       (contact_list, group_list, 'alice@jabber.org')), (False, 'Nick already in use.'))
        self.assertEqual(validate_nick("Alice",     (contact_list, group_list, 'alice@jabber.org')), (True,  ''))
        self.assertEqual(validate_nick("testgroup", (contact_list, group_list, 'alice@jabber.org')), (False, "Nick can't be a group name."))


if __name__ == '__main__':
    unittest.main(exit=False)
