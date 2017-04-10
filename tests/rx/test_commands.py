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

import datetime
import getpass
import os
import unittest

from src.common.encoding import int_to_bytes
from src.common.db_logs  import write_log_entry
from src.common.statics  import *
from src.rx.commands     import show_win_activity, select_win_cmd, clear_active_window, reset_active_window, display_logs
from src.rx.commands     import export_logs, change_master_key, change_nick, change_setting, contact_setting, remove_contact

from tests.mock_classes  import Settings, ContactList, GroupList, MasterKey, RxMWindow, WindowList, KeyList
from tests.utils         import cleanup, TFCTestCase


class TestShowWinActivity(unittest.TestCase):

    def test_function(self):
        # Setup
        window_list         = WindowList()
        window_list.windows = [RxMWindow(name='Alice', unread_messages=4)]

        # Test
        self.assertIsNone(show_win_activity(window_list))


class TestSelectWinCMD(unittest.TestCase):

    def test_function(self):
        # Setup
        window_list         = WindowList()
        window_list.windows = [RxMWindow(uid='alice@jabber.org', name='Alice'),
                               RxMWindow(uid='bob@jabber.org',   name='Bob')]

        # Test
        self.assertIsNone(select_win_cmd(b'alice@jabber.org', window_list))
        self.assertEqual(window_list.active_win.name, 'Alice')

        self.assertIsNone(select_win_cmd(b'bob@jabber.org', window_list))
        self.assertEqual(window_list.active_win.name, 'Bob')

        self.assertIsNone(select_win_cmd(FILE_R_WIN_ID_BYTES, window_list))
        self.assertEqual(window_list.active_win.uid, 'file_window')


class TestClearActiveWindow(unittest.TestCase):

    def test_function(self):
        self.assertIsNone(clear_active_window())


class TestResetActiveWindow(unittest.TestCase):

    def test_function(self):
        # Setup
        cmd_data            = b'alice@jabber.org'
        window_list         = WindowList()
        window_list.windows = [RxMWindow(uid='alice@jabber.org', name='Alice'),
                               RxMWindow(uid='bob@jabber.org',   name='Bob')]

        # Test
        self.assertIsNone(reset_active_window(cmd_data, window_list))


class TestDisplayLogs(TFCTestCase):

    def test_function(self):
        # Setup
        no_msg       = int_to_bytes(1)
        cmd_data     = b'alice@jabber.org' + US_BYTE + no_msg
        window_list  = WindowList()
        contact_list = ContactList()
        settings     = Settings()
        master_key   = MasterKey()

        # Test
        self.assertFR("Error: Could not find 'user_data/ut_logs'.", display_logs, cmd_data, window_list, contact_list, settings, master_key)


class TestExportLogs(TFCTestCase):

    def test_function(self):
        # Setup
        ts           = datetime.datetime.now()
        no_msg       = int_to_bytes(1)
        cmd_data     = b'alice@jabber.org' + US_BYTE + no_msg
        window_list  = WindowList()
        contact_list = ContactList()
        settings     = Settings()
        master_key   = MasterKey()
        write_log_entry(F_S_HEADER + bytes(255), 'alice@jabber.org', settings, master_key)

        # Test
        self.assertIsNone(export_logs(cmd_data, ts, window_list, contact_list, settings, master_key))
        os.remove('Unittest - Plaintext log (None)')
        cleanup()


class TestChangeMasterKey(unittest.TestCase):

    def test_function(self):
        # Setup
        master_key      = MasterKey()
        settings        = Settings()
        ts              = datetime.datetime.now()
        o_getpass       = getpass.getpass
        window_list     = WindowList()
        contact_list    = ContactList()
        group_list      = GroupList()
        key_list        = KeyList()
        getpass.getpass = lambda x: 'a'

        write_log_entry(F_S_HEADER + bytes(255), 'alice@jabber.org', settings, master_key)

        # Test
        self.assertEqual(master_key.master_key, bytes(32))
        self.assertIsNone(change_master_key(ts, window_list, contact_list, group_list, key_list, settings, master_key))
        self.assertNotEqual(master_key.master_key, bytes(32))

        # Teardown
        getpass.getpass = o_getpass
        cleanup()


class TestChangeNick(TFCTestCase):

    def test_invalid_nick_raises_fr(self):
        # Setup
        cmd_data     = b'alice@jabber.org' + US_BYTE + b'Me'
        ts           = datetime.datetime.now()
        window_list  = WindowList()
        contact_list = ContactList()
        group_list   = GroupList()

        # Test
        self.assertFR("'Me' is a reserved nick.", change_nick, cmd_data, ts, window_list, contact_list, group_list)


    def test_nick_change(self):
        # Setup
        cmd_data     = b'alice@jabber.org' + US_BYTE + b'Alice_'
        ts           = datetime.datetime.now()
        window_list  = WindowList()
        contact_list = ContactList(nicks=['Alice'])
        group_list   = GroupList()

        # Test
        self.assertIsNone(change_nick(cmd_data, ts, window_list, contact_list, group_list))


class TestChangeSetting(TFCTestCase):

    def test_invalid_setting_raises_r(self):
        # Setup
        cmd_data     = b'setting' + US_BYTE + b'True'
        ts           = datetime.datetime.now()
        window_list  = WindowList()
        contact_list = ContactList()
        group_list   = GroupList()
        settings     = Settings(key_list=[''])

        # Test
        self.assertFR("Invalid setting setting.", change_setting, cmd_data, ts, window_list, contact_list, group_list, settings)

    def test_valid_setting_change(self):
        # Setup
        cmd_data     = b'e_correction_ratio' + US_BYTE + b'5'
        ts           = datetime.datetime.now()
        window_list  = WindowList()
        contact_list = ContactList()
        group_list   = GroupList()
        settings     = Settings(key_list=['e_correction_ratio'])

        # Test
        self.assertIsNone(change_setting(cmd_data, ts, window_list, contact_list, group_list, settings))


class TestContactSetting(TFCTestCase):

    def test_invalid_window_raises_fr(self):
        # Setup
        cmd_data     = b'e' + US_BYTE + b'bob@jabber.org'
        ts           = datetime.datetime.now()
        window_list  = WindowList()
        contact_list = ContactList()
        group_list   = GroupList()
        setting_type = 'L'

        # Test
        self.assertFR("Error: Found no window for bob@jabber.org.", contact_setting, cmd_data, ts, window_list ,contact_list, group_list, setting_type)

    def test_enable_logging_contact(self):
        # Setup
        cmd_data     = b'e' + US_BYTE + b'bob@jabber.org'
        ts           = datetime.datetime.now()
        contact_list = ContactList(nicks=['Bob'])
        window_list  = WindowList(windows=[RxMWindow(type='contact', name='Bob', uid='bob@jabber.org')])
        group_list   = GroupList()
        setting_type = 'L'

        # Test
        contact_list.get_contact('bob@jabber.org').log_messages = False
        self.assertFalse(contact_list.get_contact('bob@jabber.org').log_messages)
        self.assertIsNone(contact_setting(cmd_data, ts, window_list, contact_list, group_list, setting_type))
        self.assertTrue(contact_list.get_contact('bob@jabber.org').log_messages)

    def test_enable_logging_group(self):
        # Setup
        cmd_data     = b'e' + US_BYTE + b'testgroup'
        ts           = datetime.datetime.now()
        contact_list = ContactList(nicks=['Bob'])
        window_list  = WindowList(windows=[RxMWindow(type='group', name='testgroup', uid='testgroup')])
        group_list   = GroupList(groups=['testgroup'])
        setting_type = 'L'

        # Test
        group_list.get_group('testgroup').log_messages = False
        self.assertIsNone(contact_setting(cmd_data, ts, window_list, contact_list, group_list, setting_type))
        self.assertTrue(group_list.get_group('testgroup').log_messages)

    def test_enable_logging_all(self):
        # Setup
        cmd_data     = b'E'
        ts           = datetime.datetime.now()
        contact_list = ContactList(nicks=['Alice', 'Bob', 'Charlie'])
        window_list  = WindowList(windows=[RxMWindow(type='group', name='testgroup', uid='testgroup')])
        group_list   = GroupList(groups=['testgroup'])
        setting_type = 'L'

        # Test
        for c in contact_list:
            c.log_messages = False

        group_list.get_group('testgroup').log_messages = False
        self.assertIsNone(contact_setting(cmd_data, ts, window_list, contact_list, group_list, setting_type))
        self.assertTrue(group_list.get_group('testgroup').log_messages)
        for c in contact_list:
            self.assertTrue(c.log_messages)

    def test_enable_file_reception_group(self):
        # Setup
        cmd_data     = b'd' + US_BYTE + b'testgroup'
        ts           = datetime.datetime.now()
        contact_list = ContactList(nicks=['Bob', 'Alice'])
        group_list   = GroupList(groups=['testgroup'])
        window_list  = WindowList(windows=[RxMWindow(type='group', name='testgroup', uid='testgroup')])
        setting_type = 'F'

        for c in contact_list:
            self.assertTrue(c.file_reception)

        # Test
        self.assertIsNone(contact_setting(cmd_data, ts, window_list, contact_list, group_list, setting_type))

        for c in contact_list:
            self.assertFalse(c.file_reception)


class TestRemoveContact(unittest.TestCase):

    def test_no_contact(self):
        # Setup
        cmd_data     = b'bob@jabber.org'
        ts           = datetime.datetime.now()
        contact_list = ContactList(nicks=['Alice'])
        group_list   = GroupList(groups=[])
        key_list     = KeyList(nicks=['Alice'])
        window_list  = WindowList()

        # Test
        self.assertIsNone(remove_contact(cmd_data, ts, window_list, contact_list, group_list, key_list))


    def test_successful_removal(self):
        # Setup
        cmd_data     = b'bob@jabber.org'
        ts           = datetime.datetime.now()
        contact_list = ContactList(nicks=['Alice', 'Bob'])
        contact      = contact_list.get_contact('bob@jabber.org')
        group_list   = GroupList(groups=['testgroup', 'testgroup2'])
        key_list     = KeyList(nicks=['Alice', 'Bob'])
        window_list  = WindowList()

        # Test
        self.assertIsNone(remove_contact(cmd_data, ts, window_list, contact_list, group_list, key_list))
        self.assertFalse(contact_list.has_contact('bob@jabber.org'))
        self.assertFalse(key_list.has_keyset('bob@jabber.org'))
        for g in group_list:
            self.assertFalse(contact in g.members)


if __name__ == '__main__':
    unittest.main(exit=False)
