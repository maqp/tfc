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

import binascii
import getpass
import os
import struct
import time
import unittest
import zlib

from datetime        import datetime
from multiprocessing import Queue

from src.common.crypto   import byte_padding, encrypt_and_sign
from src.common.db_logs  import write_log_entry
from src.common.encoding import int_to_bytes
from src.common.statics  import *

from src.rx.packet   import PacketList
from src.rx.commands import change_master_key, change_nick, change_setting, clear_active_window, contact_setting, exit_tfc, log_command
from src.rx.commands import process_command, remove_contact, remove_log, reset_active_window, select_win_cmd, show_win_activity, wipe

from tests.mock_classes import ContactList, GroupList, KeyList, MasterKey, RxWindow, Settings, WindowList
from tests.utils        import assembly_packet_creator, cleanup, ignored, TFCTestCase


class TestProcessCommand(TFCTestCase):

    def setUp(self):
        self.ts               = datetime.now()
        self.settings         = Settings()
        self.master_key       = MasterKey()
        self.group_list       = GroupList()
        self.exit_queue       = Queue()
        self.pubkey_buf       = dict()
        self.window_list      = WindowList(nicks=[LOCAL_ID])
        self.contact_list     = ContactList(nicks=[LOCAL_ID])
        self.packet_list      = PacketList(self.settings, self.contact_list)
        self.key_list         = KeyList(nicks=[LOCAL_ID])
        self.key_set          = self.key_list.get_keyset(LOCAL_ID)
        self.key_set.rx_key   = bytes(KEY_LENGTH)
        self.key_set.rx_hek   = bytes(KEY_LENGTH)
        self.key_set.tx_harac = 1
        self.key_set.rx_harac = 1

    def create_packet(self, data, header=C_S_HEADER):
        payload           = zlib.compress(data, level=COMPRESSION_LEVEL)
        packet            = header + byte_padding(payload)
        harac_in_bytes    = int_to_bytes(self.key_set.tx_harac)
        encrypted_harac   = encrypt_and_sign(harac_in_bytes, self.key_set.tx_hek)
        encrypted_message = encrypt_and_sign(packet, self.key_set.tx_key)

        return COMMAND_PACKET_HEADER + encrypted_harac + encrypted_message

    def test_incomplete_command_raises_fr(self):
        self.assertFR("Incomplete command.",
                      process_command,
                      self.ts, self.create_packet(b'ZZ', header=C_L_HEADER), self.window_list, self.packet_list,
                      self.contact_list, self.key_list, self.group_list, self.settings,
                      self.master_key, self.pubkey_buf, self.exit_queue)

    def test_invalid_command_header(self):
        self.assertFR("Error: Received an invalid command.",
                      process_command,
                      self.ts, self.create_packet(b'ZZ'), self.window_list, self.packet_list,
                      self.contact_list, self.key_list, self.group_list, self.settings,
                      self.master_key, self.pubkey_buf, self.exit_queue)

    def test_process_command(self):
        self.assertFR(f"Error: Could not find log database.",
                      process_command,
                      self.ts, self.create_packet(LOG_REMOVE_HEADER), self.window_list, self.packet_list,
                      self.contact_list, self.key_list, self.group_list, self.settings,
                      self.master_key, self.pubkey_buf, self.exit_queue)


class TestShowWinActivity(TFCTestCase):

    def setUp(self):
        self.window_list         = WindowList()
        self.window_list.windows = [RxWindow(name='Alice', unread_messages=4),
                                    RxWindow(name='Bob',   unread_messages=15)]

    def test_function(self):
        self.assertPrints(f"""\
                              ┌─────────────────┐                               
                              │ Window activity │                               
                              │    Alice: 4     │                               
                              │     Bob: 15     │                               
                              └─────────────────┘                               
{5*(CURSOR_UP_ONE_LINE+CLEAR_ENTIRE_LINE)}""", show_win_activity, self.window_list)


class TestSelectSystemWindows(unittest.TestCase):

    def setUp(self):
        self.window_list         = WindowList()
        self.window_list.windows = [RxWindow(uid='alice@jabber.org', name='Alice'),
                                    RxWindow(uid='bob@jabber.org',   name='Bob')]

    def test_window_selection(self):
        self.assertIsNone(select_win_cmd(b'alice@jabber.org', self.window_list))
        self.assertEqual(self.window_list.active_win.name, 'Alice')

        self.assertIsNone(select_win_cmd(b'bob@jabber.org', self.window_list))
        self.assertEqual(self.window_list.active_win.name, 'Bob')

        self.assertIsNone(select_win_cmd(WIN_TYPE_FILE.encode(), self.window_list))
        self.assertEqual(self.window_list.active_win.uid, WIN_TYPE_FILE)


class TestClearActiveWindow(TFCTestCase):

    def test_function(self):
        self.assertPrints(CLEAR_ENTIRE_SCREEN + CURSOR_LEFT_UP_CORNER, clear_active_window)


class TestResetActiveWindow(unittest.TestCase):

    def setUp(self):
        self.cmd_data            = b'alice@jabber.org'
        self.window_list         = WindowList()
        self.window_list.windows = [RxWindow(uid='alice@jabber.org', name='Alice'),
                                    RxWindow(uid='bob@jabber.org',   name='Bob')]
        self.window              = self.window_list.get_window('alice@jabber.org')
        self.window.message_log  = [(datetime.now(), 'Hi Bob', 'alice@jabber.org', ORIGIN_CONTACT_HEADER)]

    def test_screen_reset(self):
        self.assertEqual(len(self.window.message_log), 1)
        self.assertIsNone(reset_active_window(self.cmd_data, self.window_list))
        self.assertEqual(len(self.window.message_log), 0)


class TestExitTFC(unittest.TestCase):

    def setUp(self):
        self.exit_queue = Queue()

    def tearDown(self):
        while not self.exit_queue.empty():
            self.exit_queue.get()
        time.sleep(0.1)
        self.exit_queue.close()

    def test_function(self):
        self.assertIsNone(exit_tfc(self.exit_queue))
        time.sleep(0.1)
        self.assertEqual(self.exit_queue.qsize(), 1)


class TestLogCommand(TFCTestCase):

    def setUp(self):
        self.cmd_data          = b'alice@jabber.org' + US_BYTE + int_to_bytes(1)
        self.ts                = datetime.now()
        self.window_list       = WindowList(nicks=['Alice', 'Bob'])
        self.window            = self.window_list.get_window('alice@jabber.org')
        self.window.type_print = 'contact'
        self.contact_list      = ContactList(nicks=['Alice', 'Bob'])
        self.group_list        = GroupList()
        self.settings          = Settings()
        self.master_key        = MasterKey()

        self.o_struct_pack = struct.pack
        struct.pack        = lambda *_: binascii.unhexlify('08ceae02')

    def tearDown(self):
        struct.pack = self.o_struct_pack
        cleanup()
        with ignored(OSError):
            os.remove('UtM - Plaintext log (None)')

    def test_print(self):
        self.assertFR(f"Error: Could not find log database.",
                      log_command, self.cmd_data, None, self.window_list, self.contact_list,
                      self.group_list, self.settings, self.master_key)

    def test_export(self):
        # Setup
        for p in assembly_packet_creator(MESSAGE, b'A short message'):
            write_log_entry(p, 'bob@jabber.org', self.settings, self.master_key, origin=ORIGIN_CONTACT_HEADER)

        # Test
        self.assertIsNone(log_command(self.cmd_data, self.ts, self.window_list, self.contact_list,
                                      self.group_list, self.settings, self.master_key))

        with open('UtM - Plaintext log (None)') as f:
            data = f.read()

        self.assertEqual(data, """\
Logfile of 1 most recent message to/from None
════════════════════════════════════════════════════════════════════════════════
00:54   Bob: A short message
<End of logfile>

""")


class TestRemoveLog(TFCTestCase):

    def setUp(self):
        self.win_name   = b'alice@jabber.org'
        self.settings   = Settings()
        self.master_key = MasterKey()

    def test_remove_logfile(self):
        self.assertFR(f"Error: Could not find log database.",
                      remove_log, self.win_name, self.settings, self.master_key)


class TestChangeMasterKey(unittest.TestCase):

    def setUp(self):
        self.o_getpass    = getpass.getpass
        self.ts           = datetime.now()
        self.master_key   = MasterKey()
        self.settings     = Settings()
        self.contact_list = ContactList(nicks=[LOCAL_ID])
        self.window_list  = WindowList(nicks=[LOCAL_ID])
        self.group_list   = GroupList()
        self.key_list     = KeyList()
        getpass.getpass   = lambda _: 'a'

    def tearDown(self):
        getpass.getpass = self.o_getpass
        cleanup()

    def test_master_key_change(self):
        # Setup
        write_log_entry(F_S_HEADER + bytes(PADDING_LEN), 'alice@jabber.org', self.settings, self.master_key)

        # Test
        self.assertEqual(self.master_key.master_key, bytes(KEY_LENGTH))
        self.assertIsNone(change_master_key(self.ts, self.window_list, self.contact_list, self.group_list,
                                            self.key_list, self.settings, self.master_key))
        self.assertNotEqual(self.master_key.master_key, bytes(KEY_LENGTH))


class TestChangeNick(TFCTestCase):

    def setUp(self):
        self.ts           = datetime.now()
        self.contact_list = ContactList(nicks=['Alice'])
        self.window_list  = WindowList(contact_list=self.contact_list)
        self.group_list   = GroupList()

    def test_nick_change(self):
        # Setup
        cmd_data = b'alice@jabber.org' + US_BYTE + b'Alice_'

        # Test
        self.assertIsNone(change_nick(cmd_data, self.ts, self.window_list, self.contact_list))
        self.assertEqual(self.contact_list.get_contact('alice@jabber.org').nick, 'Alice_')
        self.assertEqual(self.window_list.get_window('alice@jabber.org').name, 'Alice_')


class TestChangeSetting(TFCTestCase):

    def setUp(self):
        self.ts           = datetime.now()
        self.window_list  = WindowList()
        self.contact_list = ContactList()
        self.group_list   = GroupList()

    def test_invalid_setting_raises_r(self):
        # Setup
        cmd_data = b'setting' + US_BYTE + b'True'
        settings = Settings(key_list=[''])

        # Test
        self.assertFR("Error: Invalid setting 'setting'",
                      change_setting, cmd_data, self.ts, self.window_list, self.contact_list, self.group_list, settings)

    def test_valid_setting_change(self):
        # Setup
        cmd_data = b'serial_error_correction' + US_BYTE + b'5'
        settings = Settings(key_list=['serial_error_correction'])

        # Test
        self.assertIsNone(change_setting(cmd_data, self.ts, self.window_list, self.contact_list, self.group_list, settings))


class TestContactSetting(TFCTestCase):

    def setUp(self):
        self.ts           = datetime.fromtimestamp(1502750000)
        self.contact_list = ContactList(nicks=['Alice', 'Bob'])
        self.group_list   = GroupList(groups=['test_group', 'test_group2'])
        self.window_list  = WindowList(contact_list=self.contact_list,
                                       group_list=self.group_list)

    def test_invalid_window_raises_fr(self):
        # Setup
        cmd_data          = ENABLE + US_BYTE + b'bob@jabber.org'
        header            = CHANGE_LOGGING_HEADER
        self.contact_list = ContactList(nicks=['Alice'])
        self.window_list  = WindowList(contact_list=self.contact_list,
                                       group_list=self.group_list)
        # Test
        self.assertFR("Error: Found no window for 'bob@jabber.org'",
                      contact_setting, cmd_data, self.ts, self.window_list, self.contact_list, self.group_list, header)

    def test_setting_change_contact(self):
        # Setup
        self.window                 = self.window_list.get_window('bob@jabber.org')
        self.window.type            = WIN_TYPE_CONTACT
        self.window.type_print      = 'contact'
        self.window.window_contacts = self.contact_list.contacts

        # Test
        for attr, header in [('log_messages', CHANGE_LOGGING_HEADER), ('notifications', CHANGE_NOTIFY_HEADER), ('file_reception', CHANGE_FILE_R_HEADER)]:
            for s in [ENABLE, ENABLE, DISABLE, DISABLE]:
                cmd_data = s + US_BYTE + b'bob@jabber.org'
                self.assertIsNone(contact_setting(cmd_data, self.ts, self.window_list, self.contact_list, self.group_list, header))
                self.assertEqual(self.contact_list.get_contact('bob@jabber.org').__getattribute__(attr), (s==ENABLE))

    def test_setting_change_group(self):
        # Setup
        self.window                 = self.window_list.get_window('test_group')
        self.window.type            = WIN_TYPE_GROUP
        self.window.type_print      = 'group'
        self.window.window_contacts = self.group_list.get_group('test_group').members

        # Test
        for attr, header in [('log_messages', CHANGE_LOGGING_HEADER), ('notifications', CHANGE_NOTIFY_HEADER), ('file_reception', CHANGE_FILE_R_HEADER)]:
            for s in [ENABLE, ENABLE, DISABLE, DISABLE]:
                cmd_data = s + US_BYTE + b'test_group'
                self.assertIsNone(contact_setting(cmd_data, self.ts, self.window_list, self.contact_list, self.group_list, header))

                if header in [CHANGE_LOGGING_HEADER, CHANGE_NOTIFY_HEADER]:
                    self.assertEqual(self.group_list.get_group('test_group').__getattribute__(attr), (s==ENABLE))

                if header == CHANGE_FILE_R_HEADER:
                    for m in self.group_list.get_group('test_group').members:
                        self.assertEqual(m.file_reception, (s==ENABLE))

    def test_setting_change_all(self):
        # Setup
        self.window                 = self.window_list.get_window('bob@jabber.org')
        self.window.type            = WIN_TYPE_CONTACT
        self.window.type_print      = 'contact'
        self.window.window_contacts = self.contact_list.contacts

        # Test
        for attr, header in [('log_messages', CHANGE_LOGGING_HEADER), ('notifications', CHANGE_NOTIFY_HEADER), ('file_reception', CHANGE_FILE_R_HEADER)]:
            for s in [ENABLE, ENABLE, DISABLE, DISABLE]:
                cmd_data = s.upper() + US_BYTE
                self.assertIsNone(contact_setting(cmd_data, self.ts, self.window_list, self.contact_list, self.group_list, header))

                if header in [CHANGE_LOGGING_HEADER, CHANGE_NOTIFY_HEADER]:
                    for c in self.contact_list.get_list_of_contacts():
                        self.assertEqual(c.__getattribute__(attr), (s==ENABLE))
                    for g in self.group_list.groups:
                        self.assertEqual(g.__getattribute__(attr), (s == ENABLE))

                if header == CHANGE_FILE_R_HEADER:
                    for c in self.contact_list.get_list_of_contacts():
                        self.assertEqual(c.__getattribute__(attr), (s==ENABLE))


class TestRemoveContact(TFCTestCase):

    def setUp(self):
        self.ts          = datetime.now()
        self.window_list = WindowList()
        self.cmd_data    = b'bob@jabber.org'

    def test_no_contact_raises_fr(self):
        # Setup
        contact_list = ContactList(nicks=['Alice'])
        group_list   = GroupList(groups=[])
        key_list     = KeyList(nicks=['Alice'])

        # Test
        self.assertFR("RxM has no account 'bob@jabber.org' to remove.",
                      remove_contact, self.cmd_data, self.ts, self.window_list, contact_list, group_list, key_list)

    def test_successful_removal(self):
        # Setup
        contact_list             = ContactList(nicks=['Alice', 'Bob'])
        contact                  = contact_list.get_contact('bob@jabber.org')
        group_list               = GroupList(groups=['testgroup', 'testgroup2'])
        key_list                 = KeyList(nicks=['Alice', 'Bob'])
        self.window_list.windows = [RxWindow(type=WIN_TYPE_GROUP)]

        # Test
        self.assertIsNone(remove_contact(self.cmd_data, self.ts, self.window_list, contact_list, group_list, key_list))
        self.assertFalse(contact_list.has_contact('bob@jabber.org'))
        self.assertFalse(key_list.has_keyset('bob@jabber.org'))
        for g in group_list:
            self.assertFalse(contact in g.members)


class TestWipe(unittest.TestCase):

    def setUp(self):
        self.exit_queue = Queue()

    def test_wipe_command(self):
        self.assertIsNone(wipe(self.exit_queue))
        self.assertEqual(self.exit_queue.get(), WIPE)


if __name__ == '__main__':
    unittest.main(exit=False)
