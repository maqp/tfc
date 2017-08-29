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
import os
import shutil
import unittest

from datetime import datetime

from src.common.encoding import int_to_bytes
from src.common.statics  import *

from src.rx.messages import process_message
from src.rx.windows  import WindowList
from src.rx.packet   import PacketList

from tests.mock_classes import ContactList, KeyList, GroupList, Settings, MasterKey
from tests.utils        import assembly_packet_creator, cleanup, ignored, TFCTestCase


class TestProcessMessage(TFCTestCase):

    def setUp(self):
        self.msg = ("Lorem ipsum dolor sit amet, consectetur adipiscing elit. Aenean condimentum consectetur purus quis"
                    " dapibus. Fusce venenatis lacus ut rhoncus faucibus. Cras sollicitudin commodo sapien, sed bibendu"
                    "m velit maximus in. Aliquam ac metus risus. Sed cursus ornare luctus. Integer aliquet lectus id ma"
                    "ssa blandit imperdiet. Ut sed massa eget quam facilisis rutrum. Mauris eget luctus nisl. Sed ut el"
                    "it iaculis, faucibus lacus eget, sodales magna. Nunc sed commodo arcu. In hac habitasse platea dic"
                    "tumst. Integer luctus aliquam justo, at vestibulum dolor iaculis ac. Etiam laoreet est eget odio r"
                    "utrum, vel malesuada lorem rhoncus. Cras finibus in neque eu euismod. Nulla facilisi. Nunc nec ali"
                    "quam quam, quis ullamcorper leo. Nunc egestas lectus eget est porttitor, in iaculis felis sceleris"
                    "que. In sem elit, fringilla id viverra commodo, sagittis varius purus. Pellentesque rutrum loborti"
                    "s neque a facilisis. Mauris id tortor placerat, aliquam dolor ac, venenatis arcu.").encode()

        self.ts              = datetime.now()
        self.master_key      = MasterKey()
        self.settings        = Settings(logfile_masking=True)

        self.contact_list    = ContactList(nicks=['Alice', 'Bob', 'Charlie', LOCAL_ID])
        self.key_list        = KeyList(    nicks=['Alice', 'Bob', 'Charlie', LOCAL_ID])
        self.group_list      = GroupList( groups=['testgroup'])
        self.packet_list     = PacketList(contact_list=self.contact_list, settings=self.settings)
        self.window_list     = WindowList(contact_list=self.contact_list, settings=self.settings, group_list=self.group_list, packet_list=self.packet_list)
        self.group_list.get_group('testgroup').log_messages = True
        for account in self.contact_list.get_list_of_accounts():
            keyset          = self.key_list.get_keyset(account)
            keyset.tx_harac = 1
            keyset.rx_harac = 1
            keyset.tx_hek   = KEY_LENGTH * b'\x01'
            keyset.rx_hek   = KEY_LENGTH * b'\x01'
            keyset.tx_key   = KEY_LENGTH * b'\x01'
            keyset.rx_key   = KEY_LENGTH * b'\x01'

        self.message = b'testgroup' + US_BYTE + b'bob@jabber.org' + US_BYTE + b'charlie@jabber.org'

    def tearDown(self):
        cleanup()
        with ignored(FileNotFoundError):
            shutil.rmtree(DIR_RX_FILES)

    # Private messages
    def test_private_msg_from_contact(self):
        # Setup
        assembly_ct_list = assembly_packet_creator(MESSAGE, self.msg, ORIGIN_CONTACT_HEADER, encrypt=True)

        # Test
        for p in assembly_ct_list:
            self.assertIsNone(process_message(self.ts, p, self.window_list, self.packet_list, self.contact_list,
                                              self.key_list, self.group_list, self.settings, self.master_key))
        self.assertEqual(os.path.getsize(f'{DIR_USER_DATA}ut_logs'), len(assembly_ct_list)*LOG_ENTRY_LENGTH)

    def test_private_msg_from_user(self):
        # Setup
        assembly_ct_list = assembly_packet_creator(MESSAGE, self.msg, ORIGIN_USER_HEADER, encrypt=True)

        # Test
        for p in assembly_ct_list:
            self.assertIsNone(process_message(self.ts, p, self.window_list, self.packet_list, self.contact_list,
                                              self.key_list, self.group_list, self.settings, self.master_key))
        self.assertEqual(os.path.getsize(f'{DIR_USER_DATA}ut_logs'), len(assembly_ct_list) * LOG_ENTRY_LENGTH)

    # Whispered messages
    def test_whisper_msg_from_contact(self):
        # Setup
        assembly_ct_list = assembly_packet_creator(MESSAGE, self.msg, ORIGIN_CONTACT_HEADER, encrypt=True, header=WHISPER_MESSAGE_HEADER)

        # Test
        for p in assembly_ct_list[:-1]:
            self.assertIsNone(process_message(self.ts, p, self.window_list, self.packet_list, self.contact_list,
                                              self.key_list, self.group_list, self.settings, self.master_key))

        for p in assembly_ct_list[-1:]:
            self.assertFR("Key message message complete.",
                          process_message, self.ts, p, self.window_list, self.packet_list,
                          self.contact_list, self.key_list, self.group_list, self.settings, self.master_key)
        self.assertEqual(os.path.getsize(f'{DIR_USER_DATA}ut_logs'), len(assembly_ct_list)*LOG_ENTRY_LENGTH)

    def test_whisper_msg_from_user(self):
        # Setup
        assembly_ct_list = assembly_packet_creator(MESSAGE, self.msg, ORIGIN_USER_HEADER, encrypt=True, header=WHISPER_MESSAGE_HEADER)

        # Test
        for p in assembly_ct_list[:-1]:
            self.assertIsNone(process_message(self.ts, p, self.window_list, self.packet_list, self.contact_list,
                                              self.key_list, self.group_list, self.settings, self.master_key))

        for p in assembly_ct_list[-1:]:
            self.assertFR("Key message message complete.",
                          process_message, self.ts, p, self.window_list, self.packet_list,
                          self.contact_list, self.key_list, self.group_list, self.settings, self.master_key)
        self.assertEqual(os.path.getsize(f'{DIR_USER_DATA}ut_logs'), len(assembly_ct_list)*LOG_ENTRY_LENGTH)

    def test_empty_whisper_msg_from_user(self):
        # Setup
        assembly_ct_list = assembly_packet_creator(MESSAGE, b' ', ORIGIN_USER_HEADER, encrypt=True, header=WHISPER_MESSAGE_HEADER)

        # Test
        for p in assembly_ct_list[:-1]:
            self.assertIsNone(process_message(self.ts, p, self.window_list, self.packet_list, self.contact_list,
                                              self.key_list, self.group_list, self.settings, self.master_key))

        for p in assembly_ct_list[-1:]:
            self.assertFR("Key message message complete.",
                          process_message, self.ts, p, self.window_list, self.packet_list,
                          self.contact_list, self.key_list, self.group_list, self.settings, self.master_key)
        self.assertEqual(os.path.getsize(f'{DIR_USER_DATA}ut_logs'), len(assembly_ct_list)*LOG_ENTRY_LENGTH)

    # Group messages
    def test_invalid_encoding_raises_fr(self):
        encrypted_packet = assembly_packet_creator(MESSAGE, b'test', ORIGIN_CONTACT_HEADER, group_name='testgroup', encrypt=True, break_g_name=True)[0]

        # Test
        self.assertFR("Error: Received an invalid group message.",
                      process_message, self.ts, encrypted_packet, self.window_list, self.packet_list,
                      self.contact_list, self.key_list, self.group_list, self.settings, self.master_key)
        self.assertEqual(os.path.getsize(f'{DIR_USER_DATA}ut_logs'), LOG_ENTRY_LENGTH)

    def test_invalid_message_header_raises_fr(self):
        # Setup
        encrypted_packet = assembly_packet_creator(MESSAGE, b'testgroup', ORIGIN_CONTACT_HEADER, header=b'Z', encrypt=True)[0]

        # Test
        self.assertFR("Error: Message from contact had an invalid header.",
                          process_message, self.ts, encrypted_packet, self.window_list, self.packet_list,
                          self.contact_list, self.key_list, self.group_list, self.settings, self.master_key)
        self.assertEqual(os.path.getsize(f'{DIR_USER_DATA}ut_logs'), LOG_ENTRY_LENGTH)

    def test_invalid_window_raises_fr(self):
        # Setup
        encrypted_packet = assembly_packet_creator(MESSAGE, b'test', ORIGIN_CONTACT_HEADER, group_name='test_group', encrypt=True)[0]

        # Test
        self.assertFR("Error: Received message to unknown group.",
                      process_message, self.ts, encrypted_packet, self.window_list, self.packet_list,
                      self.contact_list, self.key_list, self.group_list, self.settings, self.master_key)
        self.assertEqual(os.path.getsize(f'{DIR_USER_DATA}ut_logs'), LOG_ENTRY_LENGTH)

    def test_contact_not_in_group_raises_fr(self):
        # Setup
        encrypted_packet = assembly_packet_creator(MESSAGE, b'test', ORIGIN_CONTACT_HEADER, group_name='testgroup', encrypt=True, origin_acco=b'charlie@jabber.org')[0]

        # Test
        self.assertFR("Error: Account is not member of group.",
                      process_message, self.ts, encrypted_packet, self.window_list, self.packet_list,
                      self.contact_list, self.key_list, self.group_list, self.settings, self.master_key)
        self.assertEqual(os.path.getsize(f'{DIR_USER_DATA}ut_logs'), LOG_ENTRY_LENGTH)

    def test_normal_group_msg_from_contact(self):
        # Setup
        assembly_ct_list = assembly_packet_creator(MESSAGE, self.msg, ORIGIN_CONTACT_HEADER, group_name='testgroup', encrypt=True)

        for p in assembly_ct_list:
            self.assertIsNone(process_message(self.ts, p, self.window_list, self.packet_list, self.contact_list,
                                              self.key_list, self.group_list, self.settings, self.master_key))
        self.assertEqual(os.path.getsize(f'{DIR_USER_DATA}ut_logs'), len(assembly_ct_list)*LOG_ENTRY_LENGTH)

    def test_normal_group_msg_from_user(self):
        # Setup
        assembly_ct_list = assembly_packet_creator(MESSAGE, self.msg, ORIGIN_USER_HEADER, group_name='testgroup', encrypt=True)

        for p in assembly_ct_list:
            self.assertIsNone(process_message(self.ts, p, self.window_list, self.packet_list, self.contact_list,
                                              self.key_list, self.group_list, self.settings, self.master_key))
        self.assertEqual(os.path.getsize(f'{DIR_USER_DATA}ut_logs'), len(assembly_ct_list)*LOG_ENTRY_LENGTH)

    # Group management messages
    def test_group_invitation_msg_from_contact(self):
        # Setup
        assembly_ct_list = assembly_packet_creator(MESSAGE, self.message, ORIGIN_CONTACT_HEADER,
                                                   header=GROUP_MSG_INVITEJOIN_HEADER, encrypt=True)

        # Test
        for p in assembly_ct_list[:-1]:
            self.assertIsNone(process_message(self.ts, p, self.window_list, self.packet_list, self.contact_list,
                                              self.key_list, self.group_list, self.settings, self.master_key))

        for p in assembly_ct_list[-1:]:
            self.assertFR("Group management message complete.",
                          process_message, self.ts, p, self.window_list, self.packet_list,
                          self.contact_list, self.key_list, self.group_list, self.settings, self.master_key)
        self.assertEqual(os.path.getsize(f'{DIR_USER_DATA}ut_logs'), len(assembly_ct_list)*LOG_ENTRY_LENGTH)

    def test_group_invitation_msg_from_user(self):
        # Setup
        assembly_ct_list = assembly_packet_creator(MESSAGE, self.message, ORIGIN_USER_HEADER,
                                                   header=GROUP_MSG_INVITEJOIN_HEADER, encrypt=True)

        # Test
        for p in assembly_ct_list[:-1]:
            self.assertIsNone(process_message(self.ts, p, self.window_list, self.packet_list, self.contact_list,
                                              self.key_list, self.group_list, self.settings, self.master_key))

        for p in assembly_ct_list[-1:]:
            self.assertFR("Ignored group management message from user.",
                          process_message, self.ts, p, self.window_list, self.packet_list,
                          self.contact_list, self.key_list, self.group_list, self.settings, self.master_key)
        self.assertEqual(os.path.getsize(f'{DIR_USER_DATA}ut_logs'), len(assembly_ct_list)*LOG_ENTRY_LENGTH)

    def test_group_add_member_msg_from_contact(self):
        # Setup
        assembly_ct_list = assembly_packet_creator(MESSAGE, self.message, ORIGIN_CONTACT_HEADER,
                                                   header=GROUP_MSG_MEMBER_ADD_HEADER, encrypt=True)

        # Test
        for p in assembly_ct_list[:-1]:
            self.assertIsNone(process_message(self.ts, p, self.window_list, self.packet_list, self.contact_list,
                                              self.key_list, self.group_list, self.settings, self.master_key))

        for p in assembly_ct_list[-1:]:
            self.assertFR("Group management message complete.",
                          process_message, self.ts, p, self.window_list, self.packet_list,
                          self.contact_list, self.key_list, self.group_list, self.settings, self.master_key)
        self.assertEqual(os.path.getsize(f'{DIR_USER_DATA}ut_logs'), len(assembly_ct_list)*LOG_ENTRY_LENGTH)

    def test_group_remove_member_msg_from_contact(self):
        # Setup
        assembly_ct_list = assembly_packet_creator(MESSAGE, self.message, ORIGIN_CONTACT_HEADER,
                                                   header=GROUP_MSG_MEMBER_REM_HEADER, encrypt=True)

        # Test
        for p in assembly_ct_list[:-1]:
            self.assertIsNone(process_message(self.ts, p, self.window_list, self.packet_list, self.contact_list,
                                              self.key_list, self.group_list, self.settings, self.master_key))

        for p in assembly_ct_list[-1:]:
            self.assertFR("Group management message complete.",
                          process_message, self.ts, p, self.window_list, self.packet_list,
                          self.contact_list, self.key_list, self.group_list, self.settings, self.master_key)
        self.assertEqual(os.path.getsize(f'{DIR_USER_DATA}ut_logs'), len(assembly_ct_list)*LOG_ENTRY_LENGTH)

    def test_group_exit_msg_from_contact(self):
        # Setup
        assembly_ct_list = assembly_packet_creator(MESSAGE, b'testgroup', ORIGIN_CONTACT_HEADER,
                                                   header=GROUP_MSG_EXIT_GROUP_HEADER, encrypt=True)

        # Test
        for p in assembly_ct_list[:-1]:
            self.assertIsNone(process_message(self.ts, p, self.window_list, self.packet_list, self.contact_list,
                                              self.key_list, self.group_list, self.settings, self.master_key))

        for p in assembly_ct_list[-1:]:
            self.assertFR("Group management message complete.",
                          process_message, self.ts, p, self.window_list, self.packet_list,
                          self.contact_list, self.key_list, self.group_list, self.settings, self.master_key)
        self.assertEqual(os.path.getsize(f'{DIR_USER_DATA}ut_logs'), len(assembly_ct_list)*LOG_ENTRY_LENGTH)

    def test_invalid_encoding_in_group_management_message_raises_fr_but_is_logged(self):
        # Setup
        message          = b'testgroup' + US_BYTE + b'bob@jabber.org' + US_BYTE + binascii.unhexlify('a466c02c221cb135')
        encrypted_packet = assembly_packet_creator(MESSAGE, message, ORIGIN_CONTACT_HEADER, header=GROUP_MSG_INVITEJOIN_HEADER, encrypt=True)[0]

        self.settings.logfile_masking = True
        self.contact_list.get_contact('bob@jabber.org').log_messages = True

        # Test
        self.assertFR("Error: Received group management message had invalid encoding.",
                      process_message, self.ts, encrypted_packet, self.window_list, self.packet_list,
                      self.contact_list, self.key_list, self.group_list, self.settings, self.master_key)
        self.assertEqual(os.path.getsize(f'{DIR_USER_DATA}ut_logs'), LOG_ENTRY_LENGTH)

    # Files
    def test_file(self):
        # Setup
        assembly_ct_list = assembly_packet_creator(FILE, origin=ORIGIN_CONTACT_HEADER, encrypt=True)

        # Test
        for p in assembly_ct_list[:-1]:
            self.assertIsNone(process_message(self.ts, p, self.window_list, self.packet_list, self.contact_list,
                                              self.key_list, self.group_list, self.settings, self.master_key))

        for p in assembly_ct_list[-1:]:
            self.assertFR("File storage complete.",
                          process_message, self.ts, p, self.window_list, self.packet_list,
                          self.contact_list, self.key_list, self.group_list, self.settings, self.master_key)
        self.assertEqual(os.path.getsize(f'{DIR_USER_DATA}ut_logs'), len(assembly_ct_list)*LOG_ENTRY_LENGTH)

    def test_file_file_reception_is_disabled(self):
        # Setup
        payload          = int_to_bytes(1) + int_to_bytes(2) + b'testfile.txt' + US_BYTE + os.urandom(50)
        encrypted_packet = assembly_packet_creator(FILE, payload=payload, origin=ORIGIN_CONTACT_HEADER, encrypt=True)[0]

        self.contact_list.get_contact('alice@jabber.org').file_reception = False

        # Test
        self.assertFR("Alert! File transmission from Alice but reception is disabled.",
                      process_message, self.ts, encrypted_packet, self.window_list, self.packet_list,
                      self.contact_list, self.key_list, self.group_list, self.settings, self.master_key)
        self.assertEqual(os.path.getsize(f'{DIR_USER_DATA}ut_logs'), LOG_ENTRY_LENGTH)


if __name__ == '__main__':
    unittest.main(exit=False)
