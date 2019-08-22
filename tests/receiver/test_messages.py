#!/usr/bin/env python3.7
# -*- coding: utf-8 -*-

"""
TFC - Onion-routed, endpoint secure messaging system
Copyright (C) 2013-2019  Markus Ottela

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

import base64
import os
import unittest

from datetime import datetime
from unittest import mock

from src.common.encoding import bool_to_bytes
from src.common.misc     import ensure_dir
from src.common.statics  import *

from src.receiver.messages import process_message
from src.receiver.packet   import PacketList
from src.receiver.windows  import WindowList

from tests.mock_classes import ContactList, GroupList, KeyList, MasterKey, Settings
from tests.utils        import assembly_packet_creator, cd_unit_test, cleanup, group_name_to_group_id
from tests.utils        import nick_to_pub_key, TFCTestCase


class TestProcessMessage(TFCTestCase):

    def setUp(self):
        self.unit_test_dir = cd_unit_test()

        self.msg = ("Lorem ipsum dolor sit amet, consectetur adipiscing elit. Aenean condimentum consectetur purus quis"
                    " dapibus. Fusce venenatis lacus ut rhoncus faucibus. Cras sollicitudin commodo sapien, sed bibendu"
                    "m velit maximus in. Aliquam ac metus risus. Sed cursus ornare luctus. Integer aliquet lectus id ma"
                    "ssa blandit imperdiet. Ut sed massa eget quam facilisis rutrum. Mauris eget luctus nisl. Sed ut el"
                    "it iaculis, faucibus lacus eget, sodales magna. Nunc sed commodo arcu. In hac habitasse platea dic"
                    "tumst. Integer luctus aliquam justo, at vestibulum dolor iaculis ac. Etiam laoreet est eget odio r"
                    "utrum, vel malesuada lorem rhoncus. Cras finibus in neque eu euismod. Nulla facilisi. Nunc nec ali"
                    "quam quam, quis ullamcorper leo. Nunc egestas lectus eget est porttitor, in iaculis felis sceleris"
                    "que. In sem elit, fringilla id viverra commodo, sagittis varius purus. Pellentesque rutrum loborti"
                    "s neque a facilisis. Mauris id tortor placerat, aliquam dolor ac, venenatis arcu.")

        self.ts         = datetime.now()
        self.master_key = MasterKey()
        self.settings   = Settings(log_file_masking=True)
        self.file_name  = f'{DIR_USER_DATA}{self.settings.software_operation}_logs'

        self.contact_list = ContactList(nicks=['Alice', 'Bob', 'Charlie', LOCAL_ID])
        self.key_list     = KeyList(    nicks=['Alice', 'Bob', 'Charlie', LOCAL_ID])
        self.group_list   = GroupList( groups=['test_group'])
        self.packet_list  = PacketList(contact_list=self.contact_list, settings=self.settings)
        self.window_list  = WindowList(contact_list=self.contact_list, settings=self.settings, 
                                       group_list=self.group_list, packet_list=self.packet_list)
        self.group_id     = group_name_to_group_id('test_group')
        self.file_keys    = dict()

        self.group_list.get_group('test_group').log_messages = True
        self.args = (self.window_list, self.packet_list, self.contact_list, self.key_list, 
                     self.group_list, self.settings, self.master_key, self.file_keys)

        ensure_dir(DIR_USER_DATA)

    def tearDown(self):
        cleanup(self.unit_test_dir)

    # Invalid packets
    @mock.patch('time.sleep', return_value=None)
    def test_invalid_origin_header_raises_fr(self, _):
        # Setup
        invalid_origin_header = b'e'
        packet = nick_to_pub_key('Alice') + invalid_origin_header + MESSAGE_LENGTH * b'm'

        # Test
        self.assert_fr("Error: Received packet had an invalid origin-header.",
                       process_message, self.ts, packet, *self.args)

    @mock.patch('time.sleep', return_value=None)
    def test_masqueraded_command_raises_fr(self, _):
        for origin_header in [ORIGIN_USER_HEADER, ORIGIN_CONTACT_HEADER]:
            # Setup
            packet = LOCAL_PUBKEY + origin_header + MESSAGE_LENGTH * b'm'

            # Test
            self.assert_fr("Warning! Received packet masqueraded as a command.",
                           process_message, self.ts, packet, *self.args)

    # Private messages
    @mock.patch('time.sleep', return_value=None)
    def test_private_msg_from_contact(self, _):
        # Setup
        assembly_ct_list = assembly_packet_creator(MESSAGE, self.msg, origin_header=ORIGIN_CONTACT_HEADER,
                                                   encrypt_packet=True, onion_pub_key=nick_to_pub_key('Alice'))

        # Test
        for p in assembly_ct_list:
            self.assertIsNone(process_message(self.ts, p, *self.args))

        self.assertEqual(os.path.getsize(self.file_name), len(assembly_ct_list)*LOG_ENTRY_LENGTH)

    @mock.patch('time.sleep', return_value=None)
    def test_private_msg_from_user(self, _):
        # Setup
        assembly_ct_list = assembly_packet_creator(MESSAGE, self.msg, origin_header=ORIGIN_USER_HEADER,
                                                   encrypt_packet=True, onion_pub_key=nick_to_pub_key('Alice'))

        # Test
        for p in assembly_ct_list:
            self.assertIsNone(process_message(self.ts, p, *self.args))

        self.assertEqual(os.path.getsize(self.file_name), len(assembly_ct_list) * LOG_ENTRY_LENGTH)

    # Whispered messages
    @mock.patch('time.sleep', return_value=None)
    def test_whisper_msg_from_contact(self, _):
        # Setup
        assembly_ct_list = assembly_packet_creator(MESSAGE, self.msg, origin_header=ORIGIN_CONTACT_HEADER,
                                                   encrypt_packet=True, onion_pub_key=nick_to_pub_key('Alice'),
                                                   whisper_header=bool_to_bytes(True))

        # Test
        for p in assembly_ct_list[:-1]:
            self.assertIsNone(process_message(self.ts, p, *self.args))

        for p in assembly_ct_list[-1:]:
            self.assert_fr("Whisper message complete.",
                           process_message, self.ts, p, *self.args)

        self.assertEqual(os.path.getsize(self.file_name), len(assembly_ct_list)*LOG_ENTRY_LENGTH)

    @mock.patch('time.sleep', return_value=None)
    def test_whisper_msg_from_user(self, _):
        # Setup
        assembly_ct_list = assembly_packet_creator(MESSAGE, self.msg, origin_header=ORIGIN_USER_HEADER,
                                                   encrypt_packet=True, onion_pub_key=nick_to_pub_key('Alice'),
                                                   whisper_header=bool_to_bytes(True))
        # Test
        for p in assembly_ct_list[:-1]:
            self.assertIsNone(process_message(self.ts, p, *self.args))

        for p in assembly_ct_list[-1:]:
            self.assert_fr("Whisper message complete.", process_message, self.ts, p, *self.args)

        self.assertEqual(os.path.getsize(self.file_name), len(assembly_ct_list)*LOG_ENTRY_LENGTH)

    @mock.patch('time.sleep', return_value=None)
    def test_empty_whisper_msg_from_user(self, _):
        # Setup
        assembly_ct_list = assembly_packet_creator(MESSAGE, '', origin_header=ORIGIN_USER_HEADER,
                                                   encrypt_packet=True, onion_pub_key=nick_to_pub_key('Alice'),
                                                   whisper_header=bool_to_bytes(True))
        # Test
        for p in assembly_ct_list[:-1]:
            self.assertIsNone(process_message(self.ts, p, *self.args))

        for p in assembly_ct_list[-1:]:
            self.assert_fr("Whisper message complete.", process_message, self.ts, p, *self.args)

        self.assertEqual(os.path.getsize(self.file_name), len(assembly_ct_list)*LOG_ENTRY_LENGTH)

    # File key messages
    @mock.patch('time.sleep', return_value=None)
    def test_user_origin_raises_fr(self, _):
        assembly_ct_list = assembly_packet_creator(MESSAGE, ' ', origin_header=ORIGIN_USER_HEADER,
                                                   encrypt_packet=True, onion_pub_key=nick_to_pub_key('Alice'),
                                                   message_header=FILE_KEY_HEADER)

        for p in assembly_ct_list[-1:]:
            self.assert_fr("File key message from the user.", process_message, self.ts, p, *self.args)

    @mock.patch('time.sleep', return_value=None)
    def test_invalid_file_key_data_raises_fr(self, _):
        assembly_ct_list = assembly_packet_creator(MESSAGE, ' ', origin_header=ORIGIN_CONTACT_HEADER,
                                                   encrypt_packet=True, onion_pub_key=nick_to_pub_key('Alice'),
                                                   message_header=FILE_KEY_HEADER)

        for p in assembly_ct_list[-1:]:
            self.assert_fr("Error: Received an invalid file key message.", process_message, self.ts, p, *self.args)

    @mock.patch('time.sleep', return_value=None)
    def test_too_large_file_key_data_raises_fr(self, _):
        assembly_ct_list = assembly_packet_creator(MESSAGE, base64.b85encode(BLAKE2_DIGEST_LENGTH * b'a'
                                                                             + SYMMETRIC_KEY_LENGTH * b'b'
                                                                             + b'a').decode(),
                                                   origin_header=ORIGIN_CONTACT_HEADER,
                                                   encrypt_packet=True, onion_pub_key=nick_to_pub_key('Alice'),
                                                   message_header=FILE_KEY_HEADER)

        for p in assembly_ct_list[-1:]:
            self.assert_fr("Error: Received an invalid file key message.", process_message, self.ts, p, *self.args)

    @mock.patch('time.sleep', return_value=None)
    def test_valid_file_key_message(self, _):
        assembly_ct_list = assembly_packet_creator(MESSAGE, base64.b85encode(BLAKE2_DIGEST_LENGTH * b'a'
                                                                             + SYMMETRIC_KEY_LENGTH * b'b').decode(),
                                                   origin_header=ORIGIN_CONTACT_HEADER,
                                                   encrypt_packet=True, onion_pub_key=nick_to_pub_key('Alice'),
                                                   message_header=FILE_KEY_HEADER)
        for p in assembly_ct_list[-1:]:
            self.assert_fr("Received file decryption key from Alice", process_message, self.ts, p, *self.args)

    # Group messages
    @mock.patch('time.sleep', return_value=None)
    def test_invalid_message_header_raises_fr(self, _):
        # Setup
        assembly_ct_list = assembly_packet_creator(MESSAGE, 'test_message', origin_header=ORIGIN_CONTACT_HEADER,
                                                   encrypt_packet=True, onion_pub_key=nick_to_pub_key('Alice'),
                                                   message_header=b'Z')

        # Test
        self.assert_fr("Error: Message from contact had an invalid header.",
                       process_message, self.ts, assembly_ct_list[0], *self.args)

        self.assertEqual(os.path.getsize(self.file_name), LOG_ENTRY_LENGTH)

    @mock.patch('time.sleep', return_value=None)
    def test_invalid_window_raises_fr(self, _):
        # Setup
        assembly_ct_list = assembly_packet_creator(MESSAGE, 'test_message', origin_header=ORIGIN_CONTACT_HEADER,
                                                   encrypt_packet=True, onion_pub_key=nick_to_pub_key('Alice'),
                                                   group_id=self.group_id)

        self.group_list.get_group('test_group').group_id = GROUP_ID_LENGTH * b'a'

        # Test
        self.assert_fr("Error: Received message to an unknown group.",
                       process_message, self.ts, assembly_ct_list[0], *self.args)

        self.assertEqual(os.path.getsize(self.file_name), LOG_ENTRY_LENGTH)

    @mock.patch('time.sleep', return_value=None)
    def test_invalid_message_raises_fr(self, _):
        # Setup
        assembly_ct_list = assembly_packet_creator(MESSAGE, ' ', origin_header=ORIGIN_CONTACT_HEADER,
                                                   encrypt_packet=True, onion_pub_key=nick_to_pub_key('Alice'),
                                                   group_id=self.group_id, tamper_plaintext=True)

        # Test
        self.assert_fr("Error: Received an invalid group message.",
                       process_message, self.ts, assembly_ct_list[0], *self.args)

        self.assertEqual(os.path.getsize(self.file_name), LOG_ENTRY_LENGTH)

    @mock.patch('time.sleep', return_value=None)
    def test_invalid_whisper_header_raises_fr(self, _):
        # Setup
        assembly_ct_list = assembly_packet_creator(MESSAGE, '', origin_header=ORIGIN_CONTACT_HEADER,
                                                   encrypt_packet=True, onion_pub_key=nick_to_pub_key('Alice'),
                                                   whisper_header=b'', message_header=b'')

        # Test
        self.assert_fr("Error: Message from contact had an invalid whisper header.",
                       process_message, self.ts, assembly_ct_list[0], *self.args)

        self.assertEqual(os.path.getsize(self.file_name), LOG_ENTRY_LENGTH)

    @mock.patch('time.sleep', return_value=None)
    def test_contact_not_in_group_raises_fr(self, _):
        # Setup

        assembly_ct_list = assembly_packet_creator(MESSAGE, 'test_message', origin_header=ORIGIN_CONTACT_HEADER,
                                                   encrypt_packet=True, group_id=self.group_id,
                                                   onion_pub_key=nick_to_pub_key('Charlie'))

        # Test
        self.assert_fr("Error: Account is not a member of the group.",
                       process_message, self.ts, assembly_ct_list[0], *self.args)

        self.assertEqual(os.path.getsize(self.file_name), LOG_ENTRY_LENGTH)

    @mock.patch('time.sleep', return_value=None)
    def test_normal_group_msg_from_contact(self, _):
        # Setup
        assembly_ct_list = assembly_packet_creator(MESSAGE, self.msg, origin_header=ORIGIN_CONTACT_HEADER,
                                                   group_id=self.group_id, encrypt_packet=True,
                                                   onion_pub_key=nick_to_pub_key('Alice'))

        for p in assembly_ct_list:
            self.assertIsNone(process_message(self.ts, p, *self.args))

        self.assertEqual(os.path.getsize(self.file_name), len(assembly_ct_list)*LOG_ENTRY_LENGTH)

    @mock.patch('time.sleep', return_value=None)
    def test_normal_group_msg_from_user(self, _):
        # Setup
        assembly_ct_list = assembly_packet_creator(MESSAGE, self.msg, origin_header=ORIGIN_USER_HEADER,
                                                   group_id=self.group_id, encrypt_packet=True,
                                                   onion_pub_key=nick_to_pub_key('Alice'))

        for p in assembly_ct_list:
            self.assertIsNone(process_message(self.ts, p, *self.args))

        self.assertEqual(os.path.getsize(self.file_name), len(assembly_ct_list)*LOG_ENTRY_LENGTH)

    # Files
    @mock.patch('time.sleep', return_value=None)
    def test_file(self, _):
        # Setup
        assembly_ct_list = assembly_packet_creator(FILE, origin_header=ORIGIN_CONTACT_HEADER,
                                                   encrypt_packet=True, onion_pub_key=nick_to_pub_key('Alice'))

        # Test
        for p in assembly_ct_list[:-1]:
            self.assertIsNone(process_message(self.ts, p, *self.args))

        for p in assembly_ct_list[-1:]:
            self.assert_fr("File storage complete.",
                           process_message, self.ts, p, *self.args)

        self.assertEqual(os.path.getsize(self.file_name), len(assembly_ct_list)*LOG_ENTRY_LENGTH)

    @mock.patch('time.sleep', return_value=None)
    def test_file_when_reception_is_disabled(self, _):
        # Setup
        assembly_ct_list = assembly_packet_creator(FILE, origin_header=ORIGIN_CONTACT_HEADER,
                                                   encrypt_packet=True, onion_pub_key=nick_to_pub_key('Alice'))

        self.contact_list.get_contact_by_pub_key(nick_to_pub_key('Alice')).file_reception = False

        # Test
        self.assert_fr("Alert! File transmission from Alice but reception is disabled.",
                       process_message, self.ts, assembly_ct_list[0], *self.args)

        self.assertEqual(os.path.getsize(self.file_name), LOG_ENTRY_LENGTH)


if __name__ == '__main__':
    unittest.main(exit=False)
