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
import os.path
import time
import struct
import threading
import unittest

from datetime        import datetime
from multiprocessing import Queue

from src.common.db_contacts import ContactList
from src.common.db_logs     import access_logs, log_writer_loop, re_encrypt, remove_logs, write_log_entry
from src.common.statics     import *

from tests.mock_classes import create_contact, GroupList, MasterKey, RxWindow, Settings
from tests.utils        import assembly_packet_creator, cleanup, ignored, TFCTestCase


class TestLogWriterLoop(unittest.TestCase):

    def tearDown(self):
        cleanup()

    def test_function_logs_normal_data(self):
        # Setup
        settings   = Settings()
        master_key = MasterKey()
        queues     = {LOG_PACKET_QUEUE: Queue(),
                      UNITTEST_QUEUE:   Queue()}

        def queue_delayer():
            """Place messages to queue one at a time."""
            for p in [(False, False, M_S_HEADER + bytes(PADDING_LEN), 'alice@jabber.org', settings, master_key),   # Do not log message (boolean)
                      (True,  False, C_S_HEADER + bytes(PADDING_LEN), None,               settings, master_key),   # Do not log command
                      (True,  True,  P_N_HEADER + bytes(PADDING_LEN), 'alice@jabber.org', settings, master_key),   # Do not log noise packet
                      (True,  True,  F_S_HEADER + bytes(PADDING_LEN), 'alice@jabber.org', settings, master_key),   # Do not log file packet
                      (True,  False, M_S_HEADER + bytes(PADDING_LEN), 'alice@jabber.org', settings, master_key)]:  # Log message (boolean)

                time.sleep(0.1)
                queues[LOG_PACKET_QUEUE].put(p)
            time.sleep(0.1)
            queues[UNITTEST_QUEUE].put(EXIT)
            time.sleep(0.1)
            queues[LOG_PACKET_QUEUE].put((True, False, M_S_HEADER + bytes(PADDING_LEN), 'alice@jabber.org', settings, master_key))  # Log message (boolean)

        # Test
        threading.Thread(target=queue_delayer).start()
        log_writer_loop(queues, unittest=True)

        self.assertEqual(os.path.getsize(f'{DIR_USER_DATA}ut_logs'), 2*LOG_ENTRY_LENGTH)

        # Teardown
        for key in queues:
            while not queues[key].empty():
                queues[key].get()
            time.sleep(0.1)
            queues[key].close()

    def test_function_logs_traffic_masking_data(self):
        # Setup
        settings   = Settings(log_file_placeholder_data=False,
                              logfile_masking=True,
                              session_traffic_masking=True)
        master_key = MasterKey()
        queues     = {LOG_PACKET_QUEUE: Queue(),
                      UNITTEST_QUEUE:   Queue()}

        def queue_delayer():
            """Place messages to queue one at a time."""
            for p in [(False, False, M_S_HEADER + bytes(PADDING_LEN), 'alice@jabber.org', settings, master_key),   # Do not log message (boolean)
                      (True,  False, C_S_HEADER + bytes(PADDING_LEN), None,               settings, master_key),   # Do not log command
                      (True,  True,  F_S_HEADER + bytes(PADDING_LEN), 'alice@jabber.org', settings, master_key),   # Log placeholder data
                      (True,  False, M_S_HEADER + bytes(PADDING_LEN), 'alice@jabber.org', settings, master_key)]:  # Log message (boolean)
                time.sleep(0.1)
                queues[LOG_PACKET_QUEUE].put(p)
            time.sleep(0.1)
            queues[UNITTEST_QUEUE].put(EXIT)
            time.sleep(0.1)
            queues[LOG_PACKET_QUEUE].put((True, True, P_N_HEADER + bytes(PADDING_LEN), 'alice@jabber.org', settings, master_key))  # Log noise packet

        # Test
        threading.Thread(target=queue_delayer).start()
        log_writer_loop(queues, unittest=True)

        self.assertEqual(os.path.getsize(f'{DIR_USER_DATA}ut_logs'), 3*LOG_ENTRY_LENGTH)

        # Teardown
        for key in queues:
            while not queues[key].empty():
                queues[key].get()
            time.sleep(0.1)
            queues[key].close()


class TestWriteLogEntry(unittest.TestCase):

    def setUp(self):
        self.masterkey = MasterKey()
        self.settings  = Settings()

    def tearDown(self):
        cleanup()

    def test_log_entry_is_concatenated(self):
        self.assertIsNone(write_log_entry(F_S_HEADER + bytes(PADDING_LEN), 'alice@jabber.org', self.settings, self.masterkey))
        self.assertTrue(os.path.getsize(f'{DIR_USER_DATA}ut_logs'), LOG_ENTRY_LENGTH)

        self.assertIsNone(write_log_entry(F_S_HEADER + bytes(PADDING_LEN), 'alice@jabber.org', self.settings, self.masterkey))
        self.assertTrue(os.path.getsize(f'{DIR_USER_DATA}ut_logs'), 2*LOG_ENTRY_LENGTH)


class TestAccessHistoryAndPrintLogs(TFCTestCase):

    def setUp(self):
        self.masterkey = MasterKey()
        self.settings  = Settings()
        self.window    = RxWindow(type=WIN_TYPE_CONTACT, uid='alice@jabber.org', name='Alice')

        self.contact_list          = ContactList(self.masterkey, self.settings)
        self.contact_list.contacts = list(map(create_contact, ['Alice', 'Charlie']))

        self.time = datetime.fromtimestamp(struct.unpack('<L', binascii.unhexlify('08ceae02'))[0]).strftime('%H:%M')

        self.group_list = GroupList(groups=['test_group'])
        group           = self.group_list.get_group('test_group')
        group.members   = self.contact_list.contacts

        self.o_struct = struct.pack
        struct.pack   = lambda *_: binascii.unhexlify('08ceae02')

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

    def tearDown(self):
        struct.pack = self.o_struct

        cleanup()
        with ignored(OSError):
            os.remove("UtM - Plaintext log (Alice)")

    def test_missing_log_file_raises_fr(self):
        self.assertFR(f"Error: Could not find log database.",
                      access_logs, self.window, self.contact_list, self.group_list, self.settings, self.masterkey)

    def test_empty_log_file(self):
        # Setup
        open(f'{DIR_USER_DATA}{self.settings.software_operation}_logs', 'wb+').close()

        # Test
        self.assertFR(f"No logged messages for '{self.window.uid}'",
                      access_logs, self.window, self.contact_list, self.group_list, self.settings, self.masterkey)

    def test_display_short_private_message(self):
        # Setup
        # Add a message for different contact that the function should skip.
        for p in assembly_packet_creator(MESSAGE, b'A short message'):
            write_log_entry(p, 'bob@jabber.org', self.settings, self.masterkey)

        for p in assembly_packet_creator(MESSAGE, b'Hi Bob'):
            write_log_entry(p, 'alice@jabber.org', self.settings, self.masterkey, origin=ORIGIN_CONTACT_HEADER)
        for p in assembly_packet_creator(MESSAGE, b'Hi Alice'):
            write_log_entry(p, 'alice@jabber.org', self.settings, self.masterkey)

        # Test
        self.assertPrints((CLEAR_ENTIRE_SCREEN + CURSOR_LEFT_UP_CORNER + f"""\
Logfile of messages to/from Alice
════════════════════════════════════════════════════════════════════════════════
{self.time} Alice: Hi Bob
{self.time}    Me: Hi Alice
<End of logfile>

"""), access_logs, self.window, self.contact_list, self.group_list, self.settings, self.masterkey)

    def test_export_short_private_message(self):
        # Setup
        for p in assembly_packet_creator(MESSAGE, b'Hi Bob'):
            write_log_entry(p, 'alice@jabber.org', self.settings, self.masterkey, origin=ORIGIN_CONTACT_HEADER)
        for p in assembly_packet_creator(MESSAGE, b'Hi Alice'):
            write_log_entry(p, 'alice@jabber.org', self.settings, self.masterkey)

        # Test
        self.assertIsNone(access_logs(self.window, self.contact_list, self.group_list, self.settings, self.masterkey, export=True))

        with open("UtM - Plaintext log (Alice)") as f:
            exported_log = f.read()
        self.assertEqual(exported_log, f"""\
Logfile of messages to/from Alice
════════════════════════════════════════════════════════════════════════════════
{self.time} Alice: Hi Bob
{self.time}    Me: Hi Alice
<End of logfile>

""")

    def test_long_private_message(self):
        # Setup
        # Add an assembly packet sequence for contact containing cancel packet that the function should skip
        packets = assembly_packet_creator(MESSAGE, self.msg)
        packets = packets[2:] + [M_C_HEADER + bytes(PADDING_LEN)]
        for p in packets:
            write_log_entry(p, 'alice@jabber.org', self.settings, self.masterkey)

        # Add an orphaned 'append' assembly packet that the function should skip
        write_log_entry(M_A_HEADER + bytes(PADDING_LEN), 'alice@jabber.org', self.settings, self.masterkey)

        # Add a group message that the function should skip
        for p in assembly_packet_creator(MESSAGE, b'This is a short message', group_name='test_group'):
            write_log_entry(p, 'alice@jabber.org', self.settings, self.masterkey)

        # Add normal messages for contact and user that should be displayed
        for p in assembly_packet_creator(MESSAGE, self.msg):
            write_log_entry(p, 'alice@jabber.org', self.settings, self.masterkey, origin=ORIGIN_CONTACT_HEADER)
        for p in assembly_packet_creator(MESSAGE, self.msg):
            write_log_entry(p, 'alice@jabber.org', self.settings, self.masterkey)

        # Test
        self.assertPrints((CLEAR_ENTIRE_SCREEN + CURSOR_LEFT_UP_CORNER + f"""\
Logfile of messages to/from Alice
════════════════════════════════════════════════════════════════════════════════
{self.time} Alice: Lorem ipsum dolor sit amet, consectetur adipiscing elit. Aenean
             condimentum consectetur purus quis dapibus. Fusce venenatis lacus
             ut rhoncus faucibus. Cras sollicitudin commodo sapien, sed bibendum
             velit maximus in. Aliquam ac metus risus. Sed cursus ornare luctus.
             Integer aliquet lectus id massa blandit imperdiet. Ut sed massa
             eget quam facilisis rutrum. Mauris eget luctus nisl. Sed ut elit
             iaculis, faucibus lacus eget, sodales magna. Nunc sed commodo arcu.
             In hac habitasse platea dictumst. Integer luctus aliquam justo, at
             vestibulum dolor iaculis ac. Etiam laoreet est eget odio rutrum,
             vel malesuada lorem rhoncus. Cras finibus in neque eu euismod.
             Nulla facilisi. Nunc nec aliquam quam, quis ullamcorper leo. Nunc
             egestas lectus eget est porttitor, in iaculis felis scelerisque. In
             sem elit, fringilla id viverra commodo, sagittis varius purus.
             Pellentesque rutrum lobortis neque a facilisis. Mauris id tortor
             placerat, aliquam dolor ac, venenatis arcu.
{self.time}    Me: Lorem ipsum dolor sit amet, consectetur adipiscing elit. Aenean
             condimentum consectetur purus quis dapibus. Fusce venenatis lacus
             ut rhoncus faucibus. Cras sollicitudin commodo sapien, sed bibendum
             velit maximus in. Aliquam ac metus risus. Sed cursus ornare luctus.
             Integer aliquet lectus id massa blandit imperdiet. Ut sed massa
             eget quam facilisis rutrum. Mauris eget luctus nisl. Sed ut elit
             iaculis, faucibus lacus eget, sodales magna. Nunc sed commodo arcu.
             In hac habitasse platea dictumst. Integer luctus aliquam justo, at
             vestibulum dolor iaculis ac. Etiam laoreet est eget odio rutrum,
             vel malesuada lorem rhoncus. Cras finibus in neque eu euismod.
             Nulla facilisi. Nunc nec aliquam quam, quis ullamcorper leo. Nunc
             egestas lectus eget est porttitor, in iaculis felis scelerisque. In
             sem elit, fringilla id viverra commodo, sagittis varius purus.
             Pellentesque rutrum lobortis neque a facilisis. Mauris id tortor
             placerat, aliquam dolor ac, venenatis arcu.
<End of logfile>

"""), access_logs, self.window, self.contact_list, self.group_list, self.settings, self.masterkey)

    def test_short_group_message(self):
        # Setup
        self.window = RxWindow(type=WIN_TYPE_GROUP, uid='test_group', name='test_group')

        for p in assembly_packet_creator(MESSAGE, b'This is a short message', group_name='test_group'):
            write_log_entry(p, 'alice@jabber.org',   self.settings, self.masterkey)
            write_log_entry(p, 'alice@jabber.org',   self.settings, self.masterkey, origin=ORIGIN_CONTACT_HEADER)
            write_log_entry(p, 'charlie@jabber.org', self.settings, self.masterkey)
            write_log_entry(p, 'charlie@jabber.org', self.settings, self.masterkey, origin=ORIGIN_CONTACT_HEADER)

        # Test
        self.assertPrints((CLEAR_ENTIRE_SCREEN + CURSOR_LEFT_UP_CORNER + f"""\
Logfile of messages to/from test_group
════════════════════════════════════════════════════════════════════════════════
{self.time}      Me: This is a short message
{self.time}   Alice: This is a short message
{self.time} Charlie: This is a short message
<End of logfile>

"""), access_logs, self.window, self.contact_list, self.group_list, self.settings, self.masterkey)

    def test_long_group_message(self):
        # Setup
        self.window = RxWindow(type=WIN_TYPE_GROUP, uid='test_group', name='test_group')

        # Add an assembly packet sequence for contact containing cancel packet that the function should skip
        packets = assembly_packet_creator(MESSAGE, self.msg)
        packets = packets[2:] + [M_C_HEADER + bytes(PADDING_LEN)]
        for p in packets:
            write_log_entry(p, 'alice@jabber.org', self.settings, self.masterkey)

        # Add an orphaned 'append' assembly packet that the function should skip
        write_log_entry(M_A_HEADER + bytes(PADDING_LEN), 'alice@jabber.org', self.settings, self.masterkey)

        # Add a private message that the function should skip
        for p in assembly_packet_creator(MESSAGE, b'This is a short message'):
            write_log_entry(p, 'alice@jabber.org', self.settings, self.masterkey)

        # Add a group management message that the function should skip
        message = US_BYTE.join([b'test_group', b'alice@jabber.org'])
        for p in assembly_packet_creator(MESSAGE, message, header=GROUP_MSG_INVITEJOIN_HEADER):
            write_log_entry(p, 'alice@jabber.org', self.settings, self.masterkey)

        # Add a group message that the function should skip
        for p in assembly_packet_creator(MESSAGE, b'This is a short message', group_name='different_group'):
            write_log_entry(p, 'alice@jabber.org', self.settings, self.masterkey)

        for p in assembly_packet_creator(MESSAGE, self.msg, group_name='test_group'):
            write_log_entry(p, 'alice@jabber.org',   self.settings, self.masterkey)
            write_log_entry(p, 'alice@jabber.org',   self.settings, self.masterkey, origin=ORIGIN_CONTACT_HEADER)
            write_log_entry(p, 'charlie@jabber.org', self.settings, self.masterkey)
            write_log_entry(p, 'charlie@jabber.org', self.settings, self.masterkey, origin=ORIGIN_CONTACT_HEADER)

        # Test
        access_logs(self.window, self.contact_list, self.group_list, self.settings, self.masterkey)
        self.assertPrints((CLEAR_ENTIRE_SCREEN + CURSOR_LEFT_UP_CORNER + f"""\
Logfile of messages to/from test_group
════════════════════════════════════════════════════════════════════════════════
{self.time}      Me: Lorem ipsum dolor sit amet, consectetur adipiscing elit. Aenean
               condimentum consectetur purus quis dapibus. Fusce venenatis lacus
               ut rhoncus faucibus. Cras sollicitudin commodo sapien, sed
               bibendum velit maximus in. Aliquam ac metus risus. Sed cursus
               ornare luctus. Integer aliquet lectus id massa blandit imperdiet.
               Ut sed massa eget quam facilisis rutrum. Mauris eget luctus nisl.
               Sed ut elit iaculis, faucibus lacus eget, sodales magna. Nunc sed
               commodo arcu. In hac habitasse platea dictumst. Integer luctus
               aliquam justo, at vestibulum dolor iaculis ac. Etiam laoreet est
               eget odio rutrum, vel malesuada lorem rhoncus. Cras finibus in
               neque eu euismod. Nulla facilisi. Nunc nec aliquam quam, quis
               ullamcorper leo. Nunc egestas lectus eget est porttitor, in
               iaculis felis scelerisque. In sem elit, fringilla id viverra
               commodo, sagittis varius purus. Pellentesque rutrum lobortis
               neque a facilisis. Mauris id tortor placerat, aliquam dolor ac,
               venenatis arcu.
{self.time}   Alice: Lorem ipsum dolor sit amet, consectetur adipiscing elit. Aenean
               condimentum consectetur purus quis dapibus. Fusce venenatis lacus
               ut rhoncus faucibus. Cras sollicitudin commodo sapien, sed
               bibendum velit maximus in. Aliquam ac metus risus. Sed cursus
               ornare luctus. Integer aliquet lectus id massa blandit imperdiet.
               Ut sed massa eget quam facilisis rutrum. Mauris eget luctus nisl.
               Sed ut elit iaculis, faucibus lacus eget, sodales magna. Nunc sed
               commodo arcu. In hac habitasse platea dictumst. Integer luctus
               aliquam justo, at vestibulum dolor iaculis ac. Etiam laoreet est
               eget odio rutrum, vel malesuada lorem rhoncus. Cras finibus in
               neque eu euismod. Nulla facilisi. Nunc nec aliquam quam, quis
               ullamcorper leo. Nunc egestas lectus eget est porttitor, in
               iaculis felis scelerisque. In sem elit, fringilla id viverra
               commodo, sagittis varius purus. Pellentesque rutrum lobortis
               neque a facilisis. Mauris id tortor placerat, aliquam dolor ac,
               venenatis arcu.
{self.time} Charlie: Lorem ipsum dolor sit amet, consectetur adipiscing elit. Aenean
               condimentum consectetur purus quis dapibus. Fusce venenatis lacus
               ut rhoncus faucibus. Cras sollicitudin commodo sapien, sed
               bibendum velit maximus in. Aliquam ac metus risus. Sed cursus
               ornare luctus. Integer aliquet lectus id massa blandit imperdiet.
               Ut sed massa eget quam facilisis rutrum. Mauris eget luctus nisl.
               Sed ut elit iaculis, faucibus lacus eget, sodales magna. Nunc sed
               commodo arcu. In hac habitasse platea dictumst. Integer luctus
               aliquam justo, at vestibulum dolor iaculis ac. Etiam laoreet est
               eget odio rutrum, vel malesuada lorem rhoncus. Cras finibus in
               neque eu euismod. Nulla facilisi. Nunc nec aliquam quam, quis
               ullamcorper leo. Nunc egestas lectus eget est porttitor, in
               iaculis felis scelerisque. In sem elit, fringilla id viverra
               commodo, sagittis varius purus. Pellentesque rutrum lobortis
               neque a facilisis. Mauris id tortor placerat, aliquam dolor ac,
               venenatis arcu.
<End of logfile>

"""), access_logs, self.window, self.contact_list, self.group_list, self.settings, self.masterkey)


class TestReEncrypt(TFCTestCase):

    def setUp(self):
        self.old_key       = MasterKey()
        self.new_key       = MasterKey(master_key=os.urandom(32))
        self.settings      = Settings()
        self.o_struct_pack = struct.pack
        self.time          = datetime.fromtimestamp(struct.unpack('<L', binascii.unhexlify('08ceae02'))[0]).strftime('%H:%M')
        struct.pack        = lambda *_: binascii.unhexlify('08ceae02')

    def tearDown(self):
        cleanup()
        struct.pack = self.o_struct_pack

    def test_missing_log_database_raises_fr(self):
        self.assertFR(f"Error: Could not find log database.",
                      re_encrypt, self.old_key.master_key, self.new_key.master_key, self.settings)

    def test_database_encryption_with_another_key(self):
        # Setup
        window                = RxWindow(type=WIN_TYPE_CONTACT, uid='alice@jabber.org', name='Alice')
        contact_list          = ContactList(self.old_key, self.settings)
        contact_list.contacts = [create_contact()]
        group_list            = GroupList()

        # Create temp file that must be removed
        with open("user_data/ut_logs_temp", 'wb+') as f:
            f.write(os.urandom(LOG_ENTRY_LENGTH))

        for p in assembly_packet_creator(MESSAGE, b'This is a short message'):
            write_log_entry(p, 'alice@jabber.org', self.settings, self.old_key, origin=ORIGIN_CONTACT_HEADER)
        for p in assembly_packet_creator(MESSAGE, b'This is a short message'):
            write_log_entry(p, 'alice@jabber.org', self.settings, self.old_key)

        # Test
        self.assertPrints((CLEAR_ENTIRE_SCREEN + CURSOR_LEFT_UP_CORNER + f"""\
Logfile of messages to/from Alice
════════════════════════════════════════════════════════════════════════════════
{self.time} Alice: This is a short message
{self.time}    Me: This is a short message
<End of logfile>

"""), access_logs, window, contact_list, group_list, self.settings, self.old_key)

        self.assertIsNone(re_encrypt(self.old_key.master_key, self.new_key.master_key, self.settings))

        # Test that decryption works with new key
        self.assertPrints((CLEAR_ENTIRE_SCREEN + CURSOR_LEFT_UP_CORNER + f"""\
Logfile of messages to/from Alice
════════════════════════════════════════════════════════════════════════════════
{self.time} Alice: This is a short message
{self.time}    Me: This is a short message
<End of logfile>

"""), access_logs, window, contact_list, group_list, self.settings, self.new_key)

        # Test that temp file is removed
        self.assertFalse(os.path.isfile("user_data/ut_logs_temp"))


class TestRemoveLog(TFCTestCase):

    def setUp(self):
        self.masterkey = MasterKey()
        self.settings  = Settings()
        self.time      = datetime.fromtimestamp(struct.unpack('<L', binascii.unhexlify('08ceae02'))[0]).strftime('%H:%M')
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

    def tearDown(self):
        cleanup()

    def test_missing_log_file_raises_fr(self):
        self.assertFR(f"Error: Could not find log database.",
                      remove_logs, 'alice@jabber.org', self.settings, self.masterkey)

    def test_removal_of_group_logs(self):
        # Setup
        short_msg = b"Lorem ipsum dolor sit amet, consectetur adipiscing elit."

        for p in assembly_packet_creator(MESSAGE, self.msg, group_name='test_group'):
            write_log_entry(p, 'alice@jabber.org',   self.settings, self.masterkey)
            write_log_entry(p, 'charlie@jabber.org', self.settings, self.masterkey)

        for p in assembly_packet_creator(MESSAGE, short_msg, group_name='test_group'):
            write_log_entry(p, 'alice@jabber.org',   self.settings, self.masterkey)
            write_log_entry(p, 'charlie@jabber.org', self.settings, self.masterkey)

        for p in assembly_packet_creator(MESSAGE, short_msg):
            write_log_entry(p, 'david@jabber.org', self.settings, self.masterkey)

        for p in assembly_packet_creator(MESSAGE, self.msg):
            write_log_entry(p, 'david@jabber.org', self.settings, self.masterkey)

        for p in assembly_packet_creator(MESSAGE, short_msg, group_name='test_group_2'):
            write_log_entry(p, 'david@jabber.org', self.settings, self.masterkey)

        # Add an orphaned 'append' assembly packet that the function should skip
        write_log_entry(M_A_HEADER + bytes(PADDING_LEN), 'alice@jabber.org', self.settings, self.masterkey)

        # Add packet cancelled half-way
        packets = assembly_packet_creator(MESSAGE, self.msg, group_name='test_group')
        packets = packets[2:] + [M_C_HEADER + bytes(PADDING_LEN)]
        for p in packets:
            write_log_entry(p, 'david@jabber.org', self.settings, self.masterkey)

        # Add a group management message for different group that the function should keep
        message = US_BYTE.join([b'test_group_2', b'alice@jabber.org'])
        for p in assembly_packet_creator(MESSAGE, message, header=GROUP_MSG_INVITEJOIN_HEADER):
            write_log_entry(p, 'bob@jabber.org', self.settings, self.masterkey)

        # Add a group management message for group that the function should remove
        message = US_BYTE.join([b'test_group', b'alice@jabber.org'])
        for p in assembly_packet_creator(MESSAGE, message, header=GROUP_MSG_INVITEJOIN_HEADER):
            write_log_entry(p, 'alice@jabber.org', self.settings, self.masterkey)

        for p in assembly_packet_creator(MESSAGE, self.msg, group_name='test_group_2'):
            write_log_entry(p, 'david@jabber.org', self.settings, self.masterkey)

        # Test
        self.assertEqual(os.path.getsize(f'{DIR_USER_DATA}ut_logs'), 21*LOG_ENTRY_LENGTH)

        self.assertIsNone(remove_logs('test_group', self.settings, self.masterkey))
        self.assertEqual(os.path.getsize(f'{DIR_USER_DATA}ut_logs'), 9*LOG_ENTRY_LENGTH)

        self.assertIsNone(remove_logs('test_group_2', self.settings, self.masterkey))
        self.assertFR(f"Found no log entries for contact 'alice@jabber.org'",
                      remove_logs, 'alice@jabber.org', self.settings, self.masterkey)

    def test_removal_of_contact_logs(self):
        # Setup
        short_msg = b"Lorem ipsum dolor sit amet, consectetur adipiscing elit."

        for p in assembly_packet_creator(MESSAGE, self.msg):
            write_log_entry(p, 'alice@jabber.org',   self.settings, self.masterkey)
            write_log_entry(p, 'charlie@jabber.org', self.settings, self.masterkey)

        for p in assembly_packet_creator(MESSAGE, short_msg):
            write_log_entry(p, 'alice@jabber.org',   self.settings, self.masterkey)
            write_log_entry(p, 'charlie@jabber.org', self.settings, self.masterkey)

        # Test
        self.assertEqual(os.path.getsize(f'{DIR_USER_DATA}ut_logs'), 8*LOG_ENTRY_LENGTH)

        self.assertIsNone(remove_logs('alice@jabber.org', self.settings, self.masterkey))
        self.assertEqual(os.path.getsize(f'{DIR_USER_DATA}ut_logs'), 4*LOG_ENTRY_LENGTH)

        self.assertIsNone(remove_logs('charlie@jabber.org', self.settings, self.masterkey))
        self.assertEqual(os.path.getsize(f'{DIR_USER_DATA}ut_logs'), 0)

        self.assertFR(f"Found no log entries for contact 'alice@jabber.org'",
                      remove_logs, 'alice@jabber.org', self.settings, self.masterkey)


if __name__ == '__main__':
    unittest.main(exit=False)
