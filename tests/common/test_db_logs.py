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

import os
import os.path
import threading
import time
import unittest

from unittest import mock
from typing   import Any

from src.common.database    import MessageLog
from src.common.db_contacts import ContactList
from src.common.db_logs     import (access_logs, change_log_db_key, log_writer_loop, remove_logs, replace_log_db,
                                    write_log_entry)
from src.common.encoding    import bytes_to_timestamp
from src.common.statics     import (CLEAR_ENTIRE_SCREEN, CURSOR_LEFT_UP_CORNER, C_S_HEADER, DIR_USER_DATA, EXIT,
                                    F_S_HEADER, GROUP_ID_LENGTH, LOGFILE_MASKING_QUEUE, LOG_ENTRY_LENGTH,
                                    LOG_PACKET_QUEUE, LOG_SETTING_QUEUE, MESSAGE, M_A_HEADER, M_C_HEADER, M_S_HEADER,
                                    ORIGIN_CONTACT_HEADER, PADDING_LENGTH, P_N_HEADER, RX, SYMMETRIC_KEY_LENGTH,
                                    TIMESTAMP_LENGTH, TRAFFIC_MASKING_QUEUE, TX, UNIT_TEST_QUEUE, WIN_TYPE_CONTACT,
                                    WIN_TYPE_GROUP)

from tests.mock_classes import create_contact, GroupList, MasterKey, RxWindow, Settings
from tests.utils        import assembly_packet_creator, cd_unit_test, cleanup, group_name_to_group_id, nick_to_pub_key
from tests.utils        import nick_to_short_address, tear_queues, TFCTestCase, gen_queue_dict

TIMESTAMP_BYTES  = bytes.fromhex('08ceae02')
STATIC_TIMESTAMP = bytes_to_timestamp(TIMESTAMP_BYTES).strftime('%H:%M:%S.%f')[:-TIMESTAMP_LENGTH]
SLEEP_DELAY      = 0.02


class TestLogWriterLoop(unittest.TestCase):

    def setUp(self) -> None:
        """Pre-test actions."""
        self.unit_test_dir = cd_unit_test()
        self.master_key    = MasterKey()
        self.message_log   = MessageLog(f'{DIR_USER_DATA}{TX}_logs', self.master_key.master_key)

    def tearDown(self) -> None:
        """Post-test actions."""
        cleanup(self.unit_test_dir)

    def test_function_logs_normal_data(self) -> None:
        # Setup
        settings   = Settings()
        master_key = MasterKey()
        queues     = gen_queue_dict()

        def queue_delayer() -> None:
            """Place messages to queue one at a time."""
            for p in [(nick_to_pub_key('Alice'), M_S_HEADER + bytes(PADDING_LENGTH), False, False, master_key),
                      (None,                     C_S_HEADER + bytes(PADDING_LENGTH), True,  False, master_key),
                      (nick_to_pub_key('Alice'), P_N_HEADER + bytes(PADDING_LENGTH), True,  True,  master_key),
                      (nick_to_pub_key('Alice'), F_S_HEADER + bytes(PADDING_LENGTH), True,  True,  master_key),
                      (nick_to_pub_key('Alice'), M_S_HEADER + bytes(PADDING_LENGTH), True,  False, master_key)]:
                queues[LOG_PACKET_QUEUE].put(p)
                time.sleep(SLEEP_DELAY)

            queues[UNIT_TEST_QUEUE].put(EXIT)
            time.sleep(SLEEP_DELAY)

            queues[LOG_PACKET_QUEUE].put((
                nick_to_pub_key('Alice'), M_S_HEADER + bytes(PADDING_LENGTH), True, False, master_key))
            time.sleep(SLEEP_DELAY)

        # Test
        threading.Thread(target=queue_delayer).start()
        log_writer_loop(queues, settings, self.message_log, unit_test=True)

        # Teardown
        tear_queues(queues)

    def test_function_logs_traffic_masking_data(self) -> None:
        # Setup
        settings   = Settings(log_file_masking=True,
                              traffic_masking=False)
        master_key = MasterKey()
        queues     = gen_queue_dict()

        queues[TRAFFIC_MASKING_QUEUE].put(True)

        def queue_delayer() -> None:
            """Place messages to queue one at a time."""
            for p in [(nick_to_pub_key('Alice'), M_S_HEADER + bytes(PADDING_LENGTH), False, False, master_key),
                      (None,                     C_S_HEADER + bytes(PADDING_LENGTH), True,  False, master_key),
                      (nick_to_pub_key('Alice'), F_S_HEADER + bytes(PADDING_LENGTH), True,  True,  master_key),
                      (nick_to_pub_key('Alice'), M_S_HEADER + bytes(PADDING_LENGTH), True,  False, master_key)]:
                queues[LOG_PACKET_QUEUE].put(p)
                time.sleep(SLEEP_DELAY)

            queues[UNIT_TEST_QUEUE].put(EXIT)
            time.sleep(SLEEP_DELAY)

            queues[LOG_PACKET_QUEUE].put(
                (nick_to_pub_key('Alice'), P_N_HEADER + bytes(PADDING_LENGTH), True, True, master_key))
            time.sleep(SLEEP_DELAY)

        # Test
        threading.Thread(target=queue_delayer).start()
        self.assertIsNone(log_writer_loop(queues, settings, self.message_log, unit_test=True))

        # Teardown
        tear_queues(queues)

    def test_function_log_file_masking_queue_controls_log_file_masking(self) -> None:
        # Setup
        settings   = Settings(log_file_masking=False,
                              traffic_masking=True)
        master_key = MasterKey()
        queues     = gen_queue_dict()

        def queue_delayer() -> None:
            """Place messages to queue one at a time."""
            for p in [(None,                     C_S_HEADER + bytes(PADDING_LENGTH), True,  False, master_key),
                      (nick_to_pub_key('Alice'), M_S_HEADER + bytes(PADDING_LENGTH), False, False, master_key),
                      (nick_to_pub_key('Alice'), F_S_HEADER + bytes(PADDING_LENGTH), True,  True,  master_key)]:

                queues[LOG_PACKET_QUEUE].put(p)
                time.sleep(SLEEP_DELAY)

            queues[LOGFILE_MASKING_QUEUE].put(True)  # Start logging noise packets
            time.sleep(SLEEP_DELAY)

            for _ in range(2):
                queues[LOG_PACKET_QUEUE].put(
                    (nick_to_pub_key('Alice'), F_S_HEADER + bytes(PADDING_LENGTH), True, True, master_key))
                time.sleep(SLEEP_DELAY)

            queues[UNIT_TEST_QUEUE].put(EXIT)
            time.sleep(SLEEP_DELAY)

            queues[LOG_PACKET_QUEUE].put(
                (nick_to_pub_key('Alice'), M_S_HEADER + bytes(PADDING_LENGTH), True, False, master_key))
            time.sleep(SLEEP_DELAY)

        # Test
        threading.Thread(target=queue_delayer).start()
        self.assertIsNone(log_writer_loop(queues, settings, self.message_log, unit_test=True))

        # Teardown
        tear_queues(queues)

    def test_function_allows_control_of_noise_packets_based_on_log_setting_queue(self) -> None:
        # Setup
        settings   = Settings(log_file_masking=True,
                              traffic_masking=True)
        master_key = MasterKey()
        queues     = gen_queue_dict()

        noise_tuple = (nick_to_pub_key('Alice'), P_N_HEADER + bytes(PADDING_LENGTH), True, True, master_key)

        def queue_delayer() -> None:
            """Place packets to log into queue after delay."""
            for _ in range(5):
                queues[LOG_PACKET_QUEUE].put(noise_tuple)  # Not logged because logging_state is False by default
                time.sleep(SLEEP_DELAY)

            queues[LOG_SETTING_QUEUE].put(True)
            for _ in range(2):
                queues[LOG_PACKET_QUEUE].put(noise_tuple)  # Log two packets
                time.sleep(SLEEP_DELAY)

            queues[LOG_SETTING_QUEUE].put(False)
            for _ in range(3):
                queues[LOG_PACKET_QUEUE].put(noise_tuple)  # Not logged because logging_state is False
                time.sleep(SLEEP_DELAY)

            queues[UNIT_TEST_QUEUE].put(EXIT)

            queues[LOG_SETTING_QUEUE].put(True)
            queues[LOG_PACKET_QUEUE].put(noise_tuple)  # Log third packet

        # Test
        threading.Thread(target=queue_delayer).start()

        self.assertIsNone(log_writer_loop(queues, settings, self.message_log, unit_test=True))

        # Teardown
        tear_queues(queues)


class TestWriteLogEntry(unittest.TestCase):

    def setUp(self) -> None:
        """Pre-test actions."""
        self.unit_test_dir    = cd_unit_test()
        self.master_key       = MasterKey()
        self.settings         = Settings()
        self.log_file         = f'{DIR_USER_DATA}{self.settings.software_operation}_logs'
        self.tfc_log_database = MessageLog(self.log_file, self.master_key.master_key)

    def tearDown(self) -> None:
        """Post-test actions."""
        cleanup(self.unit_test_dir)

    def test_oversize_packet_raises_critical_error(self) -> None:
        # Setup
        assembly_p = F_S_HEADER + bytes(PADDING_LENGTH) + b'a'

        # Test
        with self.assertRaises(SystemExit):
            write_log_entry(assembly_p, nick_to_pub_key('Alice'), self.tfc_log_database)

    def test_log_entry_is_concatenated(self) -> None:
        for i in range(5):
            assembly_p = F_S_HEADER + bytes(PADDING_LENGTH)
            self.assertIsNone(write_log_entry(assembly_p, nick_to_pub_key('Alice'), self.tfc_log_database))


class TestAccessHistoryAndPrintLogs(TFCTestCase):

    def setUp(self) -> None:
        """Pre-test actions."""
        self.unit_test_dir    = cd_unit_test()
        self.master_key       = MasterKey()
        self.settings         = Settings()
        self.log_file         = f'{DIR_USER_DATA}{self.settings.software_operation}_logs'
        self.tfc_log_database = MessageLog(self.log_file, self.master_key.master_key)
        self.window           = RxWindow(type=WIN_TYPE_CONTACT,
                                         uid=nick_to_pub_key('Alice'),
                                         name='Alice',
                                         type_print='contact')

        self.contact_list          = ContactList(self.master_key, self.settings)
        self.contact_list.contacts = list(map(create_contact, ['Alice', 'Charlie']))

        self.time = STATIC_TIMESTAMP

        self.group_list    = GroupList(groups=['test_group'])
        self.group         = self.group_list.get_group('test_group')
        self.group.members = self.contact_list.contacts
        self.args          = self.window, self.contact_list, self.group_list, self.settings, self.master_key

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

    def tearDown(self) -> None:
        """Post-test actions."""
        cleanup(self.unit_test_dir)

    def test_missing_log_file_raises_se(self) -> None:
        # Setup
        os.remove(self.log_file)

        # Test
        self.assert_se("No log database available.", access_logs, *self.args)

    def test_empty_log_file(self) -> None:
        # Setup
        open(f'{DIR_USER_DATA}{self.settings.software_operation}_logs', 'wb+').close()

        # Test
        self.assert_se(f"No logged messages for contact '{self.window.name}'.", access_logs, *self.args)

    @mock.patch('struct.pack', return_value=TIMESTAMP_BYTES)
    def test_display_short_private_message(self, _: Any) -> None:
        # Setup
        # Add a message from user (Bob) to different contact (Charlie). access_logs should not display this message.
        for p in assembly_packet_creator(MESSAGE, 'Hi Charlie'):
            write_log_entry(p, nick_to_pub_key('Charlie'), self.tfc_log_database)

        # Add a message from contact Alice to user (Bob).
        for p in assembly_packet_creator(MESSAGE, 'Hi Bob'):
            write_log_entry(p, nick_to_pub_key('Alice'), self.tfc_log_database, origin=ORIGIN_CONTACT_HEADER)

        # Add a message from user (Bob) to Alice.
        for p in assembly_packet_creator(MESSAGE, 'Hi Alice'):
            write_log_entry(p, nick_to_pub_key('Alice'), self.tfc_log_database)

        # Test
        self.assert_prints((CLEAR_ENTIRE_SCREEN + CURSOR_LEFT_UP_CORNER + f"""\
Log file of message(s) sent to contact Alice
════════════════════════════════════════════════════════════════════════════════
{self.time} Alice: Hi Bob
{self.time}    Me: Hi Alice
<End of log file>

"""), access_logs, *self.args)

    @mock.patch('struct.pack', return_value=TIMESTAMP_BYTES)
    def test_export_short_private_message(self, _: Any) -> None:
        # Setup
        # Test title displayed by the Receiver program.
        self.settings.software_operation = RX
        self.log_file         = f'{DIR_USER_DATA}{self.settings.software_operation}_logs'
        self.tfc_log_database = MessageLog(self.log_file, self.master_key.master_key)

        # Add a message from contact Alice to user (Bob).
        for p in assembly_packet_creator(MESSAGE, 'Hi Bob'):
            write_log_entry(p, nick_to_pub_key('Alice'), self.tfc_log_database, origin=ORIGIN_CONTACT_HEADER)

        # Add a message from user (Bob) to Alice.
        for p in assembly_packet_creator(MESSAGE, 'Hi Alice'):
            write_log_entry(p, nick_to_pub_key('Alice'), self.tfc_log_database)

        # Test
        self.assertIsNone(access_logs(*self.args, export=True))

        with open("Receiver - Plaintext log (Alice)") as f:
            self.assertEqual(f.read(), f"""\
Log file of message(s) to/from contact Alice
════════════════════════════════════════════════════════════════════════════════
{self.time} Alice: Hi Bob
{self.time}    Me: Hi Alice
<End of log file>

""")

    @mock.patch('struct.pack', return_value=TIMESTAMP_BYTES)
    def test_long_private_message(self, _: Any) -> None:
        # Setup
        # Add an assembly packet sequence sent to contact Alice containing cancel packet. access_logs should skip this.
        packets = assembly_packet_creator(MESSAGE, self.msg)
        packets = packets[2:] + [M_C_HEADER + bytes(PADDING_LENGTH)]
        for p in packets:
            write_log_entry(p, nick_to_pub_key('Alice'), self.tfc_log_database)

        # Add an orphaned 'append' assembly packet the function should skip.
        write_log_entry(M_A_HEADER + bytes(PADDING_LENGTH), nick_to_pub_key('Alice'), self.tfc_log_database)

        # Add a group message for a different group the function should skip.
        for p in assembly_packet_creator(MESSAGE, 'This is a short message', group_id=GROUP_ID_LENGTH * b'1'):
            write_log_entry(p, nick_to_pub_key('Alice'), self.tfc_log_database)

        # Add a message from contact Alice to user (Bob).
        for p in assembly_packet_creator(MESSAGE, self.msg):
            write_log_entry(p, nick_to_pub_key('Alice'), self.tfc_log_database, origin=ORIGIN_CONTACT_HEADER)

        # Add a message from user (Bob) to Alice.
        for p in assembly_packet_creator(MESSAGE, self.msg):
            write_log_entry(p, nick_to_pub_key('Alice'), self.tfc_log_database)

        # Test
        self.assert_prints((CLEAR_ENTIRE_SCREEN + CURSOR_LEFT_UP_CORNER + f"""\
Log file of message(s) sent to contact Alice
════════════════════════════════════════════════════════════════════════════════
{self.time} Alice: Lorem ipsum dolor sit amet, consectetur adipiscing elit.
                   Aenean condimentum consectetur purus quis dapibus. Fusce
                   venenatis lacus ut rhoncus faucibus. Cras sollicitudin
                   commodo sapien, sed bibendum velit maximus in. Aliquam ac
                   metus risus. Sed cursus ornare luctus. Integer aliquet lectus
                   id massa blandit imperdiet. Ut sed massa eget quam facilisis
                   rutrum. Mauris eget luctus nisl. Sed ut elit iaculis,
                   faucibus lacus eget, sodales magna. Nunc sed commodo arcu. In
                   hac habitasse platea dictumst. Integer luctus aliquam justo,
                   at vestibulum dolor iaculis ac. Etiam laoreet est eget odio
                   rutrum, vel malesuada lorem rhoncus. Cras finibus in neque eu
                   euismod. Nulla facilisi. Nunc nec aliquam quam, quis
                   ullamcorper leo. Nunc egestas lectus eget est porttitor, in
                   iaculis felis scelerisque. In sem elit, fringilla id viverra
                   commodo, sagittis varius purus. Pellentesque rutrum lobortis
                   neque a facilisis. Mauris id tortor placerat, aliquam dolor
                   ac, venenatis arcu.
{self.time}    Me: Lorem ipsum dolor sit amet, consectetur adipiscing elit.
                   Aenean condimentum consectetur purus quis dapibus. Fusce
                   venenatis lacus ut rhoncus faucibus. Cras sollicitudin
                   commodo sapien, sed bibendum velit maximus in. Aliquam ac
                   metus risus. Sed cursus ornare luctus. Integer aliquet lectus
                   id massa blandit imperdiet. Ut sed massa eget quam facilisis
                   rutrum. Mauris eget luctus nisl. Sed ut elit iaculis,
                   faucibus lacus eget, sodales magna. Nunc sed commodo arcu. In
                   hac habitasse platea dictumst. Integer luctus aliquam justo,
                   at vestibulum dolor iaculis ac. Etiam laoreet est eget odio
                   rutrum, vel malesuada lorem rhoncus. Cras finibus in neque eu
                   euismod. Nulla facilisi. Nunc nec aliquam quam, quis
                   ullamcorper leo. Nunc egestas lectus eget est porttitor, in
                   iaculis felis scelerisque. In sem elit, fringilla id viverra
                   commodo, sagittis varius purus. Pellentesque rutrum lobortis
                   neque a facilisis. Mauris id tortor placerat, aliquam dolor
                   ac, venenatis arcu.
<End of log file>

"""), access_logs, *self.args)

    @mock.patch('struct.pack', return_value=TIMESTAMP_BYTES)
    def test_short_group_message(self, _: Any) -> None:
        # Setup
        self.window = RxWindow(type=WIN_TYPE_GROUP,
                               uid=group_name_to_group_id('test_group'),
                               name='test_group',
                               group=self.group,
                               type_print='group',
                               group_list=self.group_list)

        # Add messages to Alice and Charlie. Add duplicate of outgoing message that should be skipped by access_logs.
        for p in assembly_packet_creator(MESSAGE, 'This is a short message', group_id=self.window.uid):
            write_log_entry(p, nick_to_pub_key('Alice'),   self.tfc_log_database)
            write_log_entry(p, nick_to_pub_key('Alice'),   self.tfc_log_database, origin=ORIGIN_CONTACT_HEADER)
            write_log_entry(p, nick_to_pub_key('Charlie'), self.tfc_log_database)
            write_log_entry(p, nick_to_pub_key('Charlie'), self.tfc_log_database, origin=ORIGIN_CONTACT_HEADER)

        # Test
        self.assert_prints((CLEAR_ENTIRE_SCREEN + CURSOR_LEFT_UP_CORNER + f"""\
Log file of message(s) sent to group test_group
════════════════════════════════════════════════════════════════════════════════
{self.time}      Me: This is a short message
{self.time}   Alice: This is a short message
{self.time} Charlie: This is a short message
<End of log file>

"""), access_logs, self.window, self.contact_list, self.group_list, self.settings, self.master_key)

    @mock.patch('struct.pack', return_value=TIMESTAMP_BYTES)
    def test_long_group_message(self, _: Any) -> None:
        # Setup
        # Test title displayed by the Receiver program.
        self.settings.software_operation = RX
        self.log_file                    = f'{DIR_USER_DATA}{self.settings.software_operation}_logs'
        self.tfc_log_database            = MessageLog(self.log_file, self.master_key.master_key)

        self.window = RxWindow(type=WIN_TYPE_GROUP,
                               uid=group_name_to_group_id('test_group'),
                               name='test_group',
                               group=self.group,
                               type_print='group')

        # Add an assembly packet sequence sent to contact Alice in group containing cancel packet.
        # Access_logs should skip this.
        packets = assembly_packet_creator(MESSAGE, self.msg, group_id=group_name_to_group_id('test_group'))
        packets = packets[2:] + [M_C_HEADER + bytes(PADDING_LENGTH)]
        for p in packets:
            write_log_entry(p, nick_to_pub_key('Alice'), self.tfc_log_database)

        # Add an orphaned 'append' assembly packet. access_logs should skip this.
        write_log_entry(M_A_HEADER + bytes(PADDING_LENGTH), nick_to_pub_key('Alice'), self.tfc_log_database)

        # Add a private message. access_logs should skip this.
        for p in assembly_packet_creator(MESSAGE, 'This is a short private message'):
            write_log_entry(p, nick_to_pub_key('Alice'), self.tfc_log_database)

        # Add a group message for a different group. access_logs should skip this.
        for p in assembly_packet_creator(MESSAGE, 'This is a short group message', group_id=GROUP_ID_LENGTH * b'1'):
            write_log_entry(p, nick_to_pub_key('Alice'), self.tfc_log_database)

        # Add messages to Alice and Charlie in group.
        # Add duplicate of outgoing message that should be skipped by access_logs.
        for p in assembly_packet_creator(MESSAGE, self.msg, group_id=group_name_to_group_id('test_group')):
            write_log_entry(p, nick_to_pub_key('Alice'),   self.tfc_log_database)
            write_log_entry(p, nick_to_pub_key('Alice'),   self.tfc_log_database, origin=ORIGIN_CONTACT_HEADER)
            write_log_entry(p, nick_to_pub_key('Charlie'), self.tfc_log_database)
            write_log_entry(p, nick_to_pub_key('Charlie'), self.tfc_log_database, origin=ORIGIN_CONTACT_HEADER)

        # Test
        self.assert_prints((CLEAR_ENTIRE_SCREEN + CURSOR_LEFT_UP_CORNER + f"""\
Log file of message(s) to/from group test_group
════════════════════════════════════════════════════════════════════════════════
{self.time}      Me: Lorem ipsum dolor sit amet, consectetur adipiscing elit.
                     Aenean condimentum consectetur purus quis dapibus. Fusce
                     venenatis lacus ut rhoncus faucibus. Cras sollicitudin
                     commodo sapien, sed bibendum velit maximus in. Aliquam ac
                     metus risus. Sed cursus ornare luctus. Integer aliquet
                     lectus id massa blandit imperdiet. Ut sed massa eget quam
                     facilisis rutrum. Mauris eget luctus nisl. Sed ut elit
                     iaculis, faucibus lacus eget, sodales magna. Nunc sed
                     commodo arcu. In hac habitasse platea dictumst. Integer
                     luctus aliquam justo, at vestibulum dolor iaculis ac. Etiam
                     laoreet est eget odio rutrum, vel malesuada lorem rhoncus.
                     Cras finibus in neque eu euismod. Nulla facilisi. Nunc nec
                     aliquam quam, quis ullamcorper leo. Nunc egestas lectus
                     eget est porttitor, in iaculis felis scelerisque. In sem
                     elit, fringilla id viverra commodo, sagittis varius purus.
                     Pellentesque rutrum lobortis neque a facilisis. Mauris id
                     tortor placerat, aliquam dolor ac, venenatis arcu.
{self.time}   Alice: Lorem ipsum dolor sit amet, consectetur adipiscing elit.
                     Aenean condimentum consectetur purus quis dapibus. Fusce
                     venenatis lacus ut rhoncus faucibus. Cras sollicitudin
                     commodo sapien, sed bibendum velit maximus in. Aliquam ac
                     metus risus. Sed cursus ornare luctus. Integer aliquet
                     lectus id massa blandit imperdiet. Ut sed massa eget quam
                     facilisis rutrum. Mauris eget luctus nisl. Sed ut elit
                     iaculis, faucibus lacus eget, sodales magna. Nunc sed
                     commodo arcu. In hac habitasse platea dictumst. Integer
                     luctus aliquam justo, at vestibulum dolor iaculis ac. Etiam
                     laoreet est eget odio rutrum, vel malesuada lorem rhoncus.
                     Cras finibus in neque eu euismod. Nulla facilisi. Nunc nec
                     aliquam quam, quis ullamcorper leo. Nunc egestas lectus
                     eget est porttitor, in iaculis felis scelerisque. In sem
                     elit, fringilla id viverra commodo, sagittis varius purus.
                     Pellentesque rutrum lobortis neque a facilisis. Mauris id
                     tortor placerat, aliquam dolor ac, venenatis arcu.
{self.time} Charlie: Lorem ipsum dolor sit amet, consectetur adipiscing elit.
                     Aenean condimentum consectetur purus quis dapibus. Fusce
                     venenatis lacus ut rhoncus faucibus. Cras sollicitudin
                     commodo sapien, sed bibendum velit maximus in. Aliquam ac
                     metus risus. Sed cursus ornare luctus. Integer aliquet
                     lectus id massa blandit imperdiet. Ut sed massa eget quam
                     facilisis rutrum. Mauris eget luctus nisl. Sed ut elit
                     iaculis, faucibus lacus eget, sodales magna. Nunc sed
                     commodo arcu. In hac habitasse platea dictumst. Integer
                     luctus aliquam justo, at vestibulum dolor iaculis ac. Etiam
                     laoreet est eget odio rutrum, vel malesuada lorem rhoncus.
                     Cras finibus in neque eu euismod. Nulla facilisi. Nunc nec
                     aliquam quam, quis ullamcorper leo. Nunc egestas lectus
                     eget est porttitor, in iaculis felis scelerisque. In sem
                     elit, fringilla id viverra commodo, sagittis varius purus.
                     Pellentesque rutrum lobortis neque a facilisis. Mauris id
                     tortor placerat, aliquam dolor ac, venenatis arcu.
<End of log file>

"""), access_logs, self.window, self.contact_list, self.group_list, self.settings, self.master_key)


class TestReEncrypt(TFCTestCase):

    def setUp(self) -> None:
        """Pre-test actions."""
        self.unit_test_dir  = cd_unit_test()
        self.old_master_key = MasterKey()
        self.new_master_key = MasterKey(master_key=os.urandom(SYMMETRIC_KEY_LENGTH))
        self.settings       = Settings()
        self.tmp_file_name  = f"{DIR_USER_DATA}{self.settings.software_operation}_logs_temp"
        self.time           = STATIC_TIMESTAMP
        self.log_file       = f'{DIR_USER_DATA}{self.settings.software_operation}_logs'
        self.message_log    = MessageLog(self.log_file, self.old_master_key.master_key)

    def tearDown(self) -> None:
        """Post-test actions."""
        cleanup(self.unit_test_dir)

    def test_missing_log_database_raises_se(self) -> None:
        # Setup
        os.remove(self.log_file)

        # Test
        self.assert_se(f"No log database available.",
                       change_log_db_key, self.old_master_key.master_key, self.new_master_key.master_key, self.settings)

    @mock.patch('struct.pack', return_value=TIMESTAMP_BYTES)
    def test_database_encryption_with_another_key(self, _: Any) -> None:
        # Setup
        window                = RxWindow(type=WIN_TYPE_CONTACT,
                                         uid=nick_to_pub_key('Alice'),
                                         name='Alice',
                                         type_print='contact')
        contact_list          = ContactList(self.old_master_key, self.settings)
        contact_list.contacts = [create_contact('Alice')]
        group_list            = GroupList()

        # Create temp file that must be removed.
        temp_file_data = os.urandom(LOG_ENTRY_LENGTH)
        with open(self.tmp_file_name, 'wb+') as f:
            f.write(temp_file_data)

        # Add a message from contact Alice to user (Bob).
        for p in assembly_packet_creator(MESSAGE, 'This is a short message'):
            write_log_entry(p, nick_to_pub_key('Alice'), self.message_log, origin=ORIGIN_CONTACT_HEADER)

        # Add a message from user (Bob) to Alice.
        for p in assembly_packet_creator(MESSAGE, 'This is a short message'):
            write_log_entry(p, nick_to_pub_key('Alice'), self.message_log)

        # Check logfile content.
        message = (CLEAR_ENTIRE_SCREEN + CURSOR_LEFT_UP_CORNER + f"""\
Log file of message(s) sent to contact Alice
════════════════════════════════════════════════════════════════════════════════
{self.time} Alice: This is a short message
{self.time}    Me: This is a short message
<End of log file>

""")
        self.assertIsNone(
            change_log_db_key(self.old_master_key.master_key, self.new_master_key.master_key, self.settings))

        with open(self.tmp_file_name, 'rb') as f:
            purp_temp_data = f.read()
        self.assertNotEqual(purp_temp_data, temp_file_data)

        # Test that decryption with new key is identical.
        replace_log_db(self.settings)
        self.assert_prints(message, access_logs, window, contact_list, group_list, self.settings, self.new_master_key)

        # Test that temp file is removed.
        self.assertFalse(os.path.isfile(self.tmp_file_name))


class TestRemoveLog(TFCTestCase):

    def setUp(self) -> None:
        """Pre-test actions."""
        self.unit_test_dir    = cd_unit_test()
        self.master_key       = MasterKey()
        self.settings         = Settings()
        self.time             = STATIC_TIMESTAMP
        self.contact_list     = ContactList(self.master_key, self.settings)
        self.group_list       = GroupList(groups=['test_group'])
        self.file_name        = f'{DIR_USER_DATA}{self.settings.software_operation}_logs'
        self.tmp_file_name    = self.file_name + "_temp"
        self.tfc_log_database = MessageLog(self.file_name, self.master_key.master_key)
        self.args             = self.contact_list, self.group_list, self.settings, self.master_key

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

    def tearDown(self) -> None:
        """Post-test actions."""
        cleanup(self.unit_test_dir)

    def test_missing_log_file_raises_se(self) -> None:
        # Setup
        os.remove(self.file_name)

        # Test
        self.assert_se("No log database available.", remove_logs, *self.args, nick_to_pub_key('Alice'))

    def test_removal_of_group_logs(self) -> None:
        # Setup
        short_msg = "Lorem ipsum dolor sit amet, consectetur adipiscing elit."

        # Add long message from user (Bob) to Alice and Charlie. These should be removed.
        for p in assembly_packet_creator(MESSAGE, self.msg, group_id=group_name_to_group_id('test_group')):
            write_log_entry(p, nick_to_pub_key('Alice'),   self.tfc_log_database)
            write_log_entry(p, nick_to_pub_key('Charlie'), self.tfc_log_database)

        # Add short message from user (Bob) to Alice and Charlie. These should be removed.
        for p in assembly_packet_creator(MESSAGE, short_msg, group_id=group_name_to_group_id('test_group')):
            write_log_entry(p, nick_to_pub_key('Alice'),   self.tfc_log_database)
            write_log_entry(p, nick_to_pub_key('Charlie'), self.tfc_log_database)

        # Add short message from user (Bob) to David. This should be kept.
        for p in assembly_packet_creator(MESSAGE, short_msg):
            write_log_entry(p, nick_to_pub_key('David'), self.tfc_log_database)

        # Add long message from user (Bob) to David. These should be kept.
        for p in assembly_packet_creator(MESSAGE, self.msg):
            write_log_entry(p, nick_to_pub_key('David'), self.tfc_log_database)

        # Add short message from user (Bob) to David in a group. This should be kept as group is different.
        for p in assembly_packet_creator(MESSAGE, short_msg, group_id=group_name_to_group_id('different_group')):
            write_log_entry(p, nick_to_pub_key('David'), self.tfc_log_database)

        # Add an orphaned 'append' assembly packet. This should be removed as it's corrupted.
        write_log_entry(M_A_HEADER + bytes(PADDING_LENGTH), nick_to_pub_key('Alice'), self.tfc_log_database)

        # Add long message to group member David, canceled half-way. This should be removed as unviewable.
        packets = assembly_packet_creator(MESSAGE, self.msg, group_id=group_name_to_group_id('test_group'))
        packets = packets[2:] + [M_C_HEADER + bytes(PADDING_LENGTH)]
        for p in packets:
            write_log_entry(p, nick_to_pub_key('David'), self.tfc_log_database)

        # Add long message to group member David, remove_logs should keep these as group is different.
        for p in assembly_packet_creator(MESSAGE, self.msg, group_id=group_name_to_group_id('different_group')):
            write_log_entry(p, nick_to_pub_key('David'), self.tfc_log_database)

        # Test log entries were found.
        self.assert_se("Removed log entries for group 'test_group'.",
                       remove_logs, *self.args, selector=group_name_to_group_id('test_group'))

        # Test log entries were not found when removing group again.
        self.assert_se("Found no log entries for group 'test_group'.",
                       remove_logs, *self.args, selector=group_name_to_group_id('test_group'))

    def test_removal_of_contact_logs(self) -> None:
        # Setup
        short_msg = "Lorem ipsum dolor sit amet, consectetur adipiscing elit."

        # Create temp file that must be removed.
        with open(self.tmp_file_name, 'wb+') as f:
            f.write(os.urandom(LOG_ENTRY_LENGTH))

        # Add a long message sent to both Alice and Bob.
        for p in assembly_packet_creator(MESSAGE, self.msg):
            write_log_entry(p, nick_to_pub_key('Alice'),   self.tfc_log_database)
            write_log_entry(p, nick_to_pub_key('Charlie'), self.tfc_log_database)

        # Add a short message sent to both Alice and Bob.
        for p in assembly_packet_creator(MESSAGE, short_msg):
            write_log_entry(p, nick_to_pub_key('Alice'),   self.tfc_log_database)
            write_log_entry(p, nick_to_pub_key('Charlie'), self.tfc_log_database)

        # Test
        self.assert_se(f"Removed log entries for contact '{nick_to_short_address('Alice')}'.",
                       remove_logs, *self.args, selector=nick_to_pub_key('Alice'))

        self.assert_se(f"Removed log entries for contact '{nick_to_short_address('Charlie')}'.",
                       remove_logs, *self.args, selector=nick_to_pub_key('Charlie'))

        self.assert_se(f"Found no log entries for contact '{nick_to_short_address('Alice')}'.",
                       remove_logs, *self.args, selector=nick_to_pub_key('Alice'))

        self.contact_list.contacts = [create_contact('Alice')]

        self.assert_se(f"Found no log entries for contact 'Alice'.",
                       remove_logs, *self.args, selector=nick_to_pub_key('Alice'))

        self.assert_se(f"Found no log entries for group '2e8b2Wns7dWjB'.",
                       remove_logs, *self.args, selector=group_name_to_group_id('searched_group'))


if __name__ == '__main__':
    unittest.main(exit=False)
