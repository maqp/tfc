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

import os
import struct
import time
import unittest

from multiprocessing import Queue
from unittest        import mock

from src.common.statics import *

from src.transmitter.packet import cancel_packet, queue_command, queue_file, queue_message, queue_assembly_packets
from src.transmitter.packet import send_file, send_packet, split_to_assembly_packets

from tests.mock_classes import create_contact, create_group, create_keyset, Gateway, ContactList, KeyList
from tests.mock_classes import nick_to_pub_key, OnionService, Settings, TxWindow, UserInput
from tests.utils        import cd_unittest, cleanup, gen_queue_dict, tear_queue, tear_queues, TFCTestCase


class TestQueueMessage(unittest.TestCase):

    def setUp(self):
        self.queues   = gen_queue_dict()
        self.settings = Settings()
        self.args     = self.settings, self.queues

    def tearDown(self):
        tear_queues(self.queues)

    def test_private_message_header(self):
        # Setup
        user_input = UserInput(plaintext='Test message', type=MESSAGE)
        window     = TxWindow(log_messages=True)
        window.window_contacts = [create_contact('Alice')]

        # Test
        self.assertIsNone(queue_message(user_input, window, *self.args))
        self.assertEqual(self.queues[MESSAGE_PACKET_QUEUE].qsize(), 1)

    def test_group_message_header(self):
        # Setup
        user_input = UserInput(plaintext='Test message', type=MESSAGE)
        window     = TxWindow(name='test_group',
                              type=WIN_TYPE_GROUP,
                              group=create_group('test_group'),
                              log_messages=True)
        window.window_contacts = [create_contact('Alice')]

        # Test
        self.assertIsNone(queue_message(user_input, window, *self.args))
        self.assertEqual(self.queues[MESSAGE_PACKET_QUEUE].qsize(), 1)

    def test_group_management_message_header(self):
        # Setup
        user_input = UserInput(plaintext='Test message', type=MESSAGE)
        window     = TxWindow(log_messages=True)
        window.window_contacts = [create_contact('Alice')]

        # Test
        self.assertIsNone(queue_message(user_input, window, *self.args, header=GROUP_MSG_INVITE_HEADER))
        self.assertEqual(self.queues[MESSAGE_PACKET_QUEUE].qsize(), 1)


class TestSendFile(TFCTestCase):

    def setUp(self):
        self.unittest_dir  = cd_unittest()
        self.settings      = Settings()
        self.queues        = gen_queue_dict()
        self.window        = TxWindow()
        self.onion_service = OnionService()
        self.contact_list  = ContactList(nicks=['Alice', 'Bob', 'Charlie'])
        self.args          = self.settings, self.queues, self.window

    def tearDown(self):
        cleanup(self.unittest_dir)
        tear_queues(self.queues)

    def test_traffic_masking_raises_fr(self):
        self.settings.traffic_masking = True
        self.assert_fr("Error: Command is disabled during traffic masking.", send_file, "testfile.txt", *self.args)

    def test_missing_file_raises_fr(self):
        self.assert_fr("Error: File not found.", send_file, "testfile.txt", *self.args)

    def test_empty_file_raises_fr(self):
        # Setup
        open('testfile.txt', 'wb+').close()

        # Test
        self.assert_fr("Error: Target file is empty.", send_file, "testfile.txt", *self.args)

    @mock.patch('time.sleep', return_value=None)
    def test_file_transmission_to_contact(self, _):
        # Setup
        self.window.window_contacts = [self.contact_list.get_contact_by_address_or_nick('Alice')]
        self.window.type_print      = 'contact'

        input_data = os.urandom(5)
        with open('testfile.txt', 'wb+') as f:
            f.write(input_data)

        # Test
        self.assertIsNone(send_file("testfile.txt", *self.args))
        self.assertEqual(self.queues[MESSAGE_PACKET_QUEUE].qsize(), 1)
        self.assertEqual(self.queues[RELAY_PACKET_QUEUE].qsize(),   1)

    @mock.patch('time.sleep', return_value=None)
    def test_file_transmission_to_group(self, _):
        # Setup
        self.window.window_contacts = [self.contact_list.get_contact_by_address_or_nick('Alice'),
                                       self.contact_list.get_contact_by_address_or_nick('Bob')]
        self.window.type_print      = 'group'

        input_data = os.urandom(5)
        with open('testfile.txt', 'wb+') as f:
            f.write(input_data)

        self.assertIsNone(send_file("testfile.txt", *self.args))
        self.assertEqual(self.queues[MESSAGE_PACKET_QUEUE].qsize(), 2)
        self.assertEqual(self.queues[RELAY_PACKET_QUEUE].qsize(),   1)


class TestQueueFile(TFCTestCase):

    file_list = ('tx_contacts', 'tx_groups', 'tx_keys', 'tx_login_data', 'tx_settings',
                 'rx_contacts', 'rx_groups', 'rx_keys', 'rx_login_data', 'rx_settings',
                 'tx_serial_settings.json', 'nc_serial_settings.json',
                 'rx_serial_settings.json', 'tx_onion_db')

    def setUp(self):
        self.unittest_dir = cd_unittest()
        self.queues       = gen_queue_dict()

    def tearDown(self):
        cleanup(self.unittest_dir)
        tear_queues(self.queues)

    @mock.patch('time.sleep',     return_value=None)
    @mock.patch('builtins.input', side_effect=file_list)
    def test_tfc_database_raises_fr(self, *_):
        window   = TxWindow(name='Alice',
                            type=WIN_TYPE_CONTACT,
                            type_print='contact',
                            uid=nick_to_pub_key("Alice"))
        settings = Settings(traffic_masking=True,
                            disable_gui_dialog=True)

        for file in self.file_list:
            with open(file, 'wb+') as f:
                f.write(b'a')

            self.assert_fr("Error: Can't send TFC database.", queue_file, window, settings, self.queues)

    @mock.patch('shutil.get_terminal_size', return_value=[150, 150])
    @mock.patch('builtins.input',           side_effect=['./testfile.txt', 'No'])
    def test_aborted_file(self, *_):
        # Setup
        input_data = os.urandom(5)
        with open('testfile.txt', 'wb+') as f:
            f.write(input_data)

        window   = TxWindow(name='Alice',
                            type=WIN_TYPE_CONTACT,
                            type_print='contact',
                            uid=nick_to_pub_key("Alice"))
        settings = Settings(traffic_masking=True,
                            disable_gui_dialog=True)

        # Test
        self.assert_fr("File selection aborted.", queue_file, window, settings, self.queues)

    @mock.patch('shutil.get_terminal_size', return_value=[150, 150])
    @mock.patch('builtins.input',           side_effect=['./testfile.txt', 'Yes'])
    def test_file_queue_short_traffic_masking(self, *_):
        # Setup
        input_data = os.urandom(5)
        with open('testfile.txt', 'wb+') as f:
            f.write(input_data)

        window   = TxWindow(name='Alice',
                            type=WIN_TYPE_CONTACT,
                            type_print='contact',
                            uid=nick_to_pub_key("Alice"),
                            log_messages=True)
        settings = Settings(traffic_masking=True,
                            disable_gui_dialog=True)

        # Test
        self.assertIsNone(queue_file(window, settings, self.queues))
        self.assertEqual(self.queues[TM_FILE_PACKET_QUEUE].qsize(), 1)

        q_data, log_messages, log_as_ph = self.queues[TM_FILE_PACKET_QUEUE].get()
        self.assertIsInstance(q_data, bytes)
        self.assertTrue(log_messages)
        self.assertTrue(log_as_ph)

    @mock.patch('time.sleep',     return_value=None)
    @mock.patch('builtins.input', side_effect=['./testfile.txt', 'Yes'])
    def test_file_queue_long_normal(self, *_):
        # Setup
        input_data = os.urandom(2000)
        with open('testfile.txt', 'wb+') as f:
            f.write(input_data)

        window   = TxWindow(name='Alice',
                            type=WIN_TYPE_CONTACT,
                            type_print='contact',
                            uid=nick_to_pub_key("Alice"),
                            window_contacts=[create_contact('Alice')],
                            log_messages=True)
        settings = Settings(traffic_masking=False,
                            disable_gui_dialog=True,
                            confirm_sent_files=True,
                            multi_packet_random_delay=True)

        # Test
        self.assertIsNone(queue_file(window, settings, self.queues))
        self.assertEqual(self.queues[RELAY_PACKET_QUEUE].qsize(), 1)

    @mock.patch('shutil.get_terminal_size', return_value=[150, 150])
    @mock.patch('time.sleep',               return_value=None)
    @mock.patch('builtins.input',           side_effect=['./testfile.txt', KeyboardInterrupt])
    def test_keyboard_interrupt_raises_fr(self, *_):
        # Setup
        input_data = os.urandom(2000)
        with open('testfile.txt', 'wb+') as f:
            f.write(input_data)

        window   = TxWindow(name='Alice',
                            type=WIN_TYPE_CONTACT,
                            type_print='contact',
                            uid=nick_to_pub_key("Alice"),
                            window_contacts=[create_contact('Alice')],
                            log_messages=True)
        settings = Settings(traffic_masking=True,
                            disable_gui_dialog=True,
                            confirm_sent_files=True,
                            multi_packet_random_delay=True)

        # Test
        self.assert_fr("File selection aborted.", queue_file, window, settings, self.queues)
        self.assertEqual(self.queues[RELAY_PACKET_QUEUE].qsize(), 0)


class TestQueueCommand(unittest.TestCase):

    def setUp(self):
        self.settings = Settings()
        self.queues   = gen_queue_dict()

    def tearDown(self):
        tear_queues(self.queues)

    def test_queue_command(self):
        self.assertIsNone(queue_command(os.urandom(200), self.settings, self.queues))
        c_pt = self.queues[COMMAND_PACKET_QUEUE].get()
        self.assertEqual(len(c_pt), ASSEMBLY_PACKET_LENGTH)


class TestSplitToAssemblyPackets(unittest.TestCase):

    def test_short_message(self):
        packet_list = split_to_assembly_packets(b'Short message', MESSAGE)
        self.assertEqual(len(packet_list), 1)
        self.assertTrue(packet_list[0].startswith(M_S_HEADER))

    def test_long_message(self):
        packet_list = split_to_assembly_packets(os.urandom(800), MESSAGE)
        self.assertEqual(len(packet_list), 4)
        self.assertTrue(packet_list[0].startswith(M_L_HEADER))
        self.assertTrue(packet_list[1].startswith(M_A_HEADER))
        self.assertTrue(packet_list[2].startswith(M_A_HEADER))
        self.assertTrue(packet_list[3].startswith(M_E_HEADER))

    def test_short_file(self):
        packet_list = split_to_assembly_packets(os.urandom(50), FILE)
        self.assertEqual(len(packet_list), 1)
        self.assertTrue(packet_list[0].startswith(F_S_HEADER))

    def test_long_file(self):
        packet_list = split_to_assembly_packets(os.urandom(800), FILE)
        self.assertEqual(len(packet_list), 4)
        self.assertTrue(packet_list[0].startswith(F_L_HEADER + b'\x00\x00\x00\x00\x00\x00\x00\x04'))
        self.assertTrue(packet_list[1].startswith(F_A_HEADER))
        self.assertTrue(packet_list[2].startswith(F_A_HEADER))
        self.assertTrue(packet_list[3].startswith(F_E_HEADER))

    def test_short_command(self):
        packet_list = split_to_assembly_packets(os.urandom(50), COMMAND)
        self.assertEqual(len(packet_list), 1)
        self.assertTrue(packet_list[0].startswith(C_S_HEADER))

    def test_long_command(self):
        packet_list = split_to_assembly_packets(os.urandom(800), COMMAND)
        self.assertEqual(len(packet_list), 4)
        self.assertTrue(packet_list[0].startswith(C_L_HEADER))
        self.assertTrue(packet_list[1].startswith(C_A_HEADER))
        self.assertTrue(packet_list[2].startswith(C_A_HEADER))
        self.assertTrue(packet_list[3].startswith(C_E_HEADER))


class TestQueueAssemblyPackets(unittest.TestCase):

    def setUp(self):
        self.settings = Settings()
        self.queues   = gen_queue_dict()
        self.window   = TxWindow(uid=nick_to_pub_key("Alice"),
                                 log_messages=True)
        self.window.window_contacts = [create_contact('Alice')]
        self.args     = self.settings, self.queues, self.window
    
    def tearDown(self):
        tear_queues(self.queues)

    def test_queue_message_traffic_masking(self):
        # Setup
        packet_list                   = split_to_assembly_packets(os.urandom(200), MESSAGE)
        self.settings.traffic_masking = True

        # Test
        self.assertIsNone(queue_assembly_packets(packet_list, MESSAGE, *self.args))
        self.assertEqual(self.queues[TM_MESSAGE_PACKET_QUEUE].qsize(), 1)
        packet, log_messages, log_as_ph = self.queues[TM_MESSAGE_PACKET_QUEUE].get()
        self.assertIsInstance(packet, bytes)
        self.assertTrue(log_messages)
        self.assertFalse(log_as_ph)

    def test_queue_message_normal(self):
        # Setup
        packet_list = split_to_assembly_packets(os.urandom(200), MESSAGE)

        # Test
        self.assertIsNone(queue_assembly_packets(packet_list, MESSAGE, *self.args))
        self.assertEqual(self.queues[MESSAGE_PACKET_QUEUE].qsize(), 1)

        packet, pub_key, log_setting, log_as_ph, win_uid = self.queues[MESSAGE_PACKET_QUEUE].get()
        self.assertIsInstance(packet, bytes)
        self.assertEqual(pub_key, nick_to_pub_key("Alice"))
        self.assertEqual(win_uid, nick_to_pub_key("Alice"))
        self.assertTrue(log_setting)
        self.assertFalse(log_as_ph)

    def test_queue_file_traffic_masking(self):
        # Setup
        packet_list                   = split_to_assembly_packets(os.urandom(200), FILE)
        self.settings.traffic_masking = True

        # Test
        self.assertIsNone(queue_assembly_packets(packet_list, FILE, *self.args))
        self.assertEqual(self.queues[TM_FILE_PACKET_QUEUE].qsize(), 1)
        packet, log_messages, log_as_ph = self.queues[TM_FILE_PACKET_QUEUE].get()
        self.assertIsInstance(packet, bytes)
        self.assertTrue(log_messages)
        self.assertFalse(log_as_ph)

    def test_queue_command_traffic_masking(self):
        # Setup
        packet_list                   = split_to_assembly_packets(os.urandom(200), COMMAND)
        self.settings.traffic_masking = True

        # Test
        self.assertIsNone(queue_assembly_packets(packet_list, COMMAND, *self.args))
        self.assertEqual(self.queues[TM_COMMAND_PACKET_QUEUE].qsize(), 1)
        data = self.queues[TM_COMMAND_PACKET_QUEUE].get()
        self.assertIsInstance(data, bytes)

    def test_queue_command_traffic_masking_no_window(self):
        # Setup
        self.window                   = None
        packet_list                   = split_to_assembly_packets(os.urandom(200), COMMAND)
        self.settings.traffic_masking = True

        # Test
        self.assertIsNone(queue_assembly_packets(packet_list, COMMAND, *self.args))
        self.assertEqual(self.queues[TM_COMMAND_PACKET_QUEUE].qsize(), 1)
        data = self.queues[TM_COMMAND_PACKET_QUEUE].get()
        self.assertIsInstance(data, bytes)

    def test_queue_command_normal(self):
        # Setup
        packet_list = split_to_assembly_packets(os.urandom(200), COMMAND)

        # Test
        self.assertIsNone(queue_assembly_packets(packet_list, COMMAND, *self.args))
        self.assertEqual(self.queues[COMMAND_PACKET_QUEUE].qsize(), 1)
        packet = self.queues[COMMAND_PACKET_QUEUE].get()
        self.assertIsInstance(packet, bytes)


class TestSendPacket(unittest.TestCase):
    """\
    This function is by far the most critical to security in Transmitter
    Program, as it must detect the output of key material.

    Plaintext length must always be evaluated to ensure constant
    ciphertext length and hiding of output data type.

    The most likely place for error is going to be the tx_harac
    attribute of keyset, as it's the only data loaded from the sensitive
    key database, and that is sent to the contact. An alternative place
    could be a bug in the implementation where account strings would
    incorrectly contain a byte string that contained key material, which
    would cause Transmitter Program to leak keys to Networked Computer.
    """

    def setUp(self):
        self.l_queue       = Queue()
        self.key_list      = KeyList(nicks=['Alice'])
        self.settings      = Settings()
        self.gateway       = Gateway()
        self.onion_service = OnionService()

    def tearDown(self):
        tear_queue(self.l_queue)

    def test_message_length(self):
        # Check that only 256-byte plaintext messages are ever allowed
        pub_key = nick_to_pub_key("Alice")
        for l in range(1, 256):
            with self.assertRaises(SystemExit):
                send_packet(self.key_list, self.gateway, self.l_queue, bytes(l), pub_key, True)

        for l in range(257, 300):
            with self.assertRaises(SystemExit):
                send_packet(self.key_list, self.gateway, self.l_queue, bytes(l), pub_key, True)

    def test_invalid_harac_raises_raises_struct_error(self):
        # Check that in the case where an internal error caused bytestring (possible key material) to end up in hash
        # ratchet value, the system raises some error that prevents the output of packet. In this case the, error comes
        # from the unsuccessful encoding of hash ratchet counter.
        for l in range(1, 33):
            key_list         = KeyList()
            key_list.keysets = [create_keyset('Alice',
                                              tx_key=SYMMETRIC_KEY_LENGTH * b'\x02',
                                              tx_harac=l * b'k')]

            with self.assertRaises(struct.error):
                send_packet(key_list, self.gateway, self.l_queue,
                            bytes(ASSEMBLY_PACKET_LENGTH), nick_to_pub_key("Alice"), True)

    def test_valid_message_packet(self):
        # Setup
        gateway          = Gateway(serial_error_correction=5)
        key_list         = KeyList(master_key=bytes(SYMMETRIC_KEY_LENGTH))
        key_list.keysets = [create_keyset('Alice',
                                          tx_key=SYMMETRIC_KEY_LENGTH * b'\x02',
                                          tx_harac=8)]

        # Test
        self.assertIsNone(send_packet(key_list, gateway, self.l_queue,
                                      bytes(ASSEMBLY_PACKET_LENGTH), nick_to_pub_key("Alice"), True))
        self.assertEqual(len(gateway.packets), 1)
        time.sleep(0.01)
        self.assertFalse(self.l_queue.empty())

    def test_valid_command_packet(self):
        """Test that commands are output as they should.

        Since command packets have no trailer, and since only user's
        Receiver Program has local decryption key, encryption with any
        key recipient is not already in possession of does not
        compromise plaintext.
        """
        # Setup
        key_list         = KeyList(master_key=bytes(SYMMETRIC_KEY_LENGTH))
        key_list.keysets = [create_keyset(LOCAL_ID)]

        # Test
        self.assertIsNone(send_packet(key_list, self.gateway, self.l_queue,
                                      bytes(ASSEMBLY_PACKET_LENGTH)))
        self.assertEqual(len(self.gateway.packets), 1)
        self.assertEqual(len(self.gateway.packets[0]), 345)
        self.assertEqual(self.l_queue.qsize(), 1)


class TestCancelPacket(TFCTestCase):

    def setUp(self):
        self.queues = gen_queue_dict()

    def tearDown(self):
        tear_queues(self.queues)

    def test_cancel_message_during_normal(self):
        # Setup
        user_input = UserInput('cm')
        settings   = Settings()
        window     = TxWindow(name='Alice',
                              type=WIN_TYPE_CONTACT,
                              type_print='contact',
                              uid=nick_to_pub_key("Alice"))
        window.window_contacts = [create_contact('Alice')]

        self.queues[MESSAGE_PACKET_QUEUE].put(
            ('test_message1', nick_to_pub_key("Alice"),   False, False, nick_to_pub_key("Alice")))
        self.queues[MESSAGE_PACKET_QUEUE].put(
            ('test_message2', nick_to_pub_key("Charlie"), False, False, nick_to_pub_key("Charlie")))
        self.queues[MESSAGE_PACKET_QUEUE].put(
            ('test_message3', nick_to_pub_key("Alice"),   False, False, nick_to_pub_key("Alice")))

        # Test
        self.assert_fr("Cancelled queued messages to contact Alice.",
                       cancel_packet, user_input, window, settings, self.queues)
        self.assertEqual(self.queues[MESSAGE_PACKET_QUEUE].qsize(), 2)

    def test_cancel_group_message_during_normal(self):
        # Setup
        user_input = UserInput('cm')
        settings   = Settings()
        window     = TxWindow(name='test_group',
                              type=WIN_TYPE_GROUP,
                              type_print='group',
                              uid='test_group')
        window.window_contacts = [create_contact('Alice')]

        self.queues[MESSAGE_PACKET_QUEUE].put(('test_message1', nick_to_pub_key("Alice"), False, False, 'test_group'))
        self.queues[MESSAGE_PACKET_QUEUE].put(('test_message2', nick_to_pub_key("Alice"), False, False, 'test_group'))

        # Test
        self.assert_fr("Cancelled queued messages to group test_group.",
                       cancel_packet, user_input, window, settings, self.queues)
        self.assertEqual(self.queues[MESSAGE_PACKET_QUEUE].qsize(), 1)  # Cancel packet

    def test_cancel_message_during_traffic_masking(self):
        # Setup
        user_input = UserInput('cm')
        settings   = Settings(traffic_masking=True)
        window     = TxWindow()
        window.window_contacts = [create_contact('Alice')]

        self.queues[TM_MESSAGE_PACKET_QUEUE].put(('test_message1', {nick_to_pub_key("Alice"): False}))
        self.queues[TM_MESSAGE_PACKET_QUEUE].put(('test_message2', {nick_to_pub_key("Alice"): False}))

        # Test
        self.assertIsNone(cancel_packet(user_input, window, settings, self.queues))
        self.assertEqual(self.queues[TM_MESSAGE_PACKET_QUEUE].qsize(), 1)  # Cancel packet in queue

    def test_cancel_file_during_traffic_masking(self):
        # Setup
        user_input = UserInput('cf')
        settings   = Settings(traffic_masking=True)
        window     = TxWindow()
        window.window_contacts = [create_contact('Alice')]

        self.queues[TM_FILE_PACKET_QUEUE].put(('testfile1', {nick_to_pub_key("Alice"): False}))
        self.queues[TM_FILE_PACKET_QUEUE].put(('testfile2', {nick_to_pub_key("Alice"): False}))

        # Test
        self.assertIsNone(cancel_packet(user_input, window, settings, self.queues))
        self.assertEqual(self.queues[TM_FILE_PACKET_QUEUE].qsize(), 1)

    def test_cancel_file_during_normal(self):
        # Setup
        user_input = UserInput('cf')
        settings   = Settings()
        window     = TxWindow(name='Alice',
                              type=WIN_TYPE_CONTACT,
                              type_print='contact',
                              uid=nick_to_pub_key("Alice"))
        window.window_contacts = [create_contact('Alice')]

        # Test
        self.assert_fr('Files are only queued during traffic masking.',
                       cancel_packet, user_input, window, settings, self.queues)

    def test_cancel_file_when_nothing_to_cancel(self):
        # Setup
        user_input = UserInput('cf')
        settings   = Settings(traffic_masking=True)
        window     = TxWindow(name='Alice',
                              type=WIN_TYPE_CONTACT,
                              type_print='contact',
                              uid=nick_to_pub_key("Alice"))
        window.window_contacts = [create_contact('Alice')]

        # Test
        self.assertIsNone(cancel_packet(user_input, window, settings, self.queues))
        self.assertEqual(self.queues[TM_FILE_PACKET_QUEUE].qsize(), 0)

    def test_cancel_message_when_nothing_to_cancel(self):
        # Setup
        user_input = UserInput('cm')
        settings   = Settings()
        window     = TxWindow(name='Alice',
                              type=WIN_TYPE_CONTACT,
                              type_print='contact',
                              uid=nick_to_pub_key("Alice"))
        window.window_contacts = [create_contact('Alice')]

        # Test
        self.assert_fr("No messages queued for contact Alice.",
                       cancel_packet, user_input, window, settings, self.queues)
        self.assertEqual(self.queues[TM_FILE_PACKET_QUEUE].qsize(), 0)


if __name__ == '__main__':
    unittest.main(exit=False)
