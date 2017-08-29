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

import builtins
import os
import struct
import time
import unittest

from multiprocessing import Queue

from src.common.statics import *

from src.tx.packet import cancel_packet, queue_command, queue_file, queue_message
from src.tx.packet import queue_packets, split_to_assembly_packets, send_packet, transmit

from tests.mock_classes import create_contact, create_group, create_keyset, Gateway, KeyList, Settings, TxWindow, UserInput
from tests.utils        import ignored, TFCTestCase


class TestQueueMessage(unittest.TestCase):

    def setUp(self):
        self.m_queue  = Queue()
        self.settings = Settings()

    def tearDown(self):
        while not self.m_queue.empty():
            self.m_queue.get()
        time.sleep(0.1)
        self.m_queue.close()

    def test_private_message_header(self):
        # Setup
        user_input = UserInput(plaintext='Test message', type=MESSAGE)
        window     = TxWindow(log_messages=True)

        window.window_contacts = [create_contact()]

        # Test
        self.assertIsNone(queue_message(user_input, window, self.settings, self.m_queue))
        time.sleep(0.1)

        self.assertEqual(self.m_queue.qsize(), 1)

    def test_group_message_header(self):
        # Setup
        user_input = UserInput(plaintext='Test message', type=MESSAGE)
        window     = TxWindow(name='testgroup',
                              type=WIN_TYPE_GROUP,
                              group=create_group(),
                              log_messages=True)

        window.window_contacts = [create_contact()]

        # Test
        self.assertIsNone(queue_message(user_input, window, self.settings, self.m_queue))
        time.sleep(0.1)

        self.assertEqual(self.m_queue.qsize(), 1)

    def test_group_management_message_header(self):
        # Setup
        user_input = UserInput(plaintext='Test message', type=MESSAGE)
        window     = TxWindow(log_messages=True)

        window.window_contacts = [create_contact()]

        # Test
        self.assertIsNone(queue_message(user_input, window, self.settings,
                                        self.m_queue, header=GROUP_MSG_INVITEJOIN_HEADER))
        time.sleep(0.1)

        self.assertEqual(self.m_queue.qsize(), 1)


class TestQueueFile(TFCTestCase):

    def setUp(self):
        self.f_queue = Queue()

    def tearDown(self):
        while not self.f_queue.empty():
            self.f_queue.get()
        time.sleep(0.1)
        self.f_queue.close()

        with ignored(OSError):
            os.remove('testfile.txt')

    def test_aborted_file(self):
        # Setup
        input_data = os.urandom(5)
        with open('testfile.txt', 'wb+') as f:
            f.write(input_data)

        window   = TxWindow(name='Alice',
                            type=WIN_TYPE_CONTACT,
                            type_print='contact',
                            uid='alice@jabber.org')
        settings = Settings(session_traffic_masking=True,
                            disable_gui_dialog=True)
        gateway  = Gateway(txm_inter_packet_delay=0.02)

        input_list     = ['./testfile.txt', 'No']
        gen            = iter(input_list)
        builtins.input = lambda _: str(next(gen))

        # Test
        self.assertFR("File selection aborted.", queue_file, window, settings, self.f_queue, gateway)

    def test_file_queue_short_traffic_masking(self):
        # Setup
        input_data = os.urandom(5)
        with open('testfile.txt', 'wb+') as f:
            f.write(input_data)

        window   = TxWindow(name='Alice',
                            type=WIN_TYPE_CONTACT,
                            type_print='contact',
                            uid='alice@jabber.org',
                            log_messages=True)
        settings = Settings(session_traffic_masking=True,
                            disable_gui_dialog=True)
        gateway  = Gateway(txm_inter_packet_delay=0.02)

        input_list     = ['./testfile.txt', 'Yes']
        gen            = iter(input_list)
        builtins.input = lambda _: str(next(gen))

        # Test
        self.assertIsNone(queue_file(window, settings, self.f_queue, gateway))
        time.sleep(0.1)

        self.assertEqual(self.f_queue.qsize(), 1)

        q_data, log_messages, log_as_ph = self.f_queue.get()
        self.assertIsInstance(q_data, bytes)
        self.assertTrue(log_messages)
        self.assertTrue(log_as_ph)

    def test_file_queue_long_normal(self):
        # Setup
        input_data = os.urandom(2000)
        with open('testfile.txt', 'wb+') as f:
            f.write(input_data)

        window   = TxWindow(name='Alice',
                            type=WIN_TYPE_CONTACT,
                            type_print='contact',
                            uid='alice@jabber.org',
                            window_contacts=[create_contact()],
                            log_messages=True)
        settings = Settings(session_traffic_masking=False,
                            disable_gui_dialog=True,
                            confirm_sent_files=True,
                            multi_packet_random_delay=True)
        gateway  = Gateway(txm_inter_packet_delay=0.02)

        input_list     = ['./testfile.txt', 'Yes']
        gen            = iter(input_list)
        builtins.input = lambda _: str(next(gen))

        # Test
        self.assertIsNone(queue_file(window, settings, self.f_queue, gateway))
        time.sleep(0.1)

        self.assertEqual(self.f_queue.qsize(), 11)

        packet, settings, rx_account, tx_account, log_messages, log_as_ph, win_uid = self.f_queue.get()
        self.assertIsInstance(packet, bytes)
        self.assertIsInstance(settings, Settings)
        self.assertEqual(rx_account, 'alice@jabber.org')
        self.assertEqual(tx_account, 'user@jabber.org')
        self.assertEqual(win_uid, 'alice@jabber.org')
        self.assertTrue(log_messages)
        self.assertTrue(log_as_ph)


class TestQueueCommand(unittest.TestCase):

    def setUp(self):
        self.c_queue  = Queue()
        self.settings = Settings()

    def tearDown(self):
        while not self.c_queue.empty():
            self.c_queue.get()
        time.sleep(0.1)
        self.c_queue.close()

    def test_queue_command(self):
        self.assertIsNone(queue_command(os.urandom(200), self.settings, self.c_queue))
        time.sleep(0.1)

        c_pt, settings_ = self.c_queue.get()
        self.assertEqual(len(c_pt), ASSEMBLY_PACKET_LEN)
        self.assertIsInstance(settings_, Settings)


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


class TestQueuePackets(unittest.TestCase):

    def setUp(self):
        self.settings = Settings()
        self.queue    = Queue()
        self.window   = TxWindow(uid='alice@jabber.org',
                                log_messages=True)

        self.window.window_contacts = [create_contact()]

    def tearDown(self):
        while not self.queue.empty():
            self.queue.get()
        time.sleep(0.1)
        self.queue.close()

    def test_queue_message_traffic_masking(self):
        # Setup
        packet_list = split_to_assembly_packets(os.urandom(200), MESSAGE)
        self.settings.session_traffic_masking = True

        # Test
        self.assertIsNone(queue_packets(packet_list, MESSAGE, self.settings, self.queue, self.window))
        time.sleep(0.1)

        self.assertEqual(self.queue.qsize(), 1)
        packet, log_messages, log_as_ph = self.queue.get()
        self.assertIsInstance(packet, bytes)
        self.assertTrue(log_messages)
        self.assertFalse(log_as_ph)

    def test_queue_message_normal(self):
        # Setup
        packet_list = split_to_assembly_packets(os.urandom(200), MESSAGE)

        # Test
        self.assertIsNone(queue_packets(packet_list, MESSAGE, self.settings, self.queue, self.window))
        time.sleep(0.1)

        self.assertEqual(self.queue.qsize(), 1)

        packet, settings, rx_account, tx_account, log_setting, log_as_ph, win_uid = self.queue.get()
        self.assertIsInstance(packet, bytes)
        self.assertIsInstance(settings, Settings)
        self.assertEqual(rx_account, 'alice@jabber.org')
        self.assertEqual(tx_account, 'user@jabber.org')
        self.assertEqual(win_uid, 'alice@jabber.org')
        self.assertTrue(log_setting)
        self.assertFalse(log_as_ph)

    def test_queue_file_traffic_masking(self):
        # Setup
        packet_list = split_to_assembly_packets(os.urandom(200), FILE)
        self.settings.session_traffic_masking = True

        # Test
        self.assertIsNone(queue_packets(packet_list, FILE, self.settings, self.queue, self.window))
        time.sleep(0.1)

        self.assertEqual(self.queue.qsize(), 1)
        packet, log_messages, log_as_ph = self.queue.get()
        self.assertIsInstance(packet, bytes)
        self.assertTrue(log_messages)
        self.assertFalse(log_as_ph)

    def test_queue_file_normal(self):
        # Setup
        packet_list = split_to_assembly_packets(os.urandom(200), FILE)

        # Test
        self.assertIsNone(queue_packets(packet_list, FILE, self.settings, self.queue, self.window, log_as_ph=True))
        time.sleep(0.1)

        self.assertEqual(self.queue.qsize(), 1)

        packet, settings, rx_account, tx_account, log_setting, log_as_ph, window_uid = self.queue.get()
        self.assertIsInstance(packet, bytes)
        self.assertIsInstance(settings, Settings)
        self.assertEqual(rx_account, 'alice@jabber.org')
        self.assertEqual(tx_account, 'user@jabber.org')
        self.assertEqual(window_uid, 'alice@jabber.org')
        self.assertTrue(log_setting)
        self.assertTrue(log_as_ph)

    def test_queue_command_traffic_masking(self):
        # Setup
        packet_list = split_to_assembly_packets(os.urandom(200), COMMAND)
        self.settings.session_traffic_masking = True

        # Test
        self.assertIsNone(queue_packets(packet_list, COMMAND, self.settings, self.queue, self.window))
        time.sleep(0.1)

        self.assertEqual(self.queue.qsize(), 1)
        data, log_messages = self.queue.get()
        self.assertIsInstance(data, bytes)
        self.assertTrue(log_messages)

    def test_queue_command_normal(self):
        # Setup
        packet_list = split_to_assembly_packets(os.urandom(200), COMMAND)

        # Test
        self.assertIsNone(queue_packets(packet_list, COMMAND, self.settings, self.queue, self.window))
        time.sleep(0.1)

        self.assertEqual(self.queue.qsize(), 1)

        packet, settings = self.queue.get()
        self.assertIsInstance(packet, bytes)
        self.assertIsInstance(settings, Settings)


class TestSendPacket(unittest.TestCase):
    """\
    This function is by far the most critical to security in TxM,
    as it must detect output of key material.

    Plaintext length must always be evaluated to ensure constant
    ciphertext length and hiding of output data type.

    The most likely place for error is going to be the tx_harac
    attribute of keyset, as it's the only data loaded from the
    sensitive key database that is sent to contact. Alternative
    place could be a bug in implementation where account strings
    would incorrectly contain a byte string that contained key
    material.
    """

    def setUp(self):
        self.l_queue  = Queue()
        self.key_list = KeyList(nicks=['Alice'])
        self.settings = Settings()
        self.gateway  = Gateway()

    def tearDown(self):
        while not self.l_queue.empty():
            self.l_queue.get()
        time.sleep(0.1)
        self.l_queue.close()

    def test_message_length(self):
        # Check that only 256-byte plaintext messages are ever allowed
        for l in range(1, 256):
            with self.assertRaises(SystemExit):
                send_packet(self.key_list, self.gateway, self.l_queue, bytes(l),
                            self.settings, 'alice@jabber.org', 'bob@jabber.org', True)

        for l in range(257, 300):
            with self.assertRaises(SystemExit):
                send_packet(self.key_list, self.gateway, self.l_queue, bytes(l),
                            self.settings, 'alice@jabber.org', 'bob@jabber.org', True)

    def test_invalid_harac_raises_raises_struct_error(self):
        # Check that in case where internal error caused bytestring (possible key material)
        # to end up in hash ratchet value, system raises some error that prevents output of packet.
        # In this case the error comes from unsuccessful encoding of hash ratchet counter.
        for l in range(1, 33):
            key_list         = KeyList()
            key_list.keysets = [create_keyset(tx_key=KEY_LENGTH * b'\x02',
                                              tx_harac=l * b'k')]

            with self.assertRaises(struct.error):
                send_packet(key_list, self.gateway, self.l_queue, bytes(ASSEMBLY_PACKET_LEN),
                            self.settings, 'alice@jabber.org', 'bob@jabber.org', True)

    def test_invalid_account_raises_stop_iteration(self):
        # Check that in case where internal error caused bytestring (possible key material)
        # to end up in account strings, System raises some error that prevents output of packet.
        # In this case the error comes from unsuccessful encoding of string (AttributeError)
        # or KeyList lookup error when bytes are used (StopIteration). These errors are not catched.
        with self.assertRaises(StopIteration):
            send_packet(self.key_list, self.gateway, self.l_queue, bytes(ASSEMBLY_PACKET_LEN),
                        self.settings, b'alice@jabber.org', 'bob@jabber.org', True)

        with self.assertRaises(AttributeError):
            send_packet(self.key_list, self.gateway, self.l_queue, bytes(ASSEMBLY_PACKET_LEN),
                        self.settings, 'alice@jabber.org', b'bob@jabber.org', True)

    def test_valid_message_packet(self):
        # Setup
        settings         = Settings(multi_packet_random_delay=True)
        gateway          = Gateway()
        key_list         = KeyList(master_key=bytes(KEY_LENGTH))
        key_list.keysets = [create_keyset(tx_key=KEY_LENGTH * b'\x02',
                                          tx_harac=8)]

        # Test
        self.assertIsNone(send_packet(key_list, gateway, self.l_queue, bytes(ASSEMBLY_PACKET_LEN),
                                      settings, 'alice@jabber.org', 'bob@jabber.org', True))

        self.assertEqual(len(gateway.packets), 1)
        self.assertEqual(len(gateway.packets[0]), 396)

        time.sleep(0.1)
        self.assertFalse(self.l_queue.empty())

    def test_valid_command_packet(self):
        """Test that commands are output as they should.

        Since command packets have no trailer, and since only user's
        RxM has local decryption key, encryption with any key recipient
        is not already in possession of does not compromise plaintext.
        """
        # Setup
        key_list         = KeyList(master_key=bytes(KEY_LENGTH))
        key_list.keysets = [create_keyset(LOCAL_ID)]

        # Test
        self.assertIsNone(send_packet(key_list, self.gateway, self.l_queue,
                                      bytes(ASSEMBLY_PACKET_LEN), self.settings))
        time.sleep(0.1)

        self.assertEqual(len(self.gateway.packets), 1)
        self.assertEqual(len(self.gateway.packets[0]), 365)
        self.assertEqual(self.l_queue.qsize(), 1)


class TestTransmit(unittest.TestCase):

    def setUp(self):
        self.settings = Settings(local_testing_mode=True)
        self.gateway  = Gateway()

    def test_transmit(self):
        self.assertIsNone(transmit(200*b'a', self.settings, self.gateway))
        self.assertEqual(len(self.gateway.packets), 1)

    def test_transmit_with_multi_packet_random_delay(self):
        self.settings.multi_packet_random_delay = True
        self.assertIsNone(transmit(200*b'a', self.settings, self.gateway))
        self.assertEqual(len(self.gateway.packets), 1)


class TestCancelPacket(unittest.TestCase):

    def setUp(self):
        self.queues = {FILE_PACKET_QUEUE:    Queue(),
                       MESSAGE_PACKET_QUEUE: Queue()}

    def tearDown(self):
        for key in self.queues:
            while not self.queues[key].empty():
                self.queues[key].get()
            time.sleep(0.1)
            self.queues[key].close()

    def test_cancel_message_during_traffic_masking(self):
        # Setup
        user_input = UserInput('cm')
        settings   = Settings(session_traffic_masking=True)
        window     = TxWindow()
        window.window_contacts = [create_contact()]

        self.queues[MESSAGE_PACKET_QUEUE].put(('testmessage1', {'alice@jabber.org': False}))
        self.queues[MESSAGE_PACKET_QUEUE].put(('testmessage2', {'alice@jabber.org': False}))
        time.sleep(0.1)

        # Test
        self.assertIsNone(cancel_packet(user_input, window, settings, self.queues))
        time.sleep(0.1)

        self.assertEqual(self.queues[MESSAGE_PACKET_QUEUE].qsize(), 1)

    def test_cancel_file_during_traffic_masking(self):
        # Setup
        user_input = UserInput('cf')
        settings   = Settings(session_traffic_masking=True)
        window     = TxWindow()
        window.window_contacts = [create_contact()]

        self.queues[FILE_PACKET_QUEUE].put(('testfile1', {'alice@jabber.org': False}))
        self.queues[FILE_PACKET_QUEUE].put(('testfile2', {'alice@jabber.org': False}))
        time.sleep(0.1)

        # Test
        self.assertIsNone(cancel_packet(user_input, window, settings, self.queues))
        time.sleep(0.1)

        self.assertEqual(self.queues[FILE_PACKET_QUEUE].qsize(), 1)

    def test_cancel_message_during_normal(self):
        # Setup
        user_input = UserInput('cm')
        settings   = Settings()
        window     = TxWindow(name='Alice',
                              type=WIN_TYPE_CONTACT,
                              type_print='contact',
                              uid ='alice@jabber.org')
        window.window_contacts = [create_contact()]

        self.queues[MESSAGE_PACKET_QUEUE].put(('testmessage1', settings, 'alice@jabber.org',   'bob@jabber.org', False, False, 'alice@jabber.org'))
        self.queues[MESSAGE_PACKET_QUEUE].put(('testmessage2', settings, 'charlie@jabber.org', 'bob@jabber.org', False, False, 'charlie@jabber.org'))
        self.queues[MESSAGE_PACKET_QUEUE].put(('testmessage3', settings, 'alice@jabber.org',   'bob@jabber.org', False, False, 'alice@jabber.org'))
        time.sleep(0.1)

        # Test
        self.assertIsNone(cancel_packet(user_input, window, settings, self.queues))
        time.sleep(0.1)

        self.assertEqual(self.queues[MESSAGE_PACKET_QUEUE].qsize(), 2)

    def test_cancel_group_message_during_normal(self):
        # Setup
        user_input = UserInput('cm')
        settings   = Settings()
        window     = TxWindow(name='testgroup',
                              type=WIN_TYPE_GROUP,
                              type_print='group',
                              uid='testgroup')
        window.window_contacts = [create_contact()]

        self.queues[MESSAGE_PACKET_QUEUE].put(('testmessage1', settings, 'alice@jabber.org', 'bob@jabber.org', False, False, 'testgroup'))
        self.queues[MESSAGE_PACKET_QUEUE].put(('testmessage2', settings, 'alice@jabber.org', 'bob@jabber.org', False, False, 'testgroup'))
        time.sleep(0.1)

        # Test
        self.assertIsNone(cancel_packet(user_input, window, settings, self.queues))
        time.sleep(0.1)

        self.assertEqual(self.queues[MESSAGE_PACKET_QUEUE].qsize(), 1)

    def test_cancel_file_during_normal(self):
        # Setup
        user_input = UserInput('cf')
        settings   = Settings()
        window     = TxWindow(name='Alice',
                              type=WIN_TYPE_CONTACT,
                              type_print='contact',
                              uid='alice@jabber.org')
        window.window_contacts = [create_contact()]

        self.queues[FILE_PACKET_QUEUE].put(('testmessage1', settings, 'alice@jabber.org', 'bob@jabber.org', False, False, 'alice@jabber.org'))
        self.queues[FILE_PACKET_QUEUE].put(('testmessage2', settings, 'alice@jabber.org', 'bob@jabber.org', False, False, 'alice@jabber.org'))
        time.sleep(0.1)

        # Test
        self.assertIsNone(cancel_packet(user_input, window, settings, self.queues))
        time.sleep(0.1)

        self.assertEqual(self.queues[FILE_PACKET_QUEUE].qsize(), 1)

    def test_cancel_file_when_nothing_to_cancel(self):
        # Setup
        user_input = UserInput('cf')
        settings   = Settings()
        window     = TxWindow(name='Alice',
                              type=WIN_TYPE_CONTACT,
                              type_print='contact',
                              uid='alice@jabber.org')
        window.window_contacts = [create_contact()]

        # Test
        self.assertIsNone(cancel_packet(user_input, window, settings, self.queues))
        time.sleep(0.1)

        self.assertEqual(self.queues[FILE_PACKET_QUEUE].qsize(), 0)

    def test_cancel_message_when_nothing_to_cancel(self):
        # Setup
        user_input = UserInput('cm')
        settings   = Settings()
        window     = TxWindow(name='Alice',
                              type=WIN_TYPE_CONTACT,
                              type_print='contact',
                              uid='alice@jabber.org')
        window.window_contacts = [create_contact()]

        # Test
        self.assertIsNone(cancel_packet(user_input, window, settings, self.queues))
        time.sleep(0.1)

        self.assertEqual(self.queues[FILE_PACKET_QUEUE].qsize(), 0)


if __name__ == '__main__':
    unittest.main(exit=False)
