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

import os
import unittest
import struct
import time

from multiprocessing    import Queue

from src.common.statics import *
from src.tx.packet      import queue_command, send_packet, cancel_packet

from tests.mock_classes import create_contact, Gateway, create_keyset, KeyList, Settings, UserInput, Window


class TestQueueCommand(unittest.TestCase):

    def test_normal(self):
        # Setup
        settings = Settings()
        c_queue  = Queue()

        # Verify short commands
        self.assertIsNone(queue_command(os.urandom(200), settings, c_queue))
        c_pt, settings_ = c_queue.get()
        self.assertEqual(len(c_pt), 256)
        self.assertIsInstance(settings_, Settings)

        # Verify long commands
        self.assertIsNone(queue_command(os.urandom(255), settings, c_queue))

        # Long commands are split to multiple queue items.
        self.assertEqual(c_queue.qsize(), 2)

        while not c_queue.empty():
            c_pt, settings_ = c_queue.get()
            self.assertEqual(len(c_pt), 256)
            self.assertIsInstance(settings_, Settings)

        # Teardown
        time.sleep(0.2)
        c_queue.close()

    def test_trickle(self):
        # Setup
        settings = Settings(session_trickle=True)
        c_queue  = Queue()

        # Verify short commands
        self.assertIsNone(queue_command(os.urandom(200), settings, c_queue))
        c_pt = c_queue.get()
        self.assertEqual(len(c_pt), 256)

        # Verify long commands
        self.assertIsNone(queue_command(os.urandom(255), settings, c_queue))

        # Long commands are split to multiple queue items.
        self.assertEqual(c_queue.qsize(), 2)

        while not c_queue.empty():
            c_pt = c_queue.get()
            self.assertEqual(len(c_pt), 256)

        # Teardown
        time.sleep(0.2)
        c_queue.close()


class TestSendPacket(unittest.TestCase):
    """\
    This function is by far the most critical to security in TxM, as it
    must detect output of key material.

    Plaintext length must always be evaluated to ensure constant
    ciphertext length and hiding of output data type.

    The most likely place for error is going to be the tx_harac
    attribute of keyset, as it's the only data loaded from the 
    sensitive key database, that is sent to contact. Alternative place
    could be a bug in implementation where account strings would
    incorrectly contain a byte string that contained key material.
    """

    def test_message_length(self):
        # Setup
        key_list = KeyList()
        settings = Settings()
        gateway  = Gateway()
        l_queue  = Queue()

        # Check that only 256-byte plaintext messages are ever allowed
        for l in range(1, 256):
            with self.assertRaises(SystemExit):
                send_packet(bytes(l), key_list, settings, gateway, l_queue, 'alice@jabber.org', 'bob@jabber.org', True)

        for l in range(257, 300):
            with self.assertRaises(SystemExit):
                send_packet(bytes(l), key_list, settings, gateway, l_queue, 'alice@jabber.org', 'bob@jabber.org', True)

    def test_invalid_harac_crashes(self):
        # Setup
        settings = Settings()
        gateway  = Gateway()
        l_queue  = Queue()

        # Check that in case where internal error caused bytestring (possible key material)
        # to end up in hash ratchet value, system raises some error that prevents output of packet.
        # In this case the error comes from unsuccessful encoding of hash ratchet counter.
        for l in range(1, 32):
            key_list = KeyList()
            key_list.keysets = [create_keyset(tx_hek=32 * b'\x01', tx_key=32 * b'\x02', tx_harac=l * b'k')]

            with self.assertRaises(struct.error):
                send_packet(bytes(256), key_list, settings, gateway, l_queue, 'alice@jabber.org', 'bob@jabber.org', True)

    def test_invalid_account_crashes(self):
        # Setup
        settings         = Settings()
        gateway          = Gateway()
        l_queue          = Queue()
        key_list         = KeyList()
        key_list.keysets = [create_keyset('Alice')]

        # Check that in case where internal error caused bytestring (possible key material)
        # to end up in account strings, System raises some error that prevents output of packet.
        # In this case the error comes from unsuccessful encoding of string (AttributeError)
        # or KeyList lookup error when bytes are used (StopIteration). These errors are not catched.
        with self.assertRaises(StopIteration):
            send_packet(bytes(256), key_list, settings, gateway, l_queue, b'alice@jabber.org', 'bob@jabber.org', True)
        with self.assertRaises(AttributeError):
            send_packet(bytes(256), key_list, settings, gateway, l_queue, 'alice@jabber.org', b'bob@jabber.org', True)

    def test_valid_message_packet(self):
        # Setup
        settings         = Settings(long_packet_rand_d=True)
        gateway          = Gateway()
        l_queue          = Queue()
        key_list         = KeyList(master_key=bytes(32))
        key_list.keysets = [create_keyset(tx_hek  =32 * b'\x01',
                                          tx_key  =32 * b'\x02',
                                          tx_harac=8)]

        # Test
        self.assertIsNone(send_packet(bytes(256), key_list, settings, gateway, l_queue, 'alice@jabber.org', 'bob@jabber.org', True))
        self.assertEqual(len(gateway.packets), 1)
        self.assertEqual(len(gateway.packets[0]), 396)

        time.sleep(0.2)
        self.assertFalse(l_queue.empty())


    def test_valid_command_packet(self):
        """\
        Test that commands are output as they should
        Since command packets have no trailer, and since only user's RxM has local decryption key,
        encryption with any key recipient is not already in possession of does not compromise plaintext.
        """
        # Setup
        settings         = Settings()
        gateway          = Gateway()
        l_queue          = Queue()
        key_list         = KeyList(master_key=bytes(32))
        key_list.keysets = [create_keyset('local')]

        # Test
        self.assertIsNone(send_packet(bytes(256), key_list, settings, gateway, l_queue))
        self.assertEqual(len(gateway.packets), 1)
        self.assertEqual(len(gateway.packets[0]), 365)

        time.sleep(0.2)
        self.assertTrue(l_queue.empty())


class TestCancelPacket(unittest.TestCase):

    def test_cancel_message_during_trickle(self):
        # Setup
        user_input             = UserInput('cm')
        window                 = Window()
        window.window_contacts = [create_contact('Alice')]
        settings               = Settings(session_trickle=True)
        queues                 = {MESSAGE_PACKET_QUEUE: Queue(),
                                  FILE_PACKET_QUEUE:    Queue()}

        # Test
        queues[MESSAGE_PACKET_QUEUE].put(('testmessage1', {'alice@jabber.org' : False}))
        queues[MESSAGE_PACKET_QUEUE].put(('testmessage2', {'alice@jabber.org' : False}))
        time.sleep(0.2)
        self.assertIsNone(cancel_packet(user_input, window, settings, queues))
        time.sleep(0.2)
        self.assertEqual(queues[MESSAGE_PACKET_QUEUE].qsize(), 1)

    def test_cancel_file_during_trickle(self):
        # Setup
        user_input             = UserInput('cf')
        window                 = Window()
        window.window_contacts = [create_contact('Alice')]
        settings               = Settings(session_trickle=True)
        queues                 = {MESSAGE_PACKET_QUEUE: Queue(),
                                  FILE_PACKET_QUEUE:    Queue()}

        queues[FILE_PACKET_QUEUE].put(('testfile1', {'alice@jabber.org' : False}))
        queues[FILE_PACKET_QUEUE].put(('testfile2', {'alice@jabber.org' : False}))
        time.sleep(0.2)

        # Test
        self.assertIsNone(cancel_packet(user_input, window, settings, queues))
        time.sleep(0.2)
        self.assertEqual(queues[FILE_PACKET_QUEUE].qsize(), 1)

    def test_cancel_message_during_normal(self):
        # Setup
        window                 = Window(name='Alice',
                                        type='contact',
                                        uid ='alice@jabber.org')
        user_input             = UserInput('cm')
        window.window_contacts = [create_contact('Alice')]
        settings               = Settings()
        queues                 = {MESSAGE_PACKET_QUEUE: Queue(),
                                  FILE_PACKET_QUEUE:    Queue()}

        queues[MESSAGE_PACKET_QUEUE].put(('testmessage1', settings, 'alice@jabber.org',   'bob@jabber.org', False, 'alice@jabber.org'))
        queues[MESSAGE_PACKET_QUEUE].put(('testmessage2', settings, 'charlie@jabber.org', 'bob@jabber.org', False, 'charlie@jabber.org'))
        queues[MESSAGE_PACKET_QUEUE].put(('testmessage3', settings, 'alice@jabber.org',   'bob@jabber.org', False, 'alice@jabber.org'))
        time.sleep(0.4)

        # Test
        self.assertIsNone(cancel_packet(user_input, window, settings, queues))
        time.sleep(0.4)
        self.assertEqual(queues[MESSAGE_PACKET_QUEUE].qsize(), 2)

    def test_cancel_group_message_during_normal(self):
        # Setup
        window                 = Window(name='testgroup',
                                        type='group',
                                        uid ='testgroup')
        user_input             = UserInput('cm')
        window.window_contacts = [create_contact('Alice')]
        settings               = Settings()
        queues                 = {MESSAGE_PACKET_QUEUE: Queue(),
                                  FILE_PACKET_QUEUE:    Queue()}

        # Test
        queues[MESSAGE_PACKET_QUEUE].put(('testmessage1', settings, 'alice@jabber.org', 'bob@jabber.org', False, 'testgroup'))
        queues[MESSAGE_PACKET_QUEUE].put(('testmessage2', settings, 'alice@jabber.org', 'bob@jabber.org', False, 'testgroup'))
        time.sleep(0.2)
        self.assertIsNone(cancel_packet(user_input, window, settings, queues))
        time.sleep(0.2)
        self.assertEqual(queues[MESSAGE_PACKET_QUEUE].qsize(), 1)

    def test_cancel_file_during_normal(self):
        # Setup
        window                 = Window(name='Alice',
                                        type='contact',
                                        uid ='alice@jabber.org')
        user_input             = UserInput('cf')
        window.window_contacts = [create_contact('Alice')]
        settings               = Settings()
        queues                 = {MESSAGE_PACKET_QUEUE: Queue(),
                                  FILE_PACKET_QUEUE:    Queue()}

        queues[FILE_PACKET_QUEUE].put(('testmessage1', settings, 'alice@jabber.org', 'bob@jabber.org', False, 'alice@jabber.org'))
        queues[FILE_PACKET_QUEUE].put(('testmessage2', settings, 'alice@jabber.org', 'bob@jabber.org', False, 'alice@jabber.org'))
        time.sleep(0.2)

        # Test
        self.assertIsNone(cancel_packet(user_input, window, settings, queues))
        time.sleep(0.2)
        self.assertEqual(queues[FILE_PACKET_QUEUE].qsize(), 1)

    def test_cancel_file_when_nothing_to_cancel(self):
        # Setup
        window                 = Window(name='Alice',
                                        type='contact',
                                        uid ='alice@jabber.org')
        user_input             = UserInput('cf')
        window.window_contacts = [create_contact('Alice')]
        settings               = Settings()
        queues                 = {MESSAGE_PACKET_QUEUE: Queue(),
                                  FILE_PACKET_QUEUE:    Queue()}

        # Test
        self.assertIsNone(cancel_packet(user_input, window, settings, queues))
        time.sleep(0.2)
        self.assertEqual(queues[FILE_PACKET_QUEUE].qsize(), 0)

    def test_cancel_message_when_nothing_to_cancel(self):
        # Setup
        window                 = Window(name='Alice',
                                        type='contact',
                                        uid ='alice@jabber.org')
        user_input             = UserInput('cm')
        window.window_contacts = [create_contact('Alice')]
        settings               = Settings()
        queues                 = {MESSAGE_PACKET_QUEUE: Queue(),
                                  FILE_PACKET_QUEUE:    Queue()}

        # Test
        self.assertIsNone(cancel_packet(user_input, window, settings, queues))
        time.sleep(0.2)
        self.assertEqual(queues[FILE_PACKET_QUEUE].qsize(), 0)


if __name__ == '__main__':
    unittest.main(exit=False)
