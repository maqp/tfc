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

import time
import threading
import unittest

from multiprocessing import Queue

from src.common.statics import *

from src.tx.commands    import queue_command
from src.tx.packet      import queue_message, queue_to_nh
from src.tx.sender_loop import sender_loop

from tests.mock_classes import ContactList, Gateway, KeyList, Settings, UserInput, TxWindow


class TestTrafficMaskingLoop(unittest.TestCase):

    def test_loop(self):
        # Setup
        queues = {MESSAGE_PACKET_QUEUE: Queue(),
                  FILE_PACKET_QUEUE:    Queue(),
                  COMMAND_PACKET_QUEUE: Queue(),
                  NH_PACKET_QUEUE:      Queue(),
                  LOG_PACKET_QUEUE:     Queue(),
                  NOISE_PACKET_QUEUE:   Queue(),
                  NOISE_COMMAND_QUEUE:  Queue(),
                  KEY_MANAGEMENT_QUEUE: Queue(),
                  WINDOW_SELECT_QUEUE:  Queue(),
                  EXIT_QUEUE:           Queue()}

        settings               = Settings(session_traffic_masking=True)
        gateway                = Gateway()
        key_list               = KeyList(nicks=['Alice', LOCAL_ID])
        window                 = TxWindow(log_messages=True)
        contact_list           = ContactList(nicks=['Alice', LOCAL_ID])
        window.contact_list    = contact_list
        window.window_contacts = [contact_list.get_contact('Alice')]
        user_input             = UserInput(plaintext='test')

        queue_message(user_input, window, settings, queues[MESSAGE_PACKET_QUEUE])
        queue_message(user_input, window, settings, queues[MESSAGE_PACKET_QUEUE])
        queue_message(user_input, window, settings, queues[MESSAGE_PACKET_QUEUE])
        queue_command(b'test', settings, queues[COMMAND_PACKET_QUEUE])
        queue_command(b'test', settings, queues[COMMAND_PACKET_QUEUE])
        queue_command(b'test', settings, queues[COMMAND_PACKET_QUEUE], window)
        queue_to_nh(UNENCRYPTED_PACKET_HEADER + UNENCRYPTED_EXIT_COMMAND, settings, queues[NH_PACKET_QUEUE])
        queue_to_nh(UNENCRYPTED_PACKET_HEADER + UNENCRYPTED_WIPE_COMMAND, settings, queues[NH_PACKET_QUEUE])

        def queue_delayer():
            time.sleep(0.1)
            queues[WINDOW_SELECT_QUEUE].put((window, True))

        # Test
        threading.Thread(target=queue_delayer).start()
        self.assertIsNone(sender_loop(queues, settings, gateway, key_list, unittest=True))

        threading.Thread(target=queue_delayer).start()

        self.assertIsNone(sender_loop(queues, settings, gateway, key_list, unittest=True))

        threading.Thread(target=queue_delayer).start()

        self.assertIsNone(sender_loop(queues, settings, gateway, key_list, unittest=True))

        self.assertEqual(len(gateway.packets), 8)
        self.assertEqual(queues[EXIT_QUEUE].qsize(), 2)

        # Teardown
        for key in queues:
            while not queues[key].empty():
                queues[key].get()
            time.sleep(0.1)
            queues[key].close()


class TestNormalLoop(unittest.TestCase):

    def test_loop(self):
        # Setup
        queues = {MESSAGE_PACKET_QUEUE: Queue(),
                  FILE_PACKET_QUEUE:    Queue(),
                  COMMAND_PACKET_QUEUE: Queue(),
                  NH_PACKET_QUEUE:      Queue(),
                  LOG_PACKET_QUEUE:     Queue(),
                  NOISE_PACKET_QUEUE:   Queue(),
                  NOISE_COMMAND_QUEUE:  Queue(),
                  KEY_MANAGEMENT_QUEUE: Queue(),
                  WINDOW_SELECT_QUEUE:  Queue(),
                  UNITTEST_QUEUE:       Queue(),
                  EXIT_QUEUE:           Queue()}

        settings               = Settings(session_traffic_masking=False)
        gateway                = Gateway()
        key_list               = KeyList()
        window                 = TxWindow(log_messages=True)
        contact_list           = ContactList(nicks=['Alice', LOCAL_ID])
        window.contact_list    = contact_list
        window.window_contacts = [contact_list.get_contact('Alice')]
        user_input             = UserInput(plaintext='test')

        def queue_delayer():
            time.sleep(0.1)
            queue_command(b'test', settings, queues[COMMAND_PACKET_QUEUE])

            time.sleep(0.1)
            queue_to_nh(PUBLIC_KEY_PACKET_HEADER + KEY_LENGTH * b'a'
                        +b'alice@jabber.org' + US_BYTE + b'bob@jabber.org', settings, queues[NH_PACKET_QUEUE])

            time.sleep(0.1)
            queue_to_nh(UNENCRYPTED_PACKET_HEADER + UNENCRYPTED_WIPE_COMMAND, settings, queues[NH_PACKET_QUEUE])

            time.sleep(0.1)
            queue_to_nh(UNENCRYPTED_PACKET_HEADER + UNENCRYPTED_EXIT_COMMAND, settings, queues[NH_PACKET_QUEUE])

            time.sleep(0.1)
            queues[KEY_MANAGEMENT_QUEUE].put((KDB_ADD_ENTRY_HEADER, LOCAL_ID,
                                              KEY_LENGTH * b'a', KEY_LENGTH * b'a',
                                              KEY_LENGTH * b'a', KEY_LENGTH * b'a'))

            time.sleep(0.1)
            queue_message(user_input, window, settings, queues[MESSAGE_PACKET_QUEUE])

            time.sleep(0.1)
            queue_message(user_input, window, settings, queues[FILE_PACKET_QUEUE])

            time.sleep(0.1)
            queues[KEY_MANAGEMENT_QUEUE].put((KDB_ADD_ENTRY_HEADER, 'alice@jabber.org',
                                              KEY_LENGTH*b'a', KEY_LENGTH*b'a',
                                              KEY_LENGTH*b'a', KEY_LENGTH*b'a'))

            time.sleep(0.1)
            queue_message(user_input, window, settings, queues[MESSAGE_PACKET_QUEUE])

            time.sleep(0.1)
            queue_message(user_input, window, settings, queues[FILE_PACKET_QUEUE])

            time.sleep(0.1)
            queues[UNITTEST_QUEUE].put(EXIT)

        threading.Thread(target=queue_delayer).start()

        # Test
        self.assertIsNone(sender_loop(queues, settings, gateway, key_list, unittest=True))
        self.assertEqual(len(gateway.packets), 8)
        self.assertEqual(queues[EXIT_QUEUE].qsize(), 2)

        # Teardown
        for key in queues:
            while not queues[key].empty():
                queues[key].get()
            time.sleep(0.1)
            queues[key].close()


if __name__ == '__main__':
    unittest.main(exit=False)
