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

import threading
import time
import unittest

from src.common.statics import (C_N_HEADER, EXIT_QUEUE, KDB_ADD_ENTRY_HEADER, KEY_MANAGEMENT_QUEUE, LOCAL_ID,
                                LOCAL_PUBKEY, PADDING_LENGTH, PUBLIC_KEY_DATAGRAM_HEADER, P_N_HEADER,
                                RELAY_PACKET_QUEUE, SENDER_MODE_QUEUE, SYMMETRIC_KEY_LENGTH, TFC_PUBLIC_KEY_LENGTH,
                                TM_NOISE_COMMAND_QUEUE, TM_NOISE_PACKET_QUEUE, UNENCRYPTED_DATAGRAM_HEADER,
                                UNENCRYPTED_EXIT_COMMAND, UNENCRYPTED_WIPE_COMMAND, WINDOW_SELECT_QUEUE)

from src.transmitter.commands    import queue_command
from src.transmitter.packet      import queue_message, queue_to_nc
from src.transmitter.sender_loop import sender_loop, standard_sender_loop, traffic_masking_loop

from tests.mock_classes import ContactList, Gateway, KeyList, nick_to_pub_key, Settings, TxWindow, UserInput
from tests.utils        import gen_queue_dict, tear_queues


class TestSenderLoop(unittest.TestCase):

    def test_loops(self):
        queues   = gen_queue_dict()
        window   = TxWindow(log_messages=True)
        settings = Settings(traffic_masking=True,
                            tm_static_delay=0.001,
                            tm_random_delay=0.001)
        gateway  = Gateway()
        key_list = KeyList(nicks=['Bob', LOCAL_ID])  # Output Bob as existing contact

        queues[TM_NOISE_COMMAND_QUEUE].put((C_N_HEADER + bytes(PADDING_LENGTH)))
        queues[TM_NOISE_PACKET_QUEUE].put((P_N_HEADER + bytes(PADDING_LENGTH), True, True))
        queues[WINDOW_SELECT_QUEUE].put(window.window_contacts)
        queues[SENDER_MODE_QUEUE].put(settings)
        queue_command(b'test', settings, queues)  # Output command
        self.assertIsNone(sender_loop(queues, settings, gateway, key_list, unit_test=True))
        self.assertEqual(len(gateway.packets), 1)

        settings.traffic_masking = False
        queues[SENDER_MODE_QUEUE].put(settings)
        self.assertIsNone(sender_loop(queues, settings, gateway, key_list, unit_test=True))  # Output Alice & Bob again
        self.assertEqual(len(gateway.packets), 1)


class TestTrafficMaskingLoop(unittest.TestCase):

    def test_loop(self):
        # Setup
        queues                 = gen_queue_dict()
        settings               = Settings(traffic_masking=True,
                                          tm_static_delay=0.001,
                                          tm_random_delay=0.001)
        gateway                = Gateway()
        key_list               = KeyList(nicks=['Alice', LOCAL_ID])
        window                 = TxWindow(log_messages=True)
        contact_list           = ContactList(nicks=['Alice', LOCAL_ID])
        window.contact_list    = contact_list
        window.window_contacts = [contact_list.get_contact_by_address_or_nick('Alice')]
        user_input             = UserInput(plaintext='test')

        def queue_delayer():
            """Place packets to queue after delay."""
            time.sleep(0.01)
            queues[WINDOW_SELECT_QUEUE].put(window.window_contacts)
            time.sleep(0.01)
            queue_command(b'test',            settings, queues)                                              # 1
            queue_message(user_input, window, settings, queues)                                              # 2
            queue_message(user_input, window, settings, queues)                                              # 3
            queue_command(b'test',            settings, queues)                                              # 4
            queues[TM_NOISE_COMMAND_QUEUE].put((C_N_HEADER + bytes(PADDING_LENGTH)))                         # 5
            queue_to_nc(UNENCRYPTED_DATAGRAM_HEADER + UNENCRYPTED_EXIT_COMMAND, queues[RELAY_PACKET_QUEUE])  # 6
            queue_to_nc(UNENCRYPTED_DATAGRAM_HEADER + UNENCRYPTED_WIPE_COMMAND, queues[RELAY_PACKET_QUEUE])  # 7
            queues[SENDER_MODE_QUEUE].put(settings)

        # Test
        threading.Thread(target=queue_delayer).start()
        self.assertIsInstance(traffic_masking_loop(queues, settings, gateway, key_list), Settings)
        self.assertEqual(len(gateway.packets), 7)

        # Teardown
        tear_queues(queues)


class TestStandardSenderLoop(unittest.TestCase):

    def test_loop(self):
        # Setup
        queues                 = gen_queue_dict()
        settings               = Settings(traffic_masking=False)
        gateway                = Gateway()
        key_list               = KeyList()
        window                 = TxWindow(log_messages=True)
        contact_list           = ContactList(nicks=['Alice', LOCAL_ID])
        window.contact_list    = contact_list
        window.window_contacts = [contact_list.get_contact_by_address_or_nick('Alice')]
        user_input             = UserInput(plaintext='test')

        delay = 0.015

        def queue_delayer():
            """Place datagrams into queue after delay."""
            time.sleep(delay)
            queue_command(b'test', settings, queues)

            time.sleep(delay)
            queue_to_nc(PUBLIC_KEY_DATAGRAM_HEADER + TFC_PUBLIC_KEY_LENGTH * b'a' + nick_to_pub_key('Alice'),  # 1
                        queues[RELAY_PACKET_QUEUE])

            time.sleep(delay)
            queue_to_nc(UNENCRYPTED_DATAGRAM_HEADER + UNENCRYPTED_WIPE_COMMAND, queues[RELAY_PACKET_QUEUE])  # 2

            time.sleep(delay)
            queue_to_nc(UNENCRYPTED_DATAGRAM_HEADER + UNENCRYPTED_EXIT_COMMAND, queues[RELAY_PACKET_QUEUE])  # 3

            time.sleep(delay)
            queues[KEY_MANAGEMENT_QUEUE].put((KDB_ADD_ENTRY_HEADER, LOCAL_PUBKEY,  # 4
                                              SYMMETRIC_KEY_LENGTH * b'a', SYMMETRIC_KEY_LENGTH * b'a',
                                              SYMMETRIC_KEY_LENGTH * b'a', SYMMETRIC_KEY_LENGTH * b'a'))

            time.sleep(delay)
            queue_message(user_input, window, settings, queues)  # 5

            time.sleep(delay)
            queue_message(user_input, window, settings, queues)  # 6

            time.sleep(delay)
            queues[KEY_MANAGEMENT_QUEUE].put((KDB_ADD_ENTRY_HEADER, nick_to_pub_key('Alice'),
                                              SYMMETRIC_KEY_LENGTH * b'a', SYMMETRIC_KEY_LENGTH * b'a',
                                              SYMMETRIC_KEY_LENGTH * b'a', SYMMETRIC_KEY_LENGTH * b'a'))

            time.sleep(delay)
            queue_message(user_input, window, settings, queues)  # 7

            time.sleep(delay)
            queue_message(user_input, window, settings, queues)  # 8

            time.sleep(delay)
            queues[SENDER_MODE_QUEUE].put(settings)

        threading.Thread(target=queue_delayer).start()

        # Test
        settings, m_buffer = standard_sender_loop(queues, gateway, key_list)
        self.assertIsInstance(settings, Settings)
        self.assertEqual(m_buffer,                   {nick_to_pub_key('Alice'): []})
        self.assertEqual(len(gateway.packets),       8)
        self.assertEqual(queues[EXIT_QUEUE].qsize(), 2)

        # Teardown
        tear_queues(queues)


if __name__ == '__main__':
    unittest.main(exit=False)
