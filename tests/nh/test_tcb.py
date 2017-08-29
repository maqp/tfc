#!/usr/bin/env python3.5
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
import threading
import time
import unittest

from multiprocessing import Queue

from src.common.reed_solomon import RSCodec
from src.common.statics      import *

from src.nh.tcb import rxm_outgoing, txm_incoming

from tests.mock_classes import Settings, Gateway
from tests.utils        import ignored


class TestTxMIncoming(unittest.TestCase):

    def setUp(self):
        self.settings  = Settings()
        self.rs        = RSCodec(2 * self.settings.serial_error_correction)
        self.o_urandom = os.urandom
        self.queues    = {TXM_INCOMING_QUEUE: Queue(),
                          RXM_OUTGOING_QUEUE: Queue(),
                          TXM_TO_IM_QUEUE:    Queue(),
                          TXM_TO_NH_QUEUE:    Queue(),
                          TXM_TO_RXM_QUEUE:   Queue(),
                          NH_TO_IM_QUEUE:     Queue(),
                          EXIT_QUEUE:         Queue()}

    def tearDown(self):
        os.urandom = self.o_urandom

        for key in self.queues:
            while not self.queues[key].empty():
                self.queues[key].get()
            time.sleep(0.1)
            self.queues[key].close()

        for f in [8*'61', 8*'62']:
            with ignored(OSError):
                os.remove(f)

    def test_unencrypted_packet(self):
        # Setup
        packet = self.rs.encode(UNENCRYPTED_PACKET_HEADER + b'test')
        self.queues[TXM_INCOMING_QUEUE].put(640 * b'a')
        self.queues[TXM_INCOMING_QUEUE].put(packet)
        time.sleep(0.1)

        # Test
        self.assertIsNone(txm_incoming(self.queues, self.settings, unittest=True))
        time.sleep(0.1)
        self.assertEqual(self.queues[TXM_TO_NH_QUEUE].qsize(), 1)

    def test_local_key_packet(self):
        # Setup
        packet = self.rs.encode(LOCAL_KEY_PACKET_HEADER + b'test')

        def queue_delayer():
            time.sleep(0.1)
            self.queues[TXM_INCOMING_QUEUE].put(packet)

        threading.Thread(target=queue_delayer).start()

        # Test
        self.assertIsNone(txm_incoming(self.queues, self.settings, unittest=True))
        time.sleep(0.1)
        self.assertEqual(self.queues[TXM_TO_RXM_QUEUE].qsize(), 1)

    def test_command_packet(self):
        # Setup
        packet = self.rs.encode(COMMAND_PACKET_HEADER + b'test')
        self.queues[TXM_INCOMING_QUEUE].put(packet)
        time.sleep(0.1)

        # Test
        self.assertIsNone(txm_incoming(self.queues, self.settings, unittest=True))
        time.sleep(0.1)
        self.assertEqual(self.queues[TXM_TO_RXM_QUEUE].qsize(), 1)

    def test_message_packet(self):
        # Setup
        packet = self.rs.encode(MESSAGE_PACKET_HEADER + 344 * b'a'
                                + b'bob@jabber.org' + US_BYTE + b'alice@jabber.org')
        self.queues[TXM_INCOMING_QUEUE].put(packet)
        time.sleep(0.1)

        # Test
        self.assertIsNone(txm_incoming(self.queues, self.settings, unittest=True))
        time.sleep(0.1)
        self.assertEqual(self.queues[TXM_TO_IM_QUEUE].qsize(), 1)
        self.assertEqual(self.queues[RXM_OUTGOING_QUEUE].qsize(), 1)

    def test_public_key_packet(self):
        # Setup
        packet = self.rs.encode(PUBLIC_KEY_PACKET_HEADER + KEY_LENGTH * b'a'
                                + b'bob@jabber.org' + US_BYTE + b'alice@jabber.org')
        self.queues[TXM_INCOMING_QUEUE].put(packet)
        time.sleep(0.1)

        # Test
        self.assertIsNone(txm_incoming(self.queues, self.settings, unittest=True))
        time.sleep(0.1)
        self.assertEqual(self.queues[RXM_OUTGOING_QUEUE].qsize(), 1)
        self.assertEqual(self.queues[TXM_TO_IM_QUEUE].qsize(), 1)

    def test_exported_file_packet(self):
        # Setup
        open(8*'61', 'w+').close()

        packet      = self.rs.encode(EXPORTED_FILE_HEADER + 500 * b'a')
        output_list = [8*b'a', 8*b'b']
        gen         = iter(output_list)
        os.urandom  = lambda _: next(gen)

        self.queues[TXM_INCOMING_QUEUE].put(packet)
        time.sleep(0.1)

        # Test
        self.assertIsNone(txm_incoming(self.queues, self.settings, unittest=True))
        self.assertTrue(os.path.isfile(8*'62'))


class TestRxMOutGoing(unittest.TestCase):

    def setUp(self):
        self.settings = Settings()
        self.gateway  = Gateway()
        self.rs       = RSCodec(2 * self.settings.serial_error_correction)
        self.queues   = {TXM_INCOMING_QUEUE: Queue(),
                         RXM_OUTGOING_QUEUE: Queue(),
                         TXM_TO_IM_QUEUE:    Queue(),
                         TXM_TO_NH_QUEUE:    Queue(),
                         TXM_TO_RXM_QUEUE:   Queue(),
                         NH_TO_IM_QUEUE:     Queue(),
                         EXIT_QUEUE:         Queue()}

    def tearDown(self):
        for k in self.queues:
            while not self.queues[k].empty():
                self.queues[k].get()
            time.sleep(0.1)
            self.queues[k].close()

    def test_loop(self):
        # Setup
        packet = b'testpacket'
        self.queues[TXM_TO_RXM_QUEUE].put(packet)
        self.queues[RXM_OUTGOING_QUEUE].put(packet)
        time.sleep(0.1)

        # Test
        self.assertIsNone(rxm_outgoing(self.queues, self.settings, self.gateway, unittest=True))
        self.assertEqual(packet, self.rs.decode(self.gateway.packets[0]))
        

if __name__ == '__main__':
    unittest.main(exit=False)
