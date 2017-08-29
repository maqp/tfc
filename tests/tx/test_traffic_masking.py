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

import unittest
import time

from multiprocessing import Queue

from src.common.statics import *

from src.tx.traffic_masking import ConstantTime, noise_loop

from tests.mock_classes import ContactList, Settings


class TestConstantTime(unittest.TestCase):

    def setUp(self):
        self.settings = Settings(multi_packet_random_delay=True)

    def test_traffic_masking_delay(self):
        start = time.monotonic()
        with ConstantTime(self.settings, d_type=TRAFFIC_MASKING):
            pass
        duration = time.monotonic() - start
        self.assertTrue(duration > 2.0)

    def test_constant_time(self):
        start = time.monotonic()
        with ConstantTime(self.settings, length=1.0):
            pass
        duration = time.monotonic() - start
        self.assertTrue(0.9 < duration < 1.1)


class TestNoiseLoop(unittest.TestCase):

    def setUp(self):
        self.np_queue     = Queue()
        self.contact_list = ContactList(nicks=['Alice'])

    def tearDown(self):
        while not self.np_queue.empty():
            self.np_queue.get()
        time.sleep(0.1)
        self.np_queue.close()
        time.sleep(0.1)

    def test_noise_commands(self):
        self.assertIsNone(noise_loop(C_N_HEADER, self.np_queue, unittest=True))
        packet, log_messages = self.np_queue.get()
        self.assertEqual(packet, C_N_HEADER + bytes(PADDING_LEN))
        self.assertIsNone(log_messages)

    def test_noise_packets(self):
        self.assertIsNone(noise_loop(P_N_HEADER, self.np_queue, self.contact_list, unittest=True))
        packet, log_messages, log_as_ph = self.np_queue.get()
        self.assertEqual(packet, PLACEHOLDER_DATA)
        self.assertIsNone(log_messages)
        self.assertTrue(log_as_ph)


if __name__ == '__main__':
    unittest.main(exit=False)
