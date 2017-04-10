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

from multiprocessing    import Queue, Process

from src.common.statics import *
from src.tx.trickle     import noise_process

from tests.mock_classes import ContactList


class TestConstantTime(unittest.TestCase):
    """unittest module has no tests for threaded processes."""
    pass


class TestNoiseProcess(unittest.TestCase):
    """\
    Due to threading, only the output of the multiprocessing.Queue() object.
    Therefore these tests do not add to coverage.
    """

    def test_noise_packet_process(self):
        # Setup
        contact_list = ContactList(nicks=['Alice', 'Bob'])
        np_queue     = Queue()
        np           = Process(target=noise_process, args=(P_N_HEADER, np_queue, contact_list))

        # Test that queue fills to threshold
        np.start()
        time.sleep(0.5)
        self.assertEqual(np_queue.qsize(), 1000)

        # Test that noise packet process returns the noise packet plaintext and message log dictionary
        item, d = np_queue.get()
        self.assertEqual(len(item), 256)
        self.assertIsInstance(item, bytes)
        self.assertIsInstance(d, dict)
        self.assertEqual(d['alice@jabber.org'], False)
        self.assertEqual(d['bob@jabber.org'], False)

        np.terminate()


    def test_noise_command_process(self):
        # Setup
        np_queue = Queue()
        np       = Process(target=noise_process, args=(C_N_HEADER, np_queue))

        # Test that queue fills to threshold
        np.start()
        time.sleep(0.5)
        self.assertEqual(np_queue.qsize(), 1000)

        # Test that noise command process returns only noise command plaintext
        item = np_queue.get()
        self.assertEqual(len(item), 256)
        self.assertIsInstance(item, bytes)

        np.terminate()


if __name__ == '__main__':
    unittest.main(exit=False)
