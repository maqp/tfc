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

import threading
import time
import unittest

from multiprocessing import Queue

from src.common.reed_solomon import RSCodec
from src.common.statics      import *

from src.rx.receiver_loop import receiver_loop

from tests.mock_classes import Settings


class TestReceiverLoop(unittest.TestCase):

    def test_receiver_loop(self):
        # Setup
        settings = Settings()
        rs       = RSCodec(2 * settings.serial_error_correction)
        queues   = {LOCAL_KEY_PACKET_HEADER:  Queue(),
                    PUBLIC_KEY_PACKET_HEADER: Queue(),
                    MESSAGE_PACKET_HEADER:    Queue(),
                    COMMAND_PACKET_HEADER:    Queue(),
                    IMPORTED_FILE_HEADER:     Queue()}

        all_q = dict(queues)
        all_q.update({GATEWAY_QUEUE: Queue()})

        for key in queues:
            packet  = key + bytes(KEY_LENGTH)
            encoded = rs.encode(packet)

            def queue_delayer():
                time.sleep(0.1)
                all_q[GATEWAY_QUEUE].put(b'undecodable')
                all_q[GATEWAY_QUEUE].put(encoded)

            threading.Thread(target=queue_delayer).start()

            # Test
            self.assertIsNone(receiver_loop(all_q, settings, unittest=True))
            time.sleep(0.1)
            self.assertEqual(queues[key].qsize(), 1)

            # Teardown
            while not queues[key].empty():
                queues[key].get()
            time.sleep(0.1)
            queues[key].close()


if __name__ == '__main__':
    unittest.main(exit=False)
