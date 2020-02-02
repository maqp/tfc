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

import threading
import time
import unittest

from datetime        import datetime
from multiprocessing import Queue

from src.common.encoding     import int_to_bytes
from src.common.reed_solomon import RSCodec
from src.common.statics      import (COMMAND_DATAGRAM_HEADER, FILE_DATAGRAM_HEADER, GATEWAY_QUEUE,
                                     LOCAL_KEY_DATAGRAM_HEADER, MESSAGE_DATAGRAM_HEADER,
                                     ONION_SERVICE_PUBLIC_KEY_LENGTH)

from src.receiver.receiver_loop import receiver_loop

from tests.mock_classes import Gateway
from tests.utils        import tear_queue


class TestReceiverLoop(unittest.TestCase):

    def test_receiver_loop(self) -> None:
        # Setup
        gateway = Gateway(local_test=False)
        rs      = RSCodec(2 * gateway.settings.serial_error_correction)
        queues  = {MESSAGE_DATAGRAM_HEADER:   Queue(),
                   FILE_DATAGRAM_HEADER:      Queue(),
                   COMMAND_DATAGRAM_HEADER:   Queue(),
                   LOCAL_KEY_DATAGRAM_HEADER: Queue()}

        all_q = dict(queues)
        all_q.update({GATEWAY_QUEUE: Queue()})

        ts       = datetime.now()
        ts_bytes = int_to_bytes(int(ts.strftime('%Y%m%d%H%M%S%f')[:-4]))

        for key in queues:
            packet    = key + ts_bytes + bytes(ONION_SERVICE_PUBLIC_KEY_LENGTH)
            encoded   = rs.encode(packet)
            broken_p  = key + bytes.fromhex('df9005313af4136d') + bytes(ONION_SERVICE_PUBLIC_KEY_LENGTH)
            broken_p += rs.encode(b'a')

            def queue_delayer() -> None:
                """Place datagrams into queue after delay."""
                time.sleep(0.01)
                all_q[GATEWAY_QUEUE].put((datetime.now(), rs.encode(8 * b'1' + b'undecodable')))
                all_q[GATEWAY_QUEUE].put((datetime.now(), broken_p))
                all_q[GATEWAY_QUEUE].put((datetime.now(), encoded))

            threading.Thread(target=queue_delayer).start()

            # Test
            self.assertIsNone(receiver_loop(all_q, gateway, unit_test=True))
            time.sleep(0.01)
            self.assertEqual(queues[key].qsize(), 1)

            # Teardown
            tear_queue(queues[key])


if __name__ == '__main__':
    unittest.main(exit=False)
