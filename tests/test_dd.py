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

import socket
import threading
import time
import unittest

from multiprocessing import Queue
from unittest        import mock
from unittest.mock   import MagicMock

from src.common.statics import (DATA_FLOW, DST_LISTEN_SOCKET, EXIT, EXIT_QUEUE, IDLE,
                                NCDCLR, NCDCRL, RP_LISTEN_SOCKET, SCNCLR, SCNCRL)

from dd import animate, draw_frame, main, process_arguments, rx_loop, tx_loop

from tests.utils import tear_queue, TFCTestCase


class TestDrawFrame(TFCTestCase):

    def test_left_to_right_oriented_data_diode_frames(self):

        for argv in [SCNCLR, NCDCRL]:

            self.assert_prints("""\
\n\n\n\n\n\n\n\n
                                   Data flow                                    
                                       →                                        
                                 ────╮   ╭────                                  
                                  Tx │ > │ Rx                                   
                                 ────╯   ╰────                                  
""", draw_frame, argv, DATA_FLOW, high=True)

            self.assert_prints("""\
\n\n\n\n\n\n\n\n
                                   Data flow                                    
                                       →                                        
                                 ────╮   ╭────                                  
                                  Tx │   │ Rx                                   
                                 ────╯   ╰────                                  
""", draw_frame, argv, DATA_FLOW, high=False)

            self.assert_prints("""\
\n\n\n\n\n\n\n\n
                                      Idle                                      
                                                                                
                                 ────╮   ╭────                                  
                                  Tx │   │ Rx                                   
                                 ────╯   ╰────                                  
""", draw_frame, argv, IDLE)

    def test_right_to_left_oriented_data_diode_frames(self):

        for argv in [SCNCRL, NCDCLR]:

            self.assert_prints("""\
\n\n\n\n\n\n\n\n
                                   Data flow                                    
                                       ←                                        
                                 ────╮   ╭────                                  
                                  Rx │ < │ Tx                                   
                                 ────╯   ╰────                                  
""", draw_frame, argv, DATA_FLOW, high=True)

            self.assert_prints("""\
\n\n\n\n\n\n\n\n
                                   Data flow                                    
                                       ←                                        
                                 ────╮   ╭────                                  
                                  Rx │   │ Tx                                   
                                 ────╯   ╰────                                  
""", draw_frame, argv, DATA_FLOW, high=False)

            self.assert_prints("""\
\n\n\n\n\n\n\n\n
                                      Idle                                      
                                                                                
                                 ────╮   ╭────                                  
                                  Rx │   │ Tx                                   
                                 ────╯   ╰────                                  
""", draw_frame, argv, IDLE)


class TestAnimate(unittest.TestCase):

    @mock.patch('time.sleep', return_value=MagicMock)
    def test_animate(self, _):
        for arg in [SCNCLR, NCDCLR, SCNCRL, NCDCRL]:
            self.assertIsNone(animate(arg))


class TestRxLoop(unittest.TestCase):

    def setUp(self) -> None:
        """Pre-test actions."""
        self.queue = Queue()

    def tearDown(self) -> None:
        """Post-test actions."""
        tear_queue(self.queue)

    @mock.patch('multiprocessing.connection.Listener', return_value=MagicMock(
        accept=MagicMock(return_value=MagicMock(
            recv=MagicMock(side_effect=[b'test_data', b'test_data', KeyboardInterrupt, EOFError])))))
    def test_rx_loop(self, _):

        with self.assertRaises(SystemExit):
            rx_loop(self.queue, RP_LISTEN_SOCKET)

        self.assertEqual(self.queue.qsize(), 2)
        while self.queue.qsize() != 0:
            self.assertEqual(self.queue.get(), b'test_data')


class TestTxLoop(unittest.TestCase):

    def setUp(self) -> None:
        """Pre-test actions."""
        self.o_sleep = time.sleep

    def tearDown(self) -> None:
        """Post-test actions."""
        time.sleep = self.o_sleep

    @mock.patch('time.sleep',                        lambda _: None)
    @mock.patch('multiprocessing.connection.Client', side_effect=[socket.error, MagicMock(send=MagicMock)])
    def test_tx_loop(self, *_):
        # Setup
        queue = Queue()

        def queue_delayer():
            """Place packet to queue after timer runs out."""
            self.o_sleep(0.1)
            queue.put(b'test_packet')
        threading.Thread(target=queue_delayer).start()

        # Test
        tx_loop(queue, DST_LISTEN_SOCKET, NCDCLR, unit_test=True)
        self.assertEqual(queue.qsize(), 0)

        tear_queue(queue)


class TestProcessArguments(unittest.TestCase):

    def test_invalid_arguments_exit(self, *_):
        for argument in ['', 'invalid']:
            with mock.patch('sys.argv', ['dd.py', argument]):
                with self.assertRaises(SystemExit):
                    process_arguments()

    def test_valid_arguments(self, *_):
        for argument in [SCNCLR, SCNCRL, NCDCLR, NCDCRL]:
            with mock.patch('sys.argv', ['dd.py', argument]):
                arg, input_socket, output_socket = process_arguments()
                self.assertEqual(arg, argument)
                self.assertIsInstance(input_socket,  int)
                self.assertIsInstance(output_socket, int)


class TestMain(unittest.TestCase):

    def setUp(self) -> None:
        """Pre-test actions."""
        self.queue = Queue()

    def tearDown(self) -> None:
        """Post-test actions."""
        tear_queue(self.queue)

    @mock.patch('time.sleep', lambda _: None)
    @mock.patch('sys.argv',   ['dd.py', SCNCLR])
    def test_main(self, *_):
        # Setup
        queues = {EXIT_QUEUE: self.queue}

        def queue_delayer():
            """Place packet to queue after timer runs out."""
            time.sleep(0.1)
            queues[EXIT_QUEUE].put(EXIT)
        threading.Thread(target=queue_delayer).start()

        # Test
        with self.assertRaises(SystemExit):
            main(queues=queues)


if __name__ == '__main__':
    unittest.main(exit=False)
