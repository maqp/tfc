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

import multiprocessing.connection
import os
import serial
import time
import unittest

from multiprocessing import Queue

from src.common.gateway import gateway_loop, Gateway
from src.common.statics import *

from tests.mock_classes import Settings
from tests.mock_classes import Gateway as MockGateway


class TestGatewayLoop(unittest.TestCase):

    def setUp(self):
        self.queues       = {GATEWAY_QUEUE: Queue()}
        self.gateway      = MockGateway()
        self.gateway.read = lambda: "read_data"

    def tearDown(self):
        while not self.queues[GATEWAY_QUEUE].empty():
            self.queues[GATEWAY_QUEUE].get()
        time.sleep(0.1)
        self.queues[GATEWAY_QUEUE].close()

    def test_loop(self):
        self.assertIsNone(gateway_loop(self.queues, self.gateway, unittest=True))
        self.assertEqual(self.queues[GATEWAY_QUEUE].get(), "read_data")


class TestGatewaySerial(unittest.TestCase):

    class MockSerial(object):

        def __init__(self, iface_name, baudrate, timeout):
            self.iface    = iface_name
            self.baudrate = baudrate
            self.timeout  = timeout
            self.written  = []
            output_list   = [b'', bytearray(b'a'), bytearray(b'b'), b'']
            self.gen      = iter(output_list)

        def write(self, output):
            self.written.append(output)

        def read(self, _):
            time.sleep(0.1)
            return next(self.gen)

        def flush(self):
            pass

    def setUp(self):
        self.settings  = Settings(session_usb_serial_adapter=True)
        self.o_listdir = os.listdir
        self.o_serial  = serial.Serial

        input_list    = ['ttyUSB0', 'ttyS0', 'ttyUSB0', 'ttyS0', 'ttyUSB0']
        gen           = iter(input_list)
        os.listdir    = lambda _: [next(gen)]
        serial.Serial = TestGatewaySerial.MockSerial
        self.gateway  = Gateway(self.settings)

    def tearDown(self):
        os.listdir    = self.o_listdir
        serial.Serial = self.o_serial

    def test_serial(self):
        self.assertIsNone(self.gateway.write(b'test'))
        self.assertEqual(self.gateway.search_serial_interface(), '/dev/ttyUSB0')
        self.assertEqual(self.gateway.read(), b'ab')

        self.gateway.settings.session_usb_serial_adapter = False
        self.assertEqual(self.gateway.search_serial_interface(), '/dev/ttyS0')

        with self.assertRaises(SystemExit):
            self.gateway.search_serial_interface()


class TestMultiProcessingClient(unittest.TestCase):

    class MockMultiprocessingClient(object):

        def __init__(self, args):
            self.hostname  = args[0]
            self.socket_no = args[1]
            self.written   = []

        def send(self, output):
            self.written.append(output)

    def setUp(self):
        self.settings = Settings(software_operation=TX,
                                 local_testing_mode=True)
        multiprocessing.connection.Client = TestMultiProcessingClient.MockMultiprocessingClient
        self.gateway  = Gateway(self.settings)

    def test_socket(self):
        self.assertEqual(self.gateway.interface.socket_no, NH_LISTEN_SOCKET)
        self.assertEqual(self.gateway.interface.hostname, 'localhost')
        self.assertIsNone(self.gateway.write(b'test'))
        self.assertEqual(self.gateway.interface.written[0], b'test')


class TestMultiProcessingServer(unittest.TestCase):

    class MockMultiprocessingListener(object):

        def __init__(self, args):
            self.hostname  = args[0]
            self.socket_no = args[1]
            self.written   = []

        def accept(self):

            class Interface(object):

                def __init__(self, hostname, socket_no):
                    self.hostname  = hostname
                    self.socket_no = socket_no

                @staticmethod
                def recv():
                    return b'mock_message'

            return Interface(self.hostname, self.socket_no)

    def setUp(self):
        self.settings = Settings(software_operation=RX,
                                 local_testing_mode=True)
        multiprocessing.connection.Listener = TestMultiProcessingServer.MockMultiprocessingListener
        self.gateway  = Gateway(self.settings)

    def test_listener(self):
        self.assertEqual(self.gateway.interface.socket_no, RXM_LISTEN_SOCKET)
        self.assertEqual(self.gateway.interface.hostname, 'localhost')
        self.assertEqual(self.gateway.read(), b'mock_message')


if __name__ == '__main__':
    unittest.main(exit=False)
