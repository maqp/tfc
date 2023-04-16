#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
TFC - Onion-routed, endpoint secure messaging system
Copyright (C) 2013-2023  Markus Ottela

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

import os
import threading
import time
import unittest

from unittest      import mock
from unittest.mock import MagicMock
from typing        import Any

import stem.control

from src.common.misc    import validate_onion_addr
from src.common.statics import (EXIT, EXIT_QUEUE, ONION_CLOSE_QUEUE, ONION_KEY_QUEUE, ONION_SERVICE_PRIVATE_KEY_LENGTH,
                                TOR_DATA_QUEUE, TOR_SOCKS_PORT)

from src.relay.onion import get_available_port, onion_service, stem_compatible_ed25519_key_from_private_key, Tor

from tests.utils import gen_queue_dict, tear_queues


class TestGetAvailablePort(unittest.TestCase):
    @mock.patch("random.SystemRandom.randint", side_effect=[OSError, 1234])
    def test_get_available_port(self, _) -> None:
        port = get_available_port(1000, 65535)
        self.assertEqual(port, 1234)

    @mock.patch("builtins.open", mock.mock_open(read_data='TAILS_PRODUCT_NAME="Tails"'))
    def test_port_is_tor_socket_port_when_running_on_tails(self) -> None:
        port = get_available_port(1000, 65535)
        self.assertEqual(port, TOR_SOCKS_PORT)


class TestTor(unittest.TestCase):

    @mock.patch('time.sleep',     return_value=None)
    @mock.patch('os.path.isfile', return_value=False)
    def test_missing_binary_raises_critical_error(self, *_: Any) -> None:
        tor = Tor()
        with self.assertRaises(SystemExit):
            tor.connect(1234)

    @mock.patch('time.sleep',                               return_value=None)
    @mock.patch('stem.process.launch_tor_with_config',      side_effect=[MagicMock(), OSError, MagicMock()])
    @mock.patch('stem.control.Controller.from_socket_file', return_value=MagicMock(get_info=MagicMock(
        side_effect=['NOTICE BOOTSTRAP PROGRESS=100 TAG=done SUMMARY="Done"', stem.SocketClosed])))
    def test_closed_socket_raises_critical_error(self, *_: Any) -> None:
        tor = Tor()
        self.assertIsNone(tor.connect(1234))
        with self.assertRaises(SystemExit):
            tor.connect(1234)

    @mock.patch('time.sleep',                               return_value=None)
    @mock.patch('time.monotonic',                           side_effect=[1, 20, 30, 40])
    @mock.patch('stem.control.Controller.from_socket_file', return_value=MagicMock(get_info=MagicMock(
        side_effect=['NOTICE BOOTSTRAP PROGRESS=100 TAG=done SUMMARY="Nope"',
                     'NOTICE BOOTSTRAP PROGRESS=100 TAG=done SUMMARY="Done"'])))
    @mock.patch('stem.process.launch_tor_with_config',      return_value=MagicMock(poll=lambda: False))
    def test_timeout_restarts_tor(self, *_: Any) -> None:
        tor = Tor()
        self.assertIsNone(tor.connect(1234))
        tor.stop()


class TestTorKeyExpansion(unittest.TestCase):

    def test_invalid_key_size_raises_critical_error(self) -> None:
        for ks in [ks for ks in range(64) if ks != ONION_SERVICE_PRIVATE_KEY_LENGTH]:
            with self.assertRaises(SystemExit):
                stem_compatible_ed25519_key_from_private_key(os.urandom(ks))

    def test_valid_key_size(self) -> None:
        self.assertEqual(stem_compatible_ed25519_key_from_private_key(bytes(ONION_SERVICE_PRIVATE_KEY_LENGTH)),
                         'UEatwduoOIZ7K7v90MNCPli1eXC1JnqQ9XlgkkqH8VYKaoXqpkLayDVCS118jWN8AECMenPaZyt/SYUhQgtt0w==')


class TestOnionService(unittest.TestCase):

    @mock.patch('shlex.split',                              return_value=['NOTICE', 'BOOTSTRAP', 'PROGRESS=100',
                                                                          'TAG=done', 'SUMMARY=Done'])
    @mock.patch('stem.control.Controller.from_socket_file', return_value=MagicMock())
    @mock.patch('src.relay.onion.get_available_port',       side_effect=KeyboardInterrupt)
    def test_returns_with_keyboard_interrupt(self, *_: Any) -> None:
        # Setup
        queues = gen_queue_dict()
        queues[ONION_KEY_QUEUE].put((bytes(ONION_SERVICE_PRIVATE_KEY_LENGTH), b'\x01'))

        # Test
        self.assertIsNone(onion_service(queues, False))

        # Teardown
        tear_queues(queues)

    @mock.patch('shlex.split',                              return_value=['NOTICE', 'BOOTSTRAP', 'PROGRESS=100',
                                                                          'TAG=done', 'SUMMARY=Done'])
    @mock.patch('stem.control.Controller.from_socket_file', return_value=MagicMock())
    @mock.patch('stem.process.launch_tor_with_config',      return_value=MagicMock())
    def test_onion_service(self, *_: Any) -> None:
        # Setup
        queues = gen_queue_dict()

        def queue_delayer() -> None:
            """Place Onion Service data into queue after delay."""
            time.sleep(0.5)
            queues[ONION_KEY_QUEUE].put((bytes(ONION_SERVICE_PRIVATE_KEY_LENGTH), b'\x01'))
            queues[ONION_KEY_QUEUE].put((bytes(ONION_SERVICE_PRIVATE_KEY_LENGTH), b'\x01'))
            time.sleep(0.1)
            queues[ONION_CLOSE_QUEUE].put(EXIT)

        threading.Thread(target=queue_delayer).start()

        # Test
        with mock.patch("time.sleep", return_value=None):
            self.assertIsNone(onion_service(queues, False))

        port, address = queues[TOR_DATA_QUEUE].get()
        self.assertIsInstance(port, int)
        self.assertEqual(validate_onion_addr(address), '')
        self.assertEqual(queues[EXIT_QUEUE].get(), EXIT)

        # Teardown
        tear_queues(queues)

    @mock.patch('shlex.split',                              return_value=['NOTICE', 'BOOTSTRAP', 'PROGRESS=100',
                                                                          'TAG=done', 'SUMMARY=Done'])
    @mock.patch('stem.control.Controller.from_socket_file', return_value=MagicMock())
    @mock.patch('stem.process.launch_tor_with_config',      return_value=MagicMock())
    def test_test_run(self, *_: Any) -> None:
        # Setup
        queues = gen_queue_dict()

        def queue_delayer() -> None:
            """Place Onion Service data into queue after delay."""
            time.sleep(0.5)
            queues[ONION_CLOSE_QUEUE].put(EXIT)

        threading.Thread(target=queue_delayer).start()

        # Test
        with mock.patch("time.sleep", return_value=None):
            self.assertIsNone(onion_service(queues, True))

        port, address = queues[TOR_DATA_QUEUE].get()
        self.assertIsInstance(port, int)
        self.assertEqual(validate_onion_addr(address), '')
        self.assertEqual(queues[EXIT_QUEUE].get(), EXIT)

        # Teardown
        tear_queues(queues)

    @mock.patch('time.sleep',                               return_value=None)
    @mock.patch('shlex.split',                              return_value=['NOTICE', 'BOOTSTRAP', 'PROGRESS=100',
                                                                          'TAG=done', 'SUMMARY=Done'])
    @mock.patch('shutil.get_terminal_size',                 side_effect=[stem.SocketClosed])
    @mock.patch('stem.control.Controller.from_socket_file', return_value=MagicMock())
    @mock.patch('stem.process.launch_tor_with_config',      return_value=MagicMock())
    def test_exception_during_onion_service_setup_returns(self, *_: Any) -> None:
        # Setup
        queues = gen_queue_dict()
        queues[ONION_KEY_QUEUE].put((bytes(ONION_SERVICE_PRIVATE_KEY_LENGTH), b'\x01'))

        # Test
        self.assertIsNone(onion_service(queues, False))

        # Teardown
        tear_queues(queues)

    @mock.patch('time.sleep',  side_effect=[None, None, KeyboardInterrupt, stem.SocketClosed, None])
    @mock.patch('shlex.split', return_value=['NOTICE', 'BOOTSTRAP', 'PROGRESS=100', 'TAG=done', 'SUMMARY=Done'])
    @mock.patch('stem.control.Controller.from_socket_file', return_value=MagicMock())
    @mock.patch('stem.process.launch_tor_with_config',      return_value=MagicMock())
    def test_socket_closed_returns(self, *_: Any) -> None:
        # Setup
        queues = gen_queue_dict()

        controller = stem.control.Controller
        controller.create_ephemeral_hidden_service = MagicMock()

        queues[ONION_KEY_QUEUE].put((bytes(ONION_SERVICE_PRIVATE_KEY_LENGTH), b'\x01'))

        # Test
        self.assertIsNone(onion_service(queues, False))

        # Teardown
        tear_queues(queues)

    @mock.patch('stem.control.Controller.from_port', MagicMock())
    @mock.patch('builtins.open',                     mock.mock_open(read_data='TAILS_PRODUCT_NAME="Tails"'))
    def test_no_tor_process_is_created_when_tails_is_used(self, *_: Any) -> None:
        tor = Tor()
        self.assertIsNone(tor.connect(1234))
        self.assertIsNone(tor.tor_process)

    @mock.patch('time.sleep', return_value=None)
    def test_missing_tor_controller_raises_critical_error(self, *_: Any) -> None:
        # Setup
        queues           = gen_queue_dict()
        orig_tor_connect = Tor.connect
        Tor.connect      = MagicMock(return_value=None)

        controller = stem.control.Controller
        controller.create_ephemeral_hidden_service = MagicMock()

        queues[ONION_KEY_QUEUE].put((bytes(ONION_SERVICE_PRIVATE_KEY_LENGTH), b'\x01'))

        # Test
        with self.assertRaises(SystemExit):
            onion_service(queues, False)

        # Teardown
        tear_queues(queues)
        Tor.connect = orig_tor_connect


if __name__ == '__main__':
    unittest.main(exit=False)
