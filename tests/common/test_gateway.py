#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
TFC - Onion-routed, endpoint secure messaging system
Copyright (C) 2013-2022  Markus Ottela

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

import base64
import os
import unittest
import socket
import threading
import time

from datetime      import datetime
from unittest      import mock
from unittest.mock import MagicMock
from typing        import Any

from serial import SerialException

from src.common.crypto       import blake2b
from src.common.gateway      import gateway_loop, Gateway, GatewaySettings
from src.common.misc         import ensure_dir
from src.common.reed_solomon import RSCodec
from src.common.statics      import (DIR_USER_DATA, GATEWAY_QUEUE, NC, PACKET_CHECKSUM_LENGTH,
                                     QUBES_BUFFER_INCOMING_PACKET, QUBES_BUFFER_INCOMING_DIR, QUBES_DST_VM_NAME,
                                     QUBES_NET_VM_NAME, QUBES_NET_DST_POLICY, QUBES_SRC_NET_POLICY, RX, TX,)

from tests.mock_classes import Settings
from tests.utils        import cd_unit_test, cleanup, gen_queue_dict, tear_queues, TFCTestCase


class TestGatewayLoop(unittest.TestCase):

    def setUp(self) -> None:
        """Pre-test actions."""
        self.unit_test_dir = cd_unit_test()
        self.queues        = gen_queue_dict()

    def tearDown(self) -> None:
        """Post-test actions."""
        cleanup(self.unit_test_dir)
        tear_queues(self.queues)

    @mock.patch('multiprocessing.connection.Listener',
                return_value=MagicMock(accept=lambda: MagicMock(recv=MagicMock(return_value='message'))))
    def test_loop(self, _: Any) -> None:
        gateway = Gateway(operation=RX, local_test=True, dd_sockets=False, qubes=False)
        self.assertIsNone(gateway_loop(self.queues, gateway, unit_test=True))

        data = self.queues[GATEWAY_QUEUE].get()
        self.assertIsInstance(data[0], datetime)
        self.assertEqual(data[1], 'message')


class TestGatewaySerial(TFCTestCase):

    def setUp(self) -> None:
        """Pre-test actions."""
        self.unit_test_dir = cd_unit_test()
        self.settings      = Settings(session_usb_serial_adapter=True)

    def tearDown(self) -> None:
        """Post-test actions."""
        cleanup(self.unit_test_dir)

    @mock.patch('time.sleep',     return_value=None)
    @mock.patch('serial.Serial',  return_value=MagicMock())
    @mock.patch('os.listdir',     side_effect=[['ttyUSB0'], ['ttyUSB0']])
    @mock.patch('builtins.input', side_effect=['Yes'])
    def test_search_and_establish_serial(self, *_: Any) -> None:
        gateway = Gateway(operation=RX, local_test=False, dd_sockets=False, qubes=False)
        self.assertIsInstance(gateway.rs, RSCodec)
        self.assertIs(gateway.tx_serial, gateway.rx_serial)

    @mock.patch('time.sleep',     return_value=None)
    @mock.patch('serial.Serial',  side_effect=SerialException)
    @mock.patch('os.listdir',     side_effect=[['ttyUSB0'], ['ttyUSB0']])
    @mock.patch('builtins.input', side_effect=['Yes'])
    def test_serial_exception_during_establish_exists(self, *_: Any) -> None:
        with self.assertRaises(SystemExit):
            Gateway(operation=RX, local_test=False, dd_sockets=False, qubes=False)

    @mock.patch('time.sleep',     return_value=None)
    @mock.patch('serial.Serial',  return_value=MagicMock(write=MagicMock(side_effect=[SerialException, None])))
    @mock.patch('os.listdir',     side_effect=[['ttyUSB0'], ['ttyUSB0'], ['ttyUSB0']])
    @mock.patch('builtins.input', side_effect=['Yes'])
    def test_write_serial_(self, *_: Any) -> None:
        gateway = Gateway(operation=RX, local_test=False, dd_sockets=False, qubes=False)
        self.assertIsNone(gateway.write(b"message"))

    @mock.patch("time.sleep", return_value=None)
    @mock.patch("serial.Serial", return_value=MagicMock(read_all=MagicMock(
        side_effect=[KeyboardInterrupt, SerialException, b"", b"1", b"2", b""])))
    @mock.patch("os.listdir", side_effect=[["ttyUSB0"], ["ttyUSB0"], ["ttyUSB0"]])
    @mock.patch("builtins.input", side_effect=["Yes"])
    def test_serial_uninitialized_serial_interface_for_read_raises_critical_error(self, *_) -> None:
        # Setup
        gateway = Gateway(operation=RX, local_test=False, dd_sockets=False, qubes=False)
        gateway.rx_serial = None

        # Test
        with self.assertRaises(SystemExit):
            gateway.read()

    @mock.patch("multiprocessing.connection.Listener", MagicMock())
    @mock.patch("time.sleep",     return_value=None)
    @mock.patch("os.listdir",     side_effect=[["ttyUSB0"], ["ttyUSB0"], ["ttyUSB0"]])
    @mock.patch("builtins.input", side_effect=["Yes"])
    def test_serial_uninitialized_socket_interface_for_read_raises_critical_error(self, *_) -> None:
        # Setup
        gateway = Gateway(operation=RX, local_test=True, dd_sockets=False, qubes=False)
        gateway.rx_socket = None

        # Test
        with self.assertRaises(SystemExit):
            gateway.read()

    @mock.patch("multiprocessing.connection.Listener", return_value=MagicMock(
        accept=MagicMock(return_value=MagicMock(recv=MagicMock(return_value=b"12")))))
    @mock.patch("time.monotonic", side_effect=[1, 2, 3])
    @mock.patch("time.sleep",     return_value=None)
    @mock.patch("os.listdir",     side_effect=[["ttyUSB0"], ["ttyUSB0"], ["ttyUSB0"]])
    @mock.patch("builtins.input", side_effect=["Yes"])
    def test_read_socket(self, *_) -> None:
        gateway = Gateway(operation=RX, local_test=True, dd_sockets=False, qubes=False)
        data = gateway.read()
        self.assertEqual(data, b"12")

    @mock.patch("time.monotonic", side_effect=[1, 2, 3])
    @mock.patch("time.sleep",     return_value=None)
    @mock.patch("serial.Serial",  return_value=MagicMock(
        read_all=MagicMock(side_effect=[KeyboardInterrupt, SerialException, b"", b"1", b"2", b""])))
    @mock.patch("os.listdir",     side_effect=[["ttyUSB0"], ["ttyUSB0"], ["ttyUSB0"]])
    @mock.patch("builtins.input", side_effect=["Yes"])
    def test_read_serial(self, *_) -> None:
        gateway = Gateway(operation=RX, local_test=False, dd_sockets=False, qubes=False)
        data = gateway.read()
        self.assertEqual(data, b"12")

    @mock.patch("time.sleep",     return_value=None)
    @mock.patch("serial.Serial",  return_value=MagicMock())
    @mock.patch("os.listdir",     side_effect=[["ttyUSB0"], ["ttyUSB0"]])
    @mock.patch("builtins.input", side_effect=["Yes"])
    def test_add_error_correction(self, *_) -> None:
        gateway = Gateway(operation=RX, local_test=False, dd_sockets=False, qubes=False)
        packet = b"packet"

        # Test BLAKE2b based checksum
        gateway.settings.session_serial_error_correction = 0
        self.assertEqual(gateway.add_error_correction(packet),
                         packet + blake2b(packet, digest_size=PACKET_CHECKSUM_LENGTH))

        # Test Reed-Solomon erasure code
        gateway.settings.session_serial_error_correction = 5
        gateway.rs = RSCodec(gateway.settings.session_serial_error_correction)
        self.assertEqual(gateway.add_error_correction(packet),
                         gateway.rs.encode(packet))

    @mock.patch('time.sleep',     return_value=None)
    @mock.patch('serial.Serial',  return_value=MagicMock())
    @mock.patch('os.listdir',     side_effect=[['ttyUSB0'], ['ttyUSB0']])
    @mock.patch('builtins.input', side_effect=['Yes'])
    def test_detect_errors(self, *_: Any) -> None:
        gateway = Gateway(operation=RX, local_test=False, dd_sockets=False, qubes=False)
        packet  = b'packet'

        # Test BLAKE2b based checksum
        gateway.settings.session_serial_error_correction = 0
        self.assertEqual(gateway.detect_errors(gateway.add_error_correction(packet)),
                         packet)

        # Test unrecoverable error raises SoftError
        self.assert_se("Warning! Received packet had an invalid checksum.",
                       gateway.detect_errors, 300 * b'a')

        # Test Reed-Solomon erasure code
        gateway.settings.session_serial_error_correction = 5
        gateway.rs = RSCodec(gateway.settings.session_serial_error_correction)
        self.assertEqual(gateway.detect_errors(gateway.add_error_correction(packet)),
                         packet)

        # Test unrecoverable error raises SoftError
        self.assert_se("Error: Reed-Solomon failed to correct errors in the received packet.",
                       gateway.detect_errors, 300 * b'a')

        # Qubes

        # Test with B58 encoding
        gateway.settings.qubes = True
        packet_with_error_correction = base64.b85encode(gateway.add_error_correction(packet))
        self.assertEqual(gateway.detect_errors(packet_with_error_correction), packet)

        # Test invalid B85 encoding raises SoftError
        packet_with_error_correction = base64.b85encode(gateway.add_error_correction(packet))
        packet_with_error_correction += b'\x00'
        self.assert_se("Error: Received packet had invalid Base85 encoding.",
                       gateway.detect_errors, packet_with_error_correction)
        gateway.settings.qubes = False

    @mock.patch('time.sleep',     return_value=None)
    @mock.patch('serial.Serial',  return_value=MagicMock())
    @mock.patch('os.listdir',     side_effect=[['ttyUSB0'], ['ttyUSB0'], [''], ['ttyUSB0'], ['ttyS0'], ['']])
    @mock.patch('builtins.input', side_effect=['Yes'])
    def test_search_serial_interfaces(self, *_: Any) -> None:
        gateway = Gateway(operation=RX, local_test=False, dd_sockets=False, qubes=False)

        interface = gateway.search_serial_interface()
        self.assertEqual(interface, '/dev/ttyUSB0')

        # Test unavailable system serial exits:
        gateway.settings.session_usb_serial_adapter = False

        interface = gateway.search_serial_interface()
        self.assertEqual(interface, '/dev/ttyS0')

        with self.assertRaises(SystemExit):
            gateway.search_serial_interface()

    @mock.patch('time.sleep', return_value=None)
    @mock.patch('multiprocessing.connection.Client',   MagicMock())
    @mock.patch('multiprocessing.connection.Listener', MagicMock())
    def test_establish_local_testing_gateway(self, *_: Any) -> None:
        gateway = Gateway(operation=NC, local_test=True, dd_sockets=False, qubes=False)
        self.assertIsInstance(gateway.rs, RSCodec)

    @mock.patch('time.sleep', return_value=None)
    @mock.patch('multiprocessing.connection.Client', MagicMock(side_effect=KeyboardInterrupt))
    def test_keyboard_interrupt_exits(self, *_: Any) -> None:
        with self.assertRaises(SystemExit):
            Gateway(operation=TX, local_test=True, dd_sockets=False, qubes=False)

    @mock.patch('time.sleep', return_value=None)
    @mock.patch('multiprocessing.connection.Client', MagicMock(
        side_effect=[socket.error, ConnectionRefusedError, MagicMock()]))
    def test_socket_client(self, *_: Any) -> None:
        gateway = Gateway(operation=TX, local_test=True, dd_sockets=False, qubes=False)
        self.assertIsInstance(gateway, Gateway)

    @mock.patch('time.sleep', return_value=None)
    @mock.patch('multiprocessing.connection.Listener', MagicMock(
        side_effect=[MagicMock(), KeyboardInterrupt]))
    def test_socket_server(self, *_: Any) -> None:
        gateway = Gateway(operation=RX, local_test=True, dd_sockets=False, qubes=False)
        self.assertIsInstance(gateway, Gateway)

        with self.assertRaises(SystemExit):
            Gateway(operation=RX, local_test=True, dd_sockets=False, qubes=False)

    @mock.patch('time.sleep', return_value=None)
    @mock.patch('multiprocessing.connection.Listener', return_value=MagicMock(
        accept=lambda: MagicMock(recv=MagicMock(side_effect=[KeyboardInterrupt, b'data', EOFError]))))
    def test_local_testing_read(self, *_: Any) -> None:
        gateway = Gateway(operation=RX, local_test=True, dd_sockets=False, qubes=False)
        self.assertEqual(gateway.read(), b'data')
        with self.assertRaises(SystemExit):
            gateway.read()

    @mock.patch('time.sleep', return_value=None)
    @mock.patch('multiprocessing.connection.Client', return_value=MagicMock(
        send=MagicMock(side_effect=[None, BrokenPipeError])))
    def test_local_testing_write(self, *_: Any) -> None:
        gateway = Gateway(operation=TX, local_test=True, dd_sockets=False, qubes=False)
        self.assertIsNone(gateway.write(b'data'))

        with self.assertRaises(SystemExit):
            gateway.write(b'data')

    # Qubes
    def test_qubes_read_file(self, *_: Any) -> None:
        # Setup
        ensure_dir(f"{QUBES_BUFFER_INCOMING_DIR}/")

        def packet_delayer() -> None:
            """Create packets one at a time."""
            time.sleep(0.1)

            with open(f"{QUBES_BUFFER_INCOMING_DIR}/{QUBES_BUFFER_INCOMING_PACKET}.invalid", 'wb+') as fp:
                fp.write(base64.b85encode(b'data'))

            time.sleep(0.1)

            with open(f"{QUBES_BUFFER_INCOMING_DIR}/{QUBES_BUFFER_INCOMING_PACKET}.0", 'wb+') as fp:
                fp.write(base64.b85encode(b'data'))

        threading.Thread(target=packet_delayer).start()

        gateway = Gateway(operation=RX, local_test=False, dd_sockets=False, qubes=True)

        # Test
        self.assert_se("No packet was available.", gateway.read)

        time.sleep(0.3)

        self.assertIsInstance(gateway, Gateway)
        self.assertEqual(gateway.read(), b'data')

        # Test invalid packet content is handled
        with open(f"{QUBES_BUFFER_INCOMING_DIR}/{QUBES_BUFFER_INCOMING_PACKET}.1", 'wb+') as f:
            f.write(os.urandom(32))
        self.assert_se("Error: Received packet had invalid Base85 encoding.", gateway.read)

    @mock.patch('subprocess.Popen')
    def test_qubes_send_to_networkerVM(self, mock_popen) -> None:
        gateway = Gateway(operation=TX, local_test=False, dd_sockets=False, qubes=True)
        self.assertIsInstance(gateway, Gateway)
        self.assertIsNone(gateway.write(b'data'))
        mock_popen.assert_called_with(['/usr/bin/qrexec-client-vm', QUBES_NET_VM_NAME, QUBES_SRC_NET_POLICY], stderr=-3, stdin=-1, stdout=-3)

    @mock.patch('subprocess.Popen')
    def test_qubes_send_to_destinationVM(self, mock_popen) -> None:
        gateway = Gateway(operation=NC, local_test=False, dd_sockets=False, qubes=True)
        self.assertIsInstance(gateway, Gateway)
        self.assertIsNone(gateway.write(b'data'))
        mock_popen.assert_called_with(['/usr/bin/qrexec-client-vm', QUBES_DST_VM_NAME, QUBES_NET_DST_POLICY], stderr=-3, stdin=-1, stdout=-3)


class TestGatewaySettings(TFCTestCase):

    def setUp(self) -> None:
        """Pre-test actions."""
        self.unit_test_dir      = cd_unit_test()
        self.default_serialized = """\
{
    "serial_baudrate": 19200,
    "serial_error_correction": 5,
    "use_serial_usb_adapter": true,
    "built_in_serial_interface": "ttyS0"
}"""

    def tearDown(self) -> None:
        """Post-test actions."""
        cleanup(self.unit_test_dir)

    @mock.patch('os.listdir',     side_effect=[['ttyUSB0'], ['ttyS0'], ['ttyUSB0'], ['ttyS0']])
    @mock.patch('builtins.input', side_effect=['yes', 'yes', 'no', 'no'])
    def test_gateway_setup(self, *_: Any) -> None:
        settings = GatewaySettings(operation=TX, local_test=False, dd_sockets=True, qubes=False)
        self.assertIsNone(settings.setup())

    def test_store_and_load_of_settings(self) -> None:
        settings = GatewaySettings(operation=TX, local_test=True, dd_sockets=True, qubes=False)
        self.assertTrue(os.path.isfile(f'{DIR_USER_DATA}/{TX}_serial_settings.json'))

        self.assertEqual(settings.serial_baudrate,        19200)
        self.assertEqual(settings.use_serial_usb_adapter, True)
        settings.serial_baudrate        = 115200
        settings.use_serial_usb_adapter = False

        self.assertIsNone(settings.store_settings())
        settings2 = GatewaySettings(operation=TX, local_test=True, dd_sockets=True, qubes=False)

        self.assertEqual(settings2.serial_baudrate,       115200)
        self.assertEqual(settings.use_serial_usb_adapter, False)

    def test_manually_edited_settings_are_loaded(self) -> None:
        # Setup
        ensure_dir(DIR_USER_DATA)
        with open(f"{DIR_USER_DATA}{TX}_serial_settings.json", 'w+') as f:
            f.write("""\
{
    "serial_baudrate": 9600,
    "serial_error_correction": 1,
    "use_serial_usb_adapter": false,
    "built_in_serial_interface": "ttyS0"
}""")
        # Test
        settings = GatewaySettings(operation=TX, local_test=True, dd_sockets=True, qubes=False)
        self.assertEqual(settings.serial_baudrate,           9600)
        self.assertEqual(settings.serial_error_correction,   1)
        self.assertEqual(settings.use_serial_usb_adapter,    False)
        self.assertEqual(settings.built_in_serial_interface, 'ttyS0')

    def test_missing_values_are_set_to_default_and_database_is_overwritten(self) -> None:
        # Setup
        ensure_dir(DIR_USER_DATA)
        with open(f"{DIR_USER_DATA}{TX}_serial_settings.json", 'w+') as f:
            f.write("""\
{
    "serial_error_correction": 1,
    "use_serial_usb_adapter": false,
    "relay_usb_serial_adapter": false
}""")
        # Test
        settings = GatewaySettings(operation=TX, local_test=True, dd_sockets=True, qubes=False)
        self.assertEqual(settings.serial_baudrate,           19200)
        self.assertEqual(settings.serial_error_correction,   1)
        self.assertEqual(settings.use_serial_usb_adapter,    False)
        self.assertEqual(settings.built_in_serial_interface, 'ttyS0')

    def test_invalid_format_is_replaced_with_defaults(self) -> None:
        # Setup
        ensure_dir(DIR_USER_DATA)
        with open(f"{DIR_USER_DATA}{TX}_serial_settings.json", 'w+') as f:
            f.write("""\
{
    "serial_error_correction": 5,
    "use_serial_usb_adapter": false,

}""")
        # Test
        settings = GatewaySettings(operation=TX, local_test=True, dd_sockets=True, qubes=False)
        self.assertEqual(settings.serial_baudrate,           19200)
        self.assertEqual(settings.serial_error_correction,   5)
        self.assertEqual(settings.use_serial_usb_adapter,    True)
        self.assertEqual(settings.built_in_serial_interface, 'ttyS0')

        with open(settings.file_name) as f:
            data = f.read()

        self.assertEqual(data, self.default_serialized)

    def test_invalid_serial_baudrate_is_replaced_with_default(self) -> None:
        # Setup
        ensure_dir(DIR_USER_DATA)
        with open(f"{DIR_USER_DATA}{TX}_serial_settings.json", 'w+') as f:
            f.write("""\
{
    "serial_baudrate": 19201,
    "serial_error_correction": 5,
    "use_serial_usb_adapter": true,
    "built_in_serial_interface": "ttyS0"
}""")
        # Test
        settings = GatewaySettings(operation=TX, local_test=True, dd_sockets=True, qubes=False)
        self.assertEqual(settings.serial_baudrate,           19200)
        self.assertEqual(settings.serial_error_correction,   5)
        self.assertEqual(settings.use_serial_usb_adapter,    True)
        self.assertEqual(settings.built_in_serial_interface, 'ttyS0')

        with open(settings.file_name) as f:
            data = f.read()

        self.assertEqual(data, self.default_serialized)

    def test_invalid_serial_error_correction_is_replaced_with_default(self) -> None:
        # Setup
        ensure_dir(DIR_USER_DATA)
        with open(f"{DIR_USER_DATA}{TX}_serial_settings.json", 'w+') as f:
            f.write("""\
{
    "serial_baudrate": 19200,
    "serial_error_correction": -1,
    "use_serial_usb_adapter": true,
    "built_in_serial_interface": "ttyS0"
}""")
        # Test
        settings = GatewaySettings(operation=TX, local_test=True, dd_sockets=True, qubes=False)
        self.assertEqual(settings.serial_baudrate,           19200)
        self.assertEqual(settings.serial_error_correction,   5)
        self.assertEqual(settings.use_serial_usb_adapter,    True)
        self.assertEqual(settings.built_in_serial_interface, 'ttyS0')

        with open(settings.file_name) as f:
            data = f.read()

        self.assertEqual(data, self.default_serialized)

    def test_invalid_serial_interface_is_replaced_with_default(self) -> None:
        # Setup
        ensure_dir(DIR_USER_DATA)
        with open(f"{DIR_USER_DATA}{TX}_serial_settings.json", 'w+') as f:
            f.write("""\
{
    "serial_baudrate": 19200,
    "serial_error_correction": 5,
    "use_serial_usb_adapter": true,
    "built_in_serial_interface": "does_not_exist"
}""")
        # Test
        settings = GatewaySettings(operation=TX, local_test=True, dd_sockets=True, qubes=False)
        self.assertEqual(settings.serial_baudrate,           19200)
        self.assertEqual(settings.serial_error_correction,   5)
        self.assertEqual(settings.use_serial_usb_adapter,    True)
        self.assertEqual(settings.built_in_serial_interface, 'ttyS0')

        with open(settings.file_name) as f:
            data = f.read()

        self.assertEqual(data, self.default_serialized)

    def test_invalid_type_is_replaced_with_default(self) -> None:
        # Setup
        ensure_dir(DIR_USER_DATA)
        with open(f"{DIR_USER_DATA}{TX}_serial_settings.json", 'w+') as f:
            f.write("""\
{
    "serial_baudrate": "115200",
    "serial_error_correction": "5",
    "use_serial_usb_adapter": "true",
    "built_in_serial_interface": true
}""")
        # Test
        settings = GatewaySettings(operation=TX, local_test=True, dd_sockets=True, qubes=False)
        self.assertEqual(settings.serial_baudrate,           19200)
        self.assertEqual(settings.serial_error_correction,   5)
        self.assertEqual(settings.use_serial_usb_adapter,    True)
        self.assertEqual(settings.built_in_serial_interface, 'ttyS0')

        with open(settings.file_name) as f:
            data = f.read()

        self.assertEqual(data, self.default_serialized)

    def test_unknown_kv_pair_is_removed(self) -> None:
        # Setup
        ensure_dir(DIR_USER_DATA)
        with open(f"{DIR_USER_DATA}{TX}_serial_settings.json", 'w+') as f:
            f.write("""\
{
    "serial_baudrate": 19200,
    "serial_error_correction": 5,
    "use_serial_usb_adapter": true,
    "built_in_serial_interface": "ttyS0",
    "this_should_not_be_here": 1
}""")
        # Test
        settings = GatewaySettings(operation=TX, local_test=True, dd_sockets=True, qubes=False)
        self.assertEqual(settings.serial_baudrate,           19200)
        self.assertEqual(settings.serial_error_correction,   5)
        self.assertEqual(settings.use_serial_usb_adapter,    True)
        self.assertEqual(settings.built_in_serial_interface, 'ttyS0')

        with open(settings.file_name) as f:
            data = f.read()

        self.assertEqual(data, self.default_serialized)

    @mock.patch('os.listdir',    side_effect=[['ttyS0'], ['ttyUSB0'], ['ttyUSB0'], ['ttyS0']])
    @mock.patch('builtins.input', side_effect=['Yes', 'Yes', 'No', 'No'])
    def test_setup(self, *_: Any) -> None:
        # Setup
        ensure_dir(DIR_USER_DATA)
        with open(f"{DIR_USER_DATA}{TX}_serial_settings.json", 'w+') as f:
            f.write(self.default_serialized)

        settings = GatewaySettings(operation=TX, local_test=False, dd_sockets=True, qubes=False)

        # Test
        self.assertIsNone(settings.setup())
        self.assertIsNone(settings.setup())

    @mock.patch('time.sleep', return_value=None)
    def test_change_setting(self, _: Any) -> None:
        settings = GatewaySettings(operation=TX, local_test=True, dd_sockets=True, qubes=False)
        self.assert_se("Error: Invalid setting value 'Falsee'.",
                       settings.change_setting, 'serial_baudrate',        'Falsee')
        self.assert_se("Error: Invalid setting value '1.1'.",
                       settings.change_setting, 'serial_baudrate',         '1.1', )
        self.assert_se("Error: Invalid setting value '18446744073709551616'.",
                       settings.change_setting, 'serial_baudrate', str(2 ** 64))
        self.assert_se("Error: Invalid setting value 'Falsee'.",
                       settings.change_setting, 'use_serial_usb_adapter', 'Falsee')

        self.assertIsNone(settings.change_setting('serial_baudrate', '9600'))
        self.assertEqual(GatewaySettings(operation=TX, local_test=True, dd_sockets=True, qubes=False).serial_baudrate, 9600)

        settings.serial_baudrate = b'bytestring'
        with self.assertRaises(SystemExit):
            settings.change_setting('serial_baudrate', '9600')

    def test_validate_key_value_pair(self) -> None:
        settings = GatewaySettings(operation=TX, local_test=True, dd_sockets=True, qubes=False)
        self.assert_se("Error: The specified baud rate is not supported.",
                       settings.validate_key_value_pair, 'serial_baudrate', 0)
        self.assert_se("Error: The specified baud rate is not supported.",
                       settings.validate_key_value_pair, 'serial_baudrate', 10)
        self.assert_se("Error: The specified baud rate is not supported.",
                       settings.validate_key_value_pair, 'serial_baudrate', 9601)
        self.assert_se("Error: Invalid value for error correction ratio.",
                       settings.validate_key_value_pair, 'serial_error_correction', -1)

        self.assertIsNone(settings.validate_key_value_pair("serial_baudrate",          9600))
        self.assertIsNone(settings.validate_key_value_pair("serial_error_correction",  20))
        self.assertIsNone(settings.validate_key_value_pair("use_serial_usb_adapter", True))

    @mock.patch('shutil.get_terminal_size', return_value=(64, 64))
    def test_too_narrow_terminal_raises_soft_error_when_printing_settings(self, _: Any) -> None:
        settings = GatewaySettings(operation=TX, local_test=True, dd_sockets=True, qubes=False)
        self.assert_se("Error: Screen width is too small.", settings.print_settings)

    def test_print_settings(self) -> None:
        settings = GatewaySettings(operation=TX, local_test=True, dd_sockets=True, qubes=False)
        self.assert_prints("""\

Serial interface setting        Current value   Default value   Description
────────────────────────────────────────────────────────────────────────────────
serial_baudrate                 19200           19200           The speed of
                                                                serial interface
                                                                in bauds per
                                                                second

serial_error_correction         5               5               Number of byte
                                                                errors serial
                                                                datagrams can
                                                                recover from


""", settings.print_settings)


if __name__ == '__main__':
    unittest.main(exit=False)
