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

from unittest import mock

from unittest.mock import MagicMock

from src.common.encoding import int_to_bytes
from src.common.statics  import *

from src.relay.commands import add_contact, add_onion_data, change_baudrate, change_ec_ratio, clear_windows, exit_tfc
from src.relay.commands import manage_contact_req, process_command, race_condition_delay, relay_command, remove_contact
from src.relay.commands import reset_windows, wipe

from tests.mock_classes import Gateway, nick_to_pub_key
from tests.utils        import gen_queue_dict, tear_queues, TFCTestCase


class TestRelayCommand(unittest.TestCase):

    def setUp(self):
        self.gateway = Gateway()
        self.queues  = gen_queue_dict()
        self.gateway.settings.race_condition_delay = 0.0

    def tearDown(self):
        tear_queues(self.queues)

    @mock.patch('sys.stdin', MagicMock())
    @mock.patch('os.fdopen', MagicMock())
    def test_packet_reading(self, *_):

        def queue_delayer():
            """Place packet into queue after delay."""
            time.sleep(0.1)
            self.queues[SRC_TO_RELAY_QUEUE].put(UNENCRYPTED_SCREEN_CLEAR)

        threading.Thread(target=queue_delayer).start()
        self.assertIsNone(relay_command(self.queues, self.gateway, stdin_fd=1, unittest=True))


class TestProcessCommand(TFCTestCase):

    def setUp(self):
        self.gateway = Gateway()
        self.queues  = gen_queue_dict()

    def tearDown(self):
        tear_queues(self.queues)

    def test_invalid_key(self):
        self.assert_fr("Error: Received an invalid command.", process_command, b'INVALID', self.gateway, self.queues)


class TestRaceConditionDelay(unittest.TestCase):

    def setUp(self):
        self.gateway = Gateway(local_testing_mode=True,
                               data_diode_sockets=True)

    @mock.patch('time.sleep', return_value=None)
    def test_delay(self, mock_sleep):
        self.assertIsNone(race_condition_delay(self.gateway))
        self.assertEqual(mock_sleep.call_args_list, [mock.call(LOCAL_TESTING_PACKET_DELAY), mock.call(1.0)])


class TestClearWindows(TFCTestCase):

    def setUp(self):
        self.gateway = Gateway(race_condition_delay=0.0)

    def test_clear_display(self):
        self.assert_prints(CLEAR_ENTIRE_SCREEN + CURSOR_LEFT_UP_CORNER, clear_windows, self.gateway)


class TestResetWindows(TFCTestCase):

    @mock.patch('os.system', return_value=None)
    def test_reset_display(self, _):
        self.gateway = Gateway(race_condition_delay=0.0)
        self.assertIsNone(reset_windows(self.gateway))


class TestExitTFC(unittest.TestCase):

    def setUp(self):
        self.gateway = Gateway(race_condition_delay=0.0)
        self.queues  = gen_queue_dict()

    def tearDown(self):
        tear_queues(self.queues)

    def test_exit_tfc(self):
        self.assertIsNone(exit_tfc(self.gateway, self.queues))
        self.assertEqual(self.queues[ONION_CLOSE_QUEUE].get(), EXIT)


class TestChangeECRatio(TFCTestCase):

    def setUp(self):
        self.gateway = Gateway()

    def test_non_digit_value_raises_fr(self):
        self.assert_fr("Error: Received invalid EC ratio value from Transmitter Program.",
                       change_ec_ratio, b'a', self.gateway)

    def test_invalid_digit_value_raises_fr(self):
        self.assert_fr("Error: Received invalid EC ratio value from Transmitter Program.",
                       change_ec_ratio, b'-1', self.gateway)

    def test_change_value(self):
        self.assertIsNone(change_ec_ratio(b'3', self.gateway))
        self.assertEqual(self.gateway.settings.serial_error_correction, 3)


class TestChangeBaudrate(TFCTestCase):

    def setUp(self):
        self.gateway = Gateway()

    def test_non_digit_value_raises_fr(self):
        self.assert_fr("Error: Received invalid baud rate value from Transmitter Program.",
                       change_baudrate, b'a', self.gateway)

    def test_invalid_digit_value_raises_fr(self):
        self.assert_fr("Error: Received invalid baud rate value from Transmitter Program.",
                       change_baudrate, b'1300', self.gateway)

    def test_change_value(self):
        self.assertIsNone(change_baudrate(b'9600', self.gateway))
        self.assertEqual(self.gateway.settings.serial_baudrate, 9600)


class TestWipe(unittest.TestCase):

    def setUp(self):
        self.gateway = Gateway(race_condition_delay=0.0)
        self.queues  = gen_queue_dict()

    def tearDown(self):
        tear_queues(self.queues)

    @mock.patch('os.system', return_value=None)
    def test_wipe_command(self, _):
        self.assertIsNone(wipe(self.gateway, self.queues))
        self.assertEqual(self.queues[ONION_CLOSE_QUEUE].get(), WIPE)


class TestManageContactReq(unittest.TestCase):

    def setUp(self):
        self.queues = gen_queue_dict()

    def tearDown(self):
        tear_queues(self.queues)

    def test_setting_management(self):
        manage_contact_req(b'\x01', self.queues)
        self.assertTrue(self.queues[C_REQ_MGR_QUEUE].get())

        manage_contact_req(b'\x00', self.queues)
        self.assertFalse(self.queues[C_REQ_MGR_QUEUE].get())


class TestAddContact(unittest.TestCase):

        def setUp(self):
            self.queues = gen_queue_dict()

        def tearDown(self):
            tear_queues(self.queues)

        def test_add_contact(self):
            command = b''.join([nick_to_pub_key('Alice'), nick_to_pub_key('Bob')])

            self.assertIsNone(add_contact(command, True, self.queues))
            self.assertEqual(self.queues[CONTACT_KEY_QUEUE].qsize(), 1)
            for q in [GROUP_MGMT_QUEUE, F_REQ_MGMT_QUEUE]:
                command = self.queues[q].get()
                self.assertEqual(command,
                                 (RP_ADD_CONTACT_HEADER, b''.join([nick_to_pub_key('Alice'), nick_to_pub_key('Bob')])))
            self.assertEqual(self.queues[CONTACT_KEY_QUEUE].get(),
                             (RP_ADD_CONTACT_HEADER, b''.join(list(map(nick_to_pub_key, ['Alice', 'Bob']))), True))


class TestRemContact(unittest.TestCase):

        def setUp(self):
            self.queues = gen_queue_dict()

        def tearDown(self):
            tear_queues(self.queues)

        def test_add_contact(self):
            command = b''.join([nick_to_pub_key('Alice'), nick_to_pub_key('Bob')])

            self.assertIsNone(remove_contact(command, self.queues))
            self.assertEqual(self.queues[CONTACT_KEY_QUEUE].qsize(), 1)
            self.assertEqual(self.queues[CONTACT_KEY_QUEUE].get(),
                             (RP_REMOVE_CONTACT_HEADER,
                              b''.join([nick_to_pub_key('Alice'), nick_to_pub_key('Bob')]),
                              False)
                             )

            for q in [GROUP_MGMT_QUEUE, F_REQ_MGMT_QUEUE]:
                command = self.queues[q].get()
                self.assertEqual(command, (RP_REMOVE_CONTACT_HEADER,
                                           b''.join([nick_to_pub_key('Alice'), nick_to_pub_key('Bob')])))


class TestAddOnionKey(unittest.TestCase):

        def setUp(self):
            self.queues = gen_queue_dict()

        def tearDown(self):
            tear_queues(self.queues)

        def test_add_contact(self):
            command = (ONION_SERVICE_PRIVATE_KEY_LENGTH * b'a'
                       + b'b'
                       + b'\x01'
                       + int_to_bytes(1)
                       + nick_to_pub_key('Alice')
                       + nick_to_pub_key('Bob'))
            self.assertIsNone(add_onion_data(command, self.queues))
            self.assertEqual(self.queues[ONION_KEY_QUEUE].qsize(), 1)
            self.assertEqual(self.queues[ONION_KEY_QUEUE].get(), (ONION_SERVICE_PRIVATE_KEY_LENGTH * b'a', b'b'))


if __name__ == '__main__':
    unittest.main(exit=False)
