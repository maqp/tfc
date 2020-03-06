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

from unittest import mock

from unittest.mock import MagicMock

from src.common.encoding import b58encode, int_to_bytes
from src.common.statics  import (ACCOUNT_CHECK_QUEUE, CLEAR_ENTIRE_SCREEN, CONTACT_MGMT_QUEUE, CURSOR_LEFT_UP_CORNER,
                                 C_REQ_MGMT_QUEUE, C_REQ_STATE_QUEUE, EXIT, GROUP_MGMT_QUEUE,
                                 LOCAL_TESTING_PACKET_DELAY, ONION_CLOSE_QUEUE, ONION_KEY_QUEUE,
                                 ONION_SERVICE_PRIVATE_KEY_LENGTH, ONION_SERVICE_PUBLIC_KEY_LENGTH,
                                 PUB_KEY_CHECK_QUEUE, RP_ADD_CONTACT_HEADER, RP_REMOVE_CONTACT_HEADER, SRC_TO_RELAY_QUEUE,
                                 TFC_PUBLIC_KEY_LENGTH, UNENCRYPTED_SCREEN_CLEAR, WIPE)

from src.relay.commands import add_contact, add_onion_data, change_baudrate, change_ec_ratio, clear_windows
from src.relay.commands import compare_accounts, compare_pub_keys, exit_tfc, manage_contact_req, process_command
from src.relay.commands import race_condition_delay, relay_command, remove_contact, reset_windows, wipe

from tests.mock_classes import Gateway, nick_to_pub_key
from tests.utils        import gen_queue_dict, tear_queues, TFCTestCase


class TestRelayCommand(unittest.TestCase):

    def setUp(self) -> None:
        """Pre-test actions."""
        self.gateway = Gateway()
        self.queues  = gen_queue_dict()
        self.gateway.settings.race_condition_delay = 0.0

    def tearDown(self) -> None:
        """Post-test actions."""
        tear_queues(self.queues)

    @mock.patch('sys.stdin', MagicMock())
    @mock.patch('os.fdopen', MagicMock())
    def test_packet_reading(self, *_) -> None:

        def queue_delayer() -> None:
            """Place packet into queue after delay."""
            time.sleep(0.1)
            self.queues[SRC_TO_RELAY_QUEUE].put(UNENCRYPTED_SCREEN_CLEAR)

        threading.Thread(target=queue_delayer).start()
        self.assertIsNone(relay_command(self.queues, self.gateway, unit_test=True))


class TestProcessCommand(TFCTestCase):

    def setUp(self) -> None:
        """Pre-test actions."""
        self.gateway = Gateway()
        self.queues  = gen_queue_dict()

    def tearDown(self) -> None:
        """Post-test actions."""
        tear_queues(self.queues)

    def test_invalid_key(self) -> None:
        self.assert_se("Error: Received an invalid command.", process_command, b'INVALID', self.gateway, self.queues)


class TestRaceConditionDelay(unittest.TestCase):

    def setUp(self) -> None:
        """Pre-test actions."""
        self.gateway = Gateway(local_testing_mode=True,
                               data_diode_sockets=True)

    @mock.patch('time.sleep', return_value=None)
    def test_delay(self, mock_sleep) -> None:
        self.assertIsNone(race_condition_delay(self.gateway))
        self.assertEqual(mock_sleep.call_args_list, [mock.call(LOCAL_TESTING_PACKET_DELAY), mock.call(1.0)])


class TestClearWindows(TFCTestCase):

    def setUp(self) -> None:
        """Pre-test actions."""
        self.gateway = Gateway(race_condition_delay=0.0)

    def test_clear_display(self) -> None:
        self.assert_prints(CLEAR_ENTIRE_SCREEN + CURSOR_LEFT_UP_CORNER, clear_windows, self.gateway)


class TestResetWindows(TFCTestCase):

    @mock.patch('os.system', return_value=None)
    def test_reset_display(self, _) -> None:
        self.gateway = Gateway(race_condition_delay=0.0)
        self.assertIsNone(reset_windows(self.gateway))


class TestExitTFC(unittest.TestCase):

    def setUp(self) -> None:
        """Pre-test actions."""
        self.gateway = Gateway(race_condition_delay=0.0)
        self.queues  = gen_queue_dict()

    def tearDown(self) -> None:
        """Post-test actions."""
        tear_queues(self.queues)

    def test_exit_tfc(self) -> None:
        self.assertIsNone(exit_tfc(self.gateway, self.queues))
        self.assertEqual(self.queues[ONION_CLOSE_QUEUE].get(), EXIT)


class TestChangeECRatio(TFCTestCase):

    def setUp(self) -> None:
        """Pre-test actions."""
        self.gateway = Gateway()

    def test_non_digit_value_raises_soft_error(self) -> None:
        self.assert_se("Error: Received invalid EC ratio value from Transmitter Program.",
                       change_ec_ratio, b'a', self.gateway)

    def test_invalid_digit_value_raises_soft_error(self) -> None:
        self.assert_se("Error: Received invalid EC ratio value from Transmitter Program.",
                       change_ec_ratio, b'-1', self.gateway)

    def test_change_value(self) -> None:
        self.assertIsNone(change_ec_ratio(b'3', self.gateway))
        self.assertEqual(self.gateway.settings.serial_error_correction, 3)


class TestChangeBaudrate(TFCTestCase):

    def setUp(self) -> None:
        """Pre-test actions."""
        self.gateway = Gateway()

    def test_non_digit_value_raises_soft_error(self) -> None:
        self.assert_se("Error: Received invalid baud rate value from Transmitter Program.",
                       change_baudrate, b'a', self.gateway)

    def test_invalid_digit_value_raises_soft_error(self) -> None:
        self.assert_se("Error: Received invalid baud rate value from Transmitter Program.",
                       change_baudrate, b'1300', self.gateway)

    def test_change_value(self) -> None:
        self.assertIsNone(change_baudrate(b'9600', self.gateway))
        self.assertEqual(self.gateway.settings.serial_baudrate, 9600)


class TestWipe(unittest.TestCase):

    def setUp(self) -> None:
        """Pre-test actions."""
        self.gateway = Gateway(race_condition_delay=0.0)
        self.queues  = gen_queue_dict()

    def tearDown(self) -> None:
        """Post-test actions."""
        tear_queues(self.queues)

    @mock.patch('os.system', return_value=None)
    def test_wipe_command(self, _) -> None:
        self.assertIsNone(wipe(self.gateway, self.queues))
        self.assertEqual(self.queues[ONION_CLOSE_QUEUE].get(), WIPE)


class TestManageContactReq(unittest.TestCase):

    def setUp(self) -> None:
        """Pre-test actions."""
        self.queues = gen_queue_dict()

    def tearDown(self) -> None:
        """Post-test actions."""
        tear_queues(self.queues)

    def test_setting_management(self) -> None:
        manage_contact_req(b'\x01', self.queues)
        self.assertTrue(self.queues[C_REQ_STATE_QUEUE].get())

        manage_contact_req(b'\x00', self.queues)
        self.assertFalse(self.queues[C_REQ_STATE_QUEUE].get())


class TestAddContact(unittest.TestCase):

    def setUp(self) -> None:
        """Pre-test actions."""
        self.queues = gen_queue_dict()

    def tearDown(self) -> None:
        """Post-test actions."""
        tear_queues(self.queues)

    def test_add_contact(self) -> None:
        command = b''.join([nick_to_pub_key('Alice'), nick_to_pub_key('Bob')])

        self.assertIsNone(add_contact(command, self.queues, True))
        self.assertEqual(self.queues[CONTACT_MGMT_QUEUE].qsize(), 1)
        for q in [GROUP_MGMT_QUEUE, C_REQ_MGMT_QUEUE]:
            command = self.queues[q].get()
            self.assertEqual(command,
                             (RP_ADD_CONTACT_HEADER, b''.join([nick_to_pub_key('Alice'), nick_to_pub_key('Bob')])))
        self.assertEqual(self.queues[CONTACT_MGMT_QUEUE].get(),
                         (RP_ADD_CONTACT_HEADER, b''.join(list(map(nick_to_pub_key, ['Alice', 'Bob']))), True))


class TestRemContact(unittest.TestCase):

    def setUp(self) -> None:
        """Pre-test actions."""
        self.queues = gen_queue_dict()

    def tearDown(self) -> None:
        """Post-test actions."""
        tear_queues(self.queues)

    def test_add_contact(self) -> None:
        command = b''.join([nick_to_pub_key('Alice'), nick_to_pub_key('Bob')])

        self.assertIsNone(remove_contact(command, self.queues))
        self.assertEqual(self.queues[CONTACT_MGMT_QUEUE].qsize(), 1)
        self.assertEqual(self.queues[CONTACT_MGMT_QUEUE].get(),
                         (RP_REMOVE_CONTACT_HEADER,
                          b''.join([nick_to_pub_key('Alice'), nick_to_pub_key('Bob')]),
                          False)
                         )

        for q in [GROUP_MGMT_QUEUE, C_REQ_MGMT_QUEUE]:
            command = self.queues[q].get()
            self.assertEqual(command, (RP_REMOVE_CONTACT_HEADER,
                                       b''.join([nick_to_pub_key('Alice'), nick_to_pub_key('Bob')])))


class TestAddOnionKey(unittest.TestCase):

    def setUp(self) -> None:
        """Pre-test actions."""
        self.queues = gen_queue_dict()

    def tearDown(self) -> None:
        """Post-test actions."""
        tear_queues(self.queues)

    def test_add_contact(self) -> None:
        command = (ONION_SERVICE_PRIVATE_KEY_LENGTH * b'a'
                   + b'b'
                   + b'\x01'
                   + int_to_bytes(1)
                   + nick_to_pub_key('Alice')
                   + nick_to_pub_key('Bob'))
        self.assertIsNone(add_onion_data(command, self.queues))
        self.assertEqual(self.queues[ONION_KEY_QUEUE].qsize(), 1)
        self.assertEqual(self.queues[ONION_KEY_QUEUE].get(), (ONION_SERVICE_PRIVATE_KEY_LENGTH * b'a', b'b'))


class TestCompareAccounts(unittest.TestCase):

    def setUp(self) -> None:
        """Pre-test actions."""
        self.queues = gen_queue_dict()

    def tearDown(self) -> None:
        """Post-test actions."""
        tear_queues(self.queues)

    def test_compare_accounts(self):
        account = b58encode(TFC_PUBLIC_KEY_LENGTH*b'a').encode()
        compare_accounts(account, self.queues)
        self.assertEqual(self.queues[ACCOUNT_CHECK_QUEUE].get(), account.decode())


class TestComparePubKeys(unittest.TestCase):

    def setUp(self) -> None:
        """Pre-test actions."""
        self.queues = gen_queue_dict()

    def tearDown(self) -> None:
        """Post-test actions."""
        tear_queues(self.queues)

    def test_compare_pub_keys(self):
        # Setup
        onion_pub_key   = ONION_SERVICE_PUBLIC_KEY_LENGTH * b'a'
        invalid_pub_key = b58encode(TFC_PUBLIC_KEY_LENGTH * b'a').encode()

        # Test
        compare_pub_keys(onion_pub_key + invalid_pub_key, self.queues)
        self.assertEqual(self.queues[PUB_KEY_CHECK_QUEUE].get(), (onion_pub_key, invalid_pub_key))


if __name__ == '__main__':
    unittest.main(exit=False)
