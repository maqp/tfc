#!/usr/bin/env python3.5
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

import os
import threading
import time
import unittest

from multiprocessing import Queue
from tkinter         import filedialog

from src.common.statics import *

from src.nh.commands import nh_command, process_command, race_condition_delay, clear_windows, reset_windows
from src.nh.commands import exit_tfc, rxm_import, change_ec_ratio, change_baudrate, change_gui_dialog, wipe

from tests.mock_classes import Settings
from tests.utils        import ignored, TFCTestCase


class TestNHCommand(unittest.TestCase):

    def setUp(self):
        self.settings = Settings(race_condition_delay=0.0)
        self.queues   = {TXM_TO_NH_QUEUE:    Queue(),
                         NH_TO_IM_QUEUE:     Queue(),
                         EXIT_QUEUE:         Queue(),
                         RXM_OUTGOING_QUEUE: Queue()}

    def tearDown(self):
        for key in self.queues:
            while not self.queues[key]:
                self.queues[key].get()
            time.sleep(0.1)
            self.queues[key].close()

    def test_packet_reading(self):

        def queue_delayer():
            time.sleep(0.1)
            self.queues[TXM_TO_NH_QUEUE].put(UNENCRYPTED_SCREEN_CLEAR)

        threading.Thread(target=queue_delayer).start()
        self.assertIsNone(nh_command(self.queues, self.settings, stdin_fd=1, unittest=True))
        self.assertEqual(self.queues[NH_TO_IM_QUEUE].qsize(), 1)


class TestProcessCommand(TFCTestCase):

    def setUp(self):
        self.settings = Settings()
        self.queues   = {TXM_TO_NH_QUEUE:    Queue(),
                         NH_TO_IM_QUEUE:     Queue(),
                         EXIT_QUEUE:         Queue(),
                         RXM_OUTGOING_QUEUE: Queue()}

    def tearDown(self):
        for key in self.queues:
            while not self.queues[key]:
                self.queues[key].get()
            time.sleep(0.1)
            self.queues[key].close()

    def test_invalid_key(self):
        self.assertFR("Error: Received an invalid command.",
                      process_command, self.settings, b'INVALID', self.queues)


class TestRaceConditionDelay(unittest.TestCase):

    def setUp(self):
        self.settings = Settings(local_testing_mode=True,
                                 data_diode_sockets=True)

    def test_delay(self):
        start_time = time.monotonic()
        self.assertIsNone(race_condition_delay(self.settings))
        duration = time.monotonic() - start_time
        self.assertTrue(duration > 1)


class TestClearWindows(TFCTestCase):

    def setUp(self):
        self.settings    = Settings(race_condition_delay=0.0)
        self.queue_to_im = Queue()

    def tearDown(self):
        while not self.queue_to_im.empty():
            self.queue_to_im.get()
        time.sleep(0.1)
        self.queue_to_im.close()

    def test_clear_display(self):
        self.assertPrints(CLEAR_ENTIRE_SCREEN + CURSOR_LEFT_UP_CORNER,
                          clear_windows, self.settings, UNENCRYPTED_SCREEN_CLEAR, self.queue_to_im)

        self.assertEqual(self.queue_to_im.get(), UNENCRYPTED_SCREEN_CLEAR)


class TestResetWindows(TFCTestCase):

    def setUp(self):
        self.settings    = Settings(race_condition_delay=0.0)
        self.queue_to_im = Queue()

    def tearDown(self):
        while not self.queue_to_im.empty():
            self.queue_to_im.get()
        time.sleep(0.1)
        self.queue_to_im.close()

    def test_reset_display(self):
        self.assertIsNone(reset_windows(self.settings, UNENCRYPTED_SCREEN_RESET, self.queue_to_im))
        self.assertEqual(self.queue_to_im.get(), UNENCRYPTED_SCREEN_RESET)


class TestExitTFC(unittest.TestCase):

    def setUp(self):
        self.settings   = Settings(race_condition_delay=0.0)
        self.queue_exit = Queue()

    def tearDown(self):
        while not self.queue_exit.empty():
            self.queue_exit.get()
        time.sleep(0.1)
        self.queue_exit.close()

    def test_exit_tfc(self):
        self.assertIsNone(exit_tfc(self.settings, self.queue_exit))
        self.assertEqual(self.queue_exit.get(), EXIT)


class TestRxMImport(unittest.TestCase):

    def setUp(self):
        with open('testfile', 'wb+') as f:
            f.write(5000*b'a')

        self.queue_to_rxm          = Queue()
        self.o_tkfd                = filedialog.askopenfilename
        filedialog.askopenfilename = lambda title: 'testfile'
        self.settings              = Settings(local_testing_mode=True)

    def tearDown(self):
        with ignored(OSError):
            os.remove('testfile')

        filedialog.askopenfilename = self.o_tkfd

        while not self.queue_to_rxm.empty():
            self.queue_to_rxm.get()
        time.sleep(0.1)
        self.queue_to_rxm.close()

    def test_rxm_import(self):
        self.assertIsNone(rxm_import(self.settings, self.queue_to_rxm))
        time.sleep(0.1)
        self.assertEqual(self.queue_to_rxm.get(), IMPORTED_FILE_HEADER + 5000 * b'a')


class TestChangeECRatio(TFCTestCase):

    def setUp(self):
        self.settings = Settings()

    def test_non_digit_value_raises_fr(self):
        self.assertFR("Error: Received invalid EC ratio value from TxM.",
                      change_ec_ratio, self.settings, UNENCRYPTED_EC_RATIO + b'a')

    def test_invalid_digit_value_raises_fr(self):
        self.assertFR("Error: Received invalid EC ratio value from TxM.",
                      change_ec_ratio, self.settings, UNENCRYPTED_EC_RATIO + b'0')

    def test_change_value(self):
        self.assertIsNone(change_ec_ratio(self.settings, UNENCRYPTED_EC_RATIO + b'3'))
        self.assertEqual(self.settings.serial_error_correction, 3)


class TestChangeBaudrate(TFCTestCase):

    def setUp(self):
        self.settings = Settings()

    def test_non_digit_value_raises_fr(self):
        self.assertFR("Error: Received invalid baud rate value from TxM.",
                      change_baudrate, self.settings, UNENCRYPTED_BAUDRATE + b'a')

    def test_invalid_digit_value_raises_fr(self):
        self.assertFR("Error: Received invalid baud rate value from TxM.",
                      change_baudrate, self.settings, UNENCRYPTED_BAUDRATE + b'1300')

    def test_change_value(self):
        self.assertIsNone(change_baudrate(self.settings, UNENCRYPTED_BAUDRATE + b'9600'))
        self.assertEqual(self.settings.serial_baudrate, 9600)


class TestChangeGUIDialog(TFCTestCase):

    def setUp(self):
        self.settings = Settings()

    def test_invalid_value_raises_fr(self):
        self.assertFR("Error: Received invalid GUI dialog setting value from TxM.",
                      change_gui_dialog, self.settings, UNENCRYPTED_GUI_DIALOG + b'invalid')

    def test_enable_gui_dialog_setting(self):
        # Setup
        self.settings.disable_gui_dialog = False

        # Test
        self.assertIsNone(change_gui_dialog(self.settings, UNENCRYPTED_GUI_DIALOG + b'true'))
        self.assertTrue(self.settings.disable_gui_dialog)

    def test_disable_gui_dialog_setting(self):
        # Setup
        self.settings.disable_gui_dialog = True

        # Test
        self.assertIsNone(change_gui_dialog(self.settings, UNENCRYPTED_GUI_DIALOG + b'false'))
        self.assertFalse(self.settings.disable_gui_dialog)


class TestWipe(unittest.TestCase):

    def setUp(self):
        self.settings   = Settings(race_condition_delay=0.0)
        self.queue_exit = Queue()

    def test_wipe_command(self):
        self.assertIsNone(wipe(self.settings, self.queue_exit))
        self.assertEqual(self.queue_exit.get(), WIPE)


if __name__ == '__main__':
    unittest.main(exit=False)
