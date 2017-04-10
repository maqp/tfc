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

import builtins
import getpass
import os
import tkinter.filedialog
import time
import unittest

from multiprocessing import Queue

from src.common.statics import *
from src.tx.commands    import Command, process_command, print_about, clear_screens, rxm_show_cmd_win, exit_tfc, export_logs, export_file, import_file, rxm_display_f_win
from src.tx.commands    import print_help, print_logs, print_recipients, change_master_key, reset_screens, change_setting, rxm_display_unread

from tests.mock_classes import UserInput, Window, Settings, ContactList, GroupList, Gateway, MasterKey
from tests.utils        import cleanup, TFCTestCase


class TestCommandStub(unittest.TestCase):

    def test_class(self):
        command = Command('testcmd')
        self.assertEqual(command.plaintext, 'testcmd')
        self.assertEqual(command.type, 'command')


class TestProcessCommand(TFCTestCase):

    def test_function(self):
        # Setup
        user_input   = UserInput('about')
        window       = Window()
        settings     = Settings()
        queues       = {COMMAND_PACKET_QUEUE: Queue()}
        contact_list = ContactList()
        group_list   = GroupList()
        gateway      = Gateway()
        master_key   = MasterKey()

        # Test
        self.assertIsNone(process_command(user_input, window, settings, queues, contact_list, group_list, gateway, master_key))

        user_input = UserInput('abou')
        self.assertFR("Invalid command 'abou'.", process_command, user_input, window, settings, queues, contact_list, group_list, gateway, master_key)


class TestPrintAbout(unittest.TestCase):

    def test_function(self):
        self.assertIsNone(print_about())


class TestClearScreens(unittest.TestCase):

    def test_clear_screens(self):
        # Setup
        window   = Window(imc_name='alice@jabber.org')
        settings = Settings()
        c_queue  = Queue()
        gateway  = Gateway()

        # Test
        self.assertIsNone(clear_screens(window, settings, c_queue, gateway))
        self.assertEqual(len(gateway.packets), 1)
        self.assertTrue(gateway.packets[0].startswith(b'USCalice@jabber.org'))
        self.assertEqual(c_queue.qsize(), 1)

        # Teardown
        while not c_queue.empty():
            c_queue.get()
        time.sleep(0.2)

    def test_no_nh_cmd_during_trickle(self):
        # Setup
        window   = Window(imc_name='alice@jabber.org')
        settings = Settings(session_trickle=True)
        c_queue  = Queue()
        gateway  = Gateway()

        # Test
        self.assertIsNone(clear_screens(window, settings, c_queue, gateway))
        self.assertEqual(len(gateway.packets), 0)
        self.assertEqual(c_queue.qsize(), 1)

        # Teardown
        while not c_queue.empty():
            c_queue.get()
        time.sleep(0.2)


class TestRxMwin(unittest.TestCase):

    def test_command(self):
        # Setup
        window         = Window(uid='alice@jabber.org')
        settings       = Settings()
        c_queue        = Queue()
        o_input        = builtins.input
        builtins.input = lambda x: ''

        # Test
        self.assertIsNone(rxm_show_cmd_win(window, settings, c_queue))
        self.assertEqual(c_queue.qsize(), 2)

        # Teardown
        builtins.input = o_input
        while not c_queue.empty():
            c_queue.get()
        time.sleep(0.2)


class TestExitTFC(unittest.TestCase):

    def test_function(self):
        # Setup
        settings = Settings(local_testing_mode=True,
                            data_diode_sockets=True)
        c_queue  = Queue()
        gateway  = Gateway()

        # Test
        with self.assertRaises(SystemExit):
            exit_tfc(settings, c_queue, gateway)
        self.assertEqual(c_queue.qsize(), 1)
        self.assertTrue(gateway.packets[0].startswith(b'UEX'))

        # Teardown
        while not c_queue.empty():
            c_queue.get()
        time.sleep(0.2)


class TestExportLogs(TFCTestCase):

    def test_invalid_number_raises_fr(self):
        # Setup
        user_input = UserInput('export a')

        # Test
        self.assertFR("Specified invalid number of messages to export.", export_logs, user_input, None, None, None, None, None)

    def test_user_abort_raises_fr(self):
        # Setup
        user_input     = UserInput('export')
        window         = Window(uid='alice@jabber.org',
                                name='Alice')
        o_input        = builtins.input
        builtins.input = lambda x: 'No'

        # Test
        self.assertFR("Logfile export aborted.", export_logs, user_input, window, None, None, None, None)

        # Teardown
        builtins.input = o_input

    def test_succesful_export_command(self):
        # Setup
        user_input     = UserInput('export')
        window         = Window(uid='alice@jabber.org',
                                name='Alice')
        o_input        = builtins.input
        builtins.input = lambda x: 'Yes'
        contact_list   = ContactList(nicks=['Alice'])
        settings       = Settings()
        c_queue        = Queue()
        master_key     = MasterKey()

        # Test
        # Indicates that access_history was called.
        self.assertFR("Error: Could not find 'user_data/ut_logs'.", export_logs, user_input, window, contact_list, settings, c_queue, master_key)

        # Teardown
        builtins.input = o_input
        while not c_queue.empty():
            c_queue.get()
        time.sleep(0.2)
        cleanup()

    def test_succesful_export_command_with_number(self):
        # Setup
        user_input     = UserInput('export 4')
        window         = Window(uid='alice@jabber.org',
                                name='Alice')
        o_input        = builtins.input
        builtins.input = lambda x: 'Yes'
        contact_list   = ContactList(nicks=['Alice'])
        settings       = Settings()
        c_queue        = Queue()
        master_key     = MasterKey()

        # Test
        # Indicates that access_history was called.
        self.assertFR("Error: Could not find 'user_data/ut_logs'.", export_logs, user_input, window, contact_list, settings, c_queue, master_key)

        # Teardown
        builtins.input = o_input
        while not c_queue.empty():
            c_queue.get()
        time.sleep(0.2)
        cleanup()


class TestExportFile(TFCTestCase):

    def test_raises_fr_during_trickle(self):
        # Setup
        settings = Settings(session_trickle=True)

        # Test
        self.assertFR("Command disabled during trickle connection.", export_file, settings, None)

    @unittest.skipIf("TRAVIS" in os.environ and os.environ["TRAVIS"] == "true", "Skipping this test on Travis CI.")
    def test_unknown_file_raises_fr(self):
        # Setup
        settings                           = Settings()
        o_tk_aof                           = tkinter.filedialog.askopenfilename
        tkinter.filedialog.askopenfilename = lambda title: 'unknown_file'

        # Test
        self.assertFR("Error: File not found.", export_file, settings, None)

        # Teardown
        tkinter.filedialog.askopenfilename = o_tk_aof

    def test_empty_file_raises_fr(self):
        # Setup
        with open('testfile', 'wb+') as f:
            f.write(b'')
        settings       = Settings(disable_gui_dialog=True)
        o_input        = builtins.input
        builtins.input = lambda x: './testfile'

        # Test
        self.assertFR("Error: Target file is empty. No file was sent.", export_file, settings, None)

        # Teardown
        builtins.input = o_input
        os.remove('testfile')

    def test_file_export(self):
        # Setup
        with open('testfile', 'wb+') as f:
            f.write(os.urandom(300))

        settings       = Settings(disable_gui_dialog=True)
        gateway        = Gateway()
        o_input        = builtins.input
        builtins.input = lambda x: './testfile'

        # Test
        self.assertIsNone(export_file(settings, gateway))
        self.assertEqual(len(gateway.packets), 1)

        # Teardown
        builtins.input = o_input
        os.remove('testfile')


class TestImportFile(TFCTestCase):

    def test_during_trickle_raises_fr(self):
        # Setup
        settings = Settings(session_trickle=True)

        # Test
        self.assertFR("Command disabled during trickle connection.", import_file, settings, None)

    def test_import_file(self):
        # Setup
        settings = Settings()
        gateway  = Gateway()

        # Test
        self.assertIsNone(import_file(settings, gateway))
        self.assertEqual(len(gateway.packets), 1)


class TestRxMFileWin(unittest.TestCase):

    def test_command(self):
        # Setup
        window         = Window(name='alice@jabber.org',
                                uid='alice@jabber.org')
        settings       = Settings()
        c_queue        = Queue()
        o_input        = builtins.input
        builtins.input = lambda x: ''

        # Test
        self.assertIsNone(rxm_display_f_win(window, settings, c_queue))
        self.assertEqual(c_queue.qsize(), 2)

        # Teardown
        builtins.input = o_input
        while not c_queue.empty():
            c_queue.get()
        time.sleep(0.2)


class TestPrintHelp(unittest.TestCase):

    def test_print_normal(self):
        # Setup
        settings = Settings()

        # Test
        self.assertIsNone(print_help(settings))

    def test_print_trickle(self):
        # Setup
        settings = Settings(session_trickle=True)

        # Test
        self.assertIsNone(print_help(settings))


class TestPrintLogs(TFCTestCase):

    def test_invalid_export(self):
        # Test
        user_input   = UserInput("history a")
        window       = Window()
        contact_list = ContactList()
        settings     = Settings()
        c_queue      = Queue()
        master_key   = MasterKey()

        # Test
        self.assertFR("Specified invalid number of messages to print.",
                      print_logs, user_input, window, contact_list, settings, c_queue, master_key)

    def test_log_printing(self):
        # Test
        user_input   = UserInput("history 4")
        window       = Window(uid='alice@jabber.org')
        contact_list = ContactList()
        settings     = Settings()
        c_queue      = Queue()
        master_key   = MasterKey()

        # Test
        self.assertFR("Error: Could not find 'user_data/ut_logs'.",
                      print_logs, user_input, window, contact_list, settings, c_queue, master_key)
        self.assertEqual(c_queue.qsize(), 1)

        # Teardown
        while not c_queue.empty():
            c_queue.get()
        time.sleep(0.2)
        cleanup()


    def test_log_printing_all(self):
        # Test
        user_input   = UserInput("history")
        window       = Window(uid='alice@jabber.org')
        contact_list = ContactList()
        settings     = Settings()
        c_queue      = Queue()
        master_key   = MasterKey()

        # Test
        self.assertFR("Error: Could not find 'user_data/ut_logs'.",
                      print_logs, user_input, window, contact_list, settings, c_queue, master_key)
        self.assertEqual(c_queue.qsize(), 1)

        # Teardown
        while not c_queue.empty():
            c_queue.get()
        time.sleep(0.2)
        cleanup()


class TestPrintRecipients(unittest.TestCase):

    def test_printing(self):
        # Setup
        contact_list = ContactList(nicks=['Alice', 'Bob'])
        group_list   = GroupList(groups=['testgroup', 'testgroup2'])

        # Test
        self.assertIsNone(print_recipients(contact_list, group_list))


class TestChangeMasterKey(TFCTestCase):

    def test_trickle_raises_fr(self):
        # Setup
        settings = Settings(session_trickle=True)

        # Test
        self.assertFR("Command disabled during trickle connection.",
                      change_master_key, None, None, None, settings, None, None)

    def test_missing_target_sys_raises_fr(self):
        # Setup
        user_input = UserInput("passwd ")
        settings   = Settings()

        # Test
        self.assertFR("No target system specified.",
                      change_master_key, user_input, None, None, settings, None, None)

    def test_invalid_target_sys_raises_fr(self):
        # Setup
        user_input = UserInput("passwd t")
        settings   = Settings()

        # Test
        self.assertFR("Invalid target system.",
                      change_master_key, user_input, None, None, settings, None, None)

    def test_rxm_command(self):
        # Setup
        user_input   = UserInput("passwd rx")
        contact_list = ContactList()
        group_list   = GroupList()
        settings     = Settings()
        queues       = {COMMAND_PACKET_QUEUE: Queue()}
        master_key   = MasterKey()

        # Test
        self.assertIsNone(change_master_key(user_input, contact_list, group_list, settings, queues, master_key))

        # Teardown
        while not queues[COMMAND_PACKET_QUEUE].empty():
            queues[COMMAND_PACKET_QUEUE].get()

        time.sleep(0.2)

    def test_txm_command(self):
        # Setup
        user_input      = UserInput("passwd tx")
        contact_list    = ContactList()
        group_list      = GroupList()
        settings        = Settings()
        queues          = {COMMAND_PACKET_QUEUE: Queue(),
                           KEY_MANAGEMENT_QUEUE: Queue()}
        master_key      = MasterKey()
        o_getpass       = getpass.getpass
        getpass.getpass = lambda x: 'a'

        # Test
        self.assertIsNone(change_master_key(user_input, contact_list, group_list, settings, queues, master_key))

        # Teardown
        while not queues[COMMAND_PACKET_QUEUE].empty():
            queues[COMMAND_PACKET_QUEUE].get()

        while not queues[KEY_MANAGEMENT_QUEUE].empty():
            queues[KEY_MANAGEMENT_QUEUE].get()

        getpass.getpass = o_getpass
        time.sleep(0.2)
        cleanup()


class TestResetScreens(unittest.TestCase):

    def test_reset_screens(self):
        # Setup
        window   = Window(imc_name='alice@jabber.org',
                          uid='alice@jabber.org')
        settings = Settings()
        c_queue  = Queue()
        gateway  = Gateway()

        # Test
        self.assertIsNone(reset_screens(window, settings, c_queue, gateway))
        self.assertEqual(len(gateway.packets), 1)
        self.assertTrue(gateway.packets[0].startswith(b'USRalice@jabber.org'))
        self.assertEqual(c_queue.qsize(), 1)

        # Teardown
        while not c_queue.empty():
            c_queue.get()
        time.sleep(0.2)

    def test_no_nh_cmd_during_trickle(self):
        # Setup
        window   = Window(imc_name='alice@jabber.org',
                          uid='alice@jabber.org')
        settings = Settings(session_trickle=True)
        c_queue  = Queue()
        gateway  = Gateway()

        # Test
        self.assertIsNone(reset_screens(window, settings, c_queue, gateway))
        self.assertEqual(len(gateway.packets), 0)
        self.assertEqual(c_queue.qsize(), 1)

        # Teardown
        while not c_queue.empty():
            c_queue.get()
        time.sleep(0.2)


class TestChangeSetting(TFCTestCase):

    def test_missing_setting_raises_fr(self):
        # Setup
        user_input = UserInput('set')

        # Test
        self.assertFR('No setting specified.', change_setting, user_input, None, None, None, None, None)

    def test_missing_value_raises_fr(self):
        # Setup
        user_input = UserInput('set e_correction_ratio')
        settings   = Settings(key_list=['e_correction_ratio'])

        # Test
        self.assertFR('No value for setting specified.', change_setting, user_input, None, None, settings, None, None)

    def test_invalid_setting_raises_fr(self):
        # Setup
        user_input = UserInput('set e_correction_ratia true')
        settings   = Settings(key_list=['e_correction_ratio'])

        # Test
        self.assertFR('Invalid setting e_correction_ratia.', change_setting, user_input, None, None, settings, None, None)

    def test_serial_management_during_trickle_raises_fr(self):
        # Setup
        user_input = UserInput('set e_correction_ratio 5')
        settings   = Settings(session_trickle=True,
                              key_list=['e_correction_ratio'])

        # Test
        self.assertFR("Change of setting disabled during trickle connection.",
                      change_setting, user_input, None, None, settings, None, None)

    def test_nh_management(self):
        # Setup
        user_input   = UserInput('set e_correction_ratio 5')
        settings     = Settings(key_list=['e_correction_ratio', 'serial_iface_speed'])
        contact_list = ContactList()
        group_list   = GroupList()
        c_queue      = Queue()
        gateway      = Gateway()

        # Test
        self.assertIsNone(change_setting(user_input, contact_list, group_list, settings, c_queue, gateway))
        user_input = UserInput('set serial_iface_speed True')
        self.assertIsNone(change_setting(user_input, contact_list, group_list, settings, c_queue, gateway))

        # Teardown
        while not c_queue.empty():
            c_queue.get()
        time.sleep(0.2)


class TestRxMDisplayUnread(unittest.TestCase):

    def test_command(self):
        # Setup
        settings = Settings()
        c_queue  = Queue()

        # Test
        self.assertIsNone(rxm_display_unread(settings, c_queue))
        self.assertEqual(c_queue.qsize(), 1)

        # Teardown
        while not c_queue.empty():
            c_queue.get()
        time.sleep(0.2)


if __name__ == '__main__':
    unittest.main(exit=False)
