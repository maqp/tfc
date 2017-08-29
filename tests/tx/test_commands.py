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
import shutil
import time
import tkinter.filedialog
import unittest

from multiprocessing import Queue

from src.common.db_logs import write_log_entry
from src.common.statics import *

from src.tx.commands import change_master_key, change_setting, clear_screens, exit_tfc, export_file
from src.tx.commands import import_file, log_command, print_about, print_help, print_recipients
from src.tx.commands import process_command, remove_log, rxm_display_unread, rxm_show_sys_win, whisper, wipe

from tests.mock_classes import ContactList, create_contact, GroupList, MasterKey, UserInput, Settings, TxWindow
from tests.utils        import cleanup, ignored, TFCTestCase


class TestProcessCommand(TFCTestCase):

    def setUp(self):
        self.queues       = {COMMAND_PACKET_QUEUE: Queue(),
                             MESSAGE_PACKET_QUEUE: Queue(),
                             NH_PACKET_QUEUE:      Queue()}
        self.window       = TxWindow()
        self.settings     = Settings()
        self.contact_list = ContactList()
        self.group_list   = GroupList()
        self.master_key   = MasterKey()

    def tearDown(self):
        for key in self.queues:
            while not self.queues[key].empty():
                self.queues[key].get()
            time.sleep(0.1)
            self.queues[key].close()

    def test_process_command(self):
        self.assertIsNone(process_command(UserInput('about'), self.window, self.settings, self.queues,
                                          self.contact_list, self.group_list, self.master_key))

    def test_invalid_command(self):
        self.assertFR("Error: Invalid command 'abou'", process_command, UserInput('abou'), self.window, self.settings,
                      self.queues, self.contact_list, self.group_list, self.master_key)

    def test_empty_command(self):
        self.assertFR("Error: Invalid command.", process_command, UserInput(' '), self.window, self.settings,
                      self.queues, self.contact_list, self.group_list, self.master_key)


class TestPrintAbout(TFCTestCase):

    def test_print_about(self):
        print_about()
        self.assertPrints(CLEAR_ENTIRE_SCREEN + CURSOR_LEFT_UP_CORNER + """\

 Tinfoil Chat {}                           

 Website:     https://github.com/maqp/tfc/            
 Wikipage:    https://github.com/maqp/tfc/wiki        
 White paper: https://cs.helsinki.fi/u/oottela/tfc.pdf

""".format(VERSION), print_about)


class TestClearScreens(unittest.TestCase):

    def setUp(self):
        self.queues = {COMMAND_PACKET_QUEUE: Queue(),
                       NH_PACKET_QUEUE:      Queue()}
        self.settings = Settings()
        self.window   = TxWindow(imc_name='alice@jabber.org',
                                 uid='alice@jabber.org')

    def tearDown(self):
        for key in self.queues:
            while not self.queues[key].empty():
                self.queues[key].get()
            time.sleep(0.1)
            self.queues[key].close()

    def test_clear_screens(self):
        self.assertIsNone(clear_screens(UserInput(plaintext='clear'), self.window,
                                        self.settings, self.queues))
        time.sleep(0.1)
        self.assertEqual(self.queues[COMMAND_PACKET_QUEUE].qsize(), 1)
        self.assertEqual(self.queues[NH_PACKET_QUEUE].qsize(), 1)

    def test_no_nh_clear_cmd_when_traffic_masking_is_enabled(self):
        # Setup
        self.settings.session_traffic_masking = True

        # Test
        self.assertIsNone(clear_screens(UserInput(plaintext='clear'), self.window,
                                        self.settings, self.queues))
        time.sleep(0.1)
        self.assertEqual(self.queues[COMMAND_PACKET_QUEUE].qsize(), 1)
        self.assertEqual(self.queues[NH_PACKET_QUEUE].qsize(), 0)

    def test_reset_screens(self):
        self.assertIsNone(clear_screens(UserInput(plaintext='reset'), self.window,
                                        self.settings, self.queues))
        time.sleep(0.1)
        self.assertEqual(self.queues[COMMAND_PACKET_QUEUE].qsize(), 1)
        self.assertEqual(self.queues[NH_PACKET_QUEUE].qsize(), 1)

    def test_no_nh_reset_cmd_when_traffic_masking_is_enabled(self):
        # Setup
        self.settings.session_traffic_masking = True

        # Test
        self.assertIsNone(clear_screens(UserInput(plaintext='reset'), self.window,
                                        self.settings, self.queues))
        time.sleep(0.1)
        self.assertEqual(self.queues[COMMAND_PACKET_QUEUE].qsize(), 1)
        self.assertEqual(self.queues[NH_PACKET_QUEUE].qsize(), 0)


class TestRxMShowSysWin(unittest.TestCase):

    def setUp(self):
        self.o_input   = builtins.input
        builtins.input = lambda _: ''
        self.c_queue   = Queue()
        self.settings  = Settings()
        self.window    = TxWindow(name='alice@jabber.org',
                                  uid='alice@jabber.org')

    def tearDown(self):
        builtins.input = self.o_input

        while not self.c_queue.empty():
            self.c_queue.get()
        time.sleep(0.1)
        self.c_queue.close()

    def test_cmd_window(self):
        self.assertIsNone(rxm_show_sys_win(UserInput(plaintext='cmd'), self.window, self.settings, self.c_queue))
        time.sleep(0.1)
        self.assertEqual(self.c_queue.qsize(), 2)

    def test_file_window(self):
        self.assertIsNone(rxm_show_sys_win(UserInput(plaintext='fw'), self.window, self.settings, self.c_queue))
        time.sleep(0.1)
        self.assertEqual(self.c_queue.qsize(), 2)


class TestExitTFC(unittest.TestCase):

    def setUp(self):
        self.queues   = {COMMAND_PACKET_QUEUE: Queue(),
                         NH_PACKET_QUEUE:      Queue(),
                         EXIT_QUEUE:           Queue()}
        self.settings = Settings(session_traffic_masking=False,
                                 local_testing_mode=True,
                                 data_diode_sockets=True,
                                 race_condition_delay=0.0)

    def tearDown(self):
        for key in self.queues:
            while not self.queues[key].empty():
                self.queues[key].get()
            time.sleep(0.1)
            self.queues[key].close()

    def test_exit_tfc_local_test(self):
        # Setup
        for _ in range(2):
            self.queues[COMMAND_PACKET_QUEUE].put("dummy command")
        time.sleep(0.1)

        # Test
        self.assertIsNone(exit_tfc(self.settings, self.queues))
        time.sleep(0.5)
        self.assertEqual(self.queues[COMMAND_PACKET_QUEUE].qsize(), 1)
        self.assertEqual(self.queues[NH_PACKET_QUEUE].qsize(), 1)

    def test_exit_tfc(self):
        # Setup
        self.settings.local_testing_mode = False
        for _ in range(2):
            self.queues[COMMAND_PACKET_QUEUE].put("dummy command")
        time.sleep(0.1)

        # Test
        self.assertIsNone(exit_tfc(self.settings, self.queues))
        time.sleep(0.5)
        self.assertEqual(self.queues[COMMAND_PACKET_QUEUE].qsize(), 1)
        self.assertEqual(self.queues[NH_PACKET_QUEUE].qsize(), 1)


class TestAccessLogs(TFCTestCase):

    def setUp(self):
        self.o_input      = builtins.input
        self.c_queue      = Queue()
        self.window       = TxWindow(uid='alice@jabber.org',
                                     name='Alice')
        self.contact_list = ContactList()
        self.group_list   = GroupList()
        self.settings     = Settings()
        self.master_key   = MasterKey()

    def tearDown(self):
        cleanup()

        while not self.c_queue.empty():
            self.c_queue.get()
        time.sleep(0.1)
        self.c_queue.close()

    def test_invalid_export(self):
        self.assertFR("Error: Invalid number of messages.",
                      log_command, UserInput("history a"), self.window, self.contact_list,
                      self.group_list, self.settings, self.c_queue, self.master_key)

    def test_log_printing(self):
        self.assertFR(f"Error: Could not find log database.",
                      log_command, UserInput("history 4"), self.window, self.contact_list,
                      self.group_list, self.settings, self.c_queue, self.master_key)
        time.sleep(0.1)

        self.assertEqual(self.c_queue.qsize(), 1)

    def test_log_printing_all(self):
        self.assertFR(f"Error: Could not find log database.",
                      log_command, UserInput("history"), self.window, self.contact_list,
                      self.group_list, self.settings, self.c_queue, self.master_key)
        time.sleep(0.1)

        self.assertEqual(self.c_queue.qsize(), 1)

    def test_invalid_number_raises_fr(self):
        self.assertFR("Error: Invalid number of messages.",
                      log_command, UserInput('history a'), self.window, self.contact_list,
                      self.group_list, self.settings, self.c_queue, self.master_key)

    def test_too_high_number_raises_fr(self):
        self.assertFR("Error: Invalid number of messages.",
                      log_command, UserInput('history 94857634985763454345'), self.window, self.contact_list,
                      self.group_list, self.settings, self.c_queue, self.master_key)

    def test_user_abort_raises_fr(self):
        # Setup
        builtins.input = lambda _: 'No'

        # Test
        self.assertFR("Logfile export aborted.",
                      log_command, UserInput('export'), self.window, self.contact_list,
                      self.group_list, self.settings, self.c_queue, self.master_key)

    def test_successful_export_command(self):
        # Setup
        builtins.input = lambda _: 'Yes'

        # Test
        # Indicates that access_history was called.
        self.assertFR(f"Error: Could not find log database.",
                      log_command, UserInput('export'), self.window, ContactList(nicks=['Alice']),
                      self.group_list, self.settings, self.c_queue, self.master_key)

    def test_successful_export_command_with_number(self):
        # Setup
        builtins.input = lambda _: 'Yes'

        # Test
        # Indicates that access_history was called.
        self.assertFR(f"Error: Could not find log database.",
                      log_command, UserInput('export 4'), self.window, ContactList(nicks=['Alice']),
                      self.group_list, self.settings, self.c_queue, self.master_key)


class TestExportFile(TFCTestCase):

    def setUp(self):
        self.o_tk_aof = tkinter.filedialog.askopenfilename
        self.o_input  = builtins.input
        self.settings = Settings()
        self.nh_queue = Queue()

    def tearDown(self):
        tkinter.filedialog.askopenfilename = self.o_tk_aof
        builtins.input                     = self.o_input

        with ignored(OSError):
            os.remove('testfile')

    def test_raises_fr_during_traffic_masking(self):
        self.assertFR("Error: Command is disabled during traffic masking.",
                      export_file, Settings(session_traffic_masking=True), None)

    def test_unknown_file_raises_fr(self):
        # Setup
        tkinter.filedialog.askopenfilename = lambda title: 'unknown_file'

        # Test
        self.assertFR("Error: File not found.", export_file, self.settings, None)

    def test_empty_file_raises_fr(self):
        # Setup
        builtins.input = lambda _: './testfile'

        with open('testfile', 'wb+') as f:
            f.write(b'')

        # Test
        self.assertFR("Error: Target file is empty.",
                      export_file, Settings(disable_gui_dialog=True), None)

    def test_file_export(self):
        # Setup
        builtins.input = lambda _: './testfile'

        with open('testfile', 'wb+') as f:
            f.write(os.urandom(300))

        # Test
        self.assertIsNone(export_file(Settings(disable_gui_dialog=True), self.nh_queue))
        self.assertEqual(self.nh_queue.qsize(), 1)


class TestImportFile(TFCTestCase):

    def setUp(self):
        self.settings = Settings()
        self.nh_queue = Queue()

    def test_raises_fr_when_traffic_masking_is_enabled(self):
        self.assertFR("Error: Command is disabled during traffic masking.",
                      import_file, Settings(session_traffic_masking=True), None)

    def test_import_file(self):
        self.assertIsNone(import_file(self.settings, self.nh_queue))
        self.assertEqual(self.nh_queue.qsize(), 1)


class TestPrintHelp(TFCTestCase):

    def setUp(self):
        self.settings                         = Settings()
        self.settings.session_traffic_masking = False
        self.o_shutil_ttyw                    = shutil.get_terminal_size

    def tearDown(self):
        shutil.get_terminal_size = self.o_shutil_ttyw

    def test_print_normal(self):
        # Setup
        shutil.get_terminal_size = lambda: [60, 60]

        # Test
        self.assertPrints(CLEAR_ENTIRE_SCREEN + CURSOR_LEFT_UP_CORNER + """\
List of commands:

/about                    Show links to project resources
/add                      Add new contact
/cf                       Cancel file transmission to active
                          contact/group

/cm                       Cancel message transmission to
                          active contact/group

/clear, '  '              Clear screens from TxM, RxM and IM
                          client

/cmd, '//'                Display command window on RxM
/exit                     Exit TFC on TxM, NH and RxM
/export (n)               Export (n) messages from
                          recipient's logfile

/file                     Send file to active contact/group
/fingerprints             Print public key fingerprints of
                          user and contact

/fe                       Encrypt and export file to NH
/fi                       Import file from NH to RxM
/fw                       Display file reception window on
                          RxM

/help                     Display this list of commands
/history (n)              Print (n) messages from
                          recipient's logfile

/localkey                 Generate new local key pair
/logging {on,off}(' all') Change message log setting (for
                          all contacts)

/msg {A,N}                Change active recipient to account
                          A or nick N

/names                    List contacts and groups
/nick N                   Change nickname of active
                          recipient to N

/notify {on,off} (' all') Change notification settings (for
                          all contacts)

/passwd {tx,rx}           Change master password on TxM/RxM
/psk                      Open PSK import dialog on RxM
/reset                    Reset ephemeral session log on
                          TxM/RxM/IM client

/rm {A,N}                 Remove account A or nick N from
                          TxM and RxM

/rmlogs {A,N}             Remove log entries for A/N on TxM
                          and RxM

/set S V                  Change setting S to value V on
                          TxM/RxM(/NH)

/settings                 List setting names, values and
                          descriptions

/store {on,off} (' all')  Change file reception (for all
                          contacts)

/unread, ' '              List windows with unread messages
                          on RxM

/whisper M                Send message M, asking it not to
                          be logged

/wipe                     Wipe all TFC/IM user data and
                          power off systems

Shift + PgUp/PgDn         Scroll terminal up/down
────────────────────────────────────────────────────────────
Group management:

/group create G A₁ .. Aₙ  Create group G and add accounts A₁
                          .. Aₙ

/group add G A₁ .. Aₙ     Add accounts A₁ .. Aₙ to group G
/group rm G A₁ .. Aₙ      Remove accounts A₁ .. Aₙ from
                          group G

/group rm G               Remove group G
────────────────────────────────────────────────────────────

""", print_help, self.settings)

    def test_print_during_traffic_masking(self):
        # Setup
        self.settings.session_traffic_masking = True
        shutil.get_terminal_size = lambda: [80, 80]

        # Test
        self.assertPrints(CLEAR_ENTIRE_SCREEN + CURSOR_LEFT_UP_CORNER + """\
List of commands:

/about                    Show links to project resources
/cf                       Cancel file transmission to active contact/group
/cm                       Cancel message transmission to active contact/group
/clear, '  '              Clear screens from TxM, RxM and IM client
/cmd, '//'                Display command window on RxM
/exit                     Exit TFC on TxM, NH and RxM
/export (n)               Export (n) messages from recipient's logfile
/file                     Send file to active contact/group
/fingerprints             Print public key fingerprints of user and contact
/fw                       Display file reception window on RxM
/help                     Display this list of commands
/history (n)              Print (n) messages from recipient's logfile
/logging {on,off}(' all') Change message log setting (for all contacts)
/names                    List contacts and groups
/nick N                   Change nickname of active recipient to N
/notify {on,off} (' all') Change notification settings (for all contacts)
/reset                    Reset ephemeral session log on TxM/RxM/IM client
/rmlogs {A,N}             Remove log entries for A/N on TxM and RxM
/set S V                  Change setting S to value V on TxM/RxM(/NH)
/settings                 List setting names, values and descriptions
/store {on,off} (' all')  Change file reception (for all contacts)
/unread, ' '              List windows with unread messages on RxM
/whisper M                Send message M, asking it not to be logged
/wipe                     Wipe all TFC/IM user data and power off systems
Shift + PgUp/PgDn         Scroll terminal up/down
────────────────────────────────────────────────────────────────────────────────

""", print_help, self.settings)


class TestPrintRecipients(TFCTestCase):

    def setUp(self):
        self.contact_list = ContactList(nicks=['Alice', 'Bob'])
        self.group_list   = GroupList(groups=['testgroup', 'testgroup2'])

    def test_printing(self):
        self.assertIsNone(print_recipients(self.contact_list, self.group_list))


class TestChangeMasterKey(TFCTestCase):

    def setUp(self):
        self.o_getpass    = getpass.getpass
        self.user_input   = UserInput()
        self.contact_list = ContactList()
        self.group_list   = GroupList()
        self.settings     = Settings()
        self.queues       = {COMMAND_PACKET_QUEUE: Queue(),
                            KEY_MANAGEMENT_QUEUE: Queue()}
        self.master_key   = MasterKey()

    def tearDown(self):
        getpass.getpass = self.o_getpass
        cleanup()

        for key in self.queues:
            while not self.queues[key].empty():
                self.queues[key].get()
            time.sleep(0.1)
            self.queues[key].close()

    def test_raises_fr_during_traffic_masking(self):
        self.assertFR("Error: Command is disabled during traffic masking.",
                      change_master_key, self.user_input, self.contact_list, self.group_list,
                      Settings(session_traffic_masking=True), self.queues, self.master_key)

    def test_missing_target_sys_raises_fr(self):
        self.assertFR("Error: No target system specified.",
                      change_master_key, UserInput("passwd "), self.contact_list,
                      self.group_list, self.settings, self.queues, self.master_key)

    def test_invalid_target_sys_raises_fr(self):
        self.assertFR("Error: Invalid target system.",
                      change_master_key, UserInput("passwd t"), self.contact_list,
                      self.group_list, self.settings, self.queues, self.master_key)

    def test_txm_command(self):
        # Setup
        settings        = Settings(software_operation='ut')
        getpass.getpass = lambda _: 'a'
        write_log_entry(M_S_HEADER + PADDING_LEN * b'a', 'alice@jabber.org', settings, self.master_key)

        # Test
        self.assertIsNone(change_master_key(UserInput("passwd tx"), self.contact_list,
                                            self.group_list, settings, self.queues, self.master_key))
        time.sleep(0.1)
        self.assertEqual(self.queues[COMMAND_PACKET_QUEUE].qsize(), 0)
        self.assertEqual(self.queues[KEY_MANAGEMENT_QUEUE].qsize(), 1)

    def test_rxm_command(self):
        self.assertIsNone(change_master_key(UserInput("passwd rx"), self.contact_list,
                                            self.group_list, self.settings, self.queues, self.master_key))
        time.sleep(0.1)
        self.assertEqual(self.queues[COMMAND_PACKET_QUEUE].qsize(), 1)


class TestRemoveLog(TFCTestCase):

    def setUp(self):
        self.c_queue      = Queue()
        self.contact_list = ContactList(nicks=['Alice'])
        self.settings     = Settings()
        self.master_key   = MasterKey()
        self.o_input      = builtins.input
        builtins.input    = lambda _: 'Yes'

    def tearDown(self):
        builtins.input = self.o_input

        while not self.c_queue.empty():
            self.c_queue.get()
        time.sleep(0.1)
        self.c_queue.close()

        cleanup()

    def test_missing_contact_raises_fr(self):
        self.assertFR("Error: No contact/group specified.",
                      remove_log, UserInput(''), self.contact_list,
                      self.settings, self.c_queue, self.master_key)

    def test_no_aborts_removal(self):
        # Setup
        write_log_entry(M_S_HEADER + PADDING_LEN * b'a', 'alice@jabber.org', self.settings, self.master_key)
        self.assertEqual(os.path.getsize(f'{DIR_USER_DATA}ut_logs'), LOG_ENTRY_LENGTH)

        builtins.input = lambda _: 'No'
        self.assertFR("Logfile removal aborted.",
                      remove_log, UserInput('/rmlogs Alice'), self.contact_list,
                      self.settings, self.c_queue, self.master_key)

    def test_log_remove(self):
        # Setup
        write_log_entry(M_S_HEADER + PADDING_LEN * b'a', 'alice@jabber.org', self.settings, self.master_key)
        self.assertEqual(os.path.getsize(f'{DIR_USER_DATA}ut_logs'), LOG_ENTRY_LENGTH)

        # Test
        self.assertIsNone(remove_log(UserInput('/rmlogs Alice'), self.contact_list,
                                     self.settings, self.c_queue, self.master_key))
        time.sleep(0.1)
        self.assertEqual(os.path.getsize(f'{DIR_USER_DATA}ut_logs'), 0)
        self.assertEqual(self.c_queue.qsize(), 1)


class TestChangeSetting(TFCTestCase):

    def setUp(self):
        self.contact_list = ContactList()
        self.group_list   = GroupList()
        self.settings     = Settings()
        self.queues       = {COMMAND_PACKET_QUEUE: Queue(),
                             NH_PACKET_QUEUE:      Queue()}
        self.c_queue      = Queue()

    def tearDown(self):
        while not self.c_queue.empty():
            self.c_queue.get()
        time.sleep(0.1)
        self.c_queue.close()

    def test_missing_setting_raises_fr(self):
        self.assertFR("Error: No setting specified.",
                      change_setting, UserInput('set'), self.contact_list, self.group_list,
                      self.settings, self.queues)

    def test_invalid_setting_raises_fr(self):
        # Setup
        user_input = UserInput("set e_correction_ratia true")
        settings   = Settings(key_list=['serial_error_correction'])

        # Test
        self.assertFR("Error: Invalid setting 'e_correction_ratia'",
                      change_setting, user_input, self.contact_list, self.group_list,
                      settings, self.queues)

    def test_missing_value_raises_fr(self):
        # Setup
        user_input = UserInput("set serial_error_correction")
        settings   = Settings(key_list=['serial_error_correction'])

        # Test
        self.assertFR("Error: No value for setting specified.",
                      change_setting, user_input, self.contact_list, self.group_list,
                      settings, self.queues)

    def test_nh_commands_raise_fr_when_traffic_masking_is_enabled(self):
        # Setup
        key_list = ['serial_error_correction', 'serial_baudrate', 'disable_gui_dialog']
        settings = Settings(session_traffic_masking=True,
                            key_list=key_list)

        for key in key_list:
            user_input = UserInput(f"set {key} 5")
            self.assertFR("Error: Can't change this setting during traffic masking.",
                          change_setting, user_input, self.contact_list, self.group_list,
                          settings, self.queues)

    def test_nh_management(self):
        # Setup
        settings = Settings(key_list=['serial_error_correction', 'serial_baudrate', 'disable_gui_dialog'])

        # Test
        user_input = UserInput("set serial_error_correction 5")
        self.assertIsNone(change_setting(user_input, self.contact_list, self.group_list,
                                         settings, self.queues))
        self.assertEqual(self.queues[NH_PACKET_QUEUE].qsize(), 1)

        user_input = UserInput("set serial_baudrate 9600")
        self.assertIsNone(change_setting(user_input, self.contact_list, self.group_list,
                                         settings, self.queues))
        self.assertEqual(self.queues[NH_PACKET_QUEUE].qsize(), 2)

        user_input = UserInput("set disable_gui_dialog True")
        self.assertIsNone(change_setting(user_input, self.contact_list, self.group_list,
                                         settings, self.queues))
        self.assertEqual(self.queues[NH_PACKET_QUEUE].qsize(), 3)


class TestRxMDisplayUnread(unittest.TestCase):

    def setUp(self):
        self.settings = Settings()
        self.c_queue  = Queue()

    def tearDown(self):
        while not self.c_queue.empty():
            self.c_queue.get()
        time.sleep(0.1)
        self.c_queue.close()

    def test_command(self):
        self.assertIsNone(rxm_display_unread(self.settings, self.c_queue))
        time.sleep(0.1)
        self.assertEqual(self.c_queue.qsize(), 1)


class TestWhisper(unittest.TestCase):

    def setUp(self):
        self.user_input = UserInput("whisper Decryption key for file 'test_file.txt' is "
                                    "92Kocbqxo7Vcsqq1ThVVySighDUAuUUmUwcjQdyAnzZZaQjKoKm")
        self.window     = TxWindow(uid='alice@jabber.org', name='Alice',
                                   window_contacts=[create_contact()],
                                   log_messages=True)
        self.settings   = Settings()
        self.m_queue    = Queue()

    def test_whisper(self):
        self.assertIsNone(whisper(self.user_input, self.window, self.settings, self.m_queue))

        message, settings, rx_account, tx_account, logging, log_as_ph, win_uid = self.m_queue.get()

        self.assertEqual(rx_account, 'alice@jabber.org')
        self.assertEqual(tx_account, 'user@jabber.org')
        self.assertTrue(logging)
        self.assertTrue(log_as_ph)


class TestWipe(TFCTestCase):

    def setUp(self):
        self.queues   = {COMMAND_PACKET_QUEUE: Queue(),
                         NH_PACKET_QUEUE:      Queue()}
        self.settings = Settings(session_traffic_masking=False,
                                 race_condition_delay=0.0)
        self.o_input  = builtins.input

    def tearDown(self):
        builtins.input = self.o_input

    def test_no_raises_fr(self):
        # Setup
        builtins.input = lambda _: 'No'

        # Test
        self.assertFR("Wipe command aborted.",
                      wipe, self.settings, self.queues)

    def test_wipe_local_Testing(self):
        # Setup
        builtins.input = lambda _: 'Yes'
        self.settings.local_testing_mode = True
        self.settings.data_diode_sockets = True
        for _ in range(2):
            self.queues[COMMAND_PACKET_QUEUE].put("dummy command")
            self.queues[NH_PACKET_QUEUE].put("dummy packet")
        time.sleep(0.1)

        # Test
        self.assertIsNone(wipe(self.settings, self.queues))
        wipe_packet = UNENCRYPTED_PACKET_HEADER + UNENCRYPTED_WIPE_COMMAND
        self.assertTrue(self.queues[NH_PACKET_QUEUE].get()[0].startswith(wipe_packet))

    def test_wipe(self):
        # Setup
        builtins.input = lambda _: 'Yes'

        for _ in range(2):
            self.queues[COMMAND_PACKET_QUEUE].put("dummy command")
            self.queues[NH_PACKET_QUEUE].put("dummy packet")
        time.sleep(0.1)

        # Test
        self.assertIsNone(wipe(self.settings, self.queues))
        wipe_packet = UNENCRYPTED_PACKET_HEADER + UNENCRYPTED_WIPE_COMMAND
        self.assertTrue(self.queues[NH_PACKET_QUEUE].get()[0].startswith(wipe_packet))


if __name__ == '__main__':
    unittest.main(exit=False)
