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

import os
import unittest

from unittest      import mock
from unittest.mock import MagicMock

from src.common.db_logs  import write_log_entry
from src.common.encoding import bool_to_bytes
from src.common.statics  import *

from src.transmitter.commands import change_master_key, change_setting, clear_screens, exit_tfc, log_command
from src.transmitter.commands import print_about, print_help, print_recipients, print_settings, process_command
from src.transmitter.commands import remove_log, rxp_display_unread, rxp_show_sys_win, send_onion_service_key, verify
from src.transmitter.commands import whisper, whois, wipe
from src.transmitter.packet   import split_to_assembly_packets

from tests.mock_classes import ContactList, create_contact, Gateway, GroupList, MasterKey, OnionService, Settings
from tests.mock_classes import TxWindow, UserInput
from tests.utils        import assembly_packet_creator, cd_unittest, cleanup, group_name_to_group_id
from tests.utils        import gen_queue_dict, nick_to_onion_address, nick_to_pub_key, tear_queues, TFCTestCase


class TestProcessCommand(TFCTestCase):

    def setUp(self):
        self.window        = TxWindow()
        self.contact_list  = ContactList()
        self.group_list    = GroupList()
        self.settings      = Settings()
        self.queues        = gen_queue_dict()
        self.master_key    = MasterKey()
        self.onion_service = OnionService()
        self.gateway       = Gateway()
        self.args          = (self.window, self.contact_list, self.group_list, self.settings,
                              self.queues, self.master_key, self.onion_service, self.gateway)

    def tearDown(self):
        tear_queues(self.queues)

    def test_valid_command(self):
        self.assertIsNone(process_command(UserInput('about'), *self.args))

    def test_invalid_command(self):
        self.assert_fr("Error: Invalid command 'abou'.", process_command, UserInput('abou'), *self.args)

    def test_empty_command(self):
        self.assert_fr("Error: Invalid command.", process_command, UserInput(' '), *self.args)


class TestPrintAbout(TFCTestCase):

    def test_print_about(self):
        self.assert_prints(CLEAR_ENTIRE_SCREEN + CURSOR_LEFT_UP_CORNER + f"""\

 Tinfoil Chat {VERSION}

 Website:     https://github.com/maqp/tfc/
 Wikipage:    https://github.com/maqp/tfc/wiki

""", print_about)


class TestClearScreens(unittest.TestCase):

    def setUp(self):
        self.window   = TxWindow(uid=nick_to_pub_key('Alice'))
        self.settings = Settings()
        self.queues   = gen_queue_dict()
        self.args     = self.window, self.settings, self.queues

    def tearDown(self):
        tear_queues(self.queues)

    @mock.patch('os.system', return_value=None)
    def test_clear_screens(self, _):
        self.assertIsNone(clear_screens(UserInput('clear'), *self.args))
        self.assertEqual(self.queues[COMMAND_PACKET_QUEUE].qsize(), 1)
        self.assertEqual(self.queues[RELAY_PACKET_QUEUE].qsize(),   1)

    @mock.patch('os.system', return_value=None)
    def test_no_relay_clear_cmd_when_traffic_masking_is_enabled(self, _):
        # Setup
        self.settings.traffic_masking = True

        # Test
        self.assertIsNone(clear_screens(UserInput('clear'), *self.args))
        self.assertEqual(self.queues[TM_COMMAND_PACKET_QUEUE].qsize(), 1)
        self.assertEqual(self.queues[RELAY_PACKET_QUEUE].qsize(),      0)

    @mock.patch('os.system', return_value=None)
    def test_reset_screens(self, mock_os_system):
        self.assertIsNone(clear_screens(UserInput('reset'), *self.args))
        self.assertEqual(self.queues[COMMAND_PACKET_QUEUE].qsize(), 1)
        self.assertEqual(self.queues[RELAY_PACKET_QUEUE].qsize(),   1)
        mock_os_system.assert_called_with(RESET)

    @mock.patch('os.system', return_value=None)
    def test_no_relay_reset_cmd_when_traffic_masking_is_enabled(self, mock_os_system):
        # Setup
        self.settings.traffic_masking = True

        # Test
        self.assertIsNone(clear_screens(UserInput('reset'), *self.args))
        self.assertEqual(self.queues[TM_COMMAND_PACKET_QUEUE].qsize(), 1)
        self.assertEqual(self.queues[RELAY_PACKET_QUEUE].qsize(),      0)
        mock_os_system.assert_called_with(RESET)


class TestRXPShowSysWin(unittest.TestCase):

    def setUp(self):
        self.window   = TxWindow(name='Alice',
                                 uid=nick_to_pub_key('Alice'))
        self.settings = Settings()
        self.queues   = gen_queue_dict()
        self.args     = self.window, self.settings, self.queues

    def tearDown(self):
        tear_queues(self.queues)

    @mock.patch('builtins.input', side_effect=['', EOFError, KeyboardInterrupt])
    def test_cmd_window(self, _):
        self.assertIsNone(rxp_show_sys_win(UserInput(plaintext='cmd'), *self.args))
        self.assertEqual(self.queues[COMMAND_PACKET_QUEUE].qsize(), 2)
        self.assertIsNone(rxp_show_sys_win(UserInput(plaintext='cmd'), *self.args))
        self.assertEqual(self.queues[COMMAND_PACKET_QUEUE].qsize(), 4)
        self.assertIsNone(rxp_show_sys_win(UserInput(plaintext='cmd'), *self.args))
        self.assertEqual(self.queues[COMMAND_PACKET_QUEUE].qsize(), 6)

    @mock.patch('builtins.input', side_effect=['', EOFError, KeyboardInterrupt])
    def test_file_window(self, _):
        self.assertIsNone(rxp_show_sys_win(UserInput(plaintext='fw'), *self.args))
        self.assertEqual(self.queues[COMMAND_PACKET_QUEUE].qsize(), 2)
        self.assertIsNone(rxp_show_sys_win(UserInput(plaintext='fw'), *self.args))
        self.assertEqual(self.queues[COMMAND_PACKET_QUEUE].qsize(), 4)
        self.assertIsNone(rxp_show_sys_win(UserInput(plaintext='fw'), *self.args))
        self.assertEqual(self.queues[COMMAND_PACKET_QUEUE].qsize(), 6)


class TestExitTFC(unittest.TestCase):

    def setUp(self):
        self.settings = Settings(local_testing_mode=True)
        self.queues   = gen_queue_dict()
        self.gateway  = Gateway(data_diode_sockets=True)
        self.args     = self.settings, self.queues, self.gateway

    def tearDown(self):
        tear_queues(self.queues)

    @mock.patch('time.sleep', return_value=None)
    def test_exit_tfc_local_test(self, _):
        # Setup
        for _ in range(2):
            self.queues[COMMAND_PACKET_QUEUE].put("dummy command")

        # Test
        self.assertIsNone(exit_tfc(*self.args))
        self.assertEqual(self.queues[COMMAND_PACKET_QUEUE].qsize(), 1)
        self.assertEqual(self.queues[RELAY_PACKET_QUEUE].qsize(),   1)

    @mock.patch('time.sleep', return_value=None)
    def test_exit_tfc(self, _):
        # Setup
        self.settings.local_testing_mode = False
        for _ in range(2):
            self.queues[COMMAND_PACKET_QUEUE].put("dummy command")

        # Test
        self.assertIsNone(exit_tfc(*self.args))
        self.assertEqual(self.queues[COMMAND_PACKET_QUEUE].qsize(), 1)
        self.assertEqual(self.queues[RELAY_PACKET_QUEUE].qsize(),   1)


class TestLogCommand(TFCTestCase):

    def setUp(self):
        self.unittest_dir = cd_unittest()
        self.window       = TxWindow(name='Alice',
                                     uid=nick_to_pub_key('Alice'))
        self.contact_list = ContactList()
        self.group_list   = GroupList()
        self.settings     = Settings()
        self.queues       = gen_queue_dict()
        self.master_key   = MasterKey()
        self.args         = self.window, self.contact_list, self.group_list, self.settings, self.queues, self.master_key

    def tearDown(self):
        cleanup(self.unittest_dir)
        tear_queues(self.queues)

    def test_invalid_export(self):
        self.assert_fr("Error: Invalid number of messages.",
                       log_command, UserInput("history a"), *self.args)

    def test_log_printing(self):
        self.assert_fr(f"No log database available.",
                       log_command, UserInput("history 4"), *self.args)
        self.assertEqual(self.queues[COMMAND_PACKET_QUEUE].qsize(), 1)

    def test_log_printing_all(self):
        self.assert_fr(f"No log database available.",
                       log_command, UserInput("history"), *self.args)
        self.assertEqual(self.queues[COMMAND_PACKET_QUEUE].qsize(), 1)

    def test_invalid_number_raises_fr(self):
        self.assert_fr("Error: Invalid number of messages.",
                       log_command, UserInput('history a'), *self.args)

    def test_too_high_number_raises_fr(self):
        self.assert_fr("Error: Invalid number of messages.",
                       log_command, UserInput('history 94857634985763454345'), *self.args)

    @mock.patch('time.sleep',     return_value=None)
    @mock.patch('builtins.input', return_value='No')
    def test_user_abort_raises_fr(self, *_):
        self.assert_fr("Log file export aborted.",
                       log_command, UserInput('export'), *self.args)

    @mock.patch('time.sleep',     return_value=None)
    @mock.patch('builtins.input', return_value='Yes')
    def test_successful_export_command(self, *_):
        # Setup
        self.window.type = WIN_TYPE_CONTACT
        self.window.uid  = nick_to_pub_key('Alice')
        whisper_header   = bool_to_bytes(False)
        packet           = split_to_assembly_packets(whisper_header + PRIVATE_MESSAGE_HEADER + b'test', MESSAGE)[0]
        write_log_entry(packet, nick_to_pub_key('Alice'), self.settings, self.master_key)

        # Test
        for command in ['export', 'export 1']:
            self.assert_fr(f"Exported log file of contact 'Alice'.",
                           log_command, UserInput(command), self.window, ContactList(nicks=['Alice']),
                           self.group_list, self.settings, self.queues, self.master_key)


class TestSendOnionServiceKey(TFCTestCase):

    confirmation_code = b'a'

    def setUp(self):
        self.contact_list  = ContactList()
        self.settings      = Settings()
        self.onion_service = OnionService()
        self.gateway       = Gateway()
        self.args          = self.contact_list, self.settings, self.onion_service, self.gateway

    @mock.patch('time.sleep',     return_value=None)
    @mock.patch('os.urandom',     return_value=confirmation_code)
    @mock.patch('builtins.input', side_effect=['Yes', confirmation_code.hex()])
    def test_onion_service_key_delivery_traffic_masking(self, *_):
        self.assertIsNone(send_onion_service_key(*self.args))
        self.assertEqual(len(self.gateway.packets), 1)

    @mock.patch('time.sleep',     return_value=None)
    @mock.patch('os.urandom',     return_value=confirmation_code)
    @mock.patch('builtins.input', side_effect=[KeyboardInterrupt, 'No'])
    def test_onion_service_key_delivery_traffic_masking_abort(self, *_):
        # Setup
        self.settings.traffic_masking = True

        # Test
        for _ in range(2):
            self.assert_fr("Onion Service data export canceled.", send_onion_service_key, *self.args)

    @mock.patch('os.urandom',     return_value=confirmation_code)
    @mock.patch('builtins.input', return_value=confirmation_code.hex())
    def test_onion_service_key_delivery(self, *_):
        self.assertIsNone(send_onion_service_key(*self.args))
        self.assertEqual(len(self.gateway.packets), 1)

    @mock.patch('time.sleep',     return_value=None)
    @mock.patch('os.urandom',     return_value=confirmation_code)
    @mock.patch('builtins.input', side_effect=[EOFError, KeyboardInterrupt])
    def test_onion_service_key_delivery_cancel(self, *_):
        for _ in range(2):
            self.assert_fr("Onion Service data export canceled.", send_onion_service_key, *self.args)


class TestPrintHelp(TFCTestCase):

    def setUp(self):
        self.settings                 = Settings()
        self.settings.traffic_masking = False

    @mock.patch('shutil.get_terminal_size', return_value=[60, 60])
    def test_print_normal(self, _):
        self.assert_prints(CLEAR_ENTIRE_SCREEN + CURSOR_LEFT_UP_CORNER + """\
List of commands:

/about                    Show links to project resources
/add                      Add new contact
/cm                       Cancel message transmission to
                          active contact/group

/clear, '  '              Clear TFC screens
/cmd, '//'                Display command window on Receiver
/connect                  Resend Onion Service data to Relay
/exit                     Exit TFC on all three computers
/export (n)               Export (n) messages from
                          recipient's log file

/file                     Send file to active contact/group
/help                     Display this list of commands
/history (n)              Print (n) messages from
                          recipient's log file

/localkey                 Generate new local key pair
/logging {on,off}(' all') Change message log setting (for
                          all contacts)

/msg {A,N,G}              Change recipient to Account, Nick,
                          or Group

/names                    List contacts and groups
/nick N                   Change nickname of active
                          recipient/group to N

/notify {on,off} (' all') Change notification settings (for
                          all contacts)

/passwd {tx,rx}           Change master password on target
                          system

/psk                      Open PSK import dialog on Receiver
/reset                    Reset ephemeral session log for
                          active window

/rm {A,N}                 Remove contact specified by
                          account A or nick N

/rmlogs {A,N}             Remove log entries for account A
                          or nick N

/set S V                  Change setting S to value V
/settings                 List setting names, values and
                          descriptions

/store {on,off} (' all')  Change file reception (for all
                          contacts)

/unread, ' '              List windows with unread messages
                          on Receiver

/verify                   Verify fingerprints with active
                          contact

/whisper M                Send message M, asking it not to
                          be logged

/whois {A,N}              Check which A corresponds to N or
                          vice versa

/wipe                     Wipe all TFC user data and power
                          off systems

Shift + PgUp/PgDn         Scroll terminal up/down
────────────────────────────────────────────────────────────
Group management:

/group create G A₁..Aₙ  Create group G and add accounts
                        A₁..Aₙ

/group join ID G A₁..Aₙ Join group ID, call it G and add
                        accounts A₁..Aₙ

/group add G A₁..Aₙ     Add accounts A₁..Aₙ to group G
/group rm G A₁..Aₙ      Remove accounts A₁..Aₙ from group G
/group rm G             Remove group G
────────────────────────────────────────────────────────────

""", print_help, self.settings)

    @mock.patch('shutil.get_terminal_size', return_value=[80, 80])
    def test_print_during_traffic_masking(self, _):
        self.settings.traffic_masking = True
        self.assert_prints(CLEAR_ENTIRE_SCREEN + CURSOR_LEFT_UP_CORNER + """\
List of commands:

/about                    Show links to project resources
/cf                       Cancel file transmission to active contact/group
/cm                       Cancel message transmission to active contact/group
/clear, '  '              Clear TFC screens
/cmd, '//'                Display command window on Receiver
/connect                  Resend Onion Service data to Relay
/exit                     Exit TFC on all three computers
/export (n)               Export (n) messages from recipient's log file
/file                     Send file to active contact/group
/fw                       Display file reception window on Receiver
/help                     Display this list of commands
/history (n)              Print (n) messages from recipient's log file
/logging {on,off}(' all') Change message log setting (for all contacts)
/names                    List contacts and groups
/nick N                   Change nickname of active recipient/group to N
/notify {on,off} (' all') Change notification settings (for all contacts)
/reset                    Reset ephemeral session log for active window
/rmlogs {A,N}             Remove log entries for account A or nick N
/set S V                  Change setting S to value V
/settings                 List setting names, values and descriptions
/store {on,off} (' all')  Change file reception (for all contacts)
/unread, ' '              List windows with unread messages on Receiver
/verify                   Verify fingerprints with active contact
/whisper M                Send message M, asking it not to be logged
/whois {A,N}              Check which A corresponds to N or vice versa
/wipe                     Wipe all TFC user data and power off systems
Shift + PgUp/PgDn         Scroll terminal up/down
────────────────────────────────────────────────────────────────────────────────

""", print_help, self.settings)


class TestPrintRecipients(TFCTestCase):

    def setUp(self):
        self.contact_list = ContactList(nicks=['Alice', 'Bob'])
        self.group_list   = GroupList(groups=['test_group', 'test_group_2'])
        self.args         = self.contact_list, self.group_list

    def test_printing(self):
        self.assertIsNone(print_recipients(*self.args))


class TestChangeMasterKey(TFCTestCase):

    def setUp(self):
        self.unittest_dir  = cd_unittest()
        self.contact_list  = ContactList()
        self.group_list    = GroupList()
        self.settings      = Settings()
        self.queues        = gen_queue_dict()
        self.master_key    = MasterKey()
        self.onion_service = OnionService(master_key=self.master_key,
                                          file_name=f'{DIR_USER_DATA}/unittest')
        self.args          = (self.contact_list, self.group_list, self.settings,
                              self.queues, self.master_key, self.onion_service)

    def tearDown(self):
        cleanup(self.unittest_dir)
        tear_queues(self.queues)

    def test_raises_fr_during_traffic_masking(self):
        # Setup
        self.settings.traffic_masking = True

        # Test
        self.assert_fr("Error: Command is disabled during traffic masking.",
                       change_master_key, UserInput(), *self.args)

    def test_missing_target_sys_raises_fr(self):
        self.assert_fr("Error: No target-system ('tx' or 'rx') specified.",
                       change_master_key, UserInput("passwd "), *self.args)

    def test_invalid_target_sys_raises_fr(self):
        self.assert_fr("Error: Invalid target system 't'.",
                       change_master_key, UserInput("passwd t"), *self.args)

    @mock.patch('os.popen',        return_value=MagicMock(read=MagicMock(return_value='foo\nMemFree 200')))
    @mock.patch('getpass.getpass', return_value='a')
    @mock.patch('time.sleep',      return_value=None)
    @mock.patch('src.common.db_masterkey.MIN_KEY_DERIVATION_TIME', 0.01)
    def test_transmitter_command(self, *_):
        # Setup
        write_log_entry(M_S_HEADER + PADDING_LENGTH * b'a', nick_to_pub_key('Alice'), self.settings, self.master_key)

        # Test
        self.assertIsNone(change_master_key(UserInput("passwd tx"), *self.args))
        self.assertEqual(self.queues[COMMAND_PACKET_QUEUE].qsize(), 0)
        self.assertEqual(self.queues[KEY_MANAGEMENT_QUEUE].qsize(), 1)

    def test_receiver_command(self):
        self.assertIsNone(change_master_key(UserInput("passwd rx"), *self.args))
        self.assertEqual(self.queues[COMMAND_PACKET_QUEUE].qsize(), 1)
        self.assertEqual(self.queues[KEY_MANAGEMENT_QUEUE].qsize(), 0)

    @mock.patch('time.sleep',      return_value=None)
    @mock.patch('getpass.getpass', side_effect=KeyboardInterrupt)
    def test_keyboard_interrupt_raises_fr(self, *_):
        self.assert_fr("Password change aborted.",
                       change_master_key, UserInput("passwd tx"), *self.args)


class TestRemoveLog(TFCTestCase):

    def setUp(self):
        self.unittest_dir = cd_unittest()
        self.contact_list = ContactList(nicks=['Alice'])
        self.group_list   = GroupList(groups=['test_group'])
        self.settings     = Settings()
        self.queues       = gen_queue_dict()
        self.master_key   = MasterKey()
        self.file_name    = f'{DIR_USER_DATA}{self.settings.software_operation}_logs'
        self.args         = self.contact_list, self.group_list, self.settings, self.queues, self.master_key

    def tearDown(self):
        tear_queues(self.queues)
        cleanup(self.unittest_dir)

    def test_missing_contact_raises_fr(self):
        self.assert_fr("Error: No contact/group specified.",
                       remove_log, UserInput(''), *self.args)

    @mock.patch('time.sleep',     return_value=None)
    @mock.patch('builtins.input', return_value='No')
    def test_no_aborts_removal(self, *_):
        # Setup
        write_log_entry(M_S_HEADER + PADDING_LENGTH * b'a', nick_to_pub_key('Alice'), self.settings, self.master_key)
        self.assertEqual(os.path.getsize(self.file_name), LOG_ENTRY_LENGTH)

        # Test
        self.assert_fr("Log file removal aborted.",
                       remove_log, UserInput('/rmlogs Alice'), *self.args)

    @mock.patch('shutil.get_terminal_size', return_value=[150, 150])
    @mock.patch('builtins.input',           return_value='Yes')
    def test_removal_with_invalid_account_raises_fr(self, *_):
        self.assert_fr("Error: Invalid account.",
                       remove_log, UserInput(f'/rmlogs {nick_to_onion_address("Alice")[:-1] + "a"}'), *self.args)

    @mock.patch('builtins.input', return_value='Yes')
    def test_invalid_group_id_raises_fr(self, _):
        self.assert_fr("Error: Invalid group ID.",
                       remove_log, UserInput(f'/rmlogs {group_name_to_group_id("test_group")[:-1] + b"a"}'), *self.args)

    @mock.patch('builtins.input', return_value='Yes')
    def test_log_remove_with_nick(self, _):
        # Setup
        write_log_entry(M_S_HEADER + PADDING_LENGTH * b'a', nick_to_pub_key("Alice"), self.settings, self.master_key)
        self.assertEqual(os.path.getsize(self.file_name), LOG_ENTRY_LENGTH)

        # Test
        self.assert_fr("Removed log entries for contact 'Alice'.",
                       remove_log, UserInput('/rmlogs Alice'), *self.args)
        self.assertEqual(os.path.getsize(self.file_name),           0)
        self.assertEqual(self.queues[COMMAND_PACKET_QUEUE].qsize(), 1)

    @mock.patch('shutil.get_terminal_size', return_value=[150, 150])
    @mock.patch('builtins.input',           return_value='Yes')
    def test_log_remove_with_onion_address(self, *_):
        # Setup
        write_log_entry(M_S_HEADER + PADDING_LENGTH * b'a', nick_to_pub_key("Alice"), self.settings, self.master_key)
        self.assertEqual(os.path.getsize(self.file_name), LOG_ENTRY_LENGTH)

        # Test
        self.assert_fr("Removed log entries for contact 'Alice'.",
                       remove_log, UserInput(f'/rmlogs {nick_to_onion_address("Alice")}'), *self.args)
        self.assertEqual(os.path.getsize(self.file_name),           0)
        self.assertEqual(self.queues[COMMAND_PACKET_QUEUE].qsize(), 1)

    @mock.patch('shutil.get_terminal_size', return_value=[150, 150])
    @mock.patch('builtins.input',           return_value='Yes')
    def test_log_remove_with_unknown_onion_address(self, *_):
        # Setup
        write_log_entry(M_S_HEADER + PADDING_LENGTH * b'a', nick_to_pub_key("Alice"), self.settings, self.master_key)
        self.assertEqual(os.path.getsize(self.file_name), LOG_ENTRY_LENGTH)

        # Test
        self.assert_fr("Found no log entries for contact 'w5sm3'.",
                       remove_log, UserInput(f'/rmlogs {nick_to_onion_address("Unknown")}'), *self.args)
        self.assertEqual(os.path.getsize(self.file_name),           LOG_ENTRY_LENGTH)
        self.assertEqual(self.queues[COMMAND_PACKET_QUEUE].qsize(), 1)

    @mock.patch('builtins.input', return_value='Yes')
    def test_log_remove_with_group_name(self, _):
        # Setup
        for p in assembly_packet_creator(MESSAGE, 'This is a short group message',
                                         group_id=group_name_to_group_id('test_group')):
            write_log_entry(p, nick_to_pub_key('Alice'), self.settings, self.master_key)
        self.assertEqual(os.path.getsize(self.file_name), LOG_ENTRY_LENGTH)

        # Test
        self.assert_fr("Removed log entries for group 'test_group'.",
                       remove_log, UserInput(f'/rmlogs test_group'), *self.args)
        self.assertEqual(os.path.getsize(self.file_name),           0)
        self.assertEqual(self.queues[COMMAND_PACKET_QUEUE].qsize(), 1)

    @mock.patch('builtins.input', return_value='Yes')
    def test_unknown_selector_raises_fr(self, _):
        # Setup
        write_log_entry(M_S_HEADER + PADDING_LENGTH * b'a', nick_to_pub_key("Alice"), self.settings, self.master_key)
        self.assertEqual(os.path.getsize(self.file_name), LOG_ENTRY_LENGTH)

        # Test
        self.assert_fr("Error: Unknown selector.",
                       remove_log, UserInput(f'/rmlogs unknown'), *self.args)


class TestChangeSetting(TFCTestCase):

    def setUp(self):
        self.window       = TxWindow()
        self.contact_list = ContactList()
        self.group_list   = GroupList()
        self.settings     = Settings()
        self.queues       = gen_queue_dict()
        self.gateway      = Gateway()
        self.args         = self.window, self.contact_list, self.group_list, self.settings, self.queues, self.gateway

    def tearDown(self):
        tear_queues(self.queues)

    def test_missing_setting_raises_fr(self):
        self.assert_fr("Error: No setting specified.",
                       change_setting, UserInput('set'), *self.args)

    def test_invalid_setting_raises_fr(self):
        self.assert_fr("Error: Invalid setting 'e_correction_ratia'.",
                       change_setting, UserInput("set e_correction_ratia true"), *self.args)

    def test_missing_value_raises_fr(self):
        self.assert_fr("Error: No value for setting specified.",
                       change_setting, UserInput("set serial_error_correction"), *self.args)

    def test_serial_settings_raise_fr(self):
        self.assert_fr("Error: Serial interface setting can only be changed manually.",
                       change_setting, UserInput("set use_serial_usb_adapter True"), *self.args)

        self.assert_fr("Error: Serial interface setting can only be changed manually.",
                       change_setting, UserInput("set built_in_serial_interface Truej"), *self.args)

    def test_relay_commands_raise_fr_when_traffic_masking_is_enabled(self):
        # Setup
        self.settings.traffic_masking = True

        # Test
        key_list = ['serial_error_correction', 'serial_baudrate', 'allow_contact_requests']
        for key, value in zip(key_list, ['5', '5', 'True']):
            self.assert_fr("Error: Can't change this setting during traffic masking.",
                           change_setting, UserInput(f"set {key} {value}"), *self.args)

    def test_individual_settings(self):

        self.assertIsNone(change_setting(UserInput("set serial_error_correction 5"), *self.args))
        self.assertEqual(self.queues[RELAY_PACKET_QUEUE].qsize(), 1)

        self.assertIsNone(change_setting(UserInput("set serial_baudrate 9600"), *self.args))
        self.assertEqual(self.queues[RELAY_PACKET_QUEUE].qsize(), 2)

        self.assertIsNone(change_setting(UserInput("set allow_contact_requests True"), *self.args))
        self.assertEqual(self.queues[RELAY_PACKET_QUEUE].qsize(), 3)

        self.assertIsNone(change_setting(UserInput("set traffic_masking True"), *self.args))
        self.assertIsInstance(self.queues[SENDER_MODE_QUEUE].get(), Settings)
        self.assertTrue(self.queues[TRAFFIC_MASKING_QUEUE].get())

        self.settings.traffic_masking = False
        self.assertIsNone(change_setting(UserInput("set max_number_of_group_members 100"), *self.args))
        self.assertTrue(self.group_list.store_groups_called)
        self.group_list.store_groups_called = False

        self.assertIsNone(change_setting(UserInput("set max_number_of_groups 100"), *self.args))
        self.assertTrue(self.group_list.store_groups_called)
        self.group_list.store_groups_called = False

        self.assertIsNone(change_setting(UserInput("set max_number_of_contacts 100"), *self.args))
        self.assertEqual(self.queues[KEY_MANAGEMENT_QUEUE].qsize(), 1)

        self.assertIsNone(change_setting(UserInput("set log_file_masking True"), *self.args))
        self.assertTrue(self.queues[LOGFILE_MASKING_QUEUE].get())


class TestPrintSettings(TFCTestCase):

    def test_print_settings(self):
        self.assert_prints(f"""\
{CLEAR_ENTIRE_SCREEN}{CURSOR_LEFT_UP_CORNER}
Setting name                    Current value   Default value   Description
────────────────────────────────────────────────────────────────────────────────
disable_gui_dialog              False           False           True replaces
                                                                GUI dialogs with
                                                                CLI prompts

max_number_of_group_members     50              50              Maximum number
                                                                of members in a
                                                                group

max_number_of_groups            50              50              Maximum number
                                                                of groups

max_number_of_contacts          50              50              Maximum number
                                                                of contacts

log_messages_by_default         False           False           Default logging
                                                                setting for new
                                                                contacts/groups

accept_files_by_default         False           False           Default file
                                                                reception
                                                                setting for new
                                                                contacts

show_notifications_by_default   True            True            Default message
                                                                notification
                                                                setting for new
                                                                contacts/groups

log_file_masking                False           False           True hides real
                                                                size of log file
                                                                during traffic
                                                                masking

nc_bypass_messages              False           False           False removes
                                                                Networked
                                                                Computer bypass
                                                                interrupt
                                                                messages

confirm_sent_files              True            True            False sends
                                                                files without
                                                                asking for
                                                                confirmation

double_space_exits              False           False           True exits,
                                                                False clears
                                                                screen with
                                                                double space
                                                                command

traffic_masking                 False           False           True enables
                                                                traffic masking
                                                                to hide metadata

tm_static_delay                 2.0             2.0             The static delay
                                                                between traffic
                                                                masking packets

tm_random_delay                 2.0             2.0             Max random delay
                                                                for traffic
                                                                masking timing
                                                                obfuscation

allow_contact_requests          True            True            When False, does
                                                                not show TFC
                                                                contact requests

new_message_notify_preview      False           False           When True, shows
                                                                a preview of the
                                                                received message

new_message_notify_duration     1.0             1.0             Number of
                                                                seconds new
                                                                message
                                                                notification
                                                                appears

max_decompress_size             100000000       100000000       Max size
                                                                Receiver accepts
                                                                when
                                                                decompressing
                                                                file


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


""", print_settings, Settings(), Gateway())


class TestRxPDisplayUnread(unittest.TestCase):

    def setUp(self):
        self.queues = gen_queue_dict()

    def tearDown(self):
        tear_queues(self.queues)

    def test_command(self):
        self.assertIsNone(rxp_display_unread(Settings(), self.queues))
        self.assertEqual(self.queues[COMMAND_PACKET_QUEUE].qsize(), 1)


class TestVerify(TFCTestCase):

    def setUp(self):
        self.window         = TxWindow(uid=nick_to_pub_key("Alice"),
                                       name='Alice',
                                       window_contacts=[create_contact('test_group')],
                                       log_messages=True,
                                       type=WIN_TYPE_CONTACT)
        self.contact_list   = ContactList(nicks=['Alice'])
        self.contact        = self.contact_list.get_contact_by_address_or_nick('Alice')
        self.window.contact = self.contact
        self.args           = self.window, self.contact_list

    def test_active_group_raises_fr(self):
        self.window.type = WIN_TYPE_GROUP
        self.assert_fr("Error: A group is selected.", verify, *self.args)

    def test_psk_raises_fr(self):
        self.contact.kex_status = KEX_STATUS_NO_RX_PSK
        self.assert_fr("Pre-shared keys have no fingerprints.", verify, *self.args)

    @mock.patch('time.sleep',     return_value=None)
    @mock.patch('builtins.input', side_effect=['No', 'Yes'])
    def test_fingerprint_check(self, *_):
        self.contact.kex_status = KEX_STATUS_VERIFIED

        self.assertIsNone(verify(*self.args))
        self.assertEqual(self.contact.kex_status, KEX_STATUS_UNVERIFIED)

        self.assertIsNone(verify(*self.args))
        self.assertEqual(self.contact.kex_status, KEX_STATUS_VERIFIED)

    @mock.patch('time.sleep',     return_value=None)
    @mock.patch('builtins.input', side_effect=KeyboardInterrupt)
    def test_keyboard_interrupt_raises_fr(self, *_):
        self.contact.kex_status = KEX_STATUS_VERIFIED
        self.assert_fr("Fingerprint verification aborted.", verify, *self.args)
        self.assertEqual(self.contact.kex_status, KEX_STATUS_VERIFIED)


class TestWhisper(TFCTestCase):

    def setUp(self):
        self.window   = TxWindow(uid=nick_to_pub_key("Alice"),
                                 name='Alice',
                                 window_contacts=[create_contact('Alice')],
                                 log_messages=True)
        self.settings = Settings()
        self.queues   = gen_queue_dict()
        self.args     = self.window, self.settings, self.queues

    def test_empty_input_raises_fr(self):
        self.assert_fr("Error: No whisper message specified.",
                       whisper, UserInput("whisper"), *self.args)

    def test_whisper(self):
        self.assertIsNone(whisper(UserInput("whisper This message ought not to be logged."), *self.args))

        message, pub_key, logging, log_as_ph, win_uid = self.queues[MESSAGE_PACKET_QUEUE].get()
        self.assertEqual(pub_key, nick_to_pub_key("Alice"))
        self.assertTrue(logging)
        self.assertTrue(log_as_ph)


class TestWhois(TFCTestCase):

    def setUp(self):
        self.contact_list = ContactList(nicks=['Alice'])
        self.group_list   = GroupList(groups=['test_group'])
        self.args         = self.contact_list, self.group_list

    def test_missing_selector_raises_fr(self):
        self.assert_fr("Error: No account or nick specified.", whois, UserInput("whois"), *self.args)

    def test_unknown_account_raises_fr(self):
        self.assert_fr("Error: Unknown selector.", whois, UserInput("whois alice"), *self.args)

    def test_nick_from_account(self):
        self.assert_prints(
            f"""\
{BOLD_ON}     Nick of 'hpcrayuxhrcy2wtpfwgwjibderrvjll6azfr4tqat3eka2m2gbb55bid' is      {NORMAL_TEXT}
{BOLD_ON}                                     Alice                                      {NORMAL_TEXT}\n""",
            whois, UserInput("whois hpcrayuxhrcy2wtpfwgwjibderrvjll6azfr4tqat3eka2m2gbb55bid"), *self.args)

    def test_account_from_nick(self):
        self.assert_prints(
            f"""\
{BOLD_ON}                             Account of 'Alice' is                              {NORMAL_TEXT}
{BOLD_ON}            hpcrayuxhrcy2wtpfwgwjibderrvjll6azfr4tqat3eka2m2gbb55bid            {NORMAL_TEXT}\n""",
            whois, UserInput("whois Alice"), *self.args)

    def test_group_id_from_group_name(self):
        self.assert_prints(
            f"""\
{BOLD_ON}                       Group ID of group 'test_group' is                        {NORMAL_TEXT}
{BOLD_ON}                                 2dbCCptB9UGo9                                  {NORMAL_TEXT}\n""",
            whois, UserInput(f"whois test_group"), *self.args)

    def test_group_name_from_group_id(self):
        self.assert_prints(
            f"""\
{BOLD_ON}                    Name of group with ID '2dbCCptB9UGo9' is                    {NORMAL_TEXT}
{BOLD_ON}                                   test_group                                   {NORMAL_TEXT}\n""",
            whois, UserInput("whois 2dbCCptB9UGo9"), *self.args)


class TestWipe(TFCTestCase):

    def setUp(self):
        self.settings = Settings()
        self.queues   = gen_queue_dict()
        self.gateway  = Gateway()
        self.args     = self.settings, self.queues, self.gateway

    @mock.patch('builtins.input', return_value='No')
    def test_no_raises_fr(self, _):
        self.assert_fr("Wipe command aborted.", wipe, *self.args)

    @mock.patch('os.system',      return_value=None)
    @mock.patch('builtins.input', return_value='Yes')
    @mock.patch('time.sleep',     return_value=None)
    def test_wipe_local_testing(self, *_):
        # Setup
        self.settings.local_testing_mode         = True
        self.gateway.settings.data_diode_sockets = True
        for _ in range(2):
            self.queues[COMMAND_PACKET_QUEUE].put("dummy command")
            self.queues[RELAY_PACKET_QUEUE].put("dummy packet")

        # Test
        self.assertIsNone(wipe(*self.args))
        wipe_packet = UNENCRYPTED_DATAGRAM_HEADER + UNENCRYPTED_WIPE_COMMAND
        self.assertTrue(self.queues[RELAY_PACKET_QUEUE].get().startswith(wipe_packet))

    @mock.patch('os.system',      return_value=None)
    @mock.patch('builtins.input', return_value='Yes')
    @mock.patch('time.sleep',     return_value=None)
    def test_wipe(self, *_):
        # Setup
        for _ in range(2):
            self.queues[COMMAND_PACKET_QUEUE].put("dummy command")
            self.queues[RELAY_PACKET_QUEUE].put("dummy packet")

        # Test
        self.assertIsNone(wipe(*self.args))
        wipe_packet = UNENCRYPTED_DATAGRAM_HEADER + UNENCRYPTED_WIPE_COMMAND
        self.assertTrue(self.queues[RELAY_PACKET_QUEUE].get().startswith(wipe_packet))


if __name__ == '__main__':
    unittest.main(exit=False)
