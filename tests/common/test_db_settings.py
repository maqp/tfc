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
import os.path
import shutil
import unittest

from src.common.db_settings import Settings
from src.common.statics     import *

from tests.mock_classes import create_group, ContactList, GroupList, MasterKey
from tests.utils        import cleanup, TFCTestCase


class TestSettings(TFCTestCase):

    def setUp(self):
        self.o_input              = builtins.input
        builtins.input            = lambda _: 'yes'
        self.masterkey            = MasterKey()
        self.settings             = Settings(self.masterkey, operation='ut', local_test=False, dd_sockets=False)
        self.contact_list         = ContactList(nicks=['contact_{}'.format(n) for n in range(18)])
        self.group_list           = GroupList(groups=['group_{}'.format(n) for n in range(18)])
        self.group_list.groups[0] = create_group('group_0', ['contact_{}'.format(n) for n in range(18)])

    def tearDown(self):
        cleanup()
        builtins.input = self.o_input

    def test_invalid_type_raises_critical_error_on_store(self):
        self.settings.serial_error_correction = b'bytestring'
        with self.assertRaises(SystemExit):
            self.settings.store_settings()

    def test_invalid_type_raises_critical_error_on_load(self):
        with self.assertRaises(SystemExit):
            self.settings.nh_bypass_messages = b'bytestring'
            self.settings.load_settings()

    def test_store_and_load_settings(self):
        # Test store
        self.assertFalse(self.settings.disable_gui_dialog)
        self.settings.disable_gui_dialog = True
        self.settings.store_settings()
        self.assertEqual(os.path.getsize(f"{DIR_USER_DATA}ut_settings"), SETTING_LENGTH)

        # Test load
        settings2 = Settings(self.masterkey, 'ut', False, False)
        self.assertTrue(settings2.disable_gui_dialog)

    def test_invalid_type_raises_critical_error_when_changing_settings(self):
        self.settings.traffic_masking = b'bytestring'
        with self.assertRaises(SystemExit):
            self.assertIsNone(self.settings.change_setting('traffic_masking', 'True', self.contact_list, self.group_list))

    def test_change_settings(self):
        self.assertFR("Error: Invalid value 'Falsee'",               self.settings.change_setting, 'disable_gui_dialog',           'Falsee',     self.contact_list, self.group_list)
        self.assertFR("Error: Invalid value '1.1'",                  self.settings.change_setting, 'max_number_of_group_members',  '1.1',        self.contact_list, self.group_list)
        self.assertFR("Error: Invalid value '-1.1'",                 self.settings.change_setting, 'max_duration_of_random_delay', '-1.1',       self.contact_list, self.group_list)
        self.assertFR("Error: Invalid value '18446744073709551616'", self.settings.change_setting, 'serial_error_correction',      str(2 ** 64), self.contact_list, self.group_list)
        self.assertFR("Error: Invalid value 'True'",                 self.settings.change_setting, 'traffic_masking_static_delay', 'True',       self.contact_list, self.group_list)

        self.assertIsNone(self.settings.change_setting('serial_error_correction', '10',   self.contact_list, self.group_list))
        self.assertIsNone(self.settings.change_setting('rxm_usb_serial_adapter',  'True', self.contact_list, self.group_list))
        self.assertIsNone(self.settings.change_setting('traffic_masking',         'True', self.contact_list, self.group_list))

    def test_validate_key_value_pair(self):
        self.assertFR("Error: Database padding settings must be divisible by 10.", self.settings.validate_key_value_pair, 'max_number_of_group_members',  0,   self.contact_list, self.group_list)
        self.assertFR("Error: Database padding settings must be divisible by 10.", self.settings.validate_key_value_pair, 'max_number_of_group_members', 18,   self.contact_list, self.group_list)
        self.assertFR("Error: Database padding settings must be divisible by 10.", self.settings.validate_key_value_pair, 'max_number_of_groups',        18,   self.contact_list, self.group_list)
        self.assertFR("Error: Database padding settings must be divisible by 10.", self.settings.validate_key_value_pair, 'max_number_of_contacts',      18,   self.contact_list, self.group_list)
        self.assertFR("Error: Can't set max number of members lower than 20.",     self.settings.validate_key_value_pair, 'max_number_of_group_members', 10,   self.contact_list, self.group_list)
        self.assertFR("Error: Can't set max number of groups lower than 20.",      self.settings.validate_key_value_pair, 'max_number_of_groups',        10,   self.contact_list, self.group_list)
        self.assertFR("Error: Can't set max number of contacts lower than 20.",    self.settings.validate_key_value_pair, 'max_number_of_contacts',      10,   self.contact_list, self.group_list)
        self.assertFR("Error: Specified baud rate is not supported.",              self.settings.validate_key_value_pair, 'serial_baudrate',             10,   self.contact_list, self.group_list)
        self.assertFR("Error: Invalid value for error correction ratio.",          self.settings.validate_key_value_pair, 'serial_error_correction',     0,    self.contact_list, self.group_list)
        self.assertFR("Error: Invalid value for error correction ratio.",          self.settings.validate_key_value_pair, 'serial_error_correction',     -1,   self.contact_list, self.group_list)
        self.assertFR("Error: Too small value for message notify duration.",       self.settings.validate_key_value_pair, 'new_message_notify_duration', 0.04, self.contact_list, self.group_list)

        self.assertIsNone(self.settings.validate_key_value_pair("serial_baudrate", 9600, self.contact_list, self.group_list))

    def test_too_narrow_terminal_raises_fr_when_printing_settings(self):
        # Setup
        o_get_terminal_size      = shutil.get_terminal_size
        shutil.get_terminal_size = lambda: [64, 64]

        # Test
        self.assertFR("Error: Screen width is too small.", self.settings.print_settings)

        # Teardown
        shutil.get_terminal_size = o_get_terminal_size

    def test_setup(self):
        # Setup
        builtins.input = lambda _: 'No'

        # Test
        self.settings.software_operation = TX
        self.settings.setup()
        self.assertFalse(self.settings.txm_usb_serial_adapter)

        self.settings.software_operation = RX
        self.settings.setup()
        self.assertFalse(self.settings.rxm_usb_serial_adapter)

    def test_print_settings(self):
        self.settings.max_number_of_group_members  = 30
        self.settings.log_messages_by_default      = True
        self.settings.traffic_masking_static_delay = 10.2
        self.assertPrints(CLEAR_ENTIRE_SCREEN + CURSOR_LEFT_UP_CORNER + """\

Setting name                    Current value   Default value   Description
────────────────────────────────────────────────────────────────────────────────
disable_gui_dialog              False           False           True replaces
                                                                Tkinter dialogs
                                                                with CLI prompts

max_number_of_group_members     30              20              Max members in
                                                                group (TxM/RxM
                                                                must have the
                                                                same value)

max_number_of_groups            20              20              Max number of
                                                                groups (TxM/RxM
                                                                must have the
                                                                same value)

max_number_of_contacts          20              20              Max number of
                                                                contacts
                                                                (TxM/RxM must
                                                                have the same
                                                                value)

serial_baudrate                 19200           19200           The speed of
                                                                serial interface
                                                                in bauds per
                                                                second

serial_error_correction         5               5               Number of byte
                                                                errors serial
                                                                datagrams can
                                                                recover from

log_messages_by_default         True            False           Default logging
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

logfile_masking                 False           False           True hides real
                                                                size of logfile
                                                                during traffic
                                                                masking

txm_usb_serial_adapter          True            True            False uses
                                                                system's
                                                                integrated
                                                                serial interface

nh_bypass_messages              True            True            False removes NH
                                                                bypass interrupt
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

traffic_masking_static_delay    10.2            2.0             Static delay
                                                                between traffic
                                                                masking packets

traffic_masking_random_delay    2.0             2.0             Max random delay
                                                                for traffic
                                                                masking timing
                                                                obfuscation

multi_packet_random_delay       False           False           True adds IM
                                                                server spam
                                                                guard evading
                                                                delay

max_duration_of_random_delay    10.0            10.0            Maximum time for
                                                                random spam
                                                                guard evasion
                                                                delay

rxm_usb_serial_adapter          True            True            False uses
                                                                system's
                                                                integrated
                                                                serial interface

new_message_notify_preview      False           False           When True, shows
                                                                preview of
                                                                received message

new_message_notify_duration     1.0             1.0             Number of
                                                                seconds new
                                                                message
                                                                notification
                                                                appears


""", self.settings.print_settings)


if __name__ == '__main__':
    unittest.main(exit=False)
