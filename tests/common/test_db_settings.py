#!/usr/bin/env python3.6
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

import os.path
import unittest

from unittest import mock

from src.common.db_settings import Settings
from src.common.statics     import *

from tests.mock_classes import ContactList, create_group, GroupList, MasterKey
from tests.utils        import cd_unittest, cleanup, tamper_file, TFCTestCase


class TestSettings(TFCTestCase):

    def setUp(self):
        self.unittest_dir         = cd_unittest()
        self.file_name            = f"{DIR_USER_DATA}{TX}_settings"
        self.master_key           = MasterKey()
        self.settings             = Settings(self.master_key, operation=TX, local_test=False)
        self.contact_list         = ContactList(nicks=[f'contact_{n}' for n in range(18)])
        self.group_list           = GroupList(groups=[f'group_{n}' for n in range(18)])
        self.group_list.groups[0] = create_group('group_0', [f'contact_{n}' for n in range(18)])
        self.args                 = self.contact_list, self.group_list

    def tearDown(self):
        cleanup(self.unittest_dir)

    def test_invalid_type_raises_critical_error_on_store(self):
        self.settings.tm_random_delay = b'bytestring'
        with self.assertRaises(SystemExit):
            self.settings.store_settings()

    def test_invalid_type_raises_critical_error_on_load(self):
        with self.assertRaises(SystemExit):
            self.settings.nc_bypass_messages = b'bytestring'
            self.settings.load_settings()

    def test_store_and_load_tx_settings(self):
        # Test store
        self.assertFalse(self.settings.disable_gui_dialog)
        self.settings.disable_gui_dialog = True
        self.settings.store_settings()
        self.assertEqual(os.path.getsize(self.file_name), SETTING_LENGTH)

        # Test load
        settings2 = Settings(self.master_key, TX, False)
        self.assertTrue(settings2.disable_gui_dialog)

    def test_store_and_load_rx_settings(self):
        # Setup
        self.settings = Settings(self.master_key, operation=RX, local_test=False)

        # Test store
        self.assertFalse(self.settings.disable_gui_dialog)
        self.settings.disable_gui_dialog = True
        self.settings.store_settings()
        self.assertEqual(os.path.getsize(self.file_name), SETTING_LENGTH)

        # Test load
        settings2 = Settings(self.master_key, RX, False)
        self.assertTrue(settings2.disable_gui_dialog)

    def test_load_of_modified_database_raises_critical_error(self):
        # Store settings to database
        self.settings.store_settings()

        # Test reading from database works normally
        self.assertIsInstance(Settings(self.master_key, operation=TX, local_test=False), Settings)

        # Test loading of the tampered database raises CriticalError
        tamper_file(self.file_name, tamper_size=1)
        with self.assertRaises(SystemExit):
            Settings(self.master_key, operation=TX, local_test=False)

    def test_invalid_type_raises_critical_error_when_changing_settings(self):
        self.settings.traffic_masking = b'bytestring'
        with self.assertRaises(SystemExit):
            self.assertIsNone(self.settings.change_setting('traffic_masking', 'True', *self.args))

    def test_change_settings(self):
        self.assert_fr("Error: Invalid value 'Falsee'.",
                       self.settings.change_setting, 'disable_gui_dialog', 'Falsee',           *self.args)
        self.assert_fr("Error: Invalid value '1.1'.",
                       self.settings.change_setting, 'max_number_of_group_members',     '1.1', *self.args)
        self.assert_fr("Error: Invalid value '18446744073709551616'.",
                       self.settings.change_setting, 'max_number_of_contacts',   str(2 ** 64), *self.args)
        self.assert_fr("Error: Invalid value '-1.1'.",
                       self.settings.change_setting, 'tm_static_delay',                '-1.1', *self.args)
        self.assert_fr("Error: Invalid value 'True'.",
                       self.settings.change_setting, 'tm_static_delay',                'True', *self.args)

        self.assertIsNone(self.settings.change_setting('traffic_masking',             'True', *self.args))
        self.assertIsNone(self.settings.change_setting('max_number_of_group_members',  '100', *self.args))

    @mock.patch('builtins.input', side_effect=['No', 'Yes'])
    def test_validate_key_value_pair(self, _):
        self.assert_fr("Error: Database padding settings must be divisible by 10.",
                       self.settings.validate_key_value_pair, 'max_number_of_group_members',    0, *self.args)
        self.assert_fr("Error: Database padding settings must be divisible by 10.",
                       self.settings.validate_key_value_pair, 'max_number_of_group_members',   18, *self.args)
        self.assert_fr("Error: Database padding settings must be divisible by 10.",
                       self.settings.validate_key_value_pair, 'max_number_of_groups',          18, *self.args)
        self.assert_fr("Error: Database padding settings must be divisible by 10.",
                       self.settings.validate_key_value_pair, 'max_number_of_contacts',        18, *self.args)
        self.assert_fr("Error: Can't set the max number of members lower than 20.",
                       self.settings.validate_key_value_pair, 'max_number_of_group_members',   10, *self.args)
        self.assert_fr("Error: Can't set the max number of groups lower than 20.",
                       self.settings.validate_key_value_pair, 'max_number_of_groups',          10, *self.args)
        self.assert_fr("Error: Can't set the max number of contacts lower than 20.",
                       self.settings.validate_key_value_pair, 'max_number_of_contacts',        10, *self.args)
        self.assert_fr("Error: Too small value for message notify duration.",
                       self.settings.validate_key_value_pair, 'new_message_notify_duration', 0.04, *self.args)
        self.assert_fr("Error: Can't set static delay lower than 0.1.",
                       self.settings.validate_key_value_pair, 'tm_static_delay',             0.01, *self.args)
        self.assert_fr("Error: Can't set random delay lower than 0.1.",
                       self.settings.validate_key_value_pair, 'tm_random_delay',             0.01, *self.args)
        self.assert_fr("Aborted traffic masking setting change.",
                       self.settings.validate_key_value_pair, 'tm_random_delay',              0.1, *self.args)

        self.assertIsNone(self.settings.validate_key_value_pair("serial_baudrate",  9600, *self.args))
        self.assertIsNone(self.settings.validate_key_value_pair("tm_static_delay",     1, *self.args))

    @mock.patch('shutil.get_terminal_size', return_value=(64, 64))
    def test_too_narrow_terminal_raises_fr_when_printing_settings(self, _):
        # Test
        self.assert_fr("Error: Screen width is too small.", self.settings.print_settings)

    def test_print_settings(self):
        self.settings.max_number_of_group_members = 30
        self.settings.log_messages_by_default     = True
        self.settings.tm_static_delay             = 10.2
        self.assert_prints(CLEAR_ENTIRE_SCREEN + CURSOR_LEFT_UP_CORNER + """\

Setting name                    Current value   Default value   Description
────────────────────────────────────────────────────────────────────────────────
disable_gui_dialog              False           False           True replaces
                                                                GUI dialogs with
                                                                CLI prompts

max_number_of_group_members     30              50              Maximum number
                                                                of members in a
                                                                group

max_number_of_groups            50              50              Maximum number
                                                                of groups

max_number_of_contacts          50              50              Maximum number
                                                                of contacts

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

tm_static_delay                 10.2            2.0             The static delay
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

""", self.settings.print_settings)


if __name__ == '__main__':
    unittest.main(exit=False)
