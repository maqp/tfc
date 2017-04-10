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
import unittest

from src.common.db_settings import Settings
from src.common.statics     import *

from tests.mock_classes     import create_group, ContactList, GroupList, MasterKey
from tests.utils            import cleanup, TFCTestCase


class TestSettings(TFCTestCase):

    def test_class(self):
        # Setup
        masterkey            = MasterKey()
        o_input              = builtins.input
        builtins.input       = lambda x: 'yes'
        settings             = Settings(masterkey, 'ut', False, False)
        contact_list         = ContactList(nicks=['contact_{}'.format(n) for n in range(18)])
        group_list           = GroupList(groups =['group_{}'.format(n) for n in range(18)])
        group_list.groups[0] = create_group('group_0', ['contact_{}'.format(n) for n in range(18)])

        # Test store/load
        self.assertFalse(settings.disable_gui_dialog)
        settings.disable_gui_dialog = True
        settings.store_settings()

        self.assertTrue(os.path.isfile(f"{DIR_USER_DATA}/ut_settings"))
        self.assertEqual(os.path.getsize(f"{DIR_USER_DATA}/ut_settings"), 24 + 1024 + 9*8 + 12*1 + 16)

        settings2 = Settings(masterkey, 'ut', False, False)
        self.assertTrue(settings2.disable_gui_dialog)

        settings2.format_of_logfiles = b'invalid'
        with self.assertRaises(SystemExit):
            settings2.store_settings()
        with self.assertRaises(SystemExit):
            settings2.change_setting('format_of_logfiles', '%Y-%m-%d %H:%M:%S', contact_list, group_list)
        settings2.format_of_logfiles = '%Y-%m-%d %H:%M:%S'

        # Test change_setting
        self.assertFR('Invalid value Falsee.',                   settings2.change_setting, 'disable_gui_dialog', 'Falsee',              contact_list, group_list)
        self.assertFR('Invalid value 1.1.',                      settings2.change_setting, 'm_members_in_group', '1.1',                 contact_list, group_list)
        self.assertFR('Invalid value 7378697629483820650.',      settings2.change_setting, 'm_members_in_group', '7378697629483820650', contact_list, group_list)
        self.assertFR('Invalid value True.',                     settings2.change_setting, 'trickle_stat_delay', 'True',                contact_list, group_list)
        self.assertFR("Setting must be shorter than 256 chars.", settings2.change_setting, 'format_of_logfiles', 256*'a',               contact_list, group_list)

        self.assertIsNone(settings2.change_setting('format_of_logfiles', '%Y-%m-%d %H:%M:%S', contact_list, group_list))
        self.assertIsNone(settings2.change_setting('e_correction_ratio', '10',                contact_list, group_list))
        self.assertIsNone(settings2.change_setting('rxm_serial_adapter', 'True',              contact_list, group_list))
        self.assertIsNone(settings2.change_setting('trickle_connection', 'True',              contact_list, group_list))

        self.assertFR("Database padding settings must be divisible by 10.", settings2.validate_key_value_pair, 'm_members_in_group', '18', contact_list, group_list)
        self.assertFR("Database padding settings must be divisible by 10.", settings2.validate_key_value_pair, 'm_number_of_groups', '18', contact_list, group_list)
        self.assertFR("Database padding settings must be divisible by 10.", settings2.validate_key_value_pair, 'm_number_of_accnts', '18', contact_list, group_list)
        self.assertFR("Can't set max number of members lower than 20.",     settings2.validate_key_value_pair, 'm_members_in_group', '10', contact_list, group_list)
        self.assertFR("Can't set max number of groups lower than 20.",      settings2.validate_key_value_pair, 'm_number_of_groups', '10', contact_list, group_list)
        self.assertFR("Can't set max number of contacts lower than 20.",    settings2.validate_key_value_pair, 'm_number_of_accnts', '10', contact_list, group_list)
        self.assertFR("Specified baud rate is not supported.",              settings2.validate_key_value_pair, 'serial_iface_speed', '10', contact_list, group_list)
        self.assertFR("Invalid value for error correction ratio.",          settings2.validate_key_value_pair, 'e_correction_ratio', '0',  contact_list, group_list)
        self.assertFR("Invalid value for error correction ratio.",          settings2.validate_key_value_pair, 'e_correction_ratio', 'a',  contact_list, group_list)
        self.assertFR("Invalid value for error correction ratio.",          settings2.validate_key_value_pair, 'e_correction_ratio', '-1', contact_list, group_list)

        self.assertIsNone(settings2.print_settings())

        builtins.input = o_input

    def tearDown(self):
        cleanup()


if __name__ == '__main__':
    unittest.main(exit=False)
