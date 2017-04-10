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
import time
import unittest

from multiprocessing import Queue

from src.common.db_contacts import Contact
from src.common.statics     import *
from src.tx.windows         import Window, select_window

from tests.mock_classes     import ContactList, GroupList, Settings, UserInput
from tests.utils            import TFCTestCase


class TestWindow(TFCTestCase):

    def test_class(self):
        # Setup
        contact_list = ContactList(['Alice'])
        group_list   = GroupList(groups=['testgroup'])
        settings     = Settings()
        window       = Window(contact_list, group_list)
        queue_dict   = {WINDOW_SELECT_QUEUE:  Queue(),
                        COMMAND_PACKET_QUEUE: Queue()}
        window.group = group_list.get_group('testgroup')
        window.type  = 'group'

        # Test
        window.name = 'testgroup'
        self.assertIsNone(window.update_group_win_members(group_list))
        window.name = 'testgroup2'
        self.assertIsNone(window.update_group_win_members(group_list))
        window.name = 'testgroup'

        self.assertTrue(window.is_selected())
        self.assertIsNone(window.select_tx_window(settings, queue_dict, 'alice@jabber.org'))
        self.assertTrue(window.is_selected())

        settings.session_trickle = True
        window.uid               = 'alice@jabber.org'
        self.assertFR("Can't change window during trickle connection.", window.select_tx_window, settings, queue_dict, 'testgroup', cmd=True)
        settings.session_trickle = False
        self.assertIsNone(window.select_tx_window(settings, queue_dict, 'testgroup', cmd=True))
        self.assertEqual(len(window), 2)

        settings.session_trickle = True
        self.assertFR("Can't change window during trickle connection.", window.select_tx_window, settings, queue_dict, 'alice@jabber.org', cmd=True)
        self.assertFR("Error: No contact/group was found.",             window.select_tx_window, settings, queue_dict, 'david@jabber.org', cmd=True)

        user_input = UserInput('invalid')
        self.assertFR("Invalid recipient.", select_window, user_input, window, settings, queue_dict)

        for c in window:
            self.assertIsInstance(c, Contact)

        self.assertIsNone(window.deselect())
        self.assertIsNone(window.group)
        self.assertIsNone(window.contact)
        self.assertIsNone(window.name)
        self.assertIsNone(window.type)
        self.assertIsNone(window.uid)
        self.assertIsNone(window.imc_name)

        o_input        = builtins.input
        builtins.input = lambda x: 'alice@jabber.org'
        self.assertIsNone(window.select_tx_window(settings, queue_dict))
        time.sleep(1)

        # Teardown
        builtins.input = o_input


if __name__ == '__main__':
    unittest.main(exit=False)
