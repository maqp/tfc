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

from src.tx.windows import MockWindow, select_window, TxWindow

from tests.mock_classes import create_contact, ContactList, GroupList, Settings, UserInput
from tests.utils        import TFCTestCase


class TestMockWindow(unittest.TestCase):

    def setUp(self):
        self.window = MockWindow('alice@jabber.org', contacts=[create_contact(n) for n in ['Alice', 'Bob']])

    def test_window_iterates_over_contacts(self):
        for c in self.window:
            self.assertIsInstance(c, Contact)


class TestTxWindow(TFCTestCase):

    def setUp(self):
        self.o_input      = builtins.input
        self.contact_list = ContactList(['Alice', 'Bob'])
        self.group_list   = GroupList(groups=['testgroup', 'testgroup_2'])
        self.settings     = Settings()
        self.window       = TxWindow(self.contact_list, self.group_list)
        self.window.group = self.group_list.get_group('testgroup')
        self.window.type  = WIN_TYPE_GROUP
        self.queues       = {COMMAND_PACKET_QUEUE: Queue(),
                             WINDOW_SELECT_QUEUE:  Queue()}

    def tearDown(self):
        builtins.input = self.o_input

        for key in self.queues:
            while not self.queues[key].empty():
                self.queues[key].get()
            time.sleep(0.1)
            self.queues[key].close()

    def test_window_iterates_over_contacts(self):
        # Setup
        self.window.window_contacts = self.contact_list.contacts

        # Test
        for c in self.window:
            self.assertIsInstance(c, Contact)

    def test_len_returns_number_of_contacts_in_window(self):
        # Setup
        self.window.window_contacts = self.contact_list.contacts

        # Test
        self.assertEqual(len(self.window), 2)

    def test_group_window_change_during_traffic_masking_raises_fr(self):
        # Setup
        self.settings.session_traffic_masking = True
        self.window.uid                       = 'testgroup'

        # Test
        self.assertFR("Error: Can't change window during traffic masking.",
                      self.window.select_tx_window, self.settings, self.queues, selection='testgroup_2', cmd=True)

    def test_contact_window_change_during_traffic_masking_raises_fr(self):
        # Setup
        self.settings.session_traffic_masking = True
        self.window.uid                       = 'alice@jabber.org'

        # Test
        self.assertFR("Error: Can't change window during traffic masking.",
                      self.window.select_tx_window, self.settings, self.queues, selection='bob@jabber.org', cmd=True)

    def test_contact_window_reload_during_traffic_masking(self):
        # Setup
        self.settings.session_traffic_masking = True
        self.window.uid                       = 'alice@jabber.org'

        # Test
        self.assertIsNone(self.window.select_tx_window(self.settings, self.queues, selection='alice@jabber.org', cmd=True))
        self.assertEqual(self.window.uid, 'alice@jabber.org')

    def test_group_window_reload_during_traffic_masking(self):
        # Setup
        self.settings.session_traffic_masking = True
        self.window.uid                       = 'testgroup'

        # Test
        self.assertIsNone(self.window.select_tx_window(self.settings, self.queues, selection='testgroup', cmd=True))
        self.assertEqual(self.window.uid, 'testgroup')

    def test_invalid_selection_raises_fr(self):
        # Setup
        self.window.uid = 'alice@jabber.org'

        # Test
        self.assertFR("Error: No contact/group was found.",
                      self.window.select_tx_window, self.settings, self.queues, selection='charlie@jabber.org', cmd=True)

    def test_window_selection_during_traffic_masking(self):
        # Setup
        self.settings.session_traffic_masking = True
        self.window.uid                       = None
        builtins.input                        = lambda _: 'bob@jabber.org'

        # Test
        self.assertIsNone(self.window.select_tx_window(self.settings, self.queues))
        self.assertEqual(self.queues[WINDOW_SELECT_QUEUE].qsize(), 1)

    def test_contact_window_selection_from_input(self):
        # Setup
        self.window.uid = None
        builtins.input  = lambda _: 'bob@jabber.org'

        # Test
        self.assertIsNone(self.window.select_tx_window(self.settings, self.queues))
        self.assertEqual(self.window.uid, 'bob@jabber.org')

    def test_group_window_selection_from_command(self):
        # Setup
        self.window.uid = None

        # Test
        self.assertIsNone(self.window.select_tx_window(self.settings, self.queues, selection='testgroup', cmd=True))
        self.assertEqual(self.window.uid, 'testgroup')

    def test_deselect_window(self):
        # Setup
        self.window.window_contacts = self.contact_list.contacts
        self.window.contact         = self.contact_list.get_contact('bob@jabber.org')
        self.window.name            = 'Bob'
        self.window.type            = WIN_TYPE_CONTACT
        self.window.uid             = 'bob@jabber.org'
        self.window.imc_name        = 'bob@jabber.org'

        # Test
        self.assertIsNone(self.window.deselect_window())
        self.assertIsNone(self.window.contact)
        self.assertIsNone(self.window.name)
        self.assertIsNone(self.window.type)
        self.assertIsNone(self.window.uid)
        self.assertIsNone(self.window.imc_name)

    def test_is_selected(self):
        self.window.name = None
        self.assertFalse(self.window.is_selected())

        self.window.name = 'bob@jabber.org'
        self.assertTrue(self.window.is_selected())

    def test_update_log_messages_for_contact(self):
        # Setup
        self.window.type = WIN_TYPE_CONTACT
        self.window.log_messages = None
        self.window.contact = self.contact_list.get_contact('Alice')
        self.window.contact.log_messages = False

        # Test
        self.assertIsNone(self.window.update_log_messages())
        self.assertFalse(self.window.log_messages)

    def test_update_log_messages_for_group(self):
        # Setup
        self.window.type = WIN_TYPE_GROUP
        self.window.log_messages = None
        self.window.group = self.group_list.get_group('testgroup')
        self.window.group.log_messages = False

        # Test
        self.assertIsNone(self.window.update_log_messages())
        self.assertFalse(self.window.log_messages)

    def test_update_group_win_members_if_group_is_available(self):
        # Setup
        self.window.window_contacts = []
        self.window.group           = None
        self.window.name            = 'testgroup'
        self.window.type            = WIN_TYPE_GROUP
        self.window.imc_name        = None

        # Test
        self.assertIsNone(self.window.update_group_win_members(self.group_list))

        self.assertEqual(self.window.group, self.group_list.get_group('testgroup'))
        self.assertEqual(self.window.window_contacts, self.window.group.members)
        self.assertEqual(self.window.imc_name, 'alice@jabber.org')

    def test_deactivate_window_if_group_is_not_available(self):
        # Setup
        self.window.window_contacts = []
        self.window.group           = None
        self.window.name            = 'testgroup_3'
        self.window.type            = WIN_TYPE_GROUP
        self.window.imc_name        = None

        # Test
        self.assertIsNone(self.window.update_group_win_members(self.group_list))
        self.assertIsNone(self.window.contact)
        self.assertIsNone(self.window.name)
        self.assertIsNone(self.window.type)
        self.assertIsNone(self.window.uid)
        self.assertIsNone(self.window.imc_name)


class TestSelectWindow(TFCTestCase):

    def setUp(self):
        self.user_input   = UserInput()
        self.contact_list = ContactList(nicks=['Alice'])
        self.group_list   = GroupList()
        self.window       = TxWindow(self.contact_list, self.group_list)
        self.settings     = Settings()
        self.queues       = {COMMAND_PACKET_QUEUE: Queue(),
                             WINDOW_SELECT_QUEUE:  Queue()}

    def tearDown(self):
        for key in self.queues:
            while not self.queues[key].empty():
                self.queues[key].get()
            time.sleep(0.1)
            self.queues[key].close()

    def test_invalid_selection_raises_fr(self):
        # Setup
        self.user_input.plaintext = 'msg'
        self.assertFR("Error: Invalid recipient.", select_window, self.user_input, self.window, self.settings, self.queues)
        time.sleep(0.1)

        # Test
        self.assertEqual(self.queues[COMMAND_PACKET_QUEUE].qsize(), 0)
        self.assertEqual(self.queues[WINDOW_SELECT_QUEUE].qsize(), 0)

    def test_window_selection(self):
        # Setup
        self.user_input.plaintext = 'msg alice@jabber.org'

        # Test
        self.assertIsNone(select_window(self.user_input, self.window, self.settings, self.queues))
        time.sleep(0.1)

        self.assertEqual(self.queues[COMMAND_PACKET_QUEUE].qsize(), 1)
        self.assertEqual(self.queues[WINDOW_SELECT_QUEUE].qsize(), 0)


if __name__ == '__main__':
    unittest.main(exit=False)
