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
import unittest
import time

from multiprocessing import Queue

from src.common.statics import *
from src.tx.commands_g  import process_group_command, group_create, group_add_member, group_rm_member

from tests.mock_classes import Contact, ContactList, GroupList, Settings, UserInput
from tests.utils        import TFCTestCase


class TestProcessGroupCommand(TFCTestCase):

    def test_during_trickle_raises_fr(self):
        # Setup
        settings = Settings(session_trickle=True)

        # Test
        self.assertFR('Command disabled during trickle connection.', process_group_command, None, None, None, settings, None)

    def test_invalid_command_raises_fr(self):
        # Setup
        user_input = UserInput('group ')
        settings   = Settings()

        # Test
        self.assertFR('Invalid group command.', process_group_command, user_input, None, None, settings, None)

    def test_invalid_command_parameters_raises_fr(self):
        # Setup
        user_input = UserInput('group bad')
        settings   = Settings()

        # Test
        self.assertFR('Invalid group command.', process_group_command, user_input, None, None, settings, None)

    def test_missing_name_raises_fr(self):
        # Setup
        user_input = UserInput('group create ')
        settings   = Settings()

        # Test
        self.assertFR('No group name specified.', process_group_command, user_input, None, None, settings, None)

    def test_successful_command(self):
        # Setup
        user_input     = UserInput('group create team Alice')
        contact_list   = ContactList(nicks=['Alice'])
        group_list     = GroupList()
        settings       = Settings()
        queues         = {COMMAND_PACKET_QUEUE: Queue(),
                          MESSAGE_PACKET_QUEUE: Queue()}
        o_input        = builtins.input
        builtins.input = lambda x: 'Yes'

        # Test
        self.assertIsNone(process_group_command(user_input, contact_list, group_list, settings, queues))

        # Teardown
        builtins.input = o_input
        while not queues[COMMAND_PACKET_QUEUE].empty():
            queues[COMMAND_PACKET_QUEUE].get()
        time.sleep(0.2)


class TestGroupCreate(TFCTestCase):

    def test_non_printable_g_name_raises_fr(self):
        self.assertFR('Group name must be printable.', group_create, 'testgroup\x1f', None, None, None, None, None)

    def test_oversize_group_name_raises_fr(self):
        self.assertFR('Group name must be less than 255 chars long.', group_create, 255*'a', None, None, None, None, None)

    def test_use_of_padding_g_name_raises_fr(self):
        self.assertFR("Group name can't use name reserved for database padding.", group_create, 'dummy_group', None, None, None, None, None)

    def test_using_account_format_raises_fr(self):
        self.assertFR("Group name can't have format of an account.", group_create, 'alice@jabber.org', None, None, None, None, None)

    def test_use_of_contacts_nick_raises_fr(self):
        # Setup
        contact_list = ContactList(nicks=['Alice'])

        # Test
        self.assertFR("Group name can't be nick of contact.", group_create, 'Alice', None, None, contact_list, None, None)

    def test_user_abort_on_existing_group_raises_fr(self):
        # Setup
        group_list     = GroupList(groups=['testgroup'])
        contact_list   = ContactList(nicks=['Alice'])
        o_input        = builtins.input
        builtins.input = lambda x: 'No'

        # Test
        self.assertFR("Group creation aborted.", group_create, 'testgroup', None, group_list, contact_list, None, None)

        # Teardown
        builtins.input = o_input

    def test_too_many_purp_accounts_raises_fr(self):
        # Setup
        group_list    = GroupList(groups=['testgroup'])
        contact_list  = ContactList(nicks=["contact_{}".format(n) for n in range(21)])
        group         = group_list.get_group('testgroup')
        group.members = contact_list.contacts
        settings      = Settings()
        queues        = {COMMAND_PACKET_QUEUE: Queue()}

        # Test
        cl_str = ["contact_{}@jabber.org".format(n) for n in range(21)]
        self.assertFR("Error: TFC settings only allow 20 members per group.", group_create, 'testgroup_21', cl_str, group_list, contact_list, settings, queues)

    def test_full_group_list_raises_fr(self):
        # Setup
        group_list   = GroupList(groups=["testgroup_{}".format(n) for n in range(20)])
        contact_list = ContactList(nicks=['Alice'])
        settings     = Settings()

        # Test
        self.assertFR("Error: TFC settings only allow 20 groups.", group_create, 'testgroup_20', ['alice@jabber.org'], group_list, contact_list, settings, None)

    def test_successful_group_creation(self):
        # Setup
        group_list     = GroupList(groups=['testgroup'])
        contact_list   = ContactList(nicks=['Alice', 'Bob'])
        settings       = Settings()
        queues         = {COMMAND_PACKET_QUEUE: Queue(),
                          MESSAGE_PACKET_QUEUE: Queue()}
        o_input        = builtins.input
        builtins.input = lambda x: 'Yes'

        # Test
        self.assertIsNone(group_create('testgroup_2', ['alice@jabber.org'], group_list, contact_list, settings, queues))
        self.assertEqual(queues[COMMAND_PACKET_QUEUE].qsize(), 1)
        self.assertEqual(queues[MESSAGE_PACKET_QUEUE].qsize(), 1)

        # Teardown
        builtins.input = o_input
        while not queues[COMMAND_PACKET_QUEUE].empty():
            queues[COMMAND_PACKET_QUEUE].get()
        while not queues[COMMAND_PACKET_QUEUE].empty():
            queues[MESSAGE_PACKET_QUEUE].get()
        time.sleep(0.2)

    def test_successful_empty_group_creation(self):
        # Setup
        group_list     = GroupList()
        contact_list   = ContactList(nicks=['Alice', 'Bob'])
        settings       = Settings()
        queues         = {COMMAND_PACKET_QUEUE: Queue(),
                          MESSAGE_PACKET_QUEUE: Queue()}
        o_input        = builtins.input
        builtins.input = lambda x: 'Yes'

        # Test
        self.assertIsNone(group_create('testgroup_2', [], group_list, contact_list, settings, queues))
        self.assertEqual(queues[COMMAND_PACKET_QUEUE].qsize(), 1)
        self.assertEqual(queues[MESSAGE_PACKET_QUEUE].qsize(), 0)

        # Teardown
        builtins.input = o_input
        while not queues[COMMAND_PACKET_QUEUE].empty():
            queues[COMMAND_PACKET_QUEUE].get()
        while not queues[COMMAND_PACKET_QUEUE].empty():
            queues[MESSAGE_PACKET_QUEUE].get()
        time.sleep(0.2)


class TestGroupAddMember(TFCTestCase):

    def test_new_group_is_created_if_specified_group_does_not_exist_and_user_chooses_yes(self):
        # Setup
        group_list     = GroupList()
        contact_list   = ContactList(nicks=['Alice', 'Bob'])
        settings       = Settings()
        queues         = {COMMAND_PACKET_QUEUE: Queue(),
                          MESSAGE_PACKET_QUEUE: Queue()}
        o_input        = builtins.input
        builtins.input = lambda x: 'Yes'

        # Test
        self.assertIsNone(group_add_member('test_group', [], group_list, contact_list, settings, queues))
        self.assertEqual(queues[COMMAND_PACKET_QUEUE].qsize(), 1)
        self.assertEqual(queues[MESSAGE_PACKET_QUEUE].qsize(), 0)

        # Teardown
        builtins.input = o_input
        while not queues[COMMAND_PACKET_QUEUE].empty():
            queues[COMMAND_PACKET_QUEUE].get()
        while not queues[COMMAND_PACKET_QUEUE].empty():
            queues[MESSAGE_PACKET_QUEUE].get()
        time.sleep(0.2)

    def test_raises_fr_if_specified_group_does_not_exist_and_user_chooses_no(self):
        # Setup
        group_list     = GroupList()
        contact_list   = ContactList(nicks=['Alice', 'Bob'])
        settings       = Settings()
        queues         = {COMMAND_PACKET_QUEUE: Queue(),
                          MESSAGE_PACKET_QUEUE: Queue()}
        o_input        = builtins.input
        builtins.input = lambda x: 'No'

        # Test
        self.assertFR("Group creation aborted.", group_add_member, 'test_group', [], group_list, contact_list, settings, queues)

        # Teardown
        builtins.input = o_input

    def test_too_large_final_member_list_raises_fr(self):
        # Setup
        group_list    = GroupList(groups=['testgroup'])
        contact_list  = ContactList(nicks=["contact_{}".format(n) for n in range(21)])
        group         = group_list.get_group('testgroup')
        group.members = contact_list.contacts[:19]
        settings      = Settings()
        queues        = {COMMAND_PACKET_QUEUE: Queue()}

        # Test
        m_to_add = ["contact_19@jabber.org", "contact_20@jabber.org"]
        self.assertFR("Error: TFC settings only allow 20 members per group.", group_add_member, 'testgroup', m_to_add, group_list, contact_list, settings, queues)

    def test_successful_group_add(self):
        # Setup
        group_list     = GroupList(groups=['testgroup'])
        contact_list   = ContactList(nicks=["contact_{}".format(n) for n in range(21)])
        group          = group_list.get_group('testgroup')
        group.members  = contact_list.contacts[:19]
        settings       = Settings()
        queues         = {COMMAND_PACKET_QUEUE: Queue(),
                          MESSAGE_PACKET_QUEUE: Queue()}
        o_input        = builtins.input
        builtins.input = lambda x: 'Yes'

        # Test
        m_to_add = ["contact_19@jabber.org"]
        self.assertIsNone(group_add_member('testgroup', m_to_add, group_list, contact_list, settings, queues))

        group2 = group_list.get_group('testgroup')
        self.assertEqual(len(group2), 20)

        for c in group2:
            self.assertIsInstance(c, Contact)

        self.assertEqual(queues[COMMAND_PACKET_QUEUE].qsize(), 1)
        self.assertEqual(queues[MESSAGE_PACKET_QUEUE].qsize(), 20)

        # Teardown
        builtins.input = o_input
        while not queues[COMMAND_PACKET_QUEUE].empty():
            queues[COMMAND_PACKET_QUEUE].get()
        while not queues[COMMAND_PACKET_QUEUE].empty():
            queues[MESSAGE_PACKET_QUEUE].get()
        time.sleep(0.2)


class TestGroupRmMember(TFCTestCase):

    def test_cancel_of_remove_raises_fr(self):
        # Setup
        o_input        = builtins.input
        builtins.input = lambda x: 'No'

        # Test
        self.assertFR("Group removal aborted.", group_rm_member, 'testgroup', [], None, None, None, None)

        # Teardown
        builtins.input = o_input

    def test_remove_group_not_on_txm(self):
        # Setup
        o_input        = builtins.input
        builtins.input = lambda x: 'Yes'
        queues         = {COMMAND_PACKET_QUEUE: Queue()}
        settings       = Settings()
        group_list     = GroupList()

        # Test
        self.assertFR("TxM has no group testgroup to remove.", group_rm_member, 'testgroup', [], group_list, None, settings, queues)
        self.assertEqual(queues[COMMAND_PACKET_QUEUE].qsize(), 1)

        # Teardown
        builtins.input = o_input
        while not queues[COMMAND_PACKET_QUEUE].empty():
            queues[COMMAND_PACKET_QUEUE].get()
        time.sleep(0.2)

    def test_remove_group_and_notify(self):
        # Setup
        o_input        = builtins.input
        builtins.input = lambda x: 'Yes'
        queues         = {COMMAND_PACKET_QUEUE: Queue(),
                          MESSAGE_PACKET_QUEUE: Queue()}
        settings       = Settings()
        group_list     = GroupList(groups=['testgroup'])

        # Test
        self.assertFR("Removed group testgroup.", group_rm_member, 'testgroup', [], group_list, None, settings, queues)
        self.assertEqual(queues[COMMAND_PACKET_QUEUE].qsize(), 1)
        self.assertEqual(queues[MESSAGE_PACKET_QUEUE].qsize(), 2)

        # Teardown
        builtins.input = o_input
        while not queues[COMMAND_PACKET_QUEUE].empty():
            queues[COMMAND_PACKET_QUEUE].get()
        time.sleep(0.2)

    def test_remove_members_from_unknown_group(self):
        # Setup
        group_list = GroupList(groups=['testgroup2'])

        # Test
        self.assertFR("Group 'testgroup' does not exist.", group_rm_member, 'testgroup', ['alice@jabber.org'], group_list, None, None, None)

    def test_succesful_group_remove(self):
        # Setup
        o_input        = builtins.input
        builtins.input = lambda x: 'Yes'
        queues         = {COMMAND_PACKET_QUEUE: Queue(),
                          MESSAGE_PACKET_QUEUE: Queue()}
        settings       = Settings()
        group_list     = GroupList(groups=['testgroup'])
        contact_list   = ContactList(nicks=['Alice', 'Bob'])

        # Test
        self.assertIsNone(group_rm_member('testgroup', ['alice@jabber.org'], group_list, contact_list, settings, queues))
        self.assertEqual(queues[COMMAND_PACKET_QUEUE].qsize(), 1)
        self.assertEqual(queues[MESSAGE_PACKET_QUEUE].qsize(), 1)

        # Teardown
        builtins.input = o_input
        while not queues[COMMAND_PACKET_QUEUE].empty():
            queues[COMMAND_PACKET_QUEUE].get()
        time.sleep(0.2)


if __name__ == '__main__':
    unittest.main(exit=False)
