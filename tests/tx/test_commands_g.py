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

from src.common.statics import *

from src.tx.commands_g import group_add_member, group_create, group_rm_group, group_rm_member, process_group_command, validate_group_name

from tests.mock_classes import Contact, ContactList, GroupList, MasterKey, Settings, UserInput
from tests.utils        import TFCTestCase


class TestProcessGroupCommand(TFCTestCase):

    def setUp(self):
        self.o_input   = builtins.input
        builtins.input = lambda _: 'Yes'

        self.user_input   = UserInput()
        self.contact_list = ContactList(nicks=['Alice'])
        self.group_list   = GroupList()
        self.settings     = Settings()
        self.queues       = {COMMAND_PACKET_QUEUE: Queue(),
                             MESSAGE_PACKET_QUEUE: Queue()}
        self.master_key   = MasterKey()

    def tearDown(self):
        builtins.input = self.o_input

        for key in self.queues:
            while not self.queues[key].empty():
                self.queues[key].get()
            time.sleep(0.1)
            self.queues[key].close()

    def test_raises_fr_when_traffic_masking_is_enabled(self):
        self.assertFR("Error: Command is disabled during traffic masking.",
                      process_group_command, self.user_input, self.contact_list,
                      self.group_list, Settings(session_traffic_masking=True), self.queues, self.master_key)

    def test_invalid_command_raises_fr(self):
        self.assertFR("Error: Invalid group command.",
                      process_group_command, UserInput('group '), self.contact_list,
                      self.group_list, self.settings, self.queues, self.master_key)

    def test_invalid_command_parameters_raises_fr(self):
        self.assertFR("Error: Invalid group command.",
                      process_group_command, UserInput('group bad'), self.contact_list,
                      self.group_list, self.settings, self.queues, self.master_key)

    def test_missing_name_raises_fr(self):
        self.assertFR("Error: No group name specified.",
                      process_group_command, UserInput('group create '), self.contact_list,
                      self.group_list, self.settings, self.queues, self.master_key)

    def test_successful_command(self):
        self.assertIsNone(process_group_command(UserInput('group create team Alice'), self.contact_list,
                                                self.group_list, self.settings, self.queues, self.master_key))


class TestValidateGroupName(TFCTestCase):

    def setUp(self):
        self.contact_list = ContactList(nicks=['Alice'])
        self.group_list   = GroupList(groups=['testgroup'])
        builtins.input    = lambda _: 'No'

    def test_non_printable_group_name_raises_fr(self):
        self.assertFR("Error: Group name must be printable.",
                      validate_group_name, 'testgroup\x1f', self.contact_list, self.group_list)

    def test_too_long_group_name_raises_fr(self):
        self.assertFR("Error: Group name must be less than 255 chars long.",
                      validate_group_name, PADDING_LEN * 'a', self.contact_list, self.group_list)

    def test_use_of_dummy_group_name_raises_fr(self):
        self.assertFR("Error: Group name can't use name reserved for database padding.",
                      validate_group_name, DUMMY_GROUP, self.contact_list, self.group_list)

    def test_group_name_with_account_format_raises_fr(self):
        self.assertFR("Error: Group name can't have format of an account.",
                      validate_group_name, 'alice@jabber.org', self.contact_list, self.group_list)

    def test_use_of_contact_nick_raises_fr(self):
        self.assertFR("Error: Group name can't be nick of contact.",
                      validate_group_name, 'Alice', self.contact_list, self.group_list)

    def test_user_abort_on_existing_group_raises_fr(self):
        self.assertFR("Group creation aborted.",
                      validate_group_name, 'testgroup', self.contact_list, self.group_list)

    def test_valid_group_name(self):
        self.assertIsNone(validate_group_name('testgroup2', self.contact_list, self.group_list))


class TestGroupCreate(TFCTestCase):

    def setUp(self):
        self.o_input   = builtins.input
        builtins.input = lambda _: 'Yes'

        self.user_input   = UserInput()
        self.contact_list = ContactList(nicks=['Alice', 'Bob'])
        self.group_list   = GroupList()
        self.settings     = Settings()
        self.queues       = {COMMAND_PACKET_QUEUE: Queue(),
                             MESSAGE_PACKET_QUEUE: Queue()}
        self.master_key   = MasterKey()

    def tearDown(self):
        builtins.input = self.o_input

        for key in self.queues:
            while not self.queues[key].empty():
                self.queues[key].get()
            time.sleep(0.1)
            self.queues[key].close()

    def test_too_many_purp_accounts_raises_fr(self):
        # Setup
        group_list    = GroupList(groups=['testgroup'])
        contact_list  = ContactList(nicks=["contact_{}".format(n) for n in range(21)])
        group         = group_list.get_group('testgroup')
        group.members = contact_list.contacts

        # Test
        cl_str = ["contact_{}@jabber.org".format(n) for n in range(21)]
        self.assertFR("Error: TFC settings only allow 20 members per group.",
                      group_create, 'testgroup_21', cl_str, group_list, contact_list, self.settings, self.queues, self.master_key)

    def test_full_group_list_raises_fr(self):
        # Setup
        group_list   = GroupList(groups=["testgroup_{}".format(n) for n in range(20)])
        contact_list = ContactList(nicks=['Alice'])

        # Test
        self.assertFR("Error: TFC settings only allow 20 groups.",
                      group_create, 'testgroup_20', ['alice@jabber.org'], group_list, contact_list, self.settings, self.queues, self.master_key)

    def test_successful_group_creation(self):
        # Setup
        group_list = GroupList(groups=['testgroup'])

        # Test
        self.assertIsNone(group_create('testgroup_2', ['alice@jabber.org'], group_list, self.contact_list, self.settings, self.queues, self.master_key))
        time.sleep(0.1)
        self.assertEqual(self.queues[COMMAND_PACKET_QUEUE].qsize(), 1)
        self.assertEqual(self.queues[MESSAGE_PACKET_QUEUE].qsize(), 1)

    def test_successful_empty_group_creation(self):
        self.assertIsNone(group_create('testgroup_2', [], self.group_list, self.contact_list, self.settings, self.queues, self.master_key))
        time.sleep(0.1)
        self.assertEqual(self.queues[COMMAND_PACKET_QUEUE].qsize(), 1)
        self.assertEqual(self.queues[MESSAGE_PACKET_QUEUE].qsize(), 0)


class TestGroupAddMember(TFCTestCase):

    def setUp(self):
        self.o_input   = builtins.input
        builtins.input = lambda _: 'Yes'

        self.user_input   = UserInput()
        self.contact_list = ContactList(nicks=['Alice', 'Bob'])
        self.group_list   = GroupList()
        self.settings     = Settings()
        self.queues       = {COMMAND_PACKET_QUEUE: Queue(),
                             MESSAGE_PACKET_QUEUE: Queue()}
        self.master_key   = MasterKey()

    def tearDown(self):
        builtins.input = self.o_input

        for key in self.queues:
            while not self.queues[key].empty():
                self.queues[key].get()
            time.sleep(0.1)
            self.queues[key].close()

    def test_new_group_is_created_if_specified_group_does_not_exist_and_user_chooses_yes(self):
        self.assertIsNone(group_add_member('test_group', [], self.group_list, self.contact_list,
                                           self.settings, self.queues, self.master_key))
        time.sleep(0.1)
        self.assertEqual(self.queues[COMMAND_PACKET_QUEUE].qsize(), 1)
        self.assertEqual(self.queues[MESSAGE_PACKET_QUEUE].qsize(), 0)

    def test_raises_fr_if_specified_group_does_not_exist_and_user_chooses_no(self):
        # Setup
        builtins.input = lambda _: 'No'

        # Test
        self.assertFR("Group creation aborted.",
                      group_add_member, 'test_group', [], self.group_list, self.contact_list,
                      self.settings, self.queues, self.master_key)

    def test_too_large_final_member_list_raises_fr(self):
        # Setup
        group_list    = GroupList(groups=['testgroup'])
        contact_list  = ContactList(nicks=["contact_{}".format(n) for n in range(21)])
        group         = group_list.get_group('testgroup')
        group.members = contact_list.contacts[:19]

        # Test
        m_to_add = ["contact_19@jabber.org", "contact_20@jabber.org"]
        self.assertFR("Error: TFC settings only allow 20 members per group.",
                      group_add_member, 'testgroup', m_to_add, group_list, contact_list, self.settings, self.queues, self.master_key)

    def test_successful_group_add(self):
        # Setup
        group_list    = GroupList(groups=['testgroup'])
        contact_list  = ContactList(nicks=["contact_{}".format(n) for n in range(21)])
        group         = group_list.get_group('testgroup')
        group.members = contact_list.contacts[:19]

        # Test
        m_to_add = ["contact_19@jabber.org"]
        self.assertIsNone(group_add_member('testgroup', m_to_add, group_list, contact_list, self.settings, self.queues, self.master_key))
        time.sleep(0.1)

        group2 = group_list.get_group('testgroup')
        self.assertEqual(len(group2), 20)

        for c in group2:
            self.assertIsInstance(c, Contact)

        self.assertEqual(self.queues[COMMAND_PACKET_QUEUE].qsize(), 1)
        self.assertEqual(self.queues[MESSAGE_PACKET_QUEUE].qsize(), 20)


class TestGroupRmMember(TFCTestCase):

    def setUp(self):
        self.o_input   = builtins.input
        builtins.input = lambda _: 'Yes'

        self.user_input   = UserInput()
        self.contact_list = ContactList(nicks=['Alice', 'Bob'])
        self.group_list   = GroupList()
        self.settings     = Settings()
        self.queues       = {COMMAND_PACKET_QUEUE: Queue(),
                             MESSAGE_PACKET_QUEUE: Queue()}
        self.master_key   = MasterKey()

    def tearDown(self):
        builtins.input = self.o_input

        for key in self.queues:
            while not self.queues[key].empty():
                self.queues[key].get()
            time.sleep(0.1)
            self.queues[key].close()

    def test_no_accounts_removes_group(self):
        # Setup
        group_list = GroupList(groups=['testgroup'])

        # Test
        self.assertFR("Removed group 'testgroup'",
                      group_rm_member, 'testgroup', [], group_list, self.contact_list,
                      self.settings, self.queues, self.master_key)

    def test_remove_members_from_unknown_group(self):
        # Setup
        group_list = GroupList(groups=['testgroup2'])

        # Test
        self.assertFR("Group 'testgroup' does not exist.",
                      group_rm_member, 'testgroup', ['alice@jabber.org'], group_list,
                      self.contact_list, self.settings, self.queues, self.master_key)

    def test_successful_group_remove(self):
        # Setup
        group_list = GroupList(groups=['testgroup'])

        # Test
        self.assertIsNone(group_rm_member('testgroup', ['alice@jabber.org'], group_list,
                                          self.contact_list, self.settings, self.queues, self.master_key))
        time.sleep(0.1)
        self.assertEqual(self.queues[COMMAND_PACKET_QUEUE].qsize(), 1)
        self.assertEqual(self.queues[MESSAGE_PACKET_QUEUE].qsize(), 1)


class TestGroupRemoveGroup(TFCTestCase):

    def setUp(self):
        self.o_input   = builtins.input
        builtins.input = lambda _: 'Yes'

        self.user_input   = UserInput()
        self.contact_list = ContactList(nicks=['Alice', 'Bob'])
        self.group_list   = GroupList()
        self.settings     = Settings()
        self.queues       = {COMMAND_PACKET_QUEUE: Queue(),
                             MESSAGE_PACKET_QUEUE: Queue()}
        self.master_key   = MasterKey()

    def tearDown(self):
        builtins.input = self.o_input

        for key in self.queues:
            while not self.queues[key].empty():
                self.queues[key].get()
            time.sleep(0.1)
            self.queues[key].close()

    def test_cancel_of_remove_raises_fr(self):
        # Setup
        builtins.input = lambda _: 'No'

        # Test
        self.assertFR("Group removal aborted.",
                      group_rm_group, 'testgroup', self.group_list, self.settings, self.queues, self.master_key)

    def test_remove_group_not_on_txm(self):
        self.assertFR("TxM has no group 'testgroup' to remove.",
                      group_rm_group, 'testgroup', self.group_list, self.settings, self.queues, self.master_key)
        time.sleep(0.1)
        self.assertEqual(self.queues[COMMAND_PACKET_QUEUE].qsize(), 2)

    def test_remove_group_and_notify(self):
        # Setup
        group_list = GroupList(groups=['testgroup'])

        # Test
        self.assertFR("Removed group 'testgroup'",
                      group_rm_group, 'testgroup', group_list, self.settings, self.queues, self.master_key)
        time.sleep(0.1)
        self.assertEqual(self.queues[COMMAND_PACKET_QUEUE].qsize(), 2)
        self.assertEqual(self.queues[MESSAGE_PACKET_QUEUE].qsize(), 2)


if __name__ == '__main__':
    unittest.main(exit=False)
