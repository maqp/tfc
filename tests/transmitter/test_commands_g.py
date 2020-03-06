#!/usr/bin/env python3.7
# -*- coding: utf-8 -*-

"""
TFC - Onion-routed, endpoint secure messaging system
Copyright (C) 2013-2020  Markus Ottela

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

import unittest

from unittest import mock
from typing   import Any

from src.common.encoding import b58encode
from src.common.statics  import (COMMAND_PACKET_QUEUE, GROUP_ID_LENGTH, RELAY_PACKET_QUEUE,
                                 WIN_TYPE_CONTACT, WIN_TYPE_GROUP)

from src.transmitter.commands_g import (group_add_member, group_create, group_rm_group, group_rm_member,
                                        process_group_command, group_rename)

from tests.mock_classes import create_group, Contact, ContactList, GroupList, MasterKey, Settings, UserInput, TxWindow
from tests.utils        import cd_unit_test, cleanup, gen_queue_dict, nick_to_pub_key, tear_queues, TFCTestCase


class TestProcessGroupCommand(TFCTestCase):

    def setUp(self) -> None:
        """Pre-test actions."""
        self.contact_list = ContactList(nicks=['Alice'])
        self.group_list   = GroupList()
        self.settings     = Settings()
        self.queues       = gen_queue_dict()
        self.master_key   = MasterKey()
        self.args         = self.contact_list, self.group_list, self.settings, self.queues, self.settings

    def tearDown(self) -> None:
        """Post-test actions."""
        tear_queues(self.queues)

    def test_raises_fr_when_traffic_masking_is_enabled(self) -> None:
        # Setup
        self.settings.traffic_masking = True

        # Test
        self.assert_se("Error: Command is disabled during traffic masking.",
                       process_group_command, UserInput(), *self.args)

    def test_invalid_command_raises_soft_error(self) -> None:
        self.assert_se("Error: Invalid group command.", process_group_command, UserInput('group '), *self.args)

    def test_invalid_command_parameters_raises_soft_error(self) -> None:
        self.assert_se("Error: Invalid group command.", process_group_command, UserInput('group bad'), *self.args)

    def test_missing_group_id_raises_soft_error(self) -> None:
        self.assert_se("Error: No group ID specified.", process_group_command, UserInput('group join '), *self.args)

    def test_invalid_group_id_raises_soft_error(self) -> None:
        self.assert_se("Error: Invalid group ID.", process_group_command, UserInput('group join invalid'), *self.args)

    def test_missing_name_raises_soft_error(self) -> None:
        self.assert_se("Error: No group name specified.", process_group_command, UserInput('group create '), *self.args)

    @mock.patch('builtins.input', return_value='Yes')
    @mock.patch('os.urandom',     return_value=GROUP_ID_LENGTH*b'a')
    def test_successful_command(self, *_: Any) -> None:
        self.assertIsNone(process_group_command(UserInput('group create team Alice'), *self.args))
        user_input = UserInput(f"group join {b58encode(GROUP_ID_LENGTH*b'a')} team2")
        self.assert_se("Error: Group with matching ID already exists.", process_group_command, user_input, *self.args)


class TestGroupCreate(TFCTestCase):

    def setUp(self) -> None:
        """Pre-test actions."""
        self.contact_list = ContactList(nicks=['Alice', 'Bob'])
        self.group_list   = GroupList()
        self.settings     = Settings()
        self.queues       = gen_queue_dict()
        self.master_key   = MasterKey()
        self.account_list = None
        self.args         = self.contact_list, self.group_list, self.settings, self.queues, self.settings

    def tearDown(self) -> None:
        """Post-test actions."""
        tear_queues(self.queues)

    def configure_groups(self, no_contacts: int) -> None:
        """Configure group list."""
        self.contact_list  = ContactList(nicks=[str(n) for n in range(no_contacts)])
        self.group_list    = GroupList(groups=['test_group'])
        self.group         = self.group_list.get_group('test_group')
        self.group.members = self.contact_list.contacts
        self.account_list  = [nick_to_pub_key(str(n)) for n in range(no_contacts)]

    def test_invalid_group_name_raises_soft_error(self) -> None:
        # Setup
        self.configure_groups(no_contacts=21)

        # Test
        self.assert_se("Error: Group name must be printable.",
                       group_create, 'test_group\x1f', self.account_list, *self.args)

    def test_too_many_purp_accounts_raises_soft_error(self) -> None:
        # Setup
        self.configure_groups(no_contacts=60)

        # Test
        cl_str = [nick_to_pub_key(str(n)) for n in range(51)]
        self.assert_se("Error: TFC settings only allow 50 members per group.",
                       group_create, 'test_group_50', cl_str,
                       self.contact_list, self.group_list, self.settings, self.queues, self.master_key)

    def test_full_group_list_raises_soft_error(self) -> None:
        # Setup
        self.group_list = GroupList(groups=[f"testgroup_{n}" for n in range(50)])

        # Test
        self.assert_se("Error: TFC settings only allow 50 groups.",
                       group_create, 'testgroup_50', [nick_to_pub_key("Alice")],
                       self.contact_list, self.group_list, self.settings, self.queues, self.master_key)

    @mock.patch('builtins.input', return_value='Yes')
    def test_successful_group_creation(self, _: Any) -> None:
        # Test
        self.assertIsNone(group_create('test_group_2', [nick_to_pub_key("Alice")], *self.args))
        self.assertEqual(self.queues[COMMAND_PACKET_QUEUE].qsize(), 1)
        self.assertEqual(self.queues[RELAY_PACKET_QUEUE].qsize(),   1)

    def test_successful_empty_group_creation(self) -> None:
        self.assertIsNone(group_create('test_group_2', [], *self.args))
        self.assertEqual(self.queues[COMMAND_PACKET_QUEUE].qsize(), 1)
        self.assertEqual(self.queues[RELAY_PACKET_QUEUE].qsize(),   0)


class TestGroupAddMember(TFCTestCase):

    def setUp(self) -> None:
        """Pre-test actions."""
        self.user_input   = UserInput()
        self.contact_list = ContactList(nicks=['Alice', 'Bob'])
        self.group_list   = GroupList()
        self.settings     = Settings()
        self.queues       = gen_queue_dict()
        self.master_key   = MasterKey()
        self.args         = self.contact_list, self.group_list, self.settings, self.queues, self.settings

    def tearDown(self) -> None:
        """Post-test actions."""
        tear_queues(self.queues)

    def configure_groups(self, no_contacts: int) -> None:
        """Configure group database."""
        self.contact_list  = ContactList(nicks=[str(n) for n in range(no_contacts)])
        self.group_list    = GroupList(groups=['test_group'])
        self.group         = self.group_list.get_group('test_group')
        self.group.members = self.contact_list.contacts
        self.account_list  = [nick_to_pub_key(str(n)) for n in range(no_contacts)]

    @mock.patch('builtins.input', return_value='Yes')
    def test_new_group_is_created_if_specified_group_does_not_exist_and_user_chooses_yes(self, _: Any) -> None:
        self.assertIsNone(group_add_member('test_group', [], *self.args))
        self.assertEqual(self.queues[COMMAND_PACKET_QUEUE].qsize(), 1)
        self.assertEqual(self.queues[RELAY_PACKET_QUEUE].qsize(),   0)

    @mock.patch('time.sleep',     return_value=None)
    @mock.patch('builtins.input', return_value='No')
    def test_raises_fr_if_specified_group_does_not_exist_and_user_chooses_no(self, *_: Any) -> None:
        self.assert_se("Group creation aborted.", group_add_member, 'test_group', [], *self.args)

    def test_too_large_final_member_list_raises_soft_error(self) -> None:
        # Setup
        contact_list  = ContactList(nicks=[str(n) for n in range(51)])
        group_list    = GroupList(groups=['testgroup'])
        group         = group_list.get_group('testgroup')
        group.members = contact_list.contacts[:49]

        # Test
        m_to_add = [nick_to_pub_key("49"), nick_to_pub_key("50")]
        self.assert_se("Error: TFC settings only allow 50 members per group.", group_add_member,
                       'testgroup', m_to_add, contact_list, group_list, self.settings, self.queues, self.master_key)

    @mock.patch('builtins.input', return_value='Yes')
    def test_successful_group_add(self, _: Any) -> None:
        # Setup
        self.configure_groups(no_contacts=51)
        self.group.members = self.contact_list.contacts[:49]

        # Test
        self.assertIsNone(group_add_member('test_group', [nick_to_pub_key("49")], self.contact_list,
                                           self.group_list, self.settings, self.queues, self.master_key))
        group2 = self.group_list.get_group('test_group')
        self.assertEqual(len(group2), 50)

        for c in group2:
            self.assertIsInstance(c, Contact)

        self.assertEqual(self.queues[COMMAND_PACKET_QUEUE].qsize(), 1)
        self.assertEqual(self.queues[RELAY_PACKET_QUEUE].qsize(), 1)


class TestGroupRmMember(TFCTestCase):

    def setUp(self) -> None:
        """Pre-test actions."""
        self.unit_test_dir = cd_unit_test()
        self.user_input    = UserInput()
        self.contact_list  = ContactList(nicks=['Alice', 'Bob'])
        self.group_list    = GroupList(groups=["test_group"])
        self.settings      = Settings()
        self.queues        = gen_queue_dict()
        self.master_key    = MasterKey()
        self.args          = self.contact_list, self.group_list, self.settings, self.queues, self.settings

    def tearDown(self) -> None:
        """Post-test actions."""
        cleanup(self.unit_test_dir)
        tear_queues(self.queues)

    @mock.patch('time.sleep',     return_value=None)
    @mock.patch('builtins.input', return_value='Yes')
    def test_no_accounts_removes_group(self, *_: Any) -> None:
        self.assert_se("Removed group 'test_group'.", group_rm_member, 'test_group', [], *self.args)

    @mock.patch('builtins.input', return_value='Yes')
    def test_remove_members_from_unknown_group(self, _: Any) -> None:
        self.assert_se("Group 'test_group_2' does not exist.",
                       group_rm_member, 'test_group_2', [nick_to_pub_key("Alice")], *self.args)

    @mock.patch('builtins.input', return_value='Yes')
    def test_successful_group_remove(self, _: Any) -> None:
        self.assertIsNone(group_rm_member('test_group', [nick_to_pub_key("Alice")], *self.args))
        self.assertEqual(self.queues[COMMAND_PACKET_QUEUE].qsize(), 1)
        self.assertEqual(self.queues[RELAY_PACKET_QUEUE].qsize(), 1)


class TestGroupRmGroup(TFCTestCase):

    def setUp(self) -> None:
        """Pre-test actions."""
        self.unit_test_dir = cd_unit_test()
        self.user_input    = UserInput()
        self.contact_list  = ContactList(nicks=['Alice', 'Bob'])
        self.group_list    = GroupList(groups=['test_group'])
        self.settings      = Settings()
        self.queues        = gen_queue_dict()
        self.master_key    = MasterKey()
        self.args          = self.contact_list, self.group_list, self.settings, self.queues, self.settings

    def tearDown(self) -> None:
        """Post-test actions."""
        cleanup(self.unit_test_dir)
        tear_queues(self.queues)

    @mock.patch('time.sleep',     return_value=None)
    @mock.patch('builtins.input', return_value='No')
    def test_cancel_of_remove_raises_soft_error(self, *_: Any) -> None:
        self.assert_se("Group removal aborted.", group_rm_group, 'test_group', *self.args)

    @mock.patch('builtins.input', return_value='Yes')
    def test_remove_group_not_on_transmitter_raises_soft_error(self, _: Any) -> None:
        unknown_group_id = b58encode(bytes(GROUP_ID_LENGTH))
        self.assert_se("Transmitter has no group '2dVseX46KS9Sp' to remove.",
                       group_rm_group, unknown_group_id, *self.args)
        self.assertEqual(self.queues[COMMAND_PACKET_QUEUE].qsize(), 2)

    @mock.patch('builtins.input', return_value='Yes')
    def test_invalid_group_id_raises_soft_error(self, _: Any) -> None:
        invalid_group_id = b58encode(bytes(GROUP_ID_LENGTH))[:-1]
        self.assert_se("Error: Invalid group name/ID.", group_rm_group, invalid_group_id, *self.args)

    @mock.patch('time.sleep',     return_value=None)
    @mock.patch('builtins.input', return_value='Yes')
    def test_remove_group_and_notify(self, *_: Any) -> None:
        self.assert_se("Removed group 'test_group'.", group_rm_group, 'test_group', *self.args)
        self.assertEqual(self.queues[COMMAND_PACKET_QUEUE].qsize(), 2)
        self.assertEqual(self.queues[RELAY_PACKET_QUEUE].qsize(),   1)


class TestGroupRename(TFCTestCase):

    def setUp(self) -> None:
        """Pre-test actions."""
        self.queues       = gen_queue_dict()
        self.settings     = Settings()
        self.contact_list = ContactList()
        self.group_list   = GroupList(groups=['test_group'])
        self.window       = TxWindow()
        self.args         = self.window, self.contact_list, self.group_list, self.settings, self.queues

    def tearDown(self) -> None:
        """Post-test actions."""
        tear_queues(self.queues)

    def test_contact_window_raises_soft_error(self) -> None:
        # Setup
        self.window.type = WIN_TYPE_CONTACT

        # Test
        self.assert_se("Error: Selected window is not a group window.", group_rename, "window", *self.args)

    def test_invalid_group_name_raises_soft_error(self) -> None:
        # Setup
        self.window.type  = WIN_TYPE_GROUP
        self.window.group = self.group_list.get_group('test_group')

        # Test
        self.assert_se("Error: Group name must be printable.", group_rename, "window\x1f", *self.args)

    @mock.patch('time.sleep', return_value=None)
    def test_successful_group_change(self, _: Any) -> None:
        # Setup
        group             = create_group('test_group')
        self.window.type  = WIN_TYPE_GROUP
        self.window.uid   = group.group_id
        self.window.group = group

        # Test
        self.assert_se("Renamed group 'test_group' to 'window'.", group_rename, "window", *self.args)
        self.assertEqual(self.queues[COMMAND_PACKET_QUEUE].qsize(), 1)


if __name__ == '__main__':
    unittest.main(exit=False)
