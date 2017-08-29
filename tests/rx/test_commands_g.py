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

import datetime
import unittest

from src.common.statics import *
from src.rx.commands_g  import group_create, group_add_member, group_rm_member, remove_group

from tests.mock_classes import Contact, ContactList, GroupList, Settings, WindowList
from tests.utils        import TFCTestCase


class TestGroupCreate(TFCTestCase):

    def setUp(self):
        self.ts          = datetime.datetime.now()
        self.settings    = Settings()
        self.window_list = WindowList()

    def test_too_many_purp_accounts_raises_fr(self):
        # Setup
        cl            = ["contact_{}@jabber.org".format(n).encode() for n in range(21)]
        cmd_data      = US_BYTE.join([b'test_group2'] + cl)
        group_list    = GroupList(groups=['test_group'])
        contact_list  = ContactList(nicks=["contact_{}".format(n) for n in range(21)])
        group         = group_list.get_group('test_group')
        group.members = contact_list.contacts

        # Test
        self.assertFR("Error: TFC settings only allow 20 members per group.",
                      group_create, cmd_data, self.ts, self.window_list, contact_list, group_list, self.settings)

    def test_full_group_list_raises_fr(self):
        # Setup
        cmd_data     = US_BYTE.join([b'test_group_21', b'contact_21@jabber.org'])
        group_list   = GroupList(groups=["test_group_{}".format(n) for n in range(20)])
        contact_list = ContactList(nicks=['Alice'])

        # Test
        self.assertFR("Error: TFC settings only allow 20 groups.",
                      group_create, cmd_data, self.ts, self.window_list, contact_list, group_list, self.settings)

    def test_successful_group_creation(self):
        # Setup
        group_list   = GroupList(groups=['test_group'])
        cmd_data     = US_BYTE.join([b'test_group_2', b'bob@jabber.org'])
        contact_list = ContactList(nicks=['Alice', 'Bob'])
        window_list  = WindowList(nicks       =['Alice', 'Bob'],
                                  contact_list=contact_list,
                                  group_lis   =group_list,
                                  packet_list =None,
                                  settings    =Settings)
        # Test
        self.assertIsNone(group_create(cmd_data, self.ts, window_list, contact_list, group_list, self.settings))
        self.assertEqual(len(group_list.get_group('test_group')), 2)


class TestGroupAddMember(TFCTestCase):

    def setUp(self):
        self.ts          = datetime.datetime.now()
        self.settings    = Settings()
        self.window_list = WindowList()

    def test_too_large_final_member_list_raises_fr(self):
        # Setup
        group_list    = GroupList(groups=['test_group'])
        contact_list  = ContactList(nicks=["contact_{}".format(n) for n in range(21)])
        group         = group_list.get_group('test_group')
        group.members = contact_list.contacts[:20]
        cmd_data      = US_BYTE.join([b'test_group', b'contact_20@jabber.org'])

        # Test
        self.assertFR("Error: TFC settings only allow 20 members per group.",
                      group_add_member, cmd_data, self.ts, self.window_list, contact_list, group_list, self.settings)

    def test_successful_group_add(self):
        # Setup
        contact_list  = ContactList(nicks=["contact_{}".format(n) for n in range(21)])
        group_list    = GroupList(groups=['test_group'])
        group         = group_list.get_group('test_group')
        group.members = contact_list.contacts[:19]
        cmd_data      = US_BYTE.join([b'test_group', b'contact_20@jabber.org'])

        # Test
        self.assertIsNone(group_add_member(cmd_data, self.ts, self.window_list, contact_list, group_list, self.settings))

        group2 = group_list.get_group('test_group')
        self.assertEqual(len(group2), 20)

        for c in group2:
            self.assertIsInstance(c, Contact)


class TestGroupRMMember(unittest.TestCase):

    def setUp(self):
        self.ts            = datetime.datetime.now()
        self.window_list   = WindowList()
        self.cmd_data      = US_BYTE.join([b'test_group', b'contact_18@jabber.org', b'contact_20@jabber.org'])
        self.contact_list  = ContactList(nicks=["contact_{}".format(n) for n in range(21)])
        self.group_list    = GroupList(groups=['test_group'])
        self.group         = self.group_list.get_group('test_group')
        self.group.members = self.contact_list.contacts[:19]

    def test_function(self):
        self.assertIsNone(group_rm_member(self.cmd_data, self.ts, self.window_list, self.contact_list, self.group_list))
        self.assertFalse(b'contact@jabber.org' in self.group.get_list_of_member_accounts())


class TestRemoveGroup(TFCTestCase):

    def setUp(self):
        self.ts          = datetime.datetime.now()
        self.window_list = WindowList()
        self.group_list  = GroupList(groups=['test_group'])

    def test_missing_group_raises_fr(self):
        # Setup
        cmd_data = b'test_group_2'

        # Test
        self.assertFR("RxM has no group 'test_group_2' to remove.",
                      remove_group, cmd_data, self.ts, self.window_list, self.group_list)

    def test_successful_remove(self):
        # Setup
        cmd_data = b'test_group'

        # Test
        self.assertIsNone(remove_group(cmd_data, self.ts, self.window_list, self.group_list))
        self.assertEqual(len(self.group_list.groups), 0)


if __name__ == '__main__':
    unittest.main(exit=False)
