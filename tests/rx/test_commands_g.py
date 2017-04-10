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

    def test_too_many_purp_accounts_raises_fr(self):
        # Setup
        ts            = datetime.datetime.now()
        cl            = ["contact_{}@jabber.org".format(n).encode() for n in range(21)]
        cmd_data      = US_BYTE.join([b'testgroup2'] + cl)
        group_list    = GroupList(groups=['testgroup'])
        contact_list  = ContactList(nicks=["contact_{}".format(n) for n in range(21)])
        group         = group_list.get_group('testgroup')
        group.members = contact_list.contacts
        settings      = Settings()
        window_list   = WindowList()

        # Test
        self.assertFR("Error: TFC settings only allow 20 members per group.", group_create, cmd_data, ts, window_list, contact_list, group_list, settings)

    def test_full_group_list_raises_fr(self):
        # Setup
        ts           = datetime.datetime.now()
        cmd_data     = US_BYTE.join([b'testgroup_21', b'contact_21@jabber.org'])
        group_list   = GroupList(groups=["testgroup_{}".format(n) for n in range(20)])
        contact_list = ContactList(nicks=['Alice'])
        settings     = Settings()
        window_list  = WindowList()

        # Test
        self.assertFR("Error: TFC settings only allow 20 groups.", group_create, cmd_data, ts, window_list, contact_list, group_list, settings)

    def test_successful_group_creation(self):
        # Setup
        ts = datetime.datetime.now()
        group_list   = GroupList(groups=['testgroup'])
        cmd_data     = US_BYTE.join([b'testgroup_2', b'bob@jabber.org'])
        contact_list = ContactList(nicks=['Alice', 'Bob'])
        settings     = Settings()
        window_list  = WindowList(nicks       =['Alice', 'Bob'],
                                  contact_list=contact_list,
                                  group_lis   =group_list,
                                  packet_list =None,
                                  settings    =Settings)
        # Test
        self.assertIsNone(group_create(cmd_data, ts, window_list, contact_list, group_list, settings))

class TestGroupAddMember(TFCTestCase):

    def test_too_large_final_member_list_raises_fr(self):
        # Setup
        ts            = datetime.datetime.now()
        group_list    = GroupList(groups=['testgroup'])
        contact_list  = ContactList(nicks=["contact_{}".format(n) for n in range(21)])
        group         = group_list.get_group('testgroup')
        group.members = contact_list.contacts[:20]
        settings      = Settings()
        cmd_data      = US_BYTE.join([b'testgroup', b'contact_20@jabber.org'])
        window_list   = WindowList()

        # Test
        self.assertFR("Error: TFC settings only allow 20 members per group.", group_add_member, cmd_data, ts, window_list, contact_list, group_list, settings)

    def test_successful_group_add(self):
        # Setup
        ts            = datetime.datetime.now()
        contact_list  = ContactList(nicks=["contact_{}".format(n) for n in range(21)])
        group_list    = GroupList(groups=['testgroup'])
        group         = group_list.get_group('testgroup')
        group.members = contact_list.contacts[:19]
        settings      = Settings()
        cmd_data      = US_BYTE.join([b'testgroup', b'contact_20@jabber.org'])
        window_list   = WindowList()

        # Test
        self.assertIsNone(group_add_member(cmd_data, ts, window_list, contact_list, group_list, settings))

        group2 = group_list.get_group('testgroup')
        self.assertEqual(len(group2), 20)

        for c in group2:
            self.assertIsInstance(c, Contact)


class TestGroupRMMember(unittest.TestCase):

    def test_function(self):
        # Setup
        cmd_data      = US_BYTE.join([b'testgroup', b'contact_18@jabber.org', b'contact_20@jabber.org'])
        ts            = datetime.datetime.now()
        window_list   = WindowList()
        contact_list  = ContactList(nicks=["contact_{}".format(n) for n in range(21)])
        group_list    = GroupList(groups=['testgroup'])
        group         = group_list.get_group('testgroup')
        group.members = contact_list.contacts[:19]

        # Test
        self.assertIsNone(group_rm_member(cmd_data, ts, window_list, contact_list, group_list))

        members = [c.rx_account for c in group.members]
        self.assertFalse(b'contact@jabber.org' in members)


class TestRemoveGroup(TFCTestCase):

    def test_missing_group_raises_fr(self):
        # Setup
        cmd_data      = b'testgroup_2'
        ts            = datetime.datetime.now()
        window_list   = WindowList()
        group_list    = GroupList(groups=['testgroup'])

        # Test
        self.assertFR("RxM has no group testgroup_2 to remove.", remove_group, cmd_data, ts, window_list, group_list)

    def test_successful_remove(self):
        # Setup
        cmd_data      = b'testgroup'
        ts            = datetime.datetime.now()
        window_list   = WindowList()
        group_list    = GroupList(groups=['testgroup'])

        # Test
        self.assertIsNone(remove_group(cmd_data, ts, window_list, group_list))
        self.assertEqual(len(group_list.groups), 0)


if __name__ == '__main__':
    unittest.main(exit=False)
