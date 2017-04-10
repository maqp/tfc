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

import os
import unittest

from src.common.statics     import *
from src.common.db_contacts import Contact, ContactList
from src.common.db_groups   import Group, GroupList

from tests.mock_classes     import create_contact, MasterKey, Settings
from tests.utils            import cleanup


class TestGroup(unittest.TestCase):

    def test_class(self):
        # Setup
        settings = Settings()
        members  = [create_contact(n) for n in ['Alice', 'Bob', 'Charlie']]
        sg_mock  = lambda: None
        group    = Group('testgroup', False, False, members, settings, sg_mock)

        # Test
        for c in group:
            self.assertIsInstance(c, Contact)
        self.assertEqual(len(group), 3)

        bytestring = group.dump_g()
        self.assertIsInstance(bytestring, bytes)
        self.assertEqual(len(bytestring), 1024 + 2 + (20 * 1024))

        self.assertEqual(group.get_list_of_member_accounts(), ['alice@jabber.org', 'bob@jabber.org', 'charlie@jabber.org'])
        self.assertEqual(group.get_list_of_member_nicks(),    ['Alice', 'Bob', 'Charlie'])

        self.assertTrue(group.has_members())
        self.assertFalse(group.has_member('david@jabber.org'))

        group.add_members([create_contact(n) for n in ['David']])
        self.assertTrue(group.has_member('david@jabber.org'))

        self.assertFalse(group.remove_members(['eric@jabber.org']))
        self.assertTrue(group.remove_members(['david@jabber.org']))
        self.assertFalse(group.has_member('david@jabber.org'))

        # Teardown
        cleanup()


class TestGroupList(unittest.TestCase):

    def test_class(self):
        # Setup
        master_key            = MasterKey()
        settings              = Settings()
        contact_list          = ContactList(master_key, settings)
        group_list            = GroupList(master_key, settings, contact_list)
        members               = [create_contact(n) for n in ['Alice', 'Bob', 'Charlie', 'David', 'Eric',
                                                             'Fido', 'Gunter', 'Heidi', 'Ivan', 'Joana', 'Karol']]
        contact_list.contacts = members
        groups                = [Group(n, False, False, members, settings, group_list.store_groups())
                                for n in ['testgroup_1', 'testgroup_2', 'testgroup3', 'testgroup_4', 'testgroup_5',
                                          'testgroup_6', 'testgroup_7', 'testgroup8', 'testgroup_9', 'testgroup_10',
                                          'testgroup_11']]
        group_list.groups = groups
        group_list.store_groups()

        # Test
        for g in group_list:
            self.assertIsInstance(g, Group)
        self.assertEqual(len(group_list), 11)

        self.assertTrue(os.path.isfile(f'{DIR_USER_DATA}/ut_groups'))
        self.assertEqual(os.path.getsize(f'{DIR_USER_DATA}/ut_groups'), 24 + 32 + 20 * (1024 + 2 + (20 * 1024)) + 16)

        settings.m_number_of_groups = 10
        settings.m_members_in_group = 10

        group_list2 = GroupList(master_key, settings, contact_list)

        self.assertEqual(len(group_list2), 11)

        self.assertEqual(settings.m_number_of_groups, 20)
        self.assertEqual(settings.m_members_in_group, 20)

        bytestring = group_list2.generate_header()
        self.assertEqual(len(bytestring), 32)
        self.assertIsInstance(bytestring, bytes)

        dg_bytestring = group_list2.generate_dummy_group()
        self.assertEqual(len(dg_bytestring), (1024 + 2 + (20 * 1024)))
        self.assertIsInstance(dg_bytestring, bytes)

        members.append(create_contact('Laura'))
        group_list2.add_group('testgroup_12', False, False, members)
        group_list2.add_group('testgroup_12', False, True, members)
        self.assertTrue(group_list2.get_group('testgroup_12').notifications)
        self.assertEqual(len(group_list2), 12)
        self.assertEqual(group_list2.largest_group(), 12)

        g_names = ['testgroup_1', 'testgroup_2', 'testgroup3', 'testgroup_4', 'testgroup_5', 'testgroup_6',
                   'testgroup_7', 'testgroup8', 'testgroup_9', 'testgroup_10', 'testgroup_11', 'testgroup_12']
        self.assertEqual(group_list2.get_list_of_group_names(), g_names)

        g_o = group_list2.get_group('testgroup_1')
        self.assertIsInstance(g_o, Group)
        self.assertEqual(g_o.name, 'testgroup_1')
        self.assertTrue(group_list2.has_group('testgroup_12'))
        self.assertFalse(group_list2.has_group('testgroup_13'))
        self.assertTrue(group_list2.has_groups(), True)

        members = group_list2.get_group_members('testgroup_1')
        for c in members:
            self.assertIsInstance(c, Contact)

        self.assertEqual(len(group_list2), 12)
        group_list2.remove_group('testgroup_13')
        self.assertEqual(len(group_list2), 12)
        group_list2.remove_group('testgroup_12')
        self.assertEqual(len(group_list2), 11)
        self.assertIsNone(group_list2.print_groups())

        # Teardown
        cleanup()


if __name__ == '__main__':
    unittest.main(exit=False)
