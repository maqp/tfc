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

from src.common.db_contacts import Contact, ContactList
from src.common.db_groups   import Group, GroupList
from src.common.statics     import *

from tests.mock_classes import create_contact, MasterKey, Settings
from tests.utils        import cleanup, TFCTestCase


class TestGroup(unittest.TestCase):

    def setUp(self):
        members       = list(map(create_contact, ['Alice', 'Bob', 'Charlie']))
        self.settings = Settings()
        self.group    = Group('testgroup', False, False, members, self.settings, lambda: None)

    def tearDown(self):
        cleanup()

    def test_group_iterates_over_contact_objects(self):
        for c in self.group:
            self.assertIsInstance(c, Contact)

    def test_len_returns_number_of_members(self):
        self.assertEqual(len(self.group), 3)

    def test_serialize_g(self):
        serialized = self.group.serialize_g()
        self.assertIsInstance(serialized, bytes)
        self.assertEqual(len(serialized),
                         PADDED_UTF32_STR_LEN
                         + (2 * BOOLEAN_SETTING_LEN)
                         + (self.settings.max_number_of_group_members * PADDED_UTF32_STR_LEN))

    def test_add_members(self):
        self.group.members = []
        self.assertFalse(self.group.has_member('david@jabber.org'))
        self.assertFalse(self.group.has_member('eric@jabber.org'))

        self.group.add_members([create_contact(n) for n in ['David', 'Eric']])
        self.assertTrue(self.group.has_member('david@jabber.org'))
        self.assertTrue(self.group.has_member('eric@jabber.org'))

    def test_remove_members(self):
        self.assertTrue(self.group.has_member('alice@jabber.org'))
        self.assertTrue(self.group.has_member('bob@jabber.org'))
        self.assertTrue(self.group.has_member('charlie@jabber.org'))

        self.assertTrue(self.group.remove_members(['charlie@jabber.org', 'eric@jabber.org']))
        self.assertFalse(self.group.remove_members(['charlie@jabber.org', 'eric@jabber.org']))

        self.assertTrue(self.group.has_member('alice@jabber.org'))
        self.assertTrue(self.group.has_member('bob@jabber.org'))
        self.assertFalse(self.group.has_member('charlie@jabber.org'))

    def test_get_list_of_member_accounts(self):
        self.assertEqual(self.group.get_list_of_member_accounts(),
                         ['alice@jabber.org', 'bob@jabber.org', 'charlie@jabber.org'])

    def test_get_list_of_member_nicks(self):
        self.assertEqual(self.group.get_list_of_member_nicks(), ['Alice', 'Bob', 'Charlie'])

    def test_has_member(self):
        self.assertTrue(self.group.has_member('charlie@jabber.org'))
        self.assertFalse(self.group.has_member('david@jabber.org'))

    def test_has_members(self):
        self.assertTrue(self.group.has_members())
        self.group.members = []
        self.assertFalse(self.group.has_members())


class TestGroupList(TFCTestCase):

    def setUp(self):
        self.master_key   = MasterKey()
        self.settings     = Settings()
        self.contact_list = ContactList(self.master_key, self.settings)
        self.group_list   = GroupList(self.master_key, self.settings, self.contact_list)
        members           = [create_contact(n) for n in ['Alice', 'Bob', 'Charlie', 'David', 'Eric',
                                                         'Fido', 'Guido', 'Heidi', 'Ivan', 'Joana', 'Karol']]
        self.contact_list.contacts = members

        groups = [Group(n, False, False, members, self.settings, self.group_list.store_groups)
                  for n in ['testgroup_1', 'testgroup_2', 'testgroup_3', 'testgroup_4', 'testgroup_5',
                            'testgroup_6', 'testgroup_7', 'testgroup_8', 'testgroup_9', 'testgroup_10',
                            'testgroup_11']]

        self.group_list.groups = groups
        self.group_list.store_groups()

        self.single_member_data = (PADDED_UTF32_STR_LEN
                                   + (2 * BOOLEAN_SETTING_LEN)
                                   + (self.settings.max_number_of_group_members * PADDED_UTF32_STR_LEN))

    def tearDown(self):
        cleanup()

    def test_group_list_iterates_over_group_objects(self):
        for g in self.group_list:
            self.assertIsInstance(g, Group)

    def test_len_returns_number_of_groups(self):
        self.assertEqual(len(self.group_list), 11)

    def test_database_size(self):
        self.assertTrue(os.path.isfile(f'{DIR_USER_DATA}ut_groups'))
        self.assertEqual(os.path.getsize(f'{DIR_USER_DATA}ut_groups'),
                         XSALSA20_NONCE_LEN
                         + GROUP_DB_HEADER_LEN
                         + self.settings.max_number_of_groups * self.single_member_data
                         + POLY1305_TAG_LEN)

        self.settings.max_number_of_groups        = 10
        self.settings.max_number_of_group_members = 10

        group_list2 = GroupList(self.master_key, self.settings, self.contact_list)
        self.assertEqual(len(group_list2), 11)

        # Check that load_groups() function increases setting values with larger db
        self.assertEqual(self.settings.max_number_of_groups, 20)
        self.assertEqual(self.settings.max_number_of_group_members, 20)

        # Check that removed contact from contact list updates group
        self.contact_list.remove_contact('Alice')
        group_list3 = GroupList(self.master_key, self.settings, self.contact_list)
        self.assertEqual(len(group_list3.get_group('testgroup_1').members), 10)

        group_list4 = GroupList(self.master_key, self.settings, self.contact_list)
        self.assertEqual(len(group_list4.get_group('testgroup_2').members), 10)

    def test_generate_group_db_header(self):
        header = self.group_list.generate_group_db_header()
        self.assertEqual(len(header), GROUP_DB_HEADER_LEN)
        self.assertIsInstance(header, bytes)

    def test_generate_dummy_group(self):
        dummy_group = self.group_list.generate_dummy_group()
        self.assertEqual(len(dummy_group.serialize_g()), self.single_member_data)
        self.assertIsInstance(dummy_group, Group)

    def test_add_group(self):
        members = [create_contact('Laura')]
        self.group_list.add_group('testgroup_12', False, False, members)
        self.group_list.add_group('testgroup_12', False, True, members)
        self.assertTrue(self.group_list.get_group('testgroup_12').notifications)
        self.assertEqual(len(self.group_list), 12)

    def test_remove_group(self):
        self.assertEqual(len(self.group_list), 11)

        self.assertIsNone(self.group_list.remove_group('testgroup_12'))
        self.assertEqual(len(self.group_list), 11)

        self.assertIsNone(self.group_list.remove_group('testgroup_11'))
        self.assertEqual(len(self.group_list), 10)

    def test_get_list_of_group_names(self):
        g_names = ['testgroup_1', 'testgroup_2', 'testgroup_3', 'testgroup_4', 'testgroup_5', 'testgroup_6',
                   'testgroup_7', 'testgroup_8', 'testgroup_9', 'testgroup_10', 'testgroup_11']
        self.assertEqual(self.group_list.get_list_of_group_names(), g_names)

    def test_get_group(self):
        self.assertEqual(self.group_list.get_group('testgroup_3').name, 'testgroup_3')

    def test_get_group_members(self):
        members = self.group_list.get_group_members('testgroup_1')
        for c in members:
            self.assertIsInstance(c, Contact)

    def test_has_group(self):
        self.assertTrue(self.group_list.has_group('testgroup_11'))
        self.assertFalse(self.group_list.has_group('testgroup_12'))

    def test_has_groups(self):
        self.assertTrue(self.group_list.has_groups())
        self.group_list.groups = []
        self.assertFalse(self.group_list.has_groups())

    def test_largest_group(self):
        self.assertEqual(self.group_list.largest_group(), 11)

    def test_print_group(self):
        self.group_list.get_group("testgroup_1").log_messages  = True
        self.group_list.get_group("testgroup_2").notifications = True
        self.group_list.get_group("testgroup_3").members       = []
        self.assertPrints("""\
Group            Logging     Notify     Members
────────────────────────────────────────────────────────────────────────────────
testgroup_1      Yes         No         Alice, Bob, Charlie, David, Eric, Fido,
                                        Guido, Heidi, Ivan, Joana, Karol

testgroup_2      No          Yes        Alice, Bob, Charlie, David, Eric, Fido,
                                        Guido, Heidi, Ivan, Joana, Karol

testgroup_3      No          No         <Empty group>

testgroup_4      No          No         Alice, Bob, Charlie, David, Eric, Fido,
                                        Guido, Heidi, Ivan, Joana, Karol

testgroup_5      No          No         Alice, Bob, Charlie, David, Eric, Fido,
                                        Guido, Heidi, Ivan, Joana, Karol

testgroup_6      No          No         Alice, Bob, Charlie, David, Eric, Fido,
                                        Guido, Heidi, Ivan, Joana, Karol

testgroup_7      No          No         Alice, Bob, Charlie, David, Eric, Fido,
                                        Guido, Heidi, Ivan, Joana, Karol

testgroup_8      No          No         Alice, Bob, Charlie, David, Eric, Fido,
                                        Guido, Heidi, Ivan, Joana, Karol

testgroup_9      No          No         Alice, Bob, Charlie, David, Eric, Fido,
                                        Guido, Heidi, Ivan, Joana, Karol

testgroup_10     No          No         Alice, Bob, Charlie, David, Eric, Fido,
                                        Guido, Heidi, Ivan, Joana, Karol

testgroup_11     No          No         Alice, Bob, Charlie, David, Eric, Fido,
                                        Guido, Heidi, Ivan, Joana, Karol


""", self.group_list.print_groups)


if __name__ == '__main__':
    unittest.main(exit=False)
