#!/usr/bin/env python3.7
# -*- coding: utf-8 -*-

"""
TFC - Onion-routed, endpoint secure messaging system
Copyright (C) 2013-2019  Markus Ottela

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

import os
import unittest

from src.common.crypto      import encrypt_and_sign
from src.common.db_contacts import Contact, ContactList
from src.common.db_groups   import Group, GroupList
from src.common.encoding    import b58encode
from src.common.misc        import ensure_dir
from src.common.statics     import (DIR_USER_DATA, GROUP_DB_HEADER_LENGTH, GROUP_ID_LENGTH, GROUP_STATIC_LENGTH,
                                    ONION_SERVICE_PUBLIC_KEY_LENGTH, POLY1305_TAG_LENGTH, XCHACHA20_NONCE_LENGTH)

from tests.mock_classes import create_contact, group_name_to_group_id, MasterKey, nick_to_pub_key, Settings
from tests.utils        import cd_unit_test, cleanup, tamper_file, TFCTestCase


class TestGroup(unittest.TestCase):

    def setUp(self):
        """Pre-test actions."""
        self.unit_test_dir = cd_unit_test()
        self.nicks         = ['Alice', 'Bob', 'Charlie']
        members            = list(map(create_contact, self.nicks))
        self.settings      = Settings()
        self.group         = Group(name         ='test_group',
                                   group_id     =group_name_to_group_id('test_group'),
                                   log_messages =False,
                                   notifications=False,
                                   members      =members,
                                   settings     =self.settings,
                                   store_groups =lambda: None)
        ensure_dir(DIR_USER_DATA)

    def tearDown(self):
        """Post-test actions."""
        cleanup(self.unit_test_dir)

    def test_group_iterates_over_contact_objects(self):
        for c in self.group:
            self.assertIsInstance(c, Contact)

    def test_len_returns_the_number_of_members(self):
        self.assertEqual(len(self.group), len(self.nicks))

    def test_group_serialization_length_and_type(self):
        serialized = self.group.serialize_g()
        self.assertIsInstance(serialized, bytes)
        self.assertEqual(len(serialized), GROUP_STATIC_LENGTH + (self.settings.max_number_of_group_members
                                                                 * ONION_SERVICE_PUBLIC_KEY_LENGTH))

    def test_add_members(self):
        # Test members to be added are not already in group
        self.assertFalse(self.group.has_member(nick_to_pub_key('David')))
        self.assertFalse(self.group.has_member(nick_to_pub_key('Eric')))

        self.assertIsNone(self.group.add_members(list(map(create_contact, ['Alice', 'David', 'Eric']))))

        # Test new members were added
        self.assertTrue(self.group.has_member(nick_to_pub_key('David')))
        self.assertTrue(self.group.has_member(nick_to_pub_key('Eric')))

        # Test Alice was not added twice
        self.assertEqual(len(self.group), len(['Alice', 'Bob', 'Charlie', 'David', 'Eric']))

    def test_remove_members(self):
        # Test members to be removed are part of group
        self.assertTrue(self.group.has_member(nick_to_pub_key('Alice')))
        self.assertTrue(self.group.has_member(nick_to_pub_key('Bob')))
        self.assertTrue(self.group.has_member(nick_to_pub_key('Charlie')))

        # Test first attempt to remove returns True (because Charlie was removed)
        self.assertTrue(self.group.remove_members([nick_to_pub_key('Charlie'), nick_to_pub_key('Unknown')]))

        # Test second attempt to remove returns False (because no-one was removed)
        self.assertFalse(self.group.remove_members([nick_to_pub_key('Charlie'), nick_to_pub_key('Unknown')]))

        # Test Charlie was removed
        self.assertFalse(self.group.has_member(nick_to_pub_key('Charlie')))

        # Test no other members were removed
        self.assertTrue(self.group.has_member(nick_to_pub_key('Alice')))
        self.assertTrue(self.group.has_member(nick_to_pub_key('Bob')))

    def test_get_list_of_member_pub_keys(self):
        self.assertEqual(first=self.group.get_list_of_member_pub_keys(),
                         second=[nick_to_pub_key('Alice'),
                                 nick_to_pub_key('Bob'),
                                 nick_to_pub_key('Charlie')])

    def test_has_member(self):
        self.assertTrue(self.group.has_member(nick_to_pub_key('Charlie')))
        self.assertFalse(self.group.has_member(nick_to_pub_key('David')))

    def test_has_members(self):
        self.assertFalse(self.group.empty())
        self.group.members = []
        self.assertTrue(self.group.empty())


class TestGroupList(TFCTestCase):

    def setUp(self):
        """Pre-test actions."""
        self.unit_test_dir = cd_unit_test()
        self.master_key    = MasterKey()
        self.settings      = Settings()
        self.file_name     = f'{DIR_USER_DATA}{self.settings.software_operation}_groups'
        self.contact_list  = ContactList(self.master_key, self.settings)
        self.group_list    = GroupList(self.master_key, self.settings, self.contact_list)
        self.nicks         = ['Alice', 'Bob', 'Charlie', 'David', 'Eric',
                              'Fido', 'Guido', 'Heidi', 'Ivan', 'Joana', 'Karol']
        self.group_names   = ['test_group_1', 'test_group_2', 'test_group_3', 'test_group_4', 'test_group_5',
                              'test_group_6', 'test_group_7', 'test_group_8', 'test_group_9', 'test_group_10',
                              'test_group_11']
        members            = list(map(create_contact, self.nicks))

        self.contact_list.contacts = members

        self.group_list.groups = \
            [Group(name         =name,
                   group_id     =group_name_to_group_id(name),
                   log_messages =False,
                   notifications=False,
                   members      =members,
                   settings     =self.settings,
                   store_groups =self.group_list.store_groups)
             for name in self.group_names]

        self.single_member_data_len = (GROUP_STATIC_LENGTH
                                       + self.settings.max_number_of_group_members * ONION_SERVICE_PUBLIC_KEY_LENGTH)

    def tearDown(self):
        """Post-test actions."""
        cleanup(self.unit_test_dir)

    def test_group_list_iterates_over_group_objects(self):
        for g in self.group_list:
            self.assertIsInstance(g, Group)

    def test_len_returns_the_number_of_groups(self):
        self.assertEqual(len(self.group_list), len(self.group_names))

    def test_storing_and_loading_of_groups(self):
        self.group_list.store_groups()

        self.assertTrue(os.path.isfile(self.file_name))
        self.assertEqual(os.path.getsize(self.file_name),
                         XCHACHA20_NONCE_LENGTH
                         + GROUP_DB_HEADER_LENGTH
                         + self.settings.max_number_of_groups * self.single_member_data_len
                         + POLY1305_TAG_LENGTH)

        # Reduce setting values from 20 to 10
        self.settings.max_number_of_groups        = 10
        self.settings.max_number_of_group_members = 10

        group_list2 = GroupList(self.master_key, self.settings, self.contact_list)
        self.assertEqual(len(group_list2), 11)

        # Check that `_load_groups()` increased setting values back to 20 so it fits the 11 groups
        self.assertEqual(self.settings.max_number_of_groups,        20)
        self.assertEqual(self.settings.max_number_of_group_members, 20)

        # Check that removed contact from contact list updates group
        self.contact_list.remove_contact_by_address_or_nick('Alice')
        group_list3 = GroupList(self.master_key, self.settings, self.contact_list)
        self.assertEqual(len(group_list3.get_group('test_group_1').members), 10)

    def test_invalid_content_raises_critical_error(self):
        # Setup
        invalid_data = b'a'
        pt_bytes     = self.group_list._generate_group_db_header()
        pt_bytes    += b''.join([g.serialize_g() for g in (self.group_list.groups + self.group_list._dummy_groups())])
        ct_bytes     = encrypt_and_sign(pt_bytes + invalid_data, self.master_key.master_key)

        ensure_dir(DIR_USER_DATA)
        with open(self.file_name, 'wb+') as f:
            f.write(ct_bytes)

        # Test
        with self.assertRaises(SystemExit):
            GroupList(self.master_key, self.settings, self.contact_list)

    def test_load_of_modified_database_raises_critical_error(self):
        self.group_list.store_groups()

        # Test reading works normally
        self.assertIsInstance(GroupList(self.master_key, self.settings, self.contact_list), GroupList)

        # Test loading of the tampered database raises CriticalError
        tamper_file(self.file_name, tamper_size=1)
        with self.assertRaises(SystemExit):
            GroupList(self.master_key, self.settings, self.contact_list)

    def test_check_db_settings(self):
        self.assertFalse(self.group_list._check_db_settings(
            number_of_actual_groups=self.settings.max_number_of_groups,
            members_in_largest_group=self.settings.max_number_of_group_members))

        self.assertTrue(self.group_list._check_db_settings(
            number_of_actual_groups=self.settings.max_number_of_groups + 1,
            members_in_largest_group=self.settings.max_number_of_group_members))

        self.assertTrue(self.group_list._check_db_settings(
            number_of_actual_groups=self.settings.max_number_of_groups,
            members_in_largest_group=self.settings.max_number_of_group_members + 1))

    def test_generate_group_db_header(self):
        header = self.group_list._generate_group_db_header()
        self.assertEqual(len(header), GROUP_DB_HEADER_LENGTH)
        self.assertIsInstance(header, bytes)

    def test_generate_dummy_group(self):
        dummy_group = self.group_list._generate_dummy_group()
        self.assertIsInstance(dummy_group, Group)
        self.assertEqual(len(dummy_group.serialize_g()), self.single_member_data_len)

    def test_dummy_groups(self):
        dummies = self.group_list._dummy_groups()
        self.assertEqual(len(dummies), self.settings.max_number_of_contacts - len(self.nicks))
        for g in dummies:
            self.assertIsInstance(g, Group)

    def test_add_group(self):
        members = [create_contact('Laura')]
        self.group_list.add_group('test_group_12', bytes(GROUP_ID_LENGTH), False, False, members)
        self.group_list.add_group('test_group_12', bytes(GROUP_ID_LENGTH), False, True, members)
        self.assertTrue(self.group_list.get_group('test_group_12').notifications)
        self.assertEqual(len(self.group_list), len(self.group_names)+1)

    def test_remove_group_by_name(self):
        self.assertEqual(len(self.group_list), len(self.group_names))

        # Remove non-existing group
        self.assertIsNone(self.group_list.remove_group_by_name('test_group_12'))
        self.assertEqual(len(self.group_list), len(self.group_names))

        # Remove existing group
        self.assertIsNone(self.group_list.remove_group_by_name('test_group_11'))
        self.assertEqual(len(self.group_list), len(self.group_names)-1)

    def test_remove_group_by_id(self):
        self.assertEqual(len(self.group_list), len(self.group_names))

        # Remove non-existing group
        self.assertIsNone(self.group_list.remove_group_by_id(group_name_to_group_id('test_group_12')))
        self.assertEqual(len(self.group_list), len(self.group_names))

        # Remove existing group
        self.assertIsNone(self.group_list.remove_group_by_id(group_name_to_group_id('test_group_11')))
        self.assertEqual(len(self.group_list), len(self.group_names)-1)

    def test_get_group(self):
        self.assertEqual(self.group_list.get_group('test_group_3').name, 'test_group_3')

    def test_get_group_by_id(self):
        members  = [create_contact('Laura')]
        group_id = os.urandom(GROUP_ID_LENGTH)
        self.group_list.add_group('test_group_12', group_id, False, False, members)
        self.assertEqual(self.group_list.get_group_by_id(group_id).name, 'test_group_12')

    def test_get_list_of_group_names(self):
        self.assertEqual(self.group_list.get_list_of_group_names(), self.group_names)

    def test_get_list_of_group_ids(self):
        self.assertEqual(self.group_list.get_list_of_group_ids(),
                         list(map(group_name_to_group_id, self.group_names)))

    def test_get_list_of_hr_group_ids(self):
        self.assertEqual(self.group_list.get_list_of_hr_group_ids(),
                         [b58encode(gid) for gid in list(map(group_name_to_group_id, self.group_names))])

    def test_get_group_members(self):
        members = self.group_list.get_group_members(group_name_to_group_id('test_group_1'))
        for c in members:
            self.assertIsInstance(c, Contact)

    def test_has_group(self):
        self.assertTrue(self.group_list.has_group('test_group_11'))
        self.assertFalse(self.group_list.has_group('test_group_12'))

    def test_has_group_id(self):
        members  = [create_contact('Laura')]
        group_id = os.urandom(GROUP_ID_LENGTH)
        self.assertFalse(self.group_list.has_group_id(group_id))
        self.group_list.add_group('test_group_12', group_id, False, False, members)
        self.assertTrue(self.group_list.has_group_id(group_id))

    def test_largest_group(self):
        self.assertEqual(self.group_list.largest_group(), len(self.nicks))

    def test_print_group(self):
        self.group_list.get_group("test_group_1").name          = "group"
        self.group_list.get_group("test_group_2").log_messages  = True
        self.group_list.get_group("test_group_3").notifications = True
        self.group_list.get_group("test_group_4").log_messages  = True
        self.group_list.get_group("test_group_4").notifications = True
        self.group_list.get_group("test_group_5").members       = []
        self.group_list.get_group("test_group_6").members       = list(map(create_contact, ['Alice', 'Bob', 'Charlie',
                                                                                            'David', 'Eric', 'Fido']))
        self.assert_prints("""\
Group            Group ID         Logging     Notify    Members
────────────────────────────────────────────────────────────────────────────────
group            2drs4c4VcDdrP    No          No        Alice, Bob, Charlie,
                                                        David, Eric, Fido,
                                                        Guido, Heidi, Ivan,
                                                        Joana, Karol

test_group_2     2dnGTyhkThmPi    Yes         No        Alice, Bob, Charlie,
                                                        David, Eric, Fido,
                                                        Guido, Heidi, Ivan,
                                                        Joana, Karol

test_group_3     2df7s3LZhwLDw    No          Yes       Alice, Bob, Charlie,
                                                        David, Eric, Fido,
                                                        Guido, Heidi, Ivan,
                                                        Joana, Karol

test_group_4     2djy3XwUQVR8q    Yes         Yes       Alice, Bob, Charlie,
                                                        David, Eric, Fido,
                                                        Guido, Heidi, Ivan,
                                                        Joana, Karol

test_group_5     2dvbcgnjiLLMo    No          No        <Empty group>

test_group_6     2dwBRWAqWKHWv    No          No        Alice, Bob, Charlie,
                                                        David, Eric, Fido

test_group_7     2eDPg5BAM6qF4    No          No        Alice, Bob, Charlie,
                                                        David, Eric, Fido,
                                                        Guido, Heidi, Ivan,
                                                        Joana, Karol

test_group_8     2dqdayy5TJKcf    No          No        Alice, Bob, Charlie,
                                                        David, Eric, Fido,
                                                        Guido, Heidi, Ivan,
                                                        Joana, Karol

test_group_9     2e45bLYvSX3C8    No          No        Alice, Bob, Charlie,
                                                        David, Eric, Fido,
                                                        Guido, Heidi, Ivan,
                                                        Joana, Karol

test_group_10    2dgkncX9xRibh    No          No        Alice, Bob, Charlie,
                                                        David, Eric, Fido,
                                                        Guido, Heidi, Ivan,
                                                        Joana, Karol

test_group_11    2e6vAGmHmSEEJ    No          No        Alice, Bob, Charlie,
                                                        David, Eric, Fido,
                                                        Guido, Heidi, Ivan,
                                                        Joana, Karol


""", self.group_list.print_groups)


if __name__ == '__main__':
    unittest.main(exit=False)
