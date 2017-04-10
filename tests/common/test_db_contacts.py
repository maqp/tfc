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

import src.common.misc

from src.common.db_contacts import Contact, ContactList
from src.common.statics     import *

from tests.mock_classes     import create_contact, MasterKey, Settings
from tests.utils            import cleanup


class TestContact(unittest.TestCase):

    def test_dump_c(self):
        # Setup
        contact    = Contact('alice@jabber.org', 'bob@jabber.org', 'Alice',
                             32 * b'\x01', 32 * b'\x02', True, True, True)
        bytestring = contact.dump_c()

        # Test
        self.assertEqual(len(bytestring), (3 * 1024 + 32 + 32 + 1 + 1 + 1))
        self.assertIsInstance(bytestring, bytes)


class TestContactList(unittest.TestCase):

    def tearDown(self):
        cleanup()

    def test_iterate_over_contacts(self):
        # Setup
        contact            = Contact('alice@jabber.org', 'bob@jabber.org', 'Alice',
                                     32 * b'\x01', 32 * b'\x02', True, True, True)
        contact_l          = ContactList(MasterKey(), Settings())
        contact_l.contacts = 5 * [contact]

        # Test
        for c in contact_l:
            self.assertIsInstance(c, Contact)

    def test_len_returns_number_of_contacts(self):
        # Setup
        contact            = Contact('alice@jabber.org', 'bob@jabber.org', 'Alice',
                                     32 * b'\x01', 32 * b'\x02', True, True, True)
        contact_l          = ContactList(MasterKey(), Settings())
        contact_l.contacts = 5 * [contact]

        # Test
        self.assertEqual(len(contact_l), 5)

    def test_store_and_load_contacts(self):
        # Setup
        contact            = Contact('alice@jabber.org', 'bob@jabber.org', 'Alice',
                                     32 * b'\x01', 32 * b'\x02', True, True, True)
        settings           = Settings()
        master_k           = MasterKey()
        contact_l          = ContactList(master_k, settings)
        contact_l.contacts = 5 * [contact]
        contact_l.store_contacts()

        # Test
        contact_l2 = ContactList(master_k, settings)
        self.assertEqual(len(contact_l2), 5)
        for c in contact_l2:
            self.assertIsInstance(c, Contact)

        self.assertTrue(os.path.isfile(f'{DIR_USER_DATA}/ut_contacts'))
        self.assertEqual(os.path.getsize(f'{DIR_USER_DATA}/ut_contacts'), 24 + 20 * (1024 + 1024 + 1024 + 32 + 32 + 1 + 1 + 1) + 16)
        os.remove(f'{DIR_USER_DATA}/ut_contacts')

    def test_generate_dummy_contact(self):
        dummy_data = ContactList.generate_dummy_contact()
        self.assertEqual(len(dummy_data), (1024 + 1024 + 1024 + 32 + 32 + 1 + 1 + 1))
        self.assertIsInstance(dummy_data, bytes)

    def test_get_contact(self):
        # Setup
        contact1           = Contact('alice@jabber.org', 'bob@jabber.org', 'Alice',
                                     32 * b'\x01', 32 * b'\x02', True, True, True)
        contact2           = Contact('charlie@jabber.org', 'bob@jabber.org', 'Charlie',
                                     32 * b'\x01', 32 * b'\x02', True, True, True)
        settings           = Settings()
        master_k           = MasterKey()
        contact_l          = ContactList(master_k, settings)
        contact_l.contacts = [contact1, contact2]

        # Test
        co1 = contact_l.get_contact('alice@jabber.org')
        self.assertIsInstance(co1, Contact)
        self.assertEqual(co1.rx_account, 'alice@jabber.org')

        co2 = contact_l.get_contact('Alice')
        self.assertIsInstance(co2, Contact)
        self.assertEqual(co2.rx_account, 'alice@jabber.org')

    def test_getters(self):
        # Setup
        contact1           = Contact('alice@jabber.org', 'bob@jabber.org', 'Alice',
                                     32 * b'\x01', 32 * b'\x02', True, True, True)
        contact2           = Contact('charlie@jabber.org', 'bob@jabber.org', 'Charlie',
                                     32 * b'\x01', 32 * b'\x02', True, True, True)
        settings           = Settings()
        master_k           = MasterKey()
        contact_l          = ContactList(master_k, settings)
        contact_l.contacts = [contact1, contact2]

        # Test
        self.assertEqual(contact_l.contact_selectors(),          ['alice@jabber.org', 'charlie@jabber.org', 'Alice', 'Charlie'])
        self.assertEqual(contact_l.get_list_of_accounts(),       ['alice@jabber.org', 'charlie@jabber.org'])
        self.assertEqual(contact_l.get_list_of_nicks(),          ['Alice', 'Charlie'])
        self.assertEqual(contact_l.get_list_of_users_accounts(), ['bob@jabber.org'])

    def test_remove_contact(self):
        # Setup
        contact1           = Contact('alice@jabber.org', 'bob@jabber.org', 'Alice',
                                     32 * b'\x01', 32 * b'\x02', True, True, True)
        contact2           = Contact('charlie@jabber.org', 'bob@jabber.org', 'Charlie',
                                     32 * b'\x01', 32 * b'\x02', True, True, True)
        contact_l          = ContactList(MasterKey(), Settings())
        contact_l.contacts = [contact1, contact2]

        # Test
        self.assertTrue(contact_l.has_contacts())
        self.assertTrue(contact_l.has_contact('Alice'))
        self.assertTrue(contact_l.has_contact('alice@jabber.org'))

        contact_l.remove_contact('alice@jabber.org')
        self.assertFalse(contact_l.has_contact('Alice'))
        self.assertFalse(contact_l.has_contact('alice@jabber.org'))

        contact_l.remove_contact('Charlie')
        self.assertEqual(len(contact_l.contacts), 0)
        self.assertFalse(contact_l.has_contacts())

    def test_add_contact(self):
        # Setup
        contact1           = Contact('alice@jabber.org', 'bob@jabber.org', 'Alice',
                                     32 * b'\x01', 32 * b'\x02', True, True, True)
        contact2           = Contact('charlie@jabber.org', 'bob@jabber.org', 'Charlie',
                                     32 * b'\x01', 32 * b'\x02', True, True, True)
        settings           = Settings(software_operation='ut', m_number_of_accnts=20)
        master_k           = MasterKey()
        contact_l          = ContactList(master_k, settings)
        contact_l.contacts = [contact1, contact2]

        contact_l.add_contact('alice@jabber.org', 'bob@jabber.org', 'Alice',
                              32 * b'\x03', 32 * b'\x04', True, True, True)
        contact_l.add_contact('david@jabber.org', 'bob@jabber.org', 'David',
                              32 * b'\x03', 32 * b'\x04', True, True, True)

        contact_l2 = ContactList(master_k, settings)
        c_alice    = contact_l2.get_contact('Alice')
        c_david    = contact_l2.get_contact('David')

        # Test
        self.assertIsInstance(c_alice, Contact)
        self.assertIsInstance(c_david, Contact)
        self.assertEqual(c_alice.tx_fingerprint, 32 * b'\x03')
        self.assertEqual(c_david.tx_fingerprint, 32 * b'\x03')

    def test_local_contact(self):
        # Setup
        contact1                  = Contact('alice@jabber.org', 'bob@jabber.org', 'Alice',
                                            32 * b'\x01', 32 * b'\x02', True, True, True)
        contact_l                 = ContactList(MasterKey(), Settings())
        contact_l.contacts        = [contact1]
        o_get_tty_w               = src.common.misc.get_tty_w
        src.common.misc.get_tty_w = lambda x: 1

        # Test
        self.assertFalse(contact_l.has_local_contact())

        contact_l.add_contact('local', 'local', 'local',
                              32 * b'\x03', 32 * b'\x04', True, True, True)

        self.assertTrue(contact_l.has_local_contact())
        self.assertIsNone(contact_l.print_contacts())
        self.assertIsNone(contact_l.print_contacts(spacing=True))

        # Teardown
        src.common.misc.get_tty_w = o_get_tty_w

    def test_contact_printing(self):
        # Setup
        contact_list          = ContactList(MasterKey(), Settings())
        contact_list.contacts = [create_contact(n) for n in ['Alice', 'Bob', 'Charlie', 'David']]
        # Teardown
        self.assertIsNone(contact_list.print_contacts())


if __name__ == '__main__':
    unittest.main(exit=False)
