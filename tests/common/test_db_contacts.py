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
from src.common.statics     import *

from tests.mock_classes import create_contact, MasterKey, Settings
from tests.utils        import cleanup, TFCTestCase


class TestContact(unittest.TestCase):

    def test_contact_serialization_length_and_type(self):
        serialized = create_contact().serialize_c()
        self.assertEqual(len(serialized), CONTACT_LENGTH)
        self.assertIsInstance(serialized, bytes)


class TestContactList(TFCTestCase):

    def setUp(self):
        self.master_key            = MasterKey()
        self.settings              = Settings()
        self.contact_list          = ContactList(self.master_key, self.settings)
        self.contact_list.contacts = list(map(create_contact, ['Alice', 'Benny', 'Charlie', 'David', 'Eric']))

    def tearDown(self):
        cleanup()

    def test_contact_list_iterates_over_contact_objects(self):
        for c in self.contact_list:
            self.assertIsInstance(c, Contact)

    def test_len_returns_number_of_contacts(self):
        self.assertEqual(len(self.contact_list), 5)

    def test_storing_and_loading_of_contacts(self):
        # Test store
        self.contact_list.store_contacts()
        self.assertTrue(os.path.isfile(f'{DIR_USER_DATA}ut_contacts'))
        self.assertEqual(os.path.getsize(f'{DIR_USER_DATA}ut_contacts'),
                         XSALSA20_NONCE_LEN
                         + self.settings.max_number_of_contacts * CONTACT_LENGTH
                         + POLY1305_TAG_LEN)

        # Test load
        contact_list2 = ContactList(self.master_key, self.settings)
        self.assertEqual(len(contact_list2), 5)
        for c in contact_list2:
            self.assertIsInstance(c, Contact)

    def test_generate_dummy_contact(self):
        dummy_contact = ContactList.generate_dummy_contact()
        self.assertIsInstance(dummy_contact, Contact)
        self.assertEqual(len(dummy_contact.serialize_c()), CONTACT_LENGTH)

    def test_add_contact(self):
        self.assertIsNone(self.contact_list.add_contact(f'faye@jabber.org', 'bob@jabber.org', f'Faye',
                                                        FINGERPRINT_LEN * b'\x03',
                                                        FINGERPRINT_LEN * b'\x04',
                                                        True, True, True))

        contact_list2 = ContactList(MasterKey(), Settings())
        c_alice       = contact_list2.get_contact('Alice')
        c_faye        = contact_list2.get_contact('Faye')

        self.assertEqual(len(self.contact_list), 6)
        self.assertIsInstance(c_alice, Contact)
        self.assertEqual(c_alice.tx_fingerprint, FINGERPRINT_LEN * b'\x01')
        self.assertEqual(c_faye.tx_fingerprint,  FINGERPRINT_LEN * b'\x03')

    def test_replace_existing_contact(self):
        c_alice = self.contact_list.get_contact('Alice')
        self.assertEqual(c_alice.tx_fingerprint, FINGERPRINT_LEN * b'\x01')

        self.assertIsNone(self.contact_list.add_contact(f'alice@jabber.org', 'bob@jabber.org', f'Alice',
                                                        FINGERPRINT_LEN * b'\x03',
                                                        FINGERPRINT_LEN * b'\x04',
                                                        True, True, True))

        contact_list2 = ContactList(MasterKey(), Settings())
        c_alice       = contact_list2.get_contact('Alice')

        self.assertEqual(len(self.contact_list), 5)
        self.assertIsInstance(c_alice, Contact)
        self.assertEqual(c_alice.tx_fingerprint, FINGERPRINT_LEN * b'\x03')

    def test_remove_contact(self):
        self.assertTrue(self.contact_list.has_contact('Benny'))
        self.assertTrue(self.contact_list.has_contact('Charlie'))

        self.contact_list.remove_contact('benny@jabber.org')
        self.assertFalse(self.contact_list.has_contact('Benny'))

        self.contact_list.remove_contact('Charlie')
        self.assertFalse(self.contact_list.has_contact('Charlie'))

    def test_get_contact(self):
        for selector in ['benny@jabber.org', 'Benny']:
            contact = self.contact_list.get_contact(selector)
            self.assertIsInstance(contact, Contact)
            self.assertEqual(contact.rx_account, 'benny@jabber.org')

    def test_get_list_of_contacts(self):
        for c in self.contact_list.get_list_of_contacts():
            self.assertIsInstance(c, Contact)

    def test_get_list_of_accounts(self):
        self.assertEqual(self.contact_list.get_list_of_accounts(),
                         ['alice@jabber.org',   'benny@jabber.org',
                          'charlie@jabber.org', 'david@jabber.org',
                          'eric@jabber.org'])

    def test_get_list_of_nicks(self):
        self.assertEqual(self.contact_list.get_list_of_nicks(),
                         ['Alice', 'Benny', 'Charlie', 'David', 'Eric'])

    def test_get_list_of_users_accounts(self):
        self.assertEqual(self.contact_list.get_list_of_users_accounts(), ['user@jabber.org'])

    def test_contact_selectors(self):
        self.assertEqual(self.contact_list.contact_selectors(),
                         ['alice@jabber.org', 'benny@jabber.org', 'charlie@jabber.org',
                          'david@jabber.org', 'eric@jabber.org',
                          'Alice', 'Benny', 'Charlie', 'David', 'Eric'])

    def test_has_contacts(self):
        self.assertTrue(self.contact_list.has_contacts())
        self.contact_list.contacts = []
        self.assertFalse(self.contact_list.has_contacts())

    def test_has_contact(self):
        self.contact_list.contacts = []
        self.assertFalse(self.contact_list.has_contact('Benny'))
        self.assertFalse(self.contact_list.has_contact('bob@jabber.org'))

        self.contact_list.contacts = list(map(create_contact, ['Bob', 'Charlie']))
        self.assertTrue(self.contact_list.has_contact('Bob'))
        self.assertTrue(self.contact_list.has_contact('charlie@jabber.org'))

    def test_has_local_contact(self):
        self.assertFalse(self.contact_list.has_local_contact())
        self.contact_list.contacts.append(create_contact(LOCAL_ID))
        self.assertTrue(self.contact_list.has_local_contact())

    def test_contact_printing(self):
        self.contact_list.contacts.append(create_contact(LOCAL_ID))
        self.contact_list.get_contact('Alice').log_messages     = False
        self.contact_list.get_contact('Benny').notifications    = False
        self.contact_list.get_contact('Charlie').file_reception = False
        self.contact_list.get_contact('David').tx_fingerprint   = bytes(FINGERPRINT_LEN)
        self.assertPrints(CLEAR_ENTIRE_SCREEN + CURSOR_LEFT_UP_CORNER + """\

Contact     Logging     Notify     Files      Key Ex     Account
────────────────────────────────────────────────────────────────────────────────
Alice       No          Yes        Accept     X25519     alice@jabber.org
Benny       Yes         No         Accept     X25519     benny@jabber.org
Charlie     Yes         Yes        Reject     X25519     charlie@jabber.org
David       Yes         Yes        Accept     PSK        david@jabber.org
Eric        Yes         Yes        Accept     X25519     eric@jabber.org


""", self.contact_list.print_contacts)


if __name__ == '__main__':
    unittest.main(exit=False)
