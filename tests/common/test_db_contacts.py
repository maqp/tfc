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
from src.common.misc        import ensure_dir
from src.common.statics     import (CLEAR_ENTIRE_SCREEN, CONTACT_LENGTH, CURSOR_LEFT_UP_CORNER, DIR_USER_DATA, ECDHE,
                                    FINGERPRINT_LENGTH, KEX_STATUS_HAS_RX_PSK, KEX_STATUS_LOCAL_KEY, KEX_STATUS_NONE,
                                    KEX_STATUS_NO_RX_PSK, KEX_STATUS_PENDING, KEX_STATUS_UNVERIFIED,
                                    KEX_STATUS_VERIFIED, LOCAL_ID, POLY1305_TAG_LENGTH, PSK, XCHACHA20_NONCE_LENGTH)

from tests.mock_classes import create_contact, MasterKey, Settings
from tests.utils        import cd_unit_test, cleanup, nick_to_onion_address, nick_to_pub_key, tamper_file, TFCTestCase


class TestContact(unittest.TestCase):

    def setUp(self):
        """Pre-test actions."""
        self.contact = Contact(nick_to_pub_key('Bob'),
                               'Bob',
                               FINGERPRINT_LENGTH * b'\x01',
                               FINGERPRINT_LENGTH * b'\x02',
                               KEX_STATUS_UNVERIFIED,
                               log_messages  =True,
                               file_reception=True,
                               notifications =True)

    def test_contact_serialization_length_and_type(self):
        serialized = self.contact.serialize_c()
        self.assertEqual(len(serialized), CONTACT_LENGTH)
        self.assertIsInstance(serialized, bytes)

    def test_uses_psk(self):
        for kex_status in [KEX_STATUS_NO_RX_PSK, KEX_STATUS_HAS_RX_PSK]:
            self.contact.kex_status = kex_status
            self.assertTrue(self.contact.uses_psk())

        for kex_status in [KEX_STATUS_NONE, KEX_STATUS_PENDING, KEX_STATUS_UNVERIFIED,
                           KEX_STATUS_VERIFIED, KEX_STATUS_LOCAL_KEY]:
            self.contact.kex_status = kex_status
            self.assertFalse(self.contact.uses_psk())


class TestContactList(TFCTestCase):

    def setUp(self):
        """Pre-test actions."""
        self.unit_test_dir         = cd_unit_test()
        self.master_key            = MasterKey()
        self.settings              = Settings()
        self.file_name             = f'{DIR_USER_DATA}{self.settings.software_operation}_contacts'
        self.contact_list          = ContactList(self.master_key, self.settings)
        self.full_contact_list     = ['Alice', 'Bob', 'Charlie', 'David', 'Eric', LOCAL_ID]
        self.contact_list.contacts = list(map(create_contact, self.full_contact_list))
        self.real_contact_list     = self.full_contact_list[:]
        self.real_contact_list.remove(LOCAL_ID)

    def tearDown(self):
        """Post-test actions."""
        cleanup(self.unit_test_dir)

    def test_contact_list_iterates_over_contact_objects(self):
        for c in self.contact_list:
            self.assertIsInstance(c, Contact)

    def test_len_returns_the_number_of_contacts_and_excludes_the_local_key(self):
        self.assertEqual(len(self.contact_list),
                         len(self.real_contact_list))

    def test_storing_and_loading_of_contacts(self):
        # Test store
        self.contact_list.store_contacts()
        self.assertEqual(os.path.getsize(self.file_name),
                         XCHACHA20_NONCE_LENGTH
                         + (self.settings.max_number_of_contacts + 1) * CONTACT_LENGTH
                         + POLY1305_TAG_LENGTH)

        # Test load
        contact_list2 = ContactList(self.master_key, self.settings)
        self.assertEqual(len(contact_list2),          len(self.real_contact_list))
        self.assertEqual(len(contact_list2.contacts), len(self.full_contact_list))
        for c in contact_list2:
            self.assertIsInstance(c, Contact)

    def test_invalid_content_raises_critical_error(self):
        # Setup
        invalid_data = b'a'
        pt_bytes     = b''.join([c.serialize_c() for c in self.contact_list.contacts
                                                        + self.contact_list._dummy_contacts()])
        ct_bytes     = encrypt_and_sign(pt_bytes + invalid_data, self.master_key.master_key)

        ensure_dir(DIR_USER_DATA)
        with open(self.file_name, 'wb+') as f:
            f.write(ct_bytes)

        # Test
        with self.assertRaises(SystemExit):
            ContactList(self.master_key, self.settings)

    def test_load_of_modified_database_raises_critical_error(self):
        self.contact_list.store_contacts()

        # Test reading works normally
        self.assertIsInstance(ContactList(self.master_key, self.settings), ContactList)

        # Test loading of tampered database raises CriticalError
        tamper_file(self.file_name, tamper_size=1)
        with self.assertRaises(SystemExit):
            ContactList(self.master_key, self.settings)

    def test_generate_dummy_contact(self):
        dummy_contact = ContactList.generate_dummy_contact()
        self.assertIsInstance(dummy_contact, Contact)
        self.assertEqual(len(dummy_contact.serialize_c()), CONTACT_LENGTH)

    def test_dummy_contacts(self):
        dummies = self.contact_list._dummy_contacts()
        self.assertEqual(len(dummies), self.settings.max_number_of_contacts - len(self.real_contact_list))
        for c in dummies:
            self.assertIsInstance(c, Contact)

    def test_add_contact(self):
        tx_fingerprint = FINGERPRINT_LENGTH * b'\x03'
        rx_fingerprint = FINGERPRINT_LENGTH * b'\x04'

        self.assertIsNone(self.contact_list.add_contact(nick_to_pub_key('Faye'),
                                                        'Faye',
                                                        tx_fingerprint,
                                                        rx_fingerprint,
                                                        KEX_STATUS_UNVERIFIED,
                                                        self.settings.log_messages_by_default,
                                                        self.settings.accept_files_by_default,
                                                        self.settings.show_notifications_by_default))

        # Test new contact was stored by loading
        # the database from file to another object
        contact_list2 = ContactList(MasterKey(), Settings())
        faye          = contact_list2.get_contact_by_pub_key(nick_to_pub_key('Faye'))

        self.assertEqual(len(self.contact_list), len(self.real_contact_list)+1)
        self.assertIsInstance(faye, Contact)

        self.assertEqual(faye.tx_fingerprint, tx_fingerprint)
        self.assertEqual(faye.rx_fingerprint, rx_fingerprint)
        self.assertEqual(faye.kex_status,     KEX_STATUS_UNVERIFIED)

        self.assertEqual(faye.log_messages,   self.settings.log_messages_by_default)
        self.assertEqual(faye.file_reception, self.settings.accept_files_by_default)
        self.assertEqual(faye.notifications,  self.settings.show_notifications_by_default)

    def test_add_contact_that_replaces_an_existing_contact(self):
        alice              = self.contact_list.get_contact_by_pub_key(nick_to_pub_key('Alice'))
        new_nick           = 'Alice2'
        new_tx_fingerprint = FINGERPRINT_LENGTH * b'\x03'
        new_rx_fingerprint = FINGERPRINT_LENGTH * b'\x04'

        # Verify that existing nick, kex status and fingerprints are
        # different from those that will replace the existing data
        self.assertNotEqual(alice.nick,           new_nick)
        self.assertNotEqual(alice.tx_fingerprint, new_tx_fingerprint)
        self.assertNotEqual(alice.rx_fingerprint, new_rx_fingerprint)
        self.assertNotEqual(alice.kex_status,     KEX_STATUS_UNVERIFIED)

        # Make sure each contact setting is opposite from default value
        alice.log_messages   = not self.settings.log_messages_by_default
        alice.file_reception = not self.settings.accept_files_by_default
        alice.notifications  = not self.settings.show_notifications_by_default

        # Replace the existing contact
        self.assertIsNone(self.contact_list.add_contact(nick_to_pub_key('Alice'),
                                                        new_nick,
                                                        new_tx_fingerprint,
                                                        new_rx_fingerprint,
                                                        KEX_STATUS_UNVERIFIED,
                                                        self.settings.log_messages_by_default,
                                                        self.settings.accept_files_by_default,
                                                        self.settings.show_notifications_by_default))

        # Load database to another object from
        # file to verify new contact was stored
        contact_list2 = ContactList(MasterKey(), Settings())
        alice         = contact_list2.get_contact_by_pub_key(nick_to_pub_key('Alice'))

        # Verify the content of loaded data
        self.assertEqual(len(contact_list2), len(self.real_contact_list))
        self.assertIsInstance(alice, Contact)

        # Test replaced contact replaced nick, fingerprints and kex status
        self.assertEqual(alice.nick,           new_nick)
        self.assertEqual(alice.tx_fingerprint, new_tx_fingerprint)
        self.assertEqual(alice.rx_fingerprint, new_rx_fingerprint)
        self.assertEqual(alice.kex_status,     KEX_STATUS_UNVERIFIED)

        # Test replaced contact kept settings set
        # to be opposite from default settings
        self.assertNotEqual(alice.log_messages,   self.settings.log_messages_by_default)
        self.assertNotEqual(alice.file_reception, self.settings.accept_files_by_default)
        self.assertNotEqual(alice.notifications,  self.settings.show_notifications_by_default)

    def test_remove_contact_by_pub_key(self):
        # Verify both contacts exist
        self.assertTrue(self.contact_list.has_pub_key(nick_to_pub_key('Bob')))
        self.assertTrue(self.contact_list.has_pub_key(nick_to_pub_key('Charlie')))

        self.assertIsNone(self.contact_list.remove_contact_by_pub_key(nick_to_pub_key('Bob')))
        self.assertFalse(self.contact_list.has_pub_key(nick_to_pub_key('Bob')))
        self.assertTrue(self.contact_list.has_pub_key(nick_to_pub_key('Charlie')))

    def test_remove_contact_by_address_or_nick(self):
        # Verify both contacts exist
        self.assertTrue(self.contact_list.has_pub_key(nick_to_pub_key('Bob')))
        self.assertTrue(self.contact_list.has_pub_key(nick_to_pub_key('Charlie')))

        # Test removal with address
        self.assertIsNone(self.contact_list.remove_contact_by_address_or_nick(nick_to_onion_address('Bob')))
        self.assertFalse(self.contact_list.has_pub_key(nick_to_pub_key('Bob')))
        self.assertTrue(self.contact_list.has_pub_key(nick_to_pub_key('Charlie')))

        # Test removal with nick
        self.assertIsNone(self.contact_list.remove_contact_by_address_or_nick('Charlie'))
        self.assertFalse(self.contact_list.has_pub_key(nick_to_pub_key('Bob')))
        self.assertFalse(self.contact_list.has_pub_key(nick_to_pub_key('Charlie')))

    def test_get_contact_by_pub_key(self):
        self.assertIs(self.contact_list.get_contact_by_pub_key(nick_to_pub_key('Bob')),
                      self.contact_list.get_contact_by_address_or_nick('Bob'))

    def test_get_contact_by_address_or_nick_returns_the_same_contact_object_with_address_and_nick(self):
        for selector in [nick_to_onion_address('Bob'), 'Bob']:
            self.assertIsInstance(self.contact_list.get_contact_by_address_or_nick(selector), Contact)

        self.assertIs(self.contact_list.get_contact_by_address_or_nick('Bob'),
                      self.contact_list.get_contact_by_address_or_nick(nick_to_onion_address('Bob')))

    def test_get_list_of_contacts(self):
        self.assertEqual(len(self.contact_list.get_list_of_contacts()),
                         len(self.real_contact_list))
        for c in self.contact_list.get_list_of_contacts():
            self.assertIsInstance(c, Contact)

    def test_get_list_of_addresses(self):
        self.assertEqual(self.contact_list.get_list_of_addresses(),
                         [nick_to_onion_address('Alice'),
                          nick_to_onion_address('Bob'),
                          nick_to_onion_address('Charlie'),
                          nick_to_onion_address('David'),
                          nick_to_onion_address('Eric')])

    def test_get_list_of_nicks(self):
        self.assertEqual(self.contact_list.get_list_of_nicks(),
                         ['Alice', 'Bob', 'Charlie', 'David', 'Eric'])

    def test_get_list_of_pub_keys(self):
        self.assertEqual(self.contact_list.get_list_of_pub_keys(),
                         [nick_to_pub_key('Alice'),
                          nick_to_pub_key('Bob'),
                          nick_to_pub_key('Charlie'),
                          nick_to_pub_key('David'),
                          nick_to_pub_key('Eric')])

    def test_get_list_of_pending_pub_keys(self):
        # Set key exchange statuses to pending
        for nick in ['Alice', 'Bob']:
            contact            = self.contact_list.get_contact_by_address_or_nick(nick)
            contact.kex_status = KEX_STATUS_PENDING

        # Test pending contacts are returned
        self.assertEqual(self.contact_list.get_list_of_pending_pub_keys(),
                         [nick_to_pub_key('Alice'),
                          nick_to_pub_key('Bob')])

    def test_get_list_of_existing_pub_keys(self):
        self.contact_list.get_contact_by_address_or_nick('Alice').kex_status   = KEX_STATUS_UNVERIFIED
        self.contact_list.get_contact_by_address_or_nick('Bob').kex_status     = KEX_STATUS_VERIFIED
        self.contact_list.get_contact_by_address_or_nick('Charlie').kex_status = KEX_STATUS_HAS_RX_PSK
        self.contact_list.get_contact_by_address_or_nick('David').kex_status   = KEX_STATUS_NO_RX_PSK
        self.contact_list.get_contact_by_address_or_nick('Eric').kex_status    = KEX_STATUS_PENDING

        self.assertEqual(self.contact_list.get_list_of_existing_pub_keys(),
                         [nick_to_pub_key('Alice'),
                          nick_to_pub_key('Bob'),
                          nick_to_pub_key('Charlie'),
                          nick_to_pub_key('David')])

    def test_contact_selectors(self):
        self.assertEqual(self.contact_list.contact_selectors(),
                         [nick_to_onion_address('Alice'),
                          nick_to_onion_address('Bob'),
                          nick_to_onion_address('Charlie'),
                          nick_to_onion_address('David'),
                          nick_to_onion_address('Eric'),
                          'Alice', 'Bob', 'Charlie', 'David', 'Eric'])

    def test_has_contacts(self):
        self.assertTrue(self.contact_list.has_contacts())
        self.contact_list.contacts = []
        self.assertFalse(self.contact_list.has_contacts())

    def test_has_only_pending_contacts(self):
        # Change all to pending
        for contact in self.contact_list.get_list_of_contacts():
            contact.kex_status = KEX_STATUS_PENDING
        self.assertTrue(self.contact_list.has_only_pending_contacts())

        # Change one from pending
        alice            = self.contact_list.get_contact_by_address_or_nick('Alice')
        alice.kex_status = KEX_STATUS_UNVERIFIED
        self.assertFalse(self.contact_list.has_only_pending_contacts())

    def test_has_pub_key(self):
        self.contact_list.contacts = []
        self.assertFalse(self.contact_list.has_pub_key(nick_to_pub_key('Bob')))
        self.assertFalse(self.contact_list.has_pub_key(nick_to_pub_key('Bob')))

        self.contact_list.contacts = list(map(create_contact, ['Bob', 'Charlie']))
        self.assertTrue(self.contact_list.has_pub_key(nick_to_pub_key('Bob')))
        self.assertTrue(self.contact_list.has_pub_key(nick_to_pub_key('Charlie')))

    def test_has_local_contact(self):
        self.contact_list.contacts = []
        self.assertFalse(self.contact_list.has_local_contact())

        self.contact_list.contacts = [create_contact(LOCAL_ID)]
        self.assertTrue(self.contact_list.has_local_contact())

    def test_print_contacts(self):
        self.contact_list.contacts.append(create_contact(LOCAL_ID))
        self.contact_list.get_contact_by_pub_key(nick_to_pub_key('Alice')).log_messages   = False
        self.contact_list.get_contact_by_pub_key(nick_to_pub_key('Alice')).kex_status     = KEX_STATUS_PENDING
        self.contact_list.get_contact_by_pub_key(nick_to_pub_key('Bob')).notifications    = False
        self.contact_list.get_contact_by_pub_key(nick_to_pub_key('Charlie')).kex_status   = KEX_STATUS_UNVERIFIED
        self.contact_list.get_contact_by_pub_key(nick_to_pub_key('Bob')).file_reception   = False
        self.contact_list.get_contact_by_pub_key(nick_to_pub_key('Bob')).kex_status       = KEX_STATUS_VERIFIED
        self.contact_list.get_contact_by_pub_key(nick_to_pub_key('David')).rx_fingerprint = bytes(FINGERPRINT_LENGTH)
        self.contact_list.get_contact_by_pub_key(nick_to_pub_key('David')).kex_status     = bytes(KEX_STATUS_NO_RX_PSK)
        self.assert_prints(CLEAR_ENTIRE_SCREEN + CURSOR_LEFT_UP_CORNER + f"""\

Contact    Account    Logging    Notify    Files     Key Ex
────────────────────────────────────────────────────────────────────────────────
Alice      hpcra      No         Yes       Accept    {ECDHE} (Pending)
Bob        zwp3d      Yes        No        Reject    {ECDHE} (Verified)
Charlie    n2a3c      Yes        Yes       Accept    {ECDHE} (Unverified)
David      u22uy      Yes        Yes       Accept    {PSK}  (No contact key)
Eric       jszzy      Yes        Yes       Accept    {ECDHE} (Verified)


""", self.contact_list.print_contacts)


if __name__ == '__main__':
    unittest.main(exit=False)
