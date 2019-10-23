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

from unittest import mock

from src.common.crypto   import blake2b
from src.common.encoding import b58encode
from src.common.statics  import (COMMAND_PACKET_QUEUE, CONFIRM_CODE_LENGTH, ECDHE, FINGERPRINT_LENGTH,
                                 KDB_ADD_ENTRY_HEADER, KEX_STATUS_HAS_RX_PSK, KEX_STATUS_NO_RX_PSK, KEX_STATUS_PENDING,
                                 KEX_STATUS_UNVERIFIED, KEX_STATUS_VERIFIED, KEY_MANAGEMENT_QUEUE, LOCAL_ID, LOCAL_NICK,
                                 LOCAL_PUBKEY, RELAY_PACKET_QUEUE, SYMMETRIC_KEY_LENGTH, TFC_PUBLIC_KEY_LENGTH,
                                 WIN_TYPE_CONTACT, WIN_TYPE_GROUP, XCHACHA20_NONCE_LENGTH)

from src.transmitter.key_exchanges import create_pre_shared_key, export_onion_service_data, new_local_key
from src.transmitter.key_exchanges import rxp_load_psk, start_key_exchange, verify_fingerprints

from tests.mock_classes import ContactList, create_contact, Gateway, OnionService, Settings, TxWindow
from tests.utils        import cd_unit_test, cleanup, gen_queue_dict, ignored, nick_to_pub_key
from tests.utils        import nick_to_short_address, tear_queues, TFCTestCase, VALID_ECDHE_PUB_KEY


class TestOnionService(TFCTestCase):

    def setUp(self):
        """Pre-test actions."""
        self.contact_list  = ContactList()
        self.settings      = Settings()
        self.onion_service = OnionService()
        self.queues        = gen_queue_dict()
        self.gateway       = Gateway()

    @mock.patch('os.urandom',     side_effect=[b'a'])
    @mock.patch('time.sleep',     return_value=None)
    @mock.patch('builtins.input', side_effect=['invalid_cc', '', '61'])
    def test_onion_service_delivery(self, *_):
        self.assertIsNone(export_onion_service_data(self.contact_list, self.settings, self.onion_service, self.gateway))
        self.assertEqual(len(self.gateway.packets), 2)


class TestLocalKey(TFCTestCase):

    def setUp(self):
        """Pre-test actions."""
        self.contact_list = ContactList()
        self.settings     = Settings()
        self.queues       = gen_queue_dict()
        self.args         = self.contact_list, self.settings, self.queues

    def tearDown(self):
        """Post-test actions."""
        tear_queues(self.queues)

    def test_new_local_key_when_traffic_masking_is_enabled_raises_fr(self):
        self.settings.traffic_masking = True
        self.contact_list.contacts    = [create_contact(LOCAL_ID)]
        self.assert_fr("Error: Command is disabled during traffic masking.", new_local_key, *self.args)

    @mock.patch('time.sleep',     return_value=None)
    @mock.patch('builtins.input', side_effect=['bad', '', '61'])
    @mock.patch('os.getrandom',   side_effect=[SYMMETRIC_KEY_LENGTH*b'a',
                                               SYMMETRIC_KEY_LENGTH*b'a',
                                               SYMMETRIC_KEY_LENGTH*b'a',
                                               XCHACHA20_NONCE_LENGTH*b'a',
                                               SYMMETRIC_KEY_LENGTH*b'a',
                                               SYMMETRIC_KEY_LENGTH*b'a'])
    @mock.patch('os.urandom',     return_value=CONFIRM_CODE_LENGTH*b'a')
    @mock.patch('os.system',      return_value=None)
    def test_new_local_key(self, *_):
        # Setup
        self.settings.nc_bypass_messages = False
        self.settings.traffic_masking    = False

        # Test
        self.assertIsNone(new_local_key(*self.args))
        local_contact = self.contact_list.get_contact_by_pub_key(LOCAL_PUBKEY)

        self.assertEqual(local_contact.onion_pub_key,  LOCAL_PUBKEY)
        self.assertEqual(local_contact.nick,           LOCAL_NICK)
        self.assertEqual(local_contact.tx_fingerprint, bytes(FINGERPRINT_LENGTH))
        self.assertEqual(local_contact.rx_fingerprint, bytes(FINGERPRINT_LENGTH))
        self.assertFalse(local_contact.log_messages)
        self.assertFalse(local_contact.file_reception)
        self.assertFalse(local_contact.notifications)

        self.assertEqual(self.queues[COMMAND_PACKET_QUEUE].qsize(), 1)

        cmd, account, tx_key, rx_key, tx_hek, rx_hek = self.queues[KEY_MANAGEMENT_QUEUE].get()

        self.assertEqual(cmd, KDB_ADD_ENTRY_HEADER)
        self.assertEqual(account, LOCAL_PUBKEY)
        for key in [tx_key, rx_key, tx_hek, rx_hek]:
            self.assertIsInstance(key, bytes)
            self.assertEqual(len(key), SYMMETRIC_KEY_LENGTH)

    @mock.patch('time.sleep',     return_value=None)
    @mock.patch('builtins.input', side_effect=KeyboardInterrupt)
    @mock.patch('os.getrandom',   lambda x, flags: x * b'a')
    def test_keyboard_interrupt_raises_fr(self, *_):
        self.assert_fr("Local key setup aborted.", new_local_key, *self.args)


class TestVerifyFingerprints(unittest.TestCase):

    @mock.patch('builtins.input', return_value='Yes')
    def test_correct_fingerprint(self, _):
        self.assertTrue(verify_fingerprints(bytes(FINGERPRINT_LENGTH), bytes(FINGERPRINT_LENGTH)))

    @mock.patch('builtins.input', return_value='No')
    def test_incorrect_fingerprint(self, _):
        self.assertFalse(verify_fingerprints(bytes(FINGERPRINT_LENGTH), bytes(FINGERPRINT_LENGTH)))


class TestKeyExchange(TFCTestCase):

    def setUp(self):
        """Pre-test actions."""
        self.contact_list = ContactList()
        self.settings     = Settings()
        self.queues       = gen_queue_dict()
        self.args         = self.contact_list, self.settings, self.queues

    def tearDown(self):
        """Post-test actions."""
        tear_queues(self.queues)

    @mock.patch('shutil.get_terminal_size', return_value=[200, 200])
    @mock.patch('builtins.input',           return_value=b58encode(bytes(TFC_PUBLIC_KEY_LENGTH), public_key=True))
    def test_zero_public_key_raises_fr(self, *_):
        self.assert_fr("Error: Zero public key", start_key_exchange, nick_to_pub_key("Alice"), 'Alice', *self.args)

    @mock.patch('shutil.get_terminal_size', return_value=[200, 200])
    @mock.patch('builtins.input',           return_value=b58encode((TFC_PUBLIC_KEY_LENGTH-1)*b'a', public_key=True))
    def test_invalid_public_key_length_raises_fr(self, *_):
        self.assert_fr("Error: Invalid public key length",
                       start_key_exchange, nick_to_pub_key("Alice"), 'Alice', *self.args)

    @mock.patch('builtins.input', side_effect=['',                              # Empty message should resend key
                                               VALID_ECDHE_PUB_KEY[:-1],        # Short key should fail
                                               VALID_ECDHE_PUB_KEY + 'a',       # Long key should fail
                                               VALID_ECDHE_PUB_KEY[:-1] + 'a',  # Invalid key should fail
                                               VALID_ECDHE_PUB_KEY,             # Correct key
                                               'No'])                           # Fingerprint mismatch)
    @mock.patch('time.sleep',               return_value=None)
    @mock.patch('shutil.get_terminal_size', return_value=[200, 200])
    def test_fingerprint_mismatch_raises_fr(self, *_):
        self.assert_fr("Error: Fingerprint mismatch", start_key_exchange, nick_to_pub_key("Alice"), 'Alice', *self.args)

    @mock.patch('builtins.input', side_effect=['',                   # Resend public key
                                               VALID_ECDHE_PUB_KEY,  # Correct key
                                               'Yes',                # Fingerprint match
                                               '',                   # Resend contact data
                                               'ff',                 # Invalid confirmation code
                                               blake2b(nick_to_pub_key('Alice'), digest_size=CONFIRM_CODE_LENGTH).hex()
                                               ])
    @mock.patch('shutil.get_terminal_size', return_value=[200, 200])
    @mock.patch('time.sleep',               return_value=None)
    def test_successful_exchange(self, *_):
        self.assertIsNone(start_key_exchange(nick_to_pub_key("Alice"), 'Alice', *self.args))

        contact = self.contact_list.get_contact_by_pub_key(nick_to_pub_key("Alice"))
        self.assertEqual(contact.onion_pub_key,       nick_to_pub_key("Alice"))
        self.assertEqual(contact.nick,                'Alice')
        self.assertEqual(contact.kex_status,          KEX_STATUS_VERIFIED)
        self.assertIsInstance(contact.tx_fingerprint, bytes)
        self.assertIsInstance(contact.rx_fingerprint, bytes)
        self.assertEqual(len(contact.tx_fingerprint), FINGERPRINT_LENGTH)
        self.assertEqual(len(contact.rx_fingerprint), FINGERPRINT_LENGTH)
        self.assertFalse(contact.log_messages)
        self.assertFalse(contact.file_reception)
        self.assertTrue(contact.notifications)

        self.assertEqual(self.queues[COMMAND_PACKET_QUEUE].qsize(), 2)
        self.assertEqual(self.queues[RELAY_PACKET_QUEUE].qsize(),   2)

        cmd, account, tx_key, rx_key, tx_hek, rx_hek = self.queues[KEY_MANAGEMENT_QUEUE].get()

        self.assertEqual(cmd,         KDB_ADD_ENTRY_HEADER)
        self.assertEqual(account,     nick_to_pub_key("Alice"))
        self.assertEqual(len(tx_key), SYMMETRIC_KEY_LENGTH)

        for key in [tx_key, rx_key, tx_hek, rx_hek]:
            self.assertIsInstance(key, bytes)
            self.assertEqual(len(key), SYMMETRIC_KEY_LENGTH)

    @mock.patch('builtins.input', side_effect=['',                   # Resend public key
                                               VALID_ECDHE_PUB_KEY,  # Correct key
                                               KeyboardInterrupt,    # Skip fingerprint verification
                                               '',                   # Manual proceed for warning message
                                               blake2b(nick_to_pub_key('Alice'),
                                                       digest_size=CONFIRM_CODE_LENGTH).hex()])
    @mock.patch('time.sleep',               return_value=None)
    @mock.patch('shutil.get_terminal_size', return_value=[200, 200])
    def test_successful_exchange_skip_fingerprint_verification(self, *_):
        self.assertIsNone(start_key_exchange(nick_to_pub_key("Alice"), 'Alice', *self.args))

        contact = self.contact_list.get_contact_by_pub_key(nick_to_pub_key("Alice"))
        self.assertEqual(contact.onion_pub_key, nick_to_pub_key("Alice"))
        self.assertEqual(contact.nick,          'Alice')
        self.assertEqual(contact.kex_status,    KEX_STATUS_UNVERIFIED)

    @mock.patch('os.getrandom',   side_effect=[SYMMETRIC_KEY_LENGTH * b'a',
                                               SYMMETRIC_KEY_LENGTH * b'a'])
    @mock.patch('builtins.input', side_effect=[KeyboardInterrupt,
                                               VALID_ECDHE_PUB_KEY,
                                               'Yes',
                                               blake2b(nick_to_pub_key('Alice'),
                                                       digest_size=CONFIRM_CODE_LENGTH).hex()])
    @mock.patch('time.sleep',               return_value=None)
    @mock.patch('shutil.get_terminal_size', return_value=[200, 200])
    def test_successful_exchange_with_previous_key(self, *_):
        # Test caching of private key
        self.assert_fr("Key exchange interrupted.", start_key_exchange, nick_to_pub_key('Alice'), 'Alice', *self.args)

        alice = self.contact_list.get_contact_by_address_or_nick('Alice')
        self.assertEqual(alice.kex_status, KEX_STATUS_PENDING)

        # Test re-using private key
        self.assertIsNone(start_key_exchange(nick_to_pub_key('Alice'), 'Alice', *self.args))
        self.assertIsNone(alice.tfc_private_key)
        self.assertEqual(alice.kex_status, KEX_STATUS_VERIFIED)


class TestPSK(TFCTestCase):

    def setUp(self):
        """Pre-test actions."""
        self.unit_test_dir = cd_unit_test()
        self.contact_list  = ContactList()
        self.settings      = Settings(disable_gui_dialog=True)
        self.queues        = gen_queue_dict()
        self.onion_service = OnionService()
        self.args          = self.contact_list, self.settings, self.onion_service, self.queues

    def tearDown(self):
        """Post-test actions."""
        cleanup(self.unit_test_dir)

        with ignored(OSError):
            os.remove(f"{self.onion_service.user_short_address}.psk - Give to {nick_to_short_address('Alice')}")

        tear_queues(self.queues)

    @mock.patch('builtins.input',  side_effect=['/root/', '.', 'fc'])
    @mock.patch('time.sleep',      return_value=None)
    @mock.patch('getpass.getpass', return_value='test_password')
    @mock.patch('src.transmitter.key_exchanges.ARGON2_PSK_MEMORY_COST', 1000)
    @mock.patch('src.transmitter.key_exchanges.ARGON2_PSK_TIME_COST',   1)
    def test_psk_creation(self, *_):
        self.assertIsNone(create_pre_shared_key(nick_to_pub_key("Alice"), 'Alice', *self.args))

        contact = self.contact_list.get_contact_by_pub_key(nick_to_pub_key("Alice"))

        self.assertEqual(contact.onion_pub_key,  nick_to_pub_key("Alice"))
        self.assertEqual(contact.nick,           'Alice')
        self.assertEqual(contact.tx_fingerprint, bytes(FINGERPRINT_LENGTH))
        self.assertEqual(contact.rx_fingerprint, bytes(FINGERPRINT_LENGTH))
        self.assertEqual(contact.kex_status,     KEX_STATUS_NO_RX_PSK)

        self.assertFalse(contact.log_messages)
        self.assertFalse(contact.file_reception)
        self.assertTrue(contact.notifications)

        cmd, account, tx_key, rx_key, tx_hek, rx_hek = self.queues[KEY_MANAGEMENT_QUEUE].get()

        self.assertEqual(cmd,     KDB_ADD_ENTRY_HEADER)
        self.assertEqual(account, nick_to_pub_key("Alice"))

        for key in [tx_key, rx_key, tx_hek, rx_hek]:
            self.assertIsInstance(key, bytes)
            self.assertEqual(len(key), SYMMETRIC_KEY_LENGTH)

        self.assertEqual(self.queues[COMMAND_PACKET_QUEUE].qsize(), 1)
        self.assertTrue(os.path.isfile(
            f"{self.onion_service.user_short_address}.psk - Give to {nick_to_short_address('Alice')}"))

    @mock.patch('time.sleep',      return_value=None)
    @mock.patch('getpass.getpass', side_effect=KeyboardInterrupt)
    def test_keyboard_interrupt_raises_fr(self, *_):
        self.assert_fr("PSK generation aborted.", create_pre_shared_key, nick_to_pub_key("Alice"), 'Alice', *self.args)


class TestReceiverLoadPSK(TFCTestCase):

    def setUp(self):
        """Pre-test actions."""
        self.settings = Settings()
        self.queues   = gen_queue_dict()
        self.args     = self.settings, self.queues

    def tearDown(self):
        """Post-test actions."""
        tear_queues(self.queues)

    def test_raises_fr_when_traffic_masking_is_enabled(self):
        # Setup
        self.settings.traffic_masking = True

        # Test
        self.assert_fr("Error: Command is disabled during traffic masking.", rxp_load_psk, None, None, *self.args)

    def test_active_group_raises_fr(self):
        # Setup
        window = TxWindow(type=WIN_TYPE_GROUP)

        # Test
        self.assert_fr("Error: Group is selected.", rxp_load_psk, window, None, *self.args)

    def test_ecdhe_key_raises_fr(self):
        # Setup
        contact      = create_contact('Alice')
        contact_list = ContactList(contacts=[contact])
        window       = TxWindow(type=WIN_TYPE_CONTACT,
                                uid=nick_to_pub_key("Alice"),
                                contact=contact)

        # Test
        self.assert_fr(f"Error: The current key was exchanged with {ECDHE}.",
                       rxp_load_psk, window, contact_list, *self.args)

    @mock.patch('src.transmitter.key_exchanges.ARGON2_PSK_MEMORY_COST', 1000)
    @mock.patch('src.transmitter.key_exchanges.ARGON2_PSK_TIME_COST',   0.01)
    @mock.patch('time.sleep',     return_value=None)
    @mock.patch('builtins.input', side_effect=[b'0'.hex(), blake2b(nick_to_pub_key('Alice'),
                                                                   digest_size=CONFIRM_CODE_LENGTH).hex()])
    def test_successful_command(self, *_):
        # Setup
        contact      = create_contact('Alice', kex_status=KEX_STATUS_NO_RX_PSK)
        contact_list = ContactList(contacts=[contact])
        window       = TxWindow(type=WIN_TYPE_CONTACT,
                                name='Alice',
                                uid=nick_to_pub_key("Alice"),
                                contact=contact)

        # Test
        self.assert_fr("Removed PSK reminder for Alice.", rxp_load_psk, window, contact_list, *self.args)
        self.assertEqual(self.queues[COMMAND_PACKET_QUEUE].qsize(), 1)
        self.assertEqual(contact.kex_status, KEX_STATUS_HAS_RX_PSK)

    @mock.patch('time.sleep',     return_value=None)
    @mock.patch('builtins.input', side_effect=KeyboardInterrupt)
    def test_keyboard_interrupt_raises_fr(self, *_):
        # Setup
        contact      = create_contact('Alice', kex_status=KEX_STATUS_NO_RX_PSK)
        contact_list = ContactList(contacts=[contact])
        window       = TxWindow(type=WIN_TYPE_CONTACT,
                                uid=nick_to_pub_key("Alice"),
                                contact=contact)

        # Test
        self.assert_fr("PSK verification aborted.", rxp_load_psk, window, contact_list, *self.args)


if __name__ == '__main__':
    unittest.main(exit=False)
