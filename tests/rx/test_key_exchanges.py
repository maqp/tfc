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

import builtins
import datetime
import getpass
import os
import unittest

from src.common.crypto    import encrypt_and_sign, argon2_kdf
from src.common.encoding  import b58encode
from src.common.statics   import *
from src.rx.key_exchanges import process_local_key, local_key_installed, process_public_key, ecdhe_command, psk_command, psk_import

from tests.mock_classes   import Contact, ContactList, KeyList, KeySet, Settings, WindowList
from tests.utils          import TFCTestCase


class TestProcessLocalKey(TFCTestCase):

    def test_invalid_decryption_key_raises_fr(self):
        # Setup
        packet         = b''
        contact_list   = ContactList()
        key_list       = KeyList()
        o_input        = builtins.input
        builtins.input = lambda x: '2QJL5gVSPEjMTaxWPfYkzG9UJxzZDNSx6PPeVWdzS5CFN7knZy'

        # Test
        self.assertFR("Invalid key decryption key.", process_local_key, packet, contact_list, key_list)

        # Teardown
        builtins.input = o_input

    def test_successful_local_key_processing(self):
        # Setup
        conf_code      = os.urandom(1)
        key            = os.urandom(32)
        hek            = os.urandom(32)
        kek            = os.urandom(32)
        packet         = LOCAL_KEY_PACKET_HEADER + encrypt_and_sign(key + hek + conf_code, key=kek)
        contact_list   = ContactList()
        key_list       = KeyList()
        o_input        = builtins.input
        builtins.input = lambda x: b58encode(kek)

        # Test
        self.assertIsNone(process_local_key(packet, contact_list, key_list))

        # Teardown
        builtins.input = o_input


class TestLocalKeyInstalled(unittest.TestCase):

    def test_function(self):
        # Setup
        ts           = datetime.datetime.now()
        window_list  = WindowList(nicks=['local'])
        contact_list = ContactList(nicks=['local'])

        # Test
        self.assertIsNone(local_key_installed(ts, window_list, contact_list))


class TestProcessPublicKey(unittest.TestCase):

    def test_function(self):
        # Setup
        packet      = PUBLIC_KEY_PACKET_HEADER + os.urandom(32) + ORIGIN_CONTACT_HEADER + b'alice@jabber.org'
        ts          = datetime.datetime.now()
        window_list = WindowList(nicks=['local'])
        settings    = Settings()
        pubkey_buf  = dict()

        # Test
        self.assertIsNone(process_public_key(ts, packet, window_list, settings, pubkey_buf))
        packet       = PUBLIC_KEY_PACKET_HEADER + os.urandom(32) + ORIGIN_USER_HEADER + b'alice@jabber.org'
        self.assertIsNone(process_public_key(ts, packet, window_list, settings, pubkey_buf))


class TestECDHECommand(unittest.TestCase):

    def test_function(self):
        # Setup
        packet       = 32 * b'\x01' + 32 * b'\x02' \
                     + 32 * b'\x03' + 32 * b'\x04' \
                     + b'alice@jabber.org' + US_BYTE + b'Alice'
        ts           = datetime.datetime.now()
        window_list  = WindowList(nicks=['local'])
        settings     = Settings()
        pubkey_buf   = dict()
        contact_list = ContactList()
        key_list     = KeyList()

        # Test
        self.assertIsNone(ecdhe_command(packet, ts, window_list, contact_list, key_list, settings, pubkey_buf))
        keyset = key_list.get_keyset('alice@jabber.org')
        self.assertIsInstance(keyset, KeySet)
        self.assertEqual(keyset.rx_account, 'alice@jabber.org')
        self.assertEqual(keyset.tx_key, 32 * b'\x01')
        self.assertEqual(keyset.tx_hek, 32 * b'\x02')
        self.assertEqual(keyset.rx_key, 32 * b'\x03')
        self.assertEqual(keyset.rx_hek, 32 * b'\x04')

        contact = contact_list.get_contact('alice@jabber.org')
        self.assertIsInstance(contact, Contact)

        self.assertEqual(contact.rx_account, 'alice@jabber.org')
        self.assertEqual(contact.nick, 'Alice')
        self.assertEqual(contact.rx_fingerprint, bytes(32))
        self.assertEqual(contact.tx_fingerprint, bytes(32))


class TestPSKCommand(unittest.TestCase):

    def test_function(self):
        # Setup
        packet       = 32 * b'\x01' + 32 * b'\x02' + b'alice@jabber.org' + US_BYTE + b'Alice'
        ts           = datetime.datetime.now()
        window_list  = WindowList(nicks=['local'])
        settings     = Settings()
        pubkey_buf   = dict()
        contact_list = ContactList()
        key_list     = KeyList()

        # Test
        self.assertIsNone(psk_command(packet, ts, window_list, contact_list, key_list, settings, pubkey_buf))

        keyset = key_list.get_keyset('alice@jabber.org')
        self.assertIsInstance(keyset, KeySet)
        self.assertEqual(keyset.rx_account, 'alice@jabber.org')
        self.assertEqual(keyset.tx_key, 32 * b'\x01')
        self.assertEqual(keyset.tx_hek, 32 * b'\x02')
        self.assertEqual(keyset.rx_key, bytes(32))
        self.assertEqual(keyset.rx_hek, bytes(32))

        contact = contact_list.get_contact('alice@jabber.org')
        self.assertIsInstance(contact, Contact)

        self.assertEqual(contact.rx_account, 'alice@jabber.org')
        self.assertEqual(contact.nick, 'Alice')
        self.assertEqual(contact.rx_fingerprint, bytes(32))
        self.assertEqual(contact.tx_fingerprint, bytes(32))


class TestPSKImport(TFCTestCase):

    def test_unknown_account_raises_fr(self):
        # Setup
        packet       = b'alice@jabber.org'
        contact_list = ContactList()

        # Test
        self.assertFR("Unknown account alice@jabber.org.", psk_import, packet, None, None, contact_list, None, None)

    def test_invalid_psk_data_raises_fr(self):
        # Setup
        packet         = b'alice@jabber.org'
        contact_list   = ContactList(nicks=['Alice'])
        settings       = Settings(disable_gui_dialog=True)
        o_input        = builtins.input
        builtins.input = lambda x: 'ut_psk'

        with open('ut_psk', 'wb+') as f:
            f.write(os.urandom(135))

        # Test
        self.assertFR("Invalid PSK data in file.", psk_import, packet, None, None, contact_list, None, settings)

        # Teardown
        builtins.input = o_input

    def test_invalid_keys_raise_fr(self):
        # Setup
        packet          = b'alice@jabber.org'
        contact_list    = ContactList(nicks=['Alice', 'local'])
        key_list        = KeyList(nicks=['Alice', 'local'])
        keyset          = key_list.get_keyset('alice@jabber.org')
        keyset.rx_key   = bytes(32)
        keyset.rx_hek   = bytes(32)
        window_list     = WindowList(nicks=['Alice', 'local'])
        ts              = datetime.datetime.now()
        settings        = Settings(disable_gui_dialog=True)
        o_input         = builtins.input
        o_getpass       = getpass.getpass
        builtins.input  = lambda x: 'ut_psk'
        input_list      = ['bad', 'testpassword']
        gen             = iter(input_list)

        def mock_input(_):
            return str(next(gen))

        getpass.getpass = mock_input
        password        = 'testpassword'
        salt            = os.urandom(32)
        rx_key          = bytes(32)
        rx_hek          = os.urandom(32)
        kek, _          = argon2_kdf(password, salt, rounds=16, memory=128000, parallelism=1)
        ct_tag          = encrypt_and_sign(rx_key + rx_hek, key=kek)

        with open('ut_psk', 'wb+') as f:
            f.write(salt + ct_tag)

        # Test
        self.assertFR("Keys from contact are not valid.", psk_import, packet, ts, window_list, contact_list, key_list, settings)

        # Teardown
        os.remove('ut_psk')
        builtins.input  = o_input
        getpass.getpass = o_getpass

    def test_valid_psk(self):
        # Setup
        packet          = b'alice@jabber.org'
        contact_list    = ContactList(nicks=['Alice', 'local'])
        key_list        = KeyList(nicks=['Alice', 'local'])
        keyset          = key_list.get_keyset('alice@jabber.org')
        keyset.rx_key   = bytes(32)
        keyset.rx_hek   = bytes(32)
        window_list     = WindowList(nicks=['Alice', 'local'])
        ts              = datetime.datetime.now()
        settings        = Settings(disable_gui_dialog=True)
        o_input         = builtins.input
        o_getpass       = getpass.getpass
        builtins.input  = lambda x: 'ut_psk'
        getpass.getpass = lambda x: 'testpassword'
        password        = 'testpassword'
        salt            = os.urandom(32)
        rx_key          = os.urandom(32)
        rx_hek          = os.urandom(32)
        kek, _          = argon2_kdf(password, salt, rounds=16, memory=128000, parallelism=1)
        ct_tag          = encrypt_and_sign(rx_key + rx_hek, key=kek)

        with open('ut_psk', 'wb+') as f:
            f.write(salt + ct_tag)

        # Test
        self.assertTrue(os.path.isfile('ut_psk'))
        self.assertIsNone(psk_import(packet, ts, window_list, contact_list, key_list, settings))
        self.assertFalse(os.path.isfile('ut_psk'))
        self.assertEqual(keyset.rx_key, rx_key)
        self.assertEqual(keyset.rx_hek, rx_hek)

        # Teardown
        builtins.input  = o_input
        getpass.getpass = o_getpass


if __name__ == '__main__':
    unittest.main(exit=False)
