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

import binascii
import builtins
import datetime
import getpass
import os
import subprocess
import unittest

from src.common.crypto   import argon2_kdf, encrypt_and_sign
from src.common.encoding import b58encode
from src.common.statics  import *

from src.rx.key_exchanges import add_psk_tx_keys, add_x25519_keys, import_psk_rx_keys
from src.rx.key_exchanges import local_key_installed, process_local_key, process_public_key

from tests.mock_classes import Contact, ContactList, KeyList, KeySet, Settings, WindowList
from tests.utils        import ignored, TFCTestCase


class TestProcessLocalKey(TFCTestCase):

    def setUp(self):
        self.o_input      = builtins.input
        self.contact_list = ContactList(nicks=[LOCAL_ID])
        self.key_list     = KeyList(    nicks=[LOCAL_ID])
        self.window_list  = WindowList( nicks=[LOCAL_ID])
        self.settings     = Settings()
        self.ts           = datetime.datetime.now()

    def tearDown(self):
        builtins.input = self.o_input

    def test_invalid_decryption_key_raises_fr(self):
        # Setup
        packet                = b''
        builtins.input        = lambda _: '5JJwZE46Eic9B8sKJ8Qocyxa8ytUJSfcqRo7Hr5ES7YgFGeJjCJ'
        self.key_list.keysets = []

        # Test
        self.assertFR("Error: Incorrect key decryption key.",
                      process_local_key, self.ts, packet, self.window_list, self.contact_list, self.key_list, self.settings)

    def test_successful_local_key_processing_existing_local_key(self):
        # Setup
        conf_code = os.urandom(1)
        key       = os.urandom(KEY_LENGTH)
        hek       = os.urandom(KEY_LENGTH)
        kek       = os.urandom(KEY_LENGTH)
        packet    = LOCAL_KEY_PACKET_HEADER + encrypt_and_sign(key + hek + conf_code, key=kek)

        input_list     = ['5JJwZE46Eic9B8sKJ8Qocyxa8ytUJSfcqRo7Hr5ES7YgFGeJjCJ', b58encode(kek)]
        gen            = iter(input_list)
        builtins.input = lambda _: str(next(gen))

        # Test
        self.assertIsNone(process_local_key(self.ts, packet, self.window_list, self.contact_list, self.key_list, self.settings))

    def test_successful_local_key_processing_existing_bootstrap(self):
        # Setup
        conf_code = os.urandom(1)
        key       = os.urandom(KEY_LENGTH)
        hek       = os.urandom(KEY_LENGTH)
        kek       = os.urandom(KEY_LENGTH)
        packet    = LOCAL_KEY_PACKET_HEADER + encrypt_and_sign(key + hek + conf_code, key=kek)

        input_list     = [b58encode(kek)]
        gen            = iter(input_list)
        builtins.input = lambda _: str(next(gen))

        self.key_list.keysets = []

        # Test
        self.assertIsNone(process_local_key(self.ts, packet, self.window_list, self.contact_list, self.key_list, self.settings))
        self.assertEqual(self.window_list.active_win.uid, LOCAL_ID)


class TestLocalKeyInstalled(TFCTestCase):

    def setUp(self):
        self.ts           = datetime.datetime.now()
        self.window_list  = WindowList(nicks=[LOCAL_ID])
        self.contact_list = ContactList(nicks=[LOCAL_ID])

    def test_local_key_installed(self):
        self.assertPrints(f"""\
                 ┌────────────────────────────────────────────┐                 
                 │ Successfully completed local key exchange. │                 
                 └────────────────────────────────────────────┘                 
{CLEAR_ENTIRE_SCREEN+CURSOR_LEFT_UP_CORNER}
                            Waiting for new contacts                            

""", local_key_installed, self.ts, self.window_list, self.contact_list)


class TestProcessPublicKey(TFCTestCase):

    def setUp(self):
        self.ts          = datetime.datetime.now()
        self.window_list = WindowList()
        self.settings    = Settings()
        self.pubkey_buf  = dict()

    def test_invalid_account_encoding_raises_fr(self):
        packet = PUBLIC_KEY_PACKET_HEADER + os.urandom(KEY_LENGTH) + ORIGIN_CONTACT_HEADER + binascii.unhexlify('a466c02c221cb135')

        self.assertFR("Error! Account for received public key had invalid encoding.",
                      process_public_key, self.ts, packet, self.window_list, self.settings, self.pubkey_buf)

    def test_invalid_origin_raises_fr(self):
        packet = PUBLIC_KEY_PACKET_HEADER + os.urandom(KEY_LENGTH) + b'x' + b'alice@jabber.org'

        self.assertFR("Error! Received public key had an invalid origin header.",
                      process_public_key, self.ts, packet, self.window_list, self.settings, self.pubkey_buf)

    def test_receive_public_key_from_contact(self):
        packet = PUBLIC_KEY_PACKET_HEADER + KEY_LENGTH*b'a' + ORIGIN_CONTACT_HEADER + b'alice@jabber.org'

        self.assertPrints("""\
    ┌─────────────────────────────────────────────────────────────────────┐     
    │             Received public key from alice@jabber.org:              │     
    │  A   B   C   D   E   F   G   H   I   J   K   L   M   N   O   P   Q  │     
    │ 5JZ B2s 2RC tRU unK iqM bb6 rAj 3Z7 TkJ wa8 zkn L1c fTF pWo QAr d6n │     
    └─────────────────────────────────────────────────────────────────────┘     
""", process_public_key, self.ts, packet, self.window_list, self.settings, self.pubkey_buf)

    def test_outgoing_public_key_loads_most_recent_pub_key_from_contact(self):
        self.pubkey_buf['alice@jabber.org'] = KEY_LENGTH * b'a'
        packet = PUBLIC_KEY_PACKET_HEADER + KEY_LENGTH * b'a' + ORIGIN_USER_HEADER + b'alice@jabber.org'

        self.assertPrints(CLEAR_ENTIRE_SCREEN + CURSOR_LEFT_UP_CORNER + """\
    ┌─────────────────────────────────────────────────────────────────────┐     
    │                  Public key for alice@jabber.org:                   │     
    │  A   B   C   D   E   F   G   H   I   J   K   L   M   N   O   P   Q  │     
    │ 5JZ B2s 2RC tRU unK iqM bb6 rAj 3Z7 TkJ wa8 zkn L1c fTF pWo QAr d6n │     
    └─────────────────────────────────────────────────────────────────────┘     
""", process_public_key, self.ts, packet, self.window_list, self.settings, self.pubkey_buf)


class TestX25519Command(unittest.TestCase):

    def setUp(self):
        self.ts           = datetime.datetime.now()
        self.window_list  = WindowList(nicks=[LOCAL_ID])
        self.contact_list = ContactList()
        self.key_list     = KeyList()
        self.settings     = Settings()
        self.pubkey_buf   = {'alice@jabber.org': KEY_LENGTH*b'a'}

        self.packet = KEY_LENGTH * b'\x01'   + KEY_LENGTH * b'\x02' \
                      + KEY_LENGTH * b'\x03' + KEY_LENGTH * b'\x04' \
                      + b'alice@jabber.org' + US_BYTE + b'Alice'

    def test_add_x25519keys(self):
        self.assertIsNone(add_x25519_keys(self.packet, self.ts, self.window_list, self.contact_list,
                                          self.key_list, self.settings, self.pubkey_buf))

        keyset = self.key_list.get_keyset('alice@jabber.org')
        self.assertIsInstance(keyset, KeySet)

        self.assertEqual(keyset.rx_account, 'alice@jabber.org')
        self.assertEqual(keyset.tx_key, KEY_LENGTH * b'\x01')
        self.assertEqual(keyset.tx_hek, KEY_LENGTH * b'\x02')
        self.assertEqual(keyset.rx_key, KEY_LENGTH * b'\x03')
        self.assertEqual(keyset.rx_hek, KEY_LENGTH * b'\x04')

        contact = self.contact_list.get_contact('alice@jabber.org')
        self.assertIsInstance(contact, Contact)

        self.assertEqual(contact.rx_account, 'alice@jabber.org')
        self.assertEqual(contact.nick, 'Alice')
        self.assertEqual(contact.rx_fingerprint, bytes(FINGERPRINT_LEN))
        self.assertEqual(contact.tx_fingerprint, bytes(FINGERPRINT_LEN))

        self.assertFalse('alice@jabber.org' in self.pubkey_buf)


class TestAddPSKTxKeys(unittest.TestCase):

    def setUp(self):
        self.ts           = datetime.datetime.now()
        self.window_list  = WindowList(nicks=[LOCAL_ID])
        self.contact_list = ContactList()
        self.key_list     = KeyList()
        self.settings     = Settings()
        self.pubkey_buf   = {'alice@jabber.org' : KEY_LENGTH*b'a'}
        self.packet       = KEY_LENGTH * b'\x01' + KEY_LENGTH * b'\x02' + b'alice@jabber.org' + US_BYTE + b'Alice'

    def test_add_psk_tx_keys(self):
        self.assertIsNone(add_psk_tx_keys(self.packet, self.ts, self.window_list, self.contact_list,
                                          self.key_list, self.settings, self.pubkey_buf))

        keyset = self.key_list.get_keyset('alice@jabber.org')
        self.assertIsInstance(keyset, KeySet)
        self.assertEqual(keyset.rx_account, 'alice@jabber.org')
        self.assertEqual(keyset.tx_key, KEY_LENGTH * b'\x01')
        self.assertEqual(keyset.tx_hek, KEY_LENGTH * b'\x02')
        self.assertEqual(keyset.rx_key, bytes(KEY_LENGTH))
        self.assertEqual(keyset.rx_hek, bytes(KEY_LENGTH))

        contact = self.contact_list.get_contact('alice@jabber.org')
        self.assertIsInstance(contact, Contact)

        self.assertEqual(contact.rx_account, 'alice@jabber.org')
        self.assertEqual(contact.nick, 'Alice')
        self.assertEqual(contact.rx_fingerprint, bytes(FINGERPRINT_LEN))
        self.assertEqual(contact.tx_fingerprint, bytes(FINGERPRINT_LEN))

        self.assertFalse('alice@jabber.org' in self.pubkey_buf)


class TestImportPSKRxKeys(TFCTestCase):

    class MockPopen(object):
        def __init__(self, cmd, shell):
            self.cmd   = cmd
            self.shell = shell

        def wait(self):
            pass

    def setUp(self):
        self.o_input   = builtins.input
        self.o_getpass = getpass.getpass
        self.o_sp      = subprocess.Popen

        self.packet       = b'alice@jabber.org'
        self.ts           = datetime.datetime.now()
        self.window_list  = WindowList( nicks=['Alice', LOCAL_ID])
        self.contact_list = ContactList(nicks=['Alice', LOCAL_ID])
        self.key_list     = KeyList(    nicks=['Alice', LOCAL_ID])
        self.settings     = Settings(disable_gui_dialog=True)

        builtins.input = lambda _: 'ut_psk'

    def tearDown(self):
        builtins.input   = self.o_input
        getpass.getpass  = self.o_getpass
        subprocess.Popen = self.o_sp

        with ignored(OSError):
            os.remove('ut_psk')

    def test_unknown_account_raises_fr(self):
        self.assertFR("Error: Unknown account 'bob@jabber.org'",
                      import_psk_rx_keys, b'bob@jabber.org', self.ts, self.window_list, self.contact_list, self.key_list, self.settings)

    def test_invalid_psk_data_raises_fr(self):
        # Setup
        with open('ut_psk', 'wb+') as f:
            f.write(os.urandom(135))

        # Test
        self.assertFR("Error: Invalid PSK data in file.",
                      import_psk_rx_keys, self.packet, self.ts, self.window_list, self.contact_list, self.key_list, self.settings)

    def test_invalid_keys_raise_fr(self):
        # Setup
        keyset          = self.key_list.get_keyset('alice@jabber.org')
        keyset.rx_key   = bytes(KEY_LENGTH)
        keyset.rx_hek   = bytes(KEY_LENGTH)
        password        = 'password'
        input_list      = ['bad', password]
        gen             = iter(input_list)
        getpass.getpass = lambda _: str(next(gen))

        salt    = os.urandom(ARGON2_SALT_LEN)
        rx_key  = bytes(KEY_LENGTH)
        rx_hek  = os.urandom(KEY_LENGTH)
        kek, _  = argon2_kdf(password, salt, parallelism=1)
        ct_tag  = encrypt_and_sign(rx_key + rx_hek, key=kek)

        with open('ut_psk', 'wb+') as f:
            f.write(salt + ct_tag)

        # Test
        self.assertFR("Error: Received invalid keys from contact.",
                      import_psk_rx_keys, self.packet, self.ts, self.window_list, self.contact_list, self.key_list, self.settings)

    def test_valid_psk(self):
        # Setup
        keyset        = self.key_list.get_keyset('alice@jabber.org')
        keyset.rx_key = bytes(KEY_LENGTH)
        keyset.rx_hek = bytes(KEY_LENGTH)

        getpass.getpass = lambda _: 'testpassword'
        password        = 'testpassword'
        salt            = os.urandom(ARGON2_SALT_LEN)
        rx_key          = os.urandom(KEY_LENGTH)
        rx_hek          = os.urandom(KEY_LENGTH)
        kek, _          = argon2_kdf(password, salt, parallelism=1)
        ct_tag          = encrypt_and_sign(rx_key + rx_hek, key=kek)

        with open('ut_psk', 'wb+') as f:
            f.write(salt + ct_tag)

        # Test
        self.assertTrue(os.path.isfile('ut_psk'))
        self.assertIsNone(import_psk_rx_keys(self.packet, self.ts, self.window_list, self.contact_list, self.key_list, self.settings))
        self.assertFalse(os.path.isfile('ut_psk'))
        self.assertEqual(keyset.rx_key, rx_key)
        self.assertEqual(keyset.rx_hek, rx_hek)

    def test_valid_psk_overwrite_failure(self):
        # Setup
        keyset        = self.key_list.get_keyset('alice@jabber.org')
        keyset.rx_key = bytes(KEY_LENGTH)
        keyset.rx_hek = bytes(KEY_LENGTH)

        input_list       = ['ut_psk', '']
        gen              = iter(input_list)
        builtins.input   = lambda _: next(gen)
        subprocess.Popen = TestImportPSKRxKeys.MockPopen

        getpass.getpass = lambda _: 'testpassword'
        password        = 'testpassword'
        salt            = os.urandom(ARGON2_SALT_LEN)
        rx_key          = os.urandom(KEY_LENGTH)
        rx_hek          = os.urandom(KEY_LENGTH)
        kek, _          = argon2_kdf(password, salt, parallelism=1)
        ct_tag          = encrypt_and_sign(rx_key + rx_hek, key=kek)

        with open('ut_psk', 'wb+') as f:
            f.write(salt + ct_tag)

        # Test
        self.assertTrue(os.path.isfile('ut_psk'))
        self.assertIsNone(import_psk_rx_keys(self.packet, self.ts, self.window_list, self.contact_list, self.key_list, self.settings))
        self.assertTrue(os.path.isfile('ut_psk'))
        self.assertEqual(keyset.rx_key, rx_key)
        self.assertEqual(keyset.rx_hek, rx_hek)


if __name__ == '__main__':
    unittest.main(exit=False)
