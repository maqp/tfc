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

import os.path
import unittest

from src.common.crypto  import hash_chain
from src.common.db_keys import KeyList, KeySet
from src.common.statics import *

from tests.mock_classes import create_keyset, MasterKey, Settings
from tests.utils        import cleanup


class TestKeySet(unittest.TestCase):

    def setUp(self):
        self.keyset = KeySet('alice@jabber.org',
                             KEY_LENGTH * b'\x00',
                             KEY_LENGTH * b'\x00',
                             KEY_LENGTH * b'\x00',
                             KEY_LENGTH * b'\x00',
                             0, 0, lambda: None)

    def test_keyset_serialization_length_and_type(self):
        serialized = self.keyset.serialize_k()
        self.assertEqual(len(serialized), KEYSET_LENGTH)
        self.assertIsInstance(serialized, bytes)

    def test_rotate_tx_key(self):
        self.assertIsNone(self.keyset.rotate_tx_key())
        self.assertEqual(self.keyset.tx_key, hash_chain(KEY_LENGTH * b'\x00'))
        self.assertEqual(self.keyset.tx_harac, 1)

    def test_update_tx_key(self):
        self.keyset.update_key(TX,           KEY_LENGTH * b'\x01', 2)
        self.assertEqual(self.keyset.tx_key, KEY_LENGTH * b'\x01')
        self.assertEqual(self.keyset.rx_key, KEY_LENGTH * b'\x00')
        self.assertEqual(self.keyset.tx_hek, KEY_LENGTH * b'\x00')
        self.assertEqual(self.keyset.rx_hek, KEY_LENGTH * b'\x00')
        self.assertEqual(self.keyset.tx_harac, 2)

    def test_update_rx_key(self):
        self.keyset.update_key(RX,           KEY_LENGTH * b'\x01', 2)
        self.assertEqual(self.keyset.tx_key, KEY_LENGTH * b'\x00')
        self.assertEqual(self.keyset.rx_key, KEY_LENGTH * b'\x01')
        self.assertEqual(self.keyset.tx_hek, KEY_LENGTH * b'\x00')
        self.assertEqual(self.keyset.rx_hek, KEY_LENGTH * b'\x00')
        self.assertEqual(self.keyset.rx_harac, 2)

    def test_invalid_direction_raises_critical_error(self):
        with self.assertRaises(SystemExit):
            self.keyset.update_key('sx', KEY_LENGTH * b'\x01', 2)


class TestKeyList(unittest.TestCase):

    def setUp(self):
        self.master_key      = MasterKey()
        self.settings        = Settings()
        self.keylist         = KeyList(MasterKey(), Settings())
        self.keylist.keysets = [create_keyset(n, store_f=self.keylist.store_keys) for n in ['Alice', 'Bob', 'Charlie']]
        self.keylist.store_keys()

    def tearDown(self):
        cleanup()

    def test_storing_and_loading_of_keysets(self):
        # Test Store
        self.assertTrue(os.path.isfile(f'{DIR_USER_DATA}ut_keys'))
        self.assertEqual(os.path.getsize(f'{DIR_USER_DATA}ut_keys'),
                         XSALSA20_NONCE_LEN
                         + self.settings.max_number_of_contacts * KEYSET_LENGTH
                         + POLY1305_TAG_LEN)

        # Test load
        keylist2 = KeyList(MasterKey(), Settings())
        self.assertEqual(len(keylist2.keysets), 3)

    def test_change_master_key(self):
        key        = KEY_LENGTH * b'\x01'
        masterkey2 = MasterKey(master_key=key)
        self.keylist.change_master_key(masterkey2)
        self.assertEqual(self.keylist.master_key.master_key, key)

    def test_generate_dummy_keyset(self):
        dummy_keyset = self.keylist.generate_dummy_keyset()
        self.assertEqual(len(dummy_keyset.serialize_k()), KEYSET_LENGTH)
        self.assertIsInstance(dummy_keyset, KeySet)

    def test_get_keyset(self):
        keyset = self.keylist.get_keyset('alice@jabber.org')
        self.assertIsInstance(keyset, KeySet)

    def test_has_local_key_and_add_keyset(self):
        self.assertFalse(self.keylist.has_local_key())
        self.assertIsNone(self.keylist.add_keyset(LOCAL_ID,
                                                  bytes(KEY_LENGTH), bytes(KEY_LENGTH),
                                                  bytes(KEY_LENGTH), bytes(KEY_LENGTH)))
        self.assertIsNone(self.keylist.add_keyset(LOCAL_ID,
                                                  bytes(KEY_LENGTH), bytes(KEY_LENGTH),
                                                  bytes(KEY_LENGTH), bytes(KEY_LENGTH)))
        self.assertTrue(self.keylist.has_local_key())

    def test_has_keyset_and_remove_keyset(self):
        self.assertTrue(self.keylist.has_keyset('bob@jabber.org'))
        self.assertIsNone(self.keylist.remove_keyset('bob@jabber.org'))
        self.assertFalse(self.keylist.has_keyset('bob@jabber.org'))

    def test_has_rx_key(self):
        self.assertTrue(self.keylist.has_rx_key('bob@jabber.org'))
        self.keylist.get_keyset('bob@jabber.org').rx_key = bytes(KEY_LENGTH)
        self.keylist.get_keyset('bob@jabber.org').rx_hek = bytes(KEY_LENGTH)
        self.assertFalse(self.keylist.has_rx_key('bob@jabber.org'))

    def test_manage_keylist(self):
        self.assertFalse(self.keylist.has_keyset('david@jabber.org'))
        self.assertIsNone(self.keylist.manage(KDB_ADD_ENTRY_HEADER, 'david@jabber.org',
                                              bytes(KEY_LENGTH), bytes(KEY_LENGTH),
                                              bytes(KEY_LENGTH), bytes(KEY_LENGTH)))
        self.assertTrue(self.keylist.has_keyset('david@jabber.org'))

        self.assertIsNone(self.keylist.manage(KDB_REMOVE_ENTRY_HEADER, 'david@jabber.org'))
        self.assertFalse(self.keylist.has_keyset('david@jabber.org'))

        self.assertIsNone(self.keylist.manage(KDB_CHANGE_MASTER_KEY_HEADER, MasterKey(master_key=KEY_LENGTH * b'\x01')))
        self.assertEqual(self.keylist.master_key.master_key, KEY_LENGTH * b'\x01')

        with self.assertRaises(SystemExit):
            self.keylist.manage('invalid_key', None)


if __name__ == '__main__':
    unittest.main(exit=False)
