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
import os.path
import unittest

from src.common.db_keys import KeyList, KeySet
from src.common.statics import *

from tests.mock_classes import create_keyset, MasterKey, Settings
from tests.utils        import cleanup


class TestKeySet(unittest.TestCase):

    def test_class(self):
        # Setup
        m_sk   = lambda: None
        keyset = KeySet('alice@jabber.org',
                        32 * b'\x00',
                        32 * b'\x00',
                        32 * b'\x00',
                        32 * b'\x00',
                        0, 0, m_sk)

        # Test
        bytestring = keyset.dump_k()
        self.assertEqual(len(bytestring), 1024 + 4 * 32 + 8 + 8)
        self.assertIsInstance(bytestring, bytes)
        self.assertIsNone(keyset.rotate_tx_key())
        self.assertEqual(keyset.tx_key, binascii.unhexlify("8d8c36497eb93a6355112e253f705a32"
                                                           "85f3e2d82b9ac29461cd8d4f764e5d41"))
        self.assertEqual(keyset.tx_harac, 1)

        keyset.tx_key = 32 * b'\x00'

        keyset.update_key('tx', 32 * b'\x01', 2)
        self.assertEqual(keyset.tx_key, 32 * b'\x01')
        self.assertEqual(keyset.rx_key, 32 * b'\x00')
        self.assertEqual(keyset.tx_hek, 32 * b'\x00')
        self.assertEqual(keyset.rx_hek, 32 * b'\x00')
        self.assertEqual(keyset.tx_harac, 3)

        keyset.update_key('rx', 32 * b'\x01', 2)
        self.assertEqual(keyset.tx_key, 32 * b'\x01')
        self.assertEqual(keyset.rx_key, 32 * b'\x01')
        self.assertEqual(keyset.tx_hek, 32 * b'\x00')
        self.assertEqual(keyset.rx_hek, 32 * b'\x00')
        self.assertEqual(keyset.rx_harac, 2)


class TestKeyList(unittest.TestCase):

    def test_class(self):
        # Setup
        masterkey       = MasterKey()
        settings        = Settings()
        keylist         = KeyList(masterkey, settings)
        keylist.keysets = [create_keyset(n, store_f=keylist.store_keys) for n in ['Alice', 'Bob', 'Charlie']]

        keylist.store_keys()

        # Test
        self.assertTrue(os.path.isfile(f'{DIR_USER_DATA}/ut_keys'))
        self.assertEqual(os.path.getsize(f'{DIR_USER_DATA}/ut_keys'), 24 + 20 * (1024 + 4*32 + 2*8) + 16)

        keylist2 = KeyList(masterkey, settings)

        for k in keylist2.keysets:
            self.assertIsInstance(k, KeySet)

        self.assertEqual(len(keylist2.keysets), 3)

        bytestring = keylist2.generate_dummy_keyset()
        self.assertEqual(len(bytestring), 1024 + 4 * 32 + 8 + 8)
        self.assertIsInstance(bytestring, bytes)

        keyset = keylist2.get_keyset('alice@jabber.org')
        self.assertIsInstance(keyset, KeySet)

        self.assertFalse(keylist2.has_local_key())
        self.assertIsNone(keylist2.manage('ADD', 'local', bytes(32), bytes(32), bytes(32), bytes(32)))
        self.assertTrue(keylist2.has_local_key())

        self.assertTrue(keylist2.has_keyset('bob@jabber.org'))
        self.assertIsNone(keylist2.manage('REM', 'bob@jabber.org'))
        self.assertFalse(keylist2.has_keyset('bob@jabber.org'))

        keylist2.get_keyset('charlie@jabber.org').tx_harac = 1
        self.assertIsNone(keylist2.manage('ADD', 'charlie@jabber.org', bytes(32), bytes(32), bytes(32), bytes(32)))
        self.assertEqual(keylist2.get_keyset('charlie@jabber.org').tx_harac, 0)

        masterkey2            = MasterKey()
        masterkey2.master_key = 32 * b'\x01'
        keylist2.manage('KEY', masterkey2)
        self.assertEqual(keylist2.master_key.master_key, 32 * b'\x01')

        with self.assertRaises(SystemExit):
            keylist2.manage('invalid_key', masterkey2)

        # Teardown
        cleanup()


if __name__ == '__main__':
    unittest.main(exit=False)
