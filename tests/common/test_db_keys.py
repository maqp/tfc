#!/usr/bin/env python3.7
# -*- coding: utf-8 -*-

"""
TFC - Onion-routed, endpoint secure messaging system
Copyright (C) 2013-2020  Markus Ottela

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

import os.path
import threading
import time
import unittest

from unittest import mock
from typing   import Any

from src.common.crypto   import blake2b, encrypt_and_sign
from src.common.db_keys  import KeyList, KeySet
from src.common.encoding import int_to_bytes
from src.common.misc     import ensure_dir
from src.common.statics  import (DIR_USER_DATA, INITIAL_HARAC, KDB_ADD_ENTRY_HEADER, KDB_HALT_ACK_HEADER,
                                 KDB_M_KEY_CHANGE_HALT_HEADER, KDB_REMOVE_ENTRY_HEADER, KDB_UPDATE_SIZE_HEADER,
                                 KEY_MANAGEMENT_QUEUE, KEY_MGMT_ACK_QUEUE, KEYSET_LENGTH, LOCAL_ID, LOCAL_PUBKEY,
                                 POLY1305_TAG_LENGTH, RX, SYMMETRIC_KEY_LENGTH, TX, XCHACHA20_NONCE_LENGTH)

from tests.mock_classes import create_keyset, MasterKey, nick_to_pub_key, Settings
from tests.utils        import cd_unit_test, cleanup, tamper_file, gen_queue_dict


class TestKeySet(unittest.TestCase):

    def setUp(self) -> None:
        """Pre-test actions."""
        self.keyset = KeySet(onion_pub_key=nick_to_pub_key('Alice'),
                             tx_mk=bytes(SYMMETRIC_KEY_LENGTH),
                             rx_mk=bytes(SYMMETRIC_KEY_LENGTH),
                             tx_hk=bytes(SYMMETRIC_KEY_LENGTH),
                             rx_hk=bytes(SYMMETRIC_KEY_LENGTH),
                             tx_harac=INITIAL_HARAC,
                             rx_harac=INITIAL_HARAC,
                             store_keys=lambda: None)

    def test_keyset_serialization_length_and_type(self) -> None:
        serialized = self.keyset.serialize_k()
        self.assertEqual(len(serialized), KEYSET_LENGTH)
        self.assertIsInstance(serialized, bytes)

    def test_rotate_tx_mk(self) -> None:
        self.assertIsNone(self.keyset.rotate_tx_mk())
        self.assertEqual(self.keyset.tx_mk, blake2b(bytes(SYMMETRIC_KEY_LENGTH) + int_to_bytes(INITIAL_HARAC),
                                                    digest_size=SYMMETRIC_KEY_LENGTH))
        self.assertEqual(self.keyset.rx_mk, bytes(SYMMETRIC_KEY_LENGTH))
        self.assertEqual(self.keyset.tx_hk, bytes(SYMMETRIC_KEY_LENGTH))
        self.assertEqual(self.keyset.rx_hk, bytes(SYMMETRIC_KEY_LENGTH))
        self.assertEqual(self.keyset.tx_harac, 1)
        self.assertEqual(self.keyset.rx_harac, INITIAL_HARAC)

    def test_update_tx_mk(self) -> None:
        self.keyset.update_mk(TX, SYMMETRIC_KEY_LENGTH * b'\x01', 2)
        self.assertEqual(self.keyset.tx_mk, SYMMETRIC_KEY_LENGTH * b'\x01')
        self.assertEqual(self.keyset.rx_mk, bytes(SYMMETRIC_KEY_LENGTH))
        self.assertEqual(self.keyset.tx_hk, bytes(SYMMETRIC_KEY_LENGTH))
        self.assertEqual(self.keyset.rx_hk, bytes(SYMMETRIC_KEY_LENGTH))
        self.assertEqual(self.keyset.tx_harac, 2)
        self.assertEqual(self.keyset.rx_harac, INITIAL_HARAC)

    def test_update_rx_mk(self) -> None:
        self.keyset.update_mk(RX, SYMMETRIC_KEY_LENGTH * b'\x01', 2)
        self.assertEqual(self.keyset.tx_mk, bytes(SYMMETRIC_KEY_LENGTH))
        self.assertEqual(self.keyset.rx_mk, SYMMETRIC_KEY_LENGTH * b'\x01')
        self.assertEqual(self.keyset.tx_hk, bytes(SYMMETRIC_KEY_LENGTH))
        self.assertEqual(self.keyset.rx_hk, bytes(SYMMETRIC_KEY_LENGTH))
        self.assertEqual(self.keyset.tx_harac, INITIAL_HARAC)
        self.assertEqual(self.keyset.rx_harac, 2)

    def test_invalid_direction_raises_critical_error(self) -> None:
        invalid_direction = 'sx'
        with self.assertRaises(SystemExit):
            self.keyset.update_mk(invalid_direction, SYMMETRIC_KEY_LENGTH * b'\x01', 2)


class TestKeyList(unittest.TestCase):

    def setUp(self) -> None:
        """Pre-test actions."""
        self.unit_test_dir     = cd_unit_test()
        self.master_key        = MasterKey()
        self.settings          = Settings()
        self.file_name         = f'{DIR_USER_DATA}{self.settings.software_operation}_keys'
        self.keylist           = KeyList(self.master_key, self.settings)
        self.full_contact_list = ['Alice', 'Bob', 'Charlie', LOCAL_ID]
        self.keylist.keysets   = [create_keyset(n, store_f=self.keylist.store_keys) for n in self.full_contact_list]

    def tearDown(self) -> None:
        """Post-test actions."""
        cleanup(self.unit_test_dir)

    def test_storing_and_loading_of_keysets(self) -> None:
        # Test store
        self.keylist.store_keys()
        self.assertEqual(os.path.getsize(self.file_name),
                         XCHACHA20_NONCE_LENGTH
                         + (self.settings.max_number_of_contacts+1) * KEYSET_LENGTH
                         + POLY1305_TAG_LENGTH)

        # Test load
        key_list2 = KeyList(MasterKey(), Settings())
        self.assertEqual(len(key_list2.keysets), len(self.full_contact_list))

    def test_load_of_modified_database_raises_critical_error(self) -> None:
        self.keylist.store_keys()

        # Test reading works normally
        self.assertIsInstance(KeyList(self.master_key, self.settings), KeyList)

        # Test loading of the tampered database raises CriticalError
        tamper_file(self.file_name, tamper_size=1)
        with self.assertRaises(SystemExit):
            KeyList(self.master_key, self.settings)

    def test_invalid_content_raises_critical_error(self) -> None:
        # Setup
        invalid_data = b'a'
        pt_bytes     = b''.join([k.serialize_k() for k in self.keylist.keysets + self.keylist._dummy_keysets()])
        ct_bytes     = encrypt_and_sign(pt_bytes + invalid_data, self.master_key.master_key)

        ensure_dir(DIR_USER_DATA)
        with open(self.file_name, 'wb+') as f:
            f.write(ct_bytes)

        # Test
        with self.assertRaises(SystemExit):
            KeyList(self.master_key, self.settings)

    def test_generate_dummy_keyset(self) -> None:
        dummy_keyset = self.keylist.generate_dummy_keyset()
        self.assertEqual(len(dummy_keyset.serialize_k()), KEYSET_LENGTH)
        self.assertIsInstance(dummy_keyset, KeySet)

    def test_dummy_keysets(self) -> None:
        dummies = self.keylist._dummy_keysets()
        self.assertEqual(len(dummies), (self.settings.max_number_of_contacts+1) - len(self.full_contact_list))
        for c in dummies:
            self.assertIsInstance(c, KeySet)

    def test_add_keyset(self) -> None:
        new_key              = bytes(SYMMETRIC_KEY_LENGTH)
        self.keylist.keysets = [create_keyset(LOCAL_ID)]

        # Check that KeySet exists and that its keys are different
        self.assertNotEqual(self.keylist.keysets[0].rx_hk, new_key)

        # Replace existing KeySet
        self.assertIsNone(self.keylist.add_keyset(LOCAL_PUBKEY,
                                                  new_key, new_key,
                                                  new_key, new_key))

        # Check that new KeySet replaced the old one
        self.assertEqual(self.keylist.keysets[0].onion_pub_key, LOCAL_PUBKEY)
        self.assertEqual(self.keylist.keysets[0].rx_hk, new_key)

    def test_remove_keyset(self) -> None:
        # Test KeySet for Bob exists
        self.assertTrue(self.keylist.has_keyset(nick_to_pub_key('Bob')))

        # Remove KeySet for Bob
        self.assertIsNone(self.keylist.remove_keyset(nick_to_pub_key('Bob')))

        # Test KeySet was removed
        self.assertFalse(self.keylist.has_keyset(nick_to_pub_key('Bob')))

    @mock.patch('builtins.input', side_effect=['test_password'])
    def test_change_master_key(self, _: Any) -> None:
        # Setup
        key         = SYMMETRIC_KEY_LENGTH * b'\x01'
        master_key2 = MasterKey(master_key=key)
        queues      = gen_queue_dict()

        def queue_delayer() -> None:
            """Place packet to queue after timer runs out."""
            time.sleep(0.1)
            queues[KEY_MANAGEMENT_QUEUE].put(master_key2.master_key)
        threading.Thread(target=queue_delayer).start()

        # Test that new key is different from existing one
        self.assertNotEqual(key, self.master_key.master_key)

        # Change master key
        self.assertIsNone(self.keylist.change_master_key(queues))

        # Test that master key has changed
        self.assertEqual(self.keylist.master_key.master_key, key)
        self.assertEqual(self.keylist.database.database_key, key)

        self.assertEqual(queues[KEY_MGMT_ACK_QUEUE].get(), KDB_HALT_ACK_HEADER)
        self.assertEqual(queues[KEY_MGMT_ACK_QUEUE].get(), key)

    def test_update_database(self) -> None:
        # Setup
        queues = gen_queue_dict()

        # Test
        self.assertEqual(os.path.getsize(self.file_name), 9016)
        self.assertIsNone(self.keylist.manage(queues, KDB_UPDATE_SIZE_HEADER, Settings(max_number_of_contacts=100)))
        self.assertEqual(os.path.getsize(self.file_name), 17816)
        self.assertEqual(self.keylist.settings.max_number_of_contacts, 100)

    def test_get_keyset(self) -> None:
        keyset = self.keylist.get_keyset(nick_to_pub_key('Alice'))
        self.assertIsInstance(keyset, KeySet)

    def test_get_list_of_pub_keys(self) -> None:
        self.assertEqual(self.keylist.get_list_of_pub_keys(),
                         [nick_to_pub_key("Alice"),
                          nick_to_pub_key("Bob"),
                          nick_to_pub_key("Charlie")])

    def test_has_keyset(self) -> None:
        self.keylist.keysets = []
        self.assertFalse(self.keylist.has_keyset(nick_to_pub_key("Alice")))

        self.keylist.keysets = [create_keyset('Alice')]
        self.assertTrue(self.keylist.has_keyset(nick_to_pub_key("Alice")))

    def test_has_rx_mk(self) -> None:
        self.assertTrue(self.keylist.has_rx_mk(nick_to_pub_key('Bob')))
        self.keylist.get_keyset(nick_to_pub_key('Bob')).rx_mk = bytes(SYMMETRIC_KEY_LENGTH)
        self.keylist.get_keyset(nick_to_pub_key('Bob')).rx_hk = bytes(SYMMETRIC_KEY_LENGTH)
        self.assertFalse(self.keylist.has_rx_mk(nick_to_pub_key('Bob')))

    def test_has_local_keyset(self) -> None:
        self.keylist.keysets = []
        self.assertFalse(self.keylist.has_local_keyset())

        self.assertIsNone(self.keylist.add_keyset(LOCAL_PUBKEY,
                                                  bytes(SYMMETRIC_KEY_LENGTH), bytes(SYMMETRIC_KEY_LENGTH),
                                                  bytes(SYMMETRIC_KEY_LENGTH), bytes(SYMMETRIC_KEY_LENGTH)))
        self.assertTrue(self.keylist.has_local_keyset())

    def test_manage(self) -> None:
        # Setup
        queues = gen_queue_dict()

        # Test that KeySet for David does not exist
        self.assertFalse(self.keylist.has_keyset(nick_to_pub_key('David')))

        # Test adding KeySet
        self.assertIsNone(self.keylist.manage(queues, KDB_ADD_ENTRY_HEADER, nick_to_pub_key('David'),
                                              bytes(SYMMETRIC_KEY_LENGTH), bytes(SYMMETRIC_KEY_LENGTH),
                                              bytes(SYMMETRIC_KEY_LENGTH), bytes(SYMMETRIC_KEY_LENGTH)))
        self.assertTrue(self.keylist.has_keyset(nick_to_pub_key('David')))

        # Test removing KeySet
        self.assertIsNone(self.keylist.manage(queues, KDB_REMOVE_ENTRY_HEADER, nick_to_pub_key('David')))
        self.assertFalse(self.keylist.has_keyset(nick_to_pub_key('David')))

        # Test changing master key
        new_key = SYMMETRIC_KEY_LENGTH * b'\x01'

        self.assertNotEqual(self.master_key.master_key, new_key)

        queues[KEY_MANAGEMENT_QUEUE].put(new_key)
        self.assertIsNone(self.keylist.manage(queues, KDB_M_KEY_CHANGE_HALT_HEADER))

        self.assertEqual(self.keylist.master_key.master_key, new_key)
        self.assertEqual(self.keylist.database.database_key, new_key)

        # Test invalid KeyList management command raises Critical Error
        with self.assertRaises(SystemExit):
            self.keylist.manage(queues, 'invalid_key', None)


if __name__ == '__main__':
    unittest.main(exit=False)
