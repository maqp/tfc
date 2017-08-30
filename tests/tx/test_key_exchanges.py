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
import getpass
import os
import unittest
import time

from multiprocessing import Queue

from src.common.encoding import b58encode
from src.common.statics  import *

from src.tx.key_exchanges import new_local_key, create_pre_shared_key, rxm_load_psk, start_key_exchange, verify_fingerprints

from tests.mock_classes import create_contact, ContactList, Settings, TxWindow
from tests.utils        import ignored, TFCTestCase


class TestLocalKey(TFCTestCase):

    def setUp(self):
        self.o_input     = builtins.input
        self.o_urandom   = os.urandom

        if 'TRAVIS' not in os.environ or not os.environ['TRAVIS'] == 'true':
            self.o_getrandom = os.getrandom

        self.contact_list = ContactList()
        self.settings     = Settings()
        self.queues       = {COMMAND_PACKET_QUEUE: Queue(),
                             NH_PACKET_QUEUE:      Queue(),
                             KEY_MANAGEMENT_QUEUE: Queue()}

    def tearDown(self):
        builtins.input = self.o_input
        os.urandom     = self.o_urandom

        if 'TRAVIS' not in os.environ or not os.environ['TRAVIS'] == 'true':
            os.getrandom = self.o_getrandom

        for key in self.queues.keys():
            while not self.queues[key].empty():
                self.queues[key].get()
            time.sleep(0.1)
            self.queues[key].close()

    def test_new_local_key_when_traffic_masking_is_enabled_raises_fr(self):
        # Setup
        self.settings.session_traffic_masking = True

        # Test
        self.assertFR("Error: Command is disabled during traffic masking.",
                      new_local_key, self.contact_list, self.settings, self.queues)

    def test_new_local_key(self):
        # Setup
        self.settings.nh_bypass_messages      = False
        self.settings.session_traffic_masking = False

        if 'TRAVIS' not in os.environ or not os.environ['TRAVIS'] == 'true':
            os.getrandom = lambda n, flags: n * b'\xff'

        os.urandom     = lambda n:        n * b'\xff'
        input_list     = ['bad', 'resend', 'ff']
        gen            = iter(input_list)
        builtins.input = lambda _: str(next(gen))

        # Test
        self.assertIsNone(new_local_key(self.contact_list, self.settings, self.queues))
        time.sleep(0.1)

        local_contact = self.contact_list.get_contact(LOCAL_ID)

        self.assertEqual(local_contact.rx_account, LOCAL_ID)
        self.assertEqual(local_contact.tx_account, LOCAL_ID)
        self.assertEqual(local_contact.nick,       LOCAL_ID)
        self.assertEqual(local_contact.tx_fingerprint, bytes(FINGERPRINT_LEN))
        self.assertEqual(local_contact.rx_fingerprint, bytes(FINGERPRINT_LEN))
        self.assertFalse(local_contact.log_messages)
        self.assertFalse(local_contact.file_reception)
        self.assertFalse(local_contact.notifications)

        self.assertEqual(self.queues[COMMAND_PACKET_QUEUE].qsize(), 1)

        cmd, account, tx_key, rx_key, tx_hek, rx_hek = self.queues[KEY_MANAGEMENT_QUEUE].get()

        self.assertEqual(cmd, KDB_ADD_ENTRY_HEADER)
        self.assertEqual(account, LOCAL_ID)
        for key in [tx_key, rx_key, tx_hek, rx_hek]:
            self.assertIsInstance(key, bytes)
            self.assertEqual(len(key), KEY_LENGTH)


class TestVerifyFingerprints(unittest.TestCase):

    def setUp(self):
        self.o_input = builtins.input

    def tearDown(self):
        builtins.input = self.o_input

    def test_correct_fingerprint(self):
        builtins.input = lambda _: 'Yes'
        self.assertTrue(verify_fingerprints(bytes(32), bytes(32)))

    def test_incorrect_fingerprint(self):
        builtins.input = lambda _: 'No'
        self.assertFalse(verify_fingerprints(bytes(32), bytes(32)))


class TestKeyExchange(TFCTestCase):

    def setUp(self):
        self.o_input = builtins.input

        self.contact_list = ContactList()
        self.settings     = Settings()
        self.queues       = {COMMAND_PACKET_QUEUE: Queue(),
                             NH_PACKET_QUEUE:      Queue(),
                             KEY_MANAGEMENT_QUEUE: Queue()}

    def tearDown(self):
        builtins.input = self.o_input

        for key in self.queues.keys():
            while not self.queues[key].empty():
                self.queues[key].get()
            time.sleep(0.1)
            self.queues[key].close()

    def test_zero_public_key_raises_fr(self):
        # Setup
        builtins.input = lambda _: b58encode(bytes(32))

        # Test
        self.assertFR("Error: Zero public key", start_key_exchange, 'alice@jabber.org', 'user@jabber.org', 'Alice',
                      self.contact_list, self.settings, self.queues)

    def test_raises_fr_during_fingerprint_mismatch(self):
        # Setup
        input_list     = ['resend',                                                # Resend should resend key
                          '5JCVapni8CR2PEXr5v92cCY2QgSd4cztR2v3L3vK2eair7dGHi',    # Short key should fail
                          '5JCVapni8CR2PEXr5v92cCY2QgSd4cztR2v3L3vK2eair7dGHiHa',  # Long key should fail
                          '5JCVapni8CR2PEXr5v92cCY2QgSd4cztR2v3L3vK2eair7dGHia',   # Invalid key should fail
                          '5JCVapni8CR2PEXr5v92cCY2QgSd4cztR2v3L3vK2eair7dGHiH',   # Correct key
                          'No']                                                    # Fingerprint mismatch

        gen            = iter(input_list)
        builtins.input = lambda _: str(next(gen))

        # Test
        self.assertFR("Error: Fingerprint mismatch", start_key_exchange, 'alice@jabber.org', 'user@jabber.org', 'Alice',
                      self.contact_list, self.settings, self.queues)

    def test_successful_exchange(self):
        # Setup
        input_list     = ['5JCVapni8CR2PEXr5v92cCY2QgSd4cztR2v3L3vK2eair7dGHiH',  # Correct key
                          'Yes']                                                  # Fingerprint match
        gen            = iter(input_list)
        builtins.input = lambda _: str(next(gen))

        # Test
        self.assertIsNone(start_key_exchange('alice@jabber.org',  'user@jabber.org', 'Alice',
                                             self.contact_list, self.settings, self.queues))
        time.sleep(0.1)

        contact = self.contact_list.get_contact('alice@jabber.org')

        self.assertEqual(contact.rx_account, 'alice@jabber.org')
        self.assertEqual(contact.tx_account, 'user@jabber.org')
        self.assertEqual(contact.nick,       'Alice')
        self.assertIsInstance(contact.tx_fingerprint, bytes)
        self.assertIsInstance(contact.rx_fingerprint, bytes)
        self.assertEqual(len(contact.tx_fingerprint), FINGERPRINT_LEN)
        self.assertEqual(len(contact.rx_fingerprint), FINGERPRINT_LEN)
        self.assertFalse(contact.log_messages)
        self.assertFalse(contact.file_reception)
        self.assertTrue(contact.notifications)

        self.assertEqual(self.queues[COMMAND_PACKET_QUEUE].qsize(), 1)

        cmd, account, tx_key, rx_key, tx_hek, rx_hek = self.queues[KEY_MANAGEMENT_QUEUE].get()

        self.assertEqual(cmd,         KDB_ADD_ENTRY_HEADER)
        self.assertEqual(account,     'alice@jabber.org')
        self.assertEqual(len(tx_key), KEY_LENGTH)
        for key in [tx_key, rx_key, tx_hek, rx_hek]:
            self.assertIsInstance(key, bytes)
            self.assertEqual(len(key), KEY_LENGTH)

class TestPSK(TFCTestCase):

    def setUp(self):
        if 'TRAVIS' not in os.environ or not os.environ['TRAVIS'] == 'true':
            self.o_getrandom = os.getrandom

        self.o_input      = builtins.input
        self.o_getpass    = getpass.getpass
        self.contact_list = ContactList()
        self.settings     = Settings(disable_gui_dialog=True)
        self.queues       = {COMMAND_PACKET_QUEUE: Queue(),
                             KEY_MANAGEMENT_QUEUE: Queue()}

        if 'TRAVIS' not in os.environ or not os.environ['TRAVIS'] == 'true':
            os.getrandom = lambda n, flags: n * b'\x00'

        getpass.getpass = lambda _: 'test_password'
        input_list      = ['/root/',  # Invalid directory
                           '.']        # Valid directory
        gen             = iter(input_list)
        builtins.input  = lambda _: str(next(gen))

    def tearDown(self):
        builtins.input  = self.o_input
        getpass.getpass = self.o_getpass

        if 'TRAVIS' not in os.environ or not os.environ['TRAVIS'] == 'true':
            os.getrandom = self.o_getrandom

        with ignored(OSError):
            os.remove('user@jabber.org.psk - Give to alice@jabber.org')

        for key in self.queues.keys():
            while not self.queues[key].empty():
                self.queues[key].get()
            time.sleep(0.1)
            self.queues[key].close()

    def test_psk_creation(self):
        self.assertIsNone(create_pre_shared_key('alice@jabber.org', 'user@jabber.org', 'Alice',
                                                self.contact_list, self.settings, self.queues))

        contact = self.contact_list.get_contact('alice@jabber.org')

        self.assertEqual(contact.rx_account, 'alice@jabber.org')
        self.assertEqual(contact.tx_account, 'user@jabber.org')
        self.assertEqual(contact.nick,       'Alice')
        self.assertEqual(contact.tx_fingerprint, bytes(FINGERPRINT_LEN))
        self.assertEqual(contact.rx_fingerprint, bytes(FINGERPRINT_LEN))
        self.assertFalse(contact.log_messages)
        self.assertFalse(contact.file_reception)
        self.assertTrue(contact.notifications)

        cmd, account, tx_key, rx_key, tx_hek, rx_hek = self.queues[KEY_MANAGEMENT_QUEUE].get()

        self.assertEqual(cmd,         KDB_ADD_ENTRY_HEADER)
        self.assertEqual(account,     'alice@jabber.org')
        for key in [tx_key, rx_key, tx_hek, rx_hek]:
            self.assertIsInstance(key, bytes)
            self.assertEqual(len(key), KEY_LENGTH)

        self.assertEqual(self.queues[COMMAND_PACKET_QUEUE].qsize(), 1)
        self.assertTrue(os.path.isfile('user@jabber.org.psk - Give to alice@jabber.org'))


class TestRxMLoadPSK(TFCTestCase):

    def setUp(self):
        self.c_queue  = Queue()
        self.settings = Settings()

    def tearDown(self):
        while not self.c_queue.empty():
            self.c_queue.get()
        time.sleep(0.1)
        self.c_queue.close()

    def test_raises_fr_when_traffic_masking_is_enabled(self):
        # Setup
        self.settings.session_traffic_masking = True

        # Test
        self.assertFR("Error: Command is disabled during traffic masking.",
                      rxm_load_psk, None, None, self.settings, None)

    def test_active_group_raises_fr(self):
        # Setup
        window = TxWindow(type=WIN_TYPE_GROUP)

        # Test
        self.assertFR("Error: Group is selected.", rxm_load_psk, window, None, self.settings, None)

    def test_x25519_key_raises_fr(self):
        # Setup
        window       = TxWindow(type=WIN_TYPE_CONTACT,
                                uid ='alice@jabber.org')
        contact_list = ContactList(nicks=['Alice'])

        # Test
        self.assertFR("Error: Current key was exchanged with X25519.",
                      rxm_load_psk, window, contact_list, self.settings, None)

    def test_successful_command(self):
        # Setup
        window       = TxWindow(type=WIN_TYPE_CONTACT,
                                uid ='alice@jabber.org')
        contact      = create_contact(txfp=bytes(FINGERPRINT_LEN))
        contact_list = ContactList(contacts=[contact])

        # Test
        self.assertIsNone(rxm_load_psk(window, contact_list, self.settings, self.c_queue))
        time.sleep(0.1)

        self.assertEqual(self.c_queue.qsize(), 1)


if __name__ == '__main__':
    unittest.main(exit=False)
