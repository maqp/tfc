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

from src.common.statics   import *
from src.tx.key_exchanges import ask_confirmation_code, print_kdk, new_local_key, start_key_exchange, new_psk, rxm_load_psk

from tests.mock_classes   import create_contact, ContactList, Gateway, Settings, Window
from tests.utils          import TFCTestCase

class TestLocalKey(TFCTestCase):

    def test_ask_confirmation_code(self):
        # Setup
        o_input        = builtins.input
        builtins.input = lambda x : 'ff'

        # Test
        self.assertEqual(ask_confirmation_code(), 'ff')

        # Teardown
        builtins.input = o_input

    def test_print_kdk(self):

        settings = Settings()
        self.assertIsNone(print_kdk(os.urandom(32), settings))

        settings = Settings(local_testing_mode=True)
        self.assertIsNone(print_kdk(os.urandom(32), settings))


    def test_no_new_local_key_during_trickle(self):
        # Setup
        contact_list = ContactList()
        settings     = Settings(session_trickle=True)
        queues       = {COMMAND_PACKET_QUEUE: Queue(),
                        KEY_MANAGEMENT_QUEUE: Queue()}
        gateway      = Gateway()

        self.assertFR("Command disabled during trickle connection.", new_local_key, contact_list, settings, queues, gateway)

    def test_new_local_key(self):
        # Setup
        contact_list = ContactList()
        settings     = Settings(nh_bypass_messages=False)
        queues       = {COMMAND_PACKET_QUEUE: Queue(),
                        KEY_MANAGEMENT_QUEUE: Queue()}
        gateway      = Gateway()
        o_urandom    = os.urandom
        os.urandom   = lambda x: x * b'\xff'
        o_input      = builtins.input
        input_list   = ['bad', 'resend', 'ff']
        gen          = iter(input_list)

        def mock_input(_):
            return str(next(gen))
        builtins.input = mock_input

        # Test
        self.assertIsNone(new_local_key(contact_list, settings, queues, gateway))

        local_contact = contact_list.get_contact('local')

        self.assertEqual(local_contact.rx_account,    'local')
        self.assertEqual(local_contact.tx_account,    'local')
        self.assertEqual(local_contact.nick,          'local')
        self.assertEqual(local_contact.tx_fingerprint, bytes(32))
        self.assertEqual(local_contact.rx_fingerprint, bytes(32))
        self.assertFalse(local_contact.log_messages)
        self.assertFalse(local_contact.file_reception)
        self.assertFalse(local_contact.notifications)

        time.sleep(0.2)
        cmd, account, txkey, rxkey, txhek, rxhek = queues[KEY_MANAGEMENT_QUEUE].get()

        self.assertEqual(cmd,        'ADD')
        self.assertEqual(account,    'local')
        self.assertEqual(len(txkey), 32)
        self.assertIsInstance(txkey, bytes)
        self.assertEqual(len(txhek), 32)
        self.assertIsInstance(txhek, bytes)
        self.assertEqual(rxkey,      bytes(32))
        self.assertEqual(rxhek,      bytes(32))

        self.assertEqual(queues[COMMAND_PACKET_QUEUE].qsize(), 1)

        # Teardown
        os.urandom     = o_urandom
        builtins.input = o_input


class TestKeyExchange(TFCTestCase):

    def test_raises_fr_during_fingerprint_mismatch(self):
        # Setup
        contact_list = ContactList()
        settings     = Settings()
        queues       = {COMMAND_PACKET_QUEUE: Queue(),
                        KEY_MANAGEMENT_QUEUE: Queue()}
        gateway      = Gateway()
        o_input      = builtins.input

        input_list = ['2QJL5gVSPEjMTaxWPfYkzG9UJxzZDNSx6PPeVWdzS5CFN7knZ',    # Short key should fail
                      '2QJL5gVSPEjMTaxWPfYkzG9UJxzZDNSx6PPeVWdzS5CFN7knZya',  # Long key should fail
                      '2QJL5gVSPEjMTaxWPfYkzG9UJxzZDNSx6PPeVWdzS5CFN7knZa',   # Invalid key should fail
                      '2QJL5gVSPEjMTaxWPfYkzG9UJxzZDNSx6PPeVWdzS5CFN7knZy',   # Correct key
                      'No']                                                   # Fingerprint mismatch

        gen = iter(input_list)
        def mock_input(_):
            return str(next(gen))
        builtins.input = mock_input

        # Test
        self.assertFR("Fingerprint mismatch", start_key_exchange, 'alice@jabber.org', 'user@jabber.org', 'Alice', contact_list, settings, queues, gateway)

        # Teardown
        builtins.input = o_input

    def test_successful_exchange(self):
        # Setup
        contact_list = ContactList()
        settings     = Settings()
        queues       = {COMMAND_PACKET_QUEUE: Queue(),
                        KEY_MANAGEMENT_QUEUE: Queue()}
        gateway      = Gateway()
        o_input      = builtins.input
        input_list   = ['2QJL5gVSPEjMTaxWPfYkzG9UJxzZDNSx6PPeVWdzS5CFN7knZy',   # Correct key
                        'Yes']                                                  # Fingerprint match

        gen = iter(input_list)
        def mock_input(_):
            return str(next(gen))
        builtins.input = mock_input

        # Test
        self.assertIsNone(start_key_exchange('alice@jabber.org',  'user@jabber.org', 'Alice', contact_list, settings, queues, gateway))

        contact = contact_list.get_contact('alice@jabber.org')

        self.assertEqual(contact.rx_account,          'alice@jabber.org')
        self.assertEqual(contact.tx_account,          'user@jabber.org')
        self.assertEqual(contact.nick,                'Alice')
        self.assertIsInstance(contact.tx_fingerprint, bytes)
        self.assertIsInstance(contact.rx_fingerprint, bytes)
        self.assertEqual(len(contact.tx_fingerprint), 32)
        self.assertEqual(len(contact.rx_fingerprint), 32)
        self.assertFalse(contact.log_messages)
        self.assertFalse(contact.file_reception)
        self.assertFalse(contact.notifications)

        time.sleep(0.2)
        cmd, account, txkey, rxkey, txhek, rxhek = queues[KEY_MANAGEMENT_QUEUE].get()

        self.assertEqual(cmd,       'ADD')
        self.assertEqual(account,   'alice@jabber.org')
        self.assertEqual(len(txkey), 32)
        self.assertIsInstance(txkey, bytes)
        self.assertEqual(len(txhek), 32)
        self.assertIsInstance(txhek, bytes)
        self.assertEqual(rxkey,      bytes(32))
        self.assertEqual(rxhek,      bytes(32))

        self.assertEqual(queues[COMMAND_PACKET_QUEUE].qsize(), 1)

        # Teardown
        builtins.input = o_input


class TestPSK(TFCTestCase):

    def test_function(self):
        # Setup
        contact_list    = ContactList()
        settings        = Settings(disable_gui_dialog=True)
        queues          = {COMMAND_PACKET_QUEUE: Queue(),
                           KEY_MANAGEMENT_QUEUE: Queue()}
        o_urandom       = os.urandom
        os.urandom      = lambda x: x * b'\x00'
        o_input         = builtins.input
        o_getpass       = getpass.getpass
        getpass.getpass = lambda x: 'test_password'
        builtins.input  = lambda x: '.'

        # Test
        self.assertIsNone(new_psk('alice@jabber.org',  'user@jabber.org', 'Alice', contact_list, settings, queues))

        contact = contact_list.get_contact('alice@jabber.org')

        self.assertEqual(contact.rx_account,     'alice@jabber.org')
        self.assertEqual(contact.tx_account,     'user@jabber.org')
        self.assertEqual(contact.nick,           'Alice')
        self.assertEqual(contact.tx_fingerprint, bytes(32))
        self.assertEqual(contact.rx_fingerprint, bytes(32))
        self.assertFalse(contact.log_messages)
        self.assertFalse(contact.file_reception)
        self.assertFalse(contact.notifications)

        time.sleep(0.2)
        cmd, account, txkey, rxkey, txhek, rxhek = queues[KEY_MANAGEMENT_QUEUE].get()

        self.assertEqual(cmd,        'ADD')
        self.assertEqual(account,    'alice@jabber.org')
        self.assertEqual(len(txkey), 32)
        self.assertIsInstance(txkey, bytes)
        self.assertEqual(len(txhek), 32)
        self.assertIsInstance(txhek, bytes)
        self.assertEqual(rxkey,      bytes(32))
        self.assertEqual(rxhek,      bytes(32))

        self.assertEqual(queues[COMMAND_PACKET_QUEUE].qsize(), 1)
        print(os.path.curdir)
        self.assertTrue(os.path.isfile('user@jabber.org.psk - Give to alice@jabber.org'))

        # Teardown
        os.remove('user@jabber.org.psk - Give to alice@jabber.org')
        builtins.input  = o_input
        os.urandom      = o_urandom
        getpass.getpass = o_getpass


class TestRxMLoadPSK(TFCTestCase):

    def test_trickle_raises_fr(self):
        # Setup
        settings = Settings(session_trickle=True)

        #Test
        self.assertFR("Command disabled during trickle connection.", rxm_load_psk, None, None, settings, None)

    def test_active_group_raises_fr(self):
        # Setup
        settings = Settings()
        window   = Window(type='group')

        # Test
        self.assertFR("Group is selected.", rxm_load_psk, window, None, settings, None)

    def test_x25519_key_raises_fr(self):
        # Setup
        settings     = Settings()
        window       = Window(type='contact',
                              uid ='alice@jabber.org')
        contact_list = ContactList(nicks=['Alice'])

        # Test
        self.assertFR("Current key was exchanged with X25519.", rxm_load_psk, window, contact_list, settings, None)

    def test_successful_command(self):
        # Setup
        settings     = Settings()
        window       = Window(type='contact',
                              uid ='alice@jabber.org')
        contact      = create_contact('Alice', txfp=bytes(32))
        contact_list = ContactList(contacts=[contact])
        queue        = Queue()

        # Test
        self.assertIsNone(rxm_load_psk(window, contact_list, settings, queue))
        self.assertEqual(queue.qsize(), 1)

        # Teardown
        while not queue.empty():
            queue.get()
        time.sleep(0.2)


if __name__ == '__main__':
    unittest.main(exit=False)
