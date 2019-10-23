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
import tkinter
import unittest

from multiprocessing import Queue

from datetime      import datetime
from unittest      import mock
from unittest.mock import MagicMock

from src.common.crypto     import argon2_kdf, encrypt_and_sign
from src.common.encoding   import b58encode, str_to_bytes
from src.common.exceptions import FunctionReturn
from src.common.statics    import (ARGON2_SALT_LENGTH, BOLD_ON, CLEAR_ENTIRE_SCREEN, CONFIRM_CODE_LENGTH,
                                   CURSOR_LEFT_UP_CORNER, FINGERPRINT_LENGTH, LOCAL_ID, NORMAL_TEXT, PSK_FILE_SIZE,
                                   SYMMETRIC_KEY_LENGTH, WIN_TYPE_CONTACT, WIN_UID_LOCAL, XCHACHA20_NONCE_LENGTH)

from src.receiver.key_exchanges import key_ex_ecdhe, key_ex_psk_rx, key_ex_psk_tx, local_key_rdy, process_local_key

from tests.mock_classes import Contact, ContactList, KeyList, KeySet, Settings, WindowList
from tests.utils        import cd_unit_test, cleanup, nick_to_short_address, nick_to_pub_key, tear_queue, TFCTestCase
from tests.utils        import UNDECODABLE_UNICODE


class TestProcessLocalKey(TFCTestCase):

    kek     = os.urandom(SYMMETRIC_KEY_LENGTH)
    new_kek = os.urandom(SYMMETRIC_KEY_LENGTH)

    def setUp(self):
        """Pre-test actions."""
        self.contact_list  = ContactList(nicks=[LOCAL_ID, 'Alice'])
        self.key_list      = KeyList(    nicks=[LOCAL_ID, 'Alice'])
        self.window_list   = WindowList( nicks=[LOCAL_ID, 'Alice'])
        self.settings      = Settings()
        self.ts            = datetime.now()
        self.kdk_hashes    = list()
        self.packet_hashes = list()
        self.l_queue       = Queue()
        self.key           = os.urandom(SYMMETRIC_KEY_LENGTH)
        self.hek           = os.urandom(SYMMETRIC_KEY_LENGTH)
        self.conf_code     = os.urandom(CONFIRM_CODE_LENGTH)
        self.packet        = encrypt_and_sign(self.key + self.hek + self.conf_code, key=self.kek)
        self.args          = (self.window_list, self.contact_list, self.key_list, self.settings,
                              self.kdk_hashes, self.packet_hashes, self.l_queue)

    def tearDown(self):
        """Post-test actions."""
        tear_queue(self.l_queue)

    @mock.patch('tkinter.Tk',     return_value=MagicMock())
    @mock.patch('time.sleep',     return_value=None)
    @mock.patch('builtins.input', return_value='5KfgdgUvseWfNkoUPWSvxMPNStu5wBBxyjz1zpZtLEjk7ZvwEAT')
    def test_invalid_decryption_key_raises_fr(self, *_):
        # Setup
        packet                = b''
        self.key_list.keysets = []

        # Test
        self.assert_fr("Error: Incorrect key decryption key.", process_local_key, self.ts, packet, *self.args)

    @mock.patch('tkinter.Tk',     return_value=MagicMock())
    @mock.patch('time.sleep',     return_value=None)
    @mock.patch('builtins.input', side_effect=['5KfgdgUvseWfNkoUPWSvxMPNStu5wBBxyjz1zpZtLEjk7ZvwEAT', b58encode(kek)])
    @mock.patch('os.system',      return_value=None)
    def test_successful_local_key_processing_with_existing_local_key(self, *_):
        self.assert_fr("Error: Incorrect key decryption key.", process_local_key, self.ts, self.packet, *self.args)
        self.assertIsNone(process_local_key(self.ts, self.packet, *self.args))

    @mock.patch('tkinter.Tk',     return_value=MagicMock())
    @mock.patch('time.sleep',     return_value=None)
    @mock.patch('builtins.input', return_value=b58encode(kek))
    @mock.patch('os.system',      return_value=None)
    def test_successful_local_key_processing_existing_bootstrap(self, *_):
        # Setup
        self.key_list.keysets = []

        # Test
        self.assertIsNone(process_local_key(self.ts, self.packet, *self.args))
        self.assertEqual(self.window_list.active_win.uid, WIN_UID_LOCAL)

    @mock.patch('tkinter.Tk',     return_value=MagicMock())
    @mock.patch('time.sleep',     return_value=None)
    @mock.patch('builtins.input', side_effect=KeyboardInterrupt)
    def test_keyboard_interrupt_raises_fr(self, *_):
        # Setup
        self.window_list.active_win = self.window_list.get_window(nick_to_pub_key('Alice'))

        # Test
        self.assert_fr("Local key setup aborted.", process_local_key, self.ts, bytes(SYMMETRIC_KEY_LENGTH), *self.args)

    @mock.patch('tkinter.Tk',     return_value=MagicMock())
    @mock.patch('os.system',      return_value=None)
    @mock.patch('time.sleep',     return_value=None)
    @mock.patch('builtins.input', side_effect=[b58encode(kek), b58encode(kek), b58encode(kek), b58encode(new_kek)])
    def test_old_local_key_packet_raises_fr(self, *_):
        # Setup
        self.key_list.keysets = []
        new_key               = os.urandom(SYMMETRIC_KEY_LENGTH)
        new_hek               = os.urandom(SYMMETRIC_KEY_LENGTH)
        new_conf_code         = os.urandom(CONFIRM_CODE_LENGTH)
        new_packet            = encrypt_and_sign(new_key + new_hek + new_conf_code, key=self.new_kek)

        # Test
        self.assertIsNone(process_local_key(self.ts, self.packet, *self.args))
        self.assert_fr("Error: Received old local key packet.", process_local_key, self.ts, self.packet, *self.args)
        self.assertIsNone(process_local_key(self.ts, new_packet, *self.args))

    @mock.patch('tkinter.Tk',     side_effect=[MagicMock(clipboard_get  =MagicMock(return_value=b58encode(new_kek)),
                                                         clipboard_clear=MagicMock(side_effect=[tkinter.TclError]))])
    @mock.patch('os.system',      return_value=None)
    @mock.patch('time.sleep',     return_value=None)
    @mock.patch('builtins.input', side_effect=[b58encode(new_kek)])
    def test_loading_local_key_from_queue(self, *_):
        # Setup
        self.key_list.keysets = []
        new_key               = os.urandom(SYMMETRIC_KEY_LENGTH)
        new_hek               = os.urandom(SYMMETRIC_KEY_LENGTH)
        new_conf_code         = os.urandom(CONFIRM_CODE_LENGTH)
        new_packet            = encrypt_and_sign(new_key + new_hek + new_conf_code, key=self.new_kek)
        next_packet           = os.urandom(len(new_packet))
        first_packet          = os.urandom(len(new_packet))
        self.l_queue.put((datetime.now(), first_packet))
        self.l_queue.put((datetime.now(), new_packet))
        self.l_queue.put((datetime.now(), next_packet))

        # Test
        self.assertEqual(self.l_queue.qsize(), 3)
        self.assertIsNone(process_local_key(self.ts, self.packet, *self.args))
        self.assertEqual(self.l_queue.qsize(), 1)


class TestLocalKeyRdy(TFCTestCase):

    def setUp(self):
        """Pre-test actions."""
        self.ts = datetime.fromtimestamp(1502750000)

    @mock.patch('time.sleep', return_value=None)
    def test_local_key_installed_no_contacts(self, _):
        # Setup
        self.window_list  = WindowList(nicks=[LOCAL_ID])
        self.contact_list = ContactList(nicks=[LOCAL_ID])

        # Test
        self.assert_prints(f"""\
{BOLD_ON}                  Successfully completed the local key setup.                   {NORMAL_TEXT}
{CLEAR_ENTIRE_SCREEN+CURSOR_LEFT_UP_CORNER}
{BOLD_ON}                            Waiting for new contacts                            {NORMAL_TEXT}

""", local_key_rdy, self.ts, self.window_list, self.contact_list)

    @mock.patch('time.sleep', return_value=None)
    def test_local_key_installed_existing_contact(self, _):
        # Setup
        self.window_list                 = WindowList(nicks=[LOCAL_ID, 'Alice'])
        self.contact_list                = ContactList(nicks=[LOCAL_ID, 'Alice'])
        self.window_list.active_win      = self.window_list.get_window(nick_to_pub_key('Alice'))
        self.window_list.active_win.type = WIN_TYPE_CONTACT

        # Test
        self.assertIsNone(local_key_rdy(self.ts, self.window_list, self.contact_list))


class TestKeyExECDHE(TFCTestCase):

    def setUp(self):
        """Pre-test actions."""
        self.ts           = datetime.fromtimestamp(1502750000)
        self.window_list  = WindowList(nicks=[LOCAL_ID])
        self.contact_list = ContactList()
        self.key_list     = KeyList()
        self.settings     = Settings()
        self.packet       = (nick_to_pub_key("Alice")
                             + SYMMETRIC_KEY_LENGTH * b'\x01'
                             + SYMMETRIC_KEY_LENGTH * b'\x02'
                             + SYMMETRIC_KEY_LENGTH * b'\x03'
                             + SYMMETRIC_KEY_LENGTH * b'\x04'
                             + str_to_bytes('Alice'))
        self.args         = self.packet, self.ts, self.window_list, self.contact_list, self.key_list, self.settings

    @mock.patch('time.sleep', return_value=None)
    def test_invalid_nick_raises_fr(self, _):
        self.packet = (nick_to_pub_key("Alice")
                       + SYMMETRIC_KEY_LENGTH * b'\x01'
                       + SYMMETRIC_KEY_LENGTH * b'\x02'
                       + SYMMETRIC_KEY_LENGTH * b'\x03'
                       + SYMMETRIC_KEY_LENGTH * b'\x04'
                       + UNDECODABLE_UNICODE)
        self.args = self.packet, self.ts, self.window_list, self.contact_list, self.key_list, self.settings

        self.assert_fr("Error: Received invalid contact data", key_ex_ecdhe, *self.args)

    @mock.patch('time.sleep', return_value=None)
    def test_add_ecdhe_keys(self, _):
        self.assertIsNone(key_ex_ecdhe(*self.args))

        keyset = self.key_list.get_keyset(nick_to_pub_key("Alice"))
        self.assertIsInstance(keyset, KeySet)

        self.assertEqual(keyset.onion_pub_key, nick_to_pub_key("Alice"))
        self.assertEqual(keyset.tx_mk, SYMMETRIC_KEY_LENGTH * b'\x01')
        self.assertEqual(keyset.rx_mk, SYMMETRIC_KEY_LENGTH * b'\x02')
        self.assertEqual(keyset.tx_hk, SYMMETRIC_KEY_LENGTH * b'\x03')
        self.assertEqual(keyset.rx_hk, SYMMETRIC_KEY_LENGTH * b'\x04')

        contact = self.contact_list.get_contact_by_pub_key(nick_to_pub_key("Alice"))
        self.assertIsInstance(contact, Contact)
        self.assertEqual(contact.onion_pub_key, nick_to_pub_key("Alice"))
        self.assertEqual(contact.nick, 'Alice')
        self.assertEqual(contact.rx_fingerprint, bytes(FINGERPRINT_LENGTH))
        self.assertEqual(contact.tx_fingerprint, bytes(FINGERPRINT_LENGTH))


class TestKeyExPSKTx(TFCTestCase):

    def setUp(self):
        """Pre-test actions."""
        self.ts           = datetime.fromtimestamp(1502750000)
        self.window_list  = WindowList(nicks=[LOCAL_ID])
        self.contact_list = ContactList()
        self.key_list     = KeyList()
        self.settings     = Settings()
        self.packet       = (nick_to_pub_key("Alice")
                             + SYMMETRIC_KEY_LENGTH * b'\x01'
                             + bytes(SYMMETRIC_KEY_LENGTH)
                             + SYMMETRIC_KEY_LENGTH * b'\x02'
                             + bytes(SYMMETRIC_KEY_LENGTH)
                             + str_to_bytes('Alice'))
        self.args         = self.packet, self.ts, self.window_list, self.contact_list, self.key_list, self.settings

    @mock.patch('time.sleep', return_value=None)
    def test_invalid_nick_raises_fr(self, _):
        self.packet = (nick_to_pub_key("Alice")
                       + SYMMETRIC_KEY_LENGTH * b'\x01'
                       + bytes(SYMMETRIC_KEY_LENGTH)
                       + SYMMETRIC_KEY_LENGTH * b'\x02'
                       + bytes(SYMMETRIC_KEY_LENGTH)
                       + UNDECODABLE_UNICODE)
        self.args   = self.packet, self.ts, self.window_list, self.contact_list, self.key_list, self.settings

        self.assert_fr("Error: Received invalid contact data", key_ex_psk_tx, *self.args)

    @mock.patch('time.sleep', return_value=None)
    def test_add_psk_tx_keys(self, _):
        self.assertIsNone(key_ex_psk_tx(*self.args))

        keyset = self.key_list.get_keyset(nick_to_pub_key("Alice"))
        self.assertIsInstance(keyset, KeySet)

        self.assertEqual(keyset.onion_pub_key, nick_to_pub_key("Alice"))
        self.assertEqual(keyset.tx_mk,         SYMMETRIC_KEY_LENGTH * b'\x01')
        self.assertEqual(keyset.rx_mk,         bytes(SYMMETRIC_KEY_LENGTH))
        self.assertEqual(keyset.tx_hk,         SYMMETRIC_KEY_LENGTH * b'\x02')
        self.assertEqual(keyset.rx_hk,         bytes(SYMMETRIC_KEY_LENGTH))

        contact = self.contact_list.get_contact_by_pub_key(nick_to_pub_key("Alice"))
        self.assertIsInstance(contact, Contact)

        self.assertEqual(contact.onion_pub_key,  nick_to_pub_key("Alice"))
        self.assertEqual(contact.nick,           'Alice')
        self.assertEqual(contact.tx_fingerprint, bytes(FINGERPRINT_LENGTH))
        self.assertEqual(contact.rx_fingerprint, bytes(FINGERPRINT_LENGTH))


class TestKeyExPSKRx(TFCTestCase):

    file_name = f"{nick_to_short_address('User')}.psk - give to {nick_to_short_address('Alice')}"

    def setUp(self):
        """Pre-test actions."""
        self.unit_test_dir = cd_unit_test()
        self.packet        = b'\x00' + nick_to_pub_key("Alice")
        self.ts            = datetime.now()
        self.window_list   = WindowList( nicks=['Alice', LOCAL_ID])
        self.contact_list  = ContactList(nicks=['Alice', LOCAL_ID])
        self.key_list      = KeyList(    nicks=['Alice', LOCAL_ID])
        self.settings      = Settings(disable_gui_dialog=True)
        self.file_name     = self.file_name
        self.args          = self.packet, self.ts, self.window_list, self.contact_list, self.key_list, self.settings

    def tearDown(self):
        """Post-test actions."""
        cleanup(self.unit_test_dir)

    def test_unknown_account_raises_fr(self):
        self.assert_fr(f"Error: Unknown account '{nick_to_short_address('Bob')}'.",
                       key_ex_psk_rx, b'\x00' + nick_to_pub_key("Bob"),
                       self.ts, self.window_list, self.contact_list, self.key_list, self.settings)

    @mock.patch('builtins.input', return_value=file_name)
    def test_invalid_psk_data_raises_fr(self, _):
        # Setup
        with open(self.file_name, 'wb+') as f:
            f.write(os.urandom(135))

        # Test
        self.assert_fr("Error: The PSK data in the file was invalid.", key_ex_psk_rx, *self.args)

    @mock.patch('time.sleep',     return_value=None)
    @mock.patch('builtins.input', return_value=file_name)
    def test_permission_error_raises_fr(self, *_):
        # Setup
        with open(self.file_name, 'wb+') as f:
            f.write(os.urandom(PSK_FILE_SIZE))

        # Test
        error_raised = False
        try:
            with mock.patch('builtins.open', side_effect=PermissionError):
                key_ex_psk_rx(*self.args)
        except FunctionReturn as inst:
            error_raised = True
            self.assertEqual("Error: No read permission for the PSK file.", inst.message)
        self.assertTrue(error_raised)

    @mock.patch('src.receiver.key_exchanges.ARGON2_PSK_PARALLELISM', 1)
    @mock.patch('src.receiver.key_exchanges.ARGON2_PSK_TIME_COST',   1)
    @mock.patch('src.receiver.key_exchanges.ARGON2_PSK_MEMORY_COST', 100)
    @mock.patch('getpass.getpass', side_effect=['invalid', 'password'])
    @mock.patch('time.sleep',      return_value=None)
    @mock.patch('os.urandom',      side_effect=[bytes(XCHACHA20_NONCE_LENGTH)])
    @mock.patch('builtins.input',  return_value=file_name)
    def test_invalid_keys_raise_fr(self, *_):
        # Setup
        keyset       = self.key_list.get_keyset(nick_to_pub_key("Alice"))
        keyset.rx_mk = bytes(SYMMETRIC_KEY_LENGTH)
        keyset.rx_hk = bytes(SYMMETRIC_KEY_LENGTH)

        salt   = bytes(ARGON2_SALT_LENGTH)
        rx_key = bytes(SYMMETRIC_KEY_LENGTH)
        rx_hek = bytes(SYMMETRIC_KEY_LENGTH)
        kek    = argon2_kdf('password', salt, time_cost=1, memory_cost=100, parallelism=1)
        ct_tag = encrypt_and_sign(rx_key + rx_hek, key=kek)

        with open(self.file_name, 'wb+') as f:
            f.write(salt + ct_tag)

        # Test
        self.assert_fr("Error: Received invalid keys from contact.", key_ex_psk_rx, *self.args)

    @mock.patch('src.receiver.key_exchanges.ARGON2_PSK_PARALLELISM', 1)
    @mock.patch('src.receiver.key_exchanges.ARGON2_PSK_TIME_COST',   1)
    @mock.patch('src.receiver.key_exchanges.ARGON2_PSK_MEMORY_COST', 100)
    @mock.patch('time.sleep',      return_value=None)
    @mock.patch('builtins.input',  return_value=file_name)
    @mock.patch('getpass.getpass', return_value='test_password')
    def test_valid_psk(self, *_):
        # Setup
        keyset       = self.key_list.get_keyset(nick_to_pub_key("Alice"))
        keyset.rx_mk = bytes(SYMMETRIC_KEY_LENGTH)
        keyset.rx_hk = bytes(SYMMETRIC_KEY_LENGTH)
        salt         = os.urandom(ARGON2_SALT_LENGTH)
        rx_key       = os.urandom(SYMMETRIC_KEY_LENGTH)
        rx_hek       = os.urandom(SYMMETRIC_KEY_LENGTH)
        kek          = argon2_kdf('test_password', salt, time_cost=1, memory_cost=100, parallelism=1)
        ct_tag       = encrypt_and_sign(rx_key + rx_hek, key=kek)

        with open(self.file_name, 'wb+') as f:
            f.write(salt + ct_tag)

        # Test
        self.assertTrue(os.path.isfile(self.file_name))
        self.assertIsNone(key_ex_psk_rx(*self.args))
        self.assertFalse(os.path.isfile(self.file_name))
        self.assertEqual(keyset.rx_mk, rx_key)
        self.assertEqual(keyset.rx_hk, rx_hek)

    @mock.patch('src.receiver.key_exchanges.ARGON2_PSK_PARALLELISM', 1)
    @mock.patch('src.receiver.key_exchanges.ARGON2_PSK_TIME_COST',   1)
    @mock.patch('src.receiver.key_exchanges.ARGON2_PSK_MEMORY_COST', 100)
    @mock.patch('subprocess.Popen')
    @mock.patch('time.sleep',      return_value=None)
    @mock.patch('builtins.input',  side_effect=[file_name, ''])
    @mock.patch('getpass.getpass', return_value='test_password')
    def test_valid_psk_overwrite_failure(self, *_):
        # Setup
        keyset       = self.key_list.get_keyset(nick_to_pub_key("Alice"))
        keyset.rx_mk = bytes(SYMMETRIC_KEY_LENGTH)
        keyset.rx_hk = bytes(SYMMETRIC_KEY_LENGTH)

        salt   = os.urandom(ARGON2_SALT_LENGTH)
        rx_key = os.urandom(SYMMETRIC_KEY_LENGTH)
        rx_hek = os.urandom(SYMMETRIC_KEY_LENGTH)
        kek    = argon2_kdf('test_password', salt, time_cost=1, memory_cost=100, parallelism=1)
        ct_tag = encrypt_and_sign(rx_key + rx_hek, key=kek)

        with open(self.file_name, 'wb+') as f:
            f.write(salt + ct_tag)

        # Test
        self.assertTrue(os.path.isfile(self.file_name))
        self.assertIsNone(key_ex_psk_rx(*self.args))
        self.assertTrue(os.path.isfile(self.file_name))
        self.assertEqual(keyset.rx_mk, rx_key)
        self.assertEqual(keyset.rx_hk, rx_hek)

    @mock.patch('src.receiver.key_exchanges.ARGON2_PSK_TIME_COST',   1)
    @mock.patch('src.receiver.key_exchanges.ARGON2_PSK_MEMORY_COST', 100)
    @mock.patch('subprocess.Popen')
    @mock.patch('time.sleep',      return_value=None)
    @mock.patch('builtins.input',  side_effect=[file_name, ''])
    @mock.patch('getpass.getpass', side_effect=[KeyboardInterrupt])
    def test_valid_psk_keyboard_interrupt_raises_fr(self, *_):
        with open(self.file_name, 'wb+') as f:
            f.write(bytes(PSK_FILE_SIZE))

        self.assert_fr("PSK import aborted.",
                       key_ex_psk_rx, *self.args)


if __name__ == '__main__':
    unittest.main(exit=False)
