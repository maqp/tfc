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

import multiprocessing
import os.path
import time
import unittest
import zlib

from typing import List

from src.common.crypto      import byte_padding, encrypt_and_sign
from src.common.errors      import FunctionReturn
from src.common.encoding    import double_to_bytes
from src.common.misc        import split_byte_string
from src.common.db_contacts import ContactList
from src.common.db_logs     import access_history, log_writer, re_encrypt, write_log_entry
from src.common.statics     import *

from tests.mock_classes     import create_contact, MasterKey, Settings, Window
from tests.utils            import cleanup


class TestLogWriter(unittest.TestCase):

    def test_lw_process(self):
        # Setup
        cleanup()
        m_queue = multiprocessing.Queue()
        lwp     = multiprocessing.Process(target=log_writer, args=(m_queue,))
        lwp.start()
        time.sleep(0.1)

        settings   = Settings()
        master_key = MasterKey()

        m_queue.put((P_N_HEADER + bytes(255), 'alice@ajbber.org', settings, master_key))
        m_queue.put((M_S_HEADER + bytes(255), 'alice@ajbber.org', settings, master_key))
        m_queue.put((F_S_HEADER + bytes(255), 'alice@ajbber.org', settings, master_key))

        time.sleep(0.2)
        lwp.terminate()

        # Test
        self.assertTrue(os.path.isfile(f'{DIR_USER_DATA}/ut_logs'))
        entry_size = 24 + 4 + 1 + 1024 + 1 + 255 + 16
        self.assertTrue(os.path.getsize(f'{DIR_USER_DATA}/ut_logs') % entry_size == 0)

        # Teardown
        cleanup()


class TestWriteLogEntry(unittest.TestCase):

    def test_function(self):
        #Setup
        masterkey = MasterKey()
        settings  = Settings()

        # Test
        self.assertIsNone(write_log_entry(F_S_HEADER + bytes(255), 'alice@jabber.org', settings, masterkey))
        self.assertTrue(os.path.isfile(f'{DIR_USER_DATA}/ut_logs'))
        entry_size = 24 + 4 + 1 + 1024 + 1 + 255 + 16
        self.assertTrue(os.path.getsize(f'{DIR_USER_DATA}/ut_logs') % entry_size == 0)
        self.assertIsNone(write_log_entry(F_S_HEADER + bytes(255), 'alice@jabber.org', settings, masterkey))
        self.assertTrue(os.path.getsize(f'{DIR_USER_DATA}/ut_logs') % entry_size == 0)

        # Teardown
        cleanup()

class TestAccessHistory(unittest.TestCase):

    @staticmethod
    def mock_entry_preprocessor(message: str, header: bytes = b'', group: bool = False) -> List[bytes]:
        if not header:
            if group:
                timestamp = double_to_bytes(time.time() * 1000)
                header    = GROUP_MESSAGE_HEADER + timestamp + 'testgroup'.encode() + US_BYTE
            else:
                header = PRIVATE_MESSAGE_HEADER

        plaintext = message.encode()
        payload   = header + plaintext
        payload   = zlib.compress(payload, level=9)

        if len(payload) < 255:
            padded      = byte_padding(payload)
            packet_list = [M_S_HEADER + padded]
        else:
            msg_key  = bytes(32)
            payload  = encrypt_and_sign(payload, msg_key)
            payload += msg_key
            padded   = byte_padding(payload)
            p_list   = split_byte_string(padded, item_len=255)

            packet_list = ([M_L_HEADER + p_list[0]] +
                           [M_A_HEADER + p for p in p_list[1:-1]] +
                           [M_E_HEADER + p_list[-1]])

        return packet_list


    def test_read_private_message(self):
        # Setup
        masterkey = MasterKey()
        settings  = Settings()
        window    = Window(type='contact', uid='alice@jabber.org', name='Alice')

        contact_list          = ContactList(masterkey, settings)
        contact_list.contacts = [create_contact('Alice')]

        with self.assertRaises(FunctionReturn):
            self.assertIsNone(access_history(window, contact_list, settings, masterkey))

        for p in self.mock_entry_preprocessor('This is a short message'):
            write_log_entry(p, 'alice@jabber.org', settings, masterkey)

        long_msg = ("Lorem ipsum dolor sit amet, consectetur adipiscing elit. Aenean condimentum consectetur purus quis"
                    " dapibus. Fusce venenatis lacus ut rhoncus faucibus. Cras sollicitudin commodo sapien, sed bibendu"
                    "m velit maximus in. Aliquam ac metus risus. Sed cursus ornare luctus. Integer aliquet lectus id ma"
                    "ssa blandit imperdiet. Ut sed massa eget quam facilisis rutrum. Mauris eget luctus nisl. Sed ut el"
                    "it iaculis, faucibus lacus eget, sodales magna. Nunc sed commodo arcu. In hac habitasse platea dic"
                    "tumst. Integer luctus aliquam justo, at vestibulum dolor iaculis ac. Etiam laoreet est eget odio r"
                    "utrum, vel malesuada lorem rhoncus. Cras finibus in neque eu euismod. Nulla facilisi. Nunc nec ali"
                    "quam quam, quis ullamcorper leo. Nunc egestas lectus eget est porttitor, in iaculis felis sceleris"
                    "que. In sem elit, fringilla id viverra commodo, sagittis varius purus. Pellentesque rutrum loborti"
                    "s neque a facilisis. Mauris id tortor placerat, aliquam dolor ac, venenatis arcu.")

        for p in self.mock_entry_preprocessor(long_msg):
            write_log_entry(p, 'alice@jabber.org', settings, masterkey)

        # Add packet cancelled half-way
        packets = self.mock_entry_preprocessor(long_msg)
        packets = packets[2:] + [M_C_HEADER + bytes(255)]
        for p in packets:
            write_log_entry(p, 'alice@jabber.org', settings, masterkey)

        # Test
        self.assertIsNone(access_history(window, contact_list, settings, masterkey))

        # Test window UID mismatch
        window.uid = 'bob@jabber.org'
        self.assertIsNone(access_history(window, contact_list, settings, masterkey))

        # Test window type mismatch
        window.uid  = 'alice@jabber.org'
        window.type = 'group'
        self.assertIsNone(access_history(window, contact_list, settings, masterkey))

        # Group messages

        window = Window(type='group', uid='testgroup', name='testgroup')

        contact_list          = ContactList(masterkey, settings)
        contact_list.contacts = [create_contact(n) for n in ['Alice', 'Charlie']]

        for p in self.mock_entry_preprocessor('This is a short message', group=True):
            write_log_entry(p, 'alice@jabber.org',   settings, masterkey)
            write_log_entry(p, 'charlie@jabber.org', settings, masterkey)

        long_msg = ("Lorem ipsum dolor sit amet, consectetur adipiscing elit. Aenean condimentum consectetur purus quis"
                    " dapibus. Fusce venenatis lacus ut rhoncus faucibus. Cras sollicitudin commodo sapien, sed bibendu"
                    "m velit maximus in. Aliquam ac metus risus. Sed cursus ornare luctus. Integer aliquet lectus id ma"
                    "ssa blandit imperdiet. Ut sed massa eget quam facilisis rutrum. Mauris eget luctus nisl. Sed ut el"
                    "it iaculis, faucibus lacus eget, sodales magna. Nunc sed commodo arcu. In hac habitasse platea dic"
                    "tumst. Integer luctus aliquam justo, at vestibulum dolor iaculis ac. Etiam laoreet est eget odio r"
                    "utrum, vel malesuada lorem rhoncus. Cras finibus in neque eu euismod. Nulla facilisi. Nunc nec ali"
                    "quam quam, quis ullamcorper leo. Nunc egestas lectus eget est porttitor, in iaculis felis sceleris"
                    "que. In sem elit, fringilla id viverra commodo, sagittis varius purus. Pellentesque rutrum loborti"
                    "s neque a facilisis. Mauris id tortor placerat, aliquam dolor ac, venenatis arcu.")

        for p in self.mock_entry_preprocessor(long_msg, group=True):
            write_log_entry(p, 'alice@jabber.org',   settings, masterkey)
            write_log_entry(p, 'charlie@jabber.org', settings, masterkey)

        # Test
        self.assertIsNone(access_history(window, contact_list, settings, masterkey))

        # Test window name mismatch
        window.name = 'bob@jabber.org'
        self.assertIsNone(access_history(window, contact_list, settings, masterkey))

        # Test window type mismatch
        window.name = 'testgroup'
        window.type = 'contact'
        self.assertIsNone(access_history(window, contact_list, settings, masterkey))

        # Re-encrypt log database

        # Create garbage file to remove
        with open(f'{DIR_USER_DATA}/{settings.software_operation}_logs_temp', 'wb+') as f:
            f.write(b'will screw decryption')

        self.assertIsNone(re_encrypt(masterkey.master_key, 32 * b'\x01', settings))
        masterkey.master_key = 32 * b'\x01'
        self.assertIsNone(access_history(window, contact_list, settings, masterkey))
        self.assertIsNone(access_history(window, contact_list, settings, masterkey, export=True))

        cleanup()
        with self.assertRaises(FunctionReturn):
            re_encrypt(masterkey.master_key, 32 * b'\x01', settings)

        # Teardown
        os.remove("Unittest - Plaintext log (testgroup)")
        cleanup()

if __name__ == '__main__':
    unittest.main(exit=False)
