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

import base64
import datetime
import os
import shutil
import time
import unittest
import zlib

from src.common.crypto   import encrypt_and_sign, byte_padding, hash_chain
from src.common.encoding import int_to_bytes, double_to_bytes
from src.common.misc     import split_byte_string
from src.common.statics  import *
from src.rx.messages     import process_message
from src.rx.windows      import WindowList
from src.rx.packet       import PacketList

from tests.mock_classes  import ContactList, KeyList, GroupList, Settings, MasterKey
from tests.utils         import cleanup, TFCTestCase


class TestProcessMessage(TFCTestCase):

    @staticmethod
    def create_message_apct(origin, message, header=None, group_name=None):
        if not header:
            if group_name is not None:
                timestamp = double_to_bytes(time.time() * 1000)
                header    = GROUP_MESSAGE_HEADER + timestamp + group_name + US_BYTE
            else:
                header = PRIVATE_MESSAGE_HEADER

        plaintext = header + message
        payload   = zlib.compress(plaintext, level=9)
        if len(payload) < 255:
            padded      = byte_padding(payload)
            packet_list = [M_S_HEADER + padded]
        else:
            msg_key  = os.urandom(32)
            payload  = encrypt_and_sign(payload, msg_key)
            payload += msg_key
            padded   = byte_padding(payload)
            p_list   = split_byte_string(padded, item_len=255)

            packet_list = ([M_L_HEADER + p_list[0]] +
                           [M_A_HEADER + p for p in p_list[1:-1]] +
                           [M_E_HEADER + p_list[-1]])

        harac = 1
        m_key = 32 * b'\x01'
        apctl = []
        for p in packet_list:
            harac_in_bytes    = int_to_bytes(harac)
            encrypted_harac   = encrypt_and_sign(harac_in_bytes, 32 * b'\x01')
            encrypted_message = encrypt_and_sign(p, m_key)
            encrypted_packet  = MESSAGE_PACKET_HEADER + encrypted_harac + encrypted_message + origin + b'alice@jabber.org'
            apctl.append(encrypted_packet)
            harac += 1
            m_key  = hash_chain(m_key)
        return apctl

    @staticmethod
    def create_file_apct():

        def mock_file_preprocessor(payload):
            payload = bytes(8) + payload
            padded  = byte_padding(payload)
            p_list  = split_byte_string(padded, item_len=255)

            packet_list = ([F_L_HEADER + int_to_bytes(len(p_list)) + p_list[0][8:]] +
                           [F_A_HEADER + p for p in p_list[1:-1]] +
                           [F_E_HEADER + p_list[-1]])
            return packet_list

        file_data  = os.urandom(10000)
        compressed = zlib.compress(file_data, level=9)
        file_key   = os.urandom(32)
        encrypted  = encrypt_and_sign(compressed, key=file_key)
        encrypted += file_key
        encoded    = base64.b85encode(encrypted)

        file_data = US_BYTE.join([b'testfile.txt', b'11.0B', b'00d 00h 00m 00s', encoded])
        packets   = mock_file_preprocessor(file_data)

        harac = 1
        m_key = 32 * b'\x01'
        apctl = []

        for p in packets:
            harac_in_bytes    = int_to_bytes(harac)
            encrypted_harac   = encrypt_and_sign(harac_in_bytes, 32 * b'\x01')
            encrypted_message = encrypt_and_sign(p, m_key)
            encrypted_packet  = MESSAGE_PACKET_HEADER + encrypted_harac + encrypted_message + ORIGIN_CONTACT_HEADER + b'alice@jabber.org'
            apctl.append(encrypted_packet)
            harac += 1
            m_key  = hash_chain(m_key)

        return apctl

    def test_normal_msg(self):
        # Setup
        message = ("Lorem ipsum dolor sit amet, consectetur adipiscing elit. Aenean condimentum consectetur purus quis"
                   " dapibus. Fusce venenatis lacus ut rhoncus faucibus. Cras sollicitudin commodo sapien, sed bibendu"
                   "m velit maximus in. Aliquam ac metus risus. Sed cursus ornare luctus. Integer aliquet lectus id ma"
                   "ssa blandit imperdiet. Ut sed massa eget quam facilisis rutrum. Mauris eget luctus nisl. Sed ut el"
                   "it iaculis, faucibus lacus eget, sodales magna. Nunc sed commodo arcu. In hac habitasse platea dic"
                   "tumst. Integer luctus aliquam justo, at vestibulum dolor iaculis ac. Etiam laoreet est eget odio r"
                   "utrum, vel malesuada lorem rhoncus. Cras finibus in neque eu euismod. Nulla facilisi. Nunc nec ali"
                   "quam quam, quis ullamcorper leo. Nunc egestas lectus eget est porttitor, in iaculis felis sceleris"
                   "que. In sem elit, fringilla id viverra commodo, sagittis varius purus. Pellentesque rutrum loborti"
                   "s neque a facilisis. Mauris id tortor placerat, aliquam dolor ac, venenatis arcu.".encode())
        ts              = datetime.datetime.now()
        apct_list       = self.create_message_apct(ORIGIN_CONTACT_HEADER, message)
        contact_list    = ContactList(nicks=['Alice', 'Bob', 'local'])
        key_list        = KeyList(nicks=['Alice', 'Bob', 'local'])
        keyset          = key_list.get_keyset('alice@jabber.org')
        keyset.rx_harac = 1
        keyset.rx_key   = 32 * b'\x01'
        keyset.rx_hek   = 32 * b'\x01'
        group_list      = GroupList(groups=['testgroup'])
        settings        = Settings()
        packet_list     = PacketList(contact_list=contact_list, settings=settings)
        window_list     = WindowList(contact_list=contact_list, group_list=group_list, packet_list=packet_list, settings=settings)
        master_key      = MasterKey()

        # Test
        for p in apct_list:
            self.assertIsNone(process_message(ts, p, window_list, packet_list, contact_list, key_list, group_list, settings, master_key))

        # Teardown
        cleanup()


    def test_group_invitation_msg(self):
        # Setup
        message         = b'testgroup' + US_BYTE + b'bob@jabber.org' + US_BYTE + b'charlie@jabber.org'
        ts              = datetime.datetime.now()
        apct_list       = self.create_message_apct(ORIGIN_CONTACT_HEADER, message, header=GROUP_MSG_INVITATION_HEADER)
        contact_list    = ContactList(nicks=['Alice', 'Bob', 'local'])
        key_list        = KeyList(nicks=['Alice', 'Bob', 'local'])
        keyset          = key_list.get_keyset('alice@jabber.org')
        keyset.rx_harac = 1
        keyset.rx_key   = 32 * b'\x01'
        keyset.rx_hek   = 32 * b'\x01'
        group_list      = GroupList(groups=['testgroup'])
        settings        = Settings()
        packet_list     = PacketList(contact_list=contact_list, settings=settings)
        window_list     = WindowList(contact_list=contact_list, group_list=group_list, packet_list=packet_list, settings=settings)
        master_key      = MasterKey()

        # Test
        for p in apct_list:
            self.assertIsNone(process_message(ts, p, window_list, packet_list, contact_list, key_list, group_list, settings, master_key))

        # Teardown
        cleanup()

    def test_group_invitation_msg_from_user(self):
        # Setup
        message         = b'testgroup' + US_BYTE + b'bob@jabber.org' + US_BYTE + b'charlie@jabber.org'
        ts              = datetime.datetime.now()
        apct_list       = self.create_message_apct(ORIGIN_USER_HEADER, message, header=GROUP_MSG_INVITATION_HEADER)
        contact_list    = ContactList(nicks=['Alice', 'Bob', 'local'])
        key_list        = KeyList(nicks=['Alice', 'Bob', 'local'])
        keyset          = key_list.get_keyset('alice@jabber.org')
        keyset.tx_harac = 1
        keyset.tx_key   = 32 * b'\x01'
        keyset.tx_hek   = 32 * b'\x01'
        group_list      = GroupList(groups=['testgroup'])
        settings        = Settings()
        packet_list     = PacketList(contact_list=contact_list, settings=settings)
        window_list     = WindowList(contact_list=contact_list, group_list=group_list, packet_list=packet_list, settings=settings)
        master_key      = MasterKey()

        # Test
        for p in apct_list:
            self.assertIsNone(process_message(ts, p, window_list, packet_list, contact_list, key_list, group_list, settings, master_key))

        # Teardown
        cleanup()

    def test_group_add_member_msg(self):
        # Setup
        message         = b'testgroup' + US_BYTE + b'bob@jabber.org' + US_BYTE + b'charlie@jabber.org'
        ts              = datetime.datetime.now()
        apct_list       = self.create_message_apct(ORIGIN_CONTACT_HEADER, message, header=GROUP_MSG_ADD_NOTIFY_HEADER)
        contact_list    = ContactList(nicks=['Alice', 'Bob', 'local'])
        key_list        = KeyList(nicks=['Alice', 'Bob', 'local'])
        keyset          = key_list.get_keyset('alice@jabber.org')
        keyset.rx_harac = 1
        keyset.rx_key   = 32 * b'\x01'
        keyset.rx_hek   = 32 * b'\x01'
        group_list      = GroupList(groups=['testgroup'])
        settings        = Settings()
        packet_list     = PacketList(contact_list=contact_list, settings=settings)
        window_list     = WindowList(contact_list=contact_list, group_list=group_list, packet_list=packet_list, settings=settings)
        master_key      = MasterKey()

        # Test
        for p in apct_list:
            self.assertIsNone(process_message(ts, p, window_list, packet_list, contact_list, key_list, group_list, settings, master_key))

        # Teardown
        cleanup()

    def test_group_remove_member_msg(self):
        # Setup
        message         = b'testgroup' + US_BYTE + b'bob@jabber.org' + US_BYTE + b'charlie@jabber.org'
        ts              = datetime.datetime.now()
        apct_list       = self.create_message_apct(ORIGIN_CONTACT_HEADER, message, header=GROUP_MSG_MEMBER_RM_HEADER)
        contact_list    = ContactList(nicks=['Alice', 'Bob', 'local'])
        key_list        = KeyList(nicks=['Alice', 'Bob', 'local'])
        keyset          = key_list.get_keyset('alice@jabber.org')
        keyset.rx_harac = 1
        keyset.rx_key   = 32 * b'\x01'
        keyset.rx_hek   = 32 * b'\x01'
        group_list      = GroupList(groups=['testgroup'])
        settings        = Settings()
        packet_list     = PacketList(contact_list=contact_list, settings=settings)
        window_list     = WindowList(contact_list=contact_list, group_list=group_list, packet_list=packet_list, settings=settings)
        master_key      = MasterKey()

        # Test
        for p in apct_list:
            self.assertIsNone(process_message(ts, p, window_list, packet_list, contact_list, key_list, group_list, settings, master_key))

        # Teardown
        cleanup()

    def test_group_exit_msg(self):
        # Setup
        message         = b'testgroup'
        ts              = datetime.datetime.now()
        apct_list       = self.create_message_apct(ORIGIN_CONTACT_HEADER, message, header=GROUP_MSG_EXIT_GROUP_HEADER)
        contact_list    = ContactList(nicks=['Alice', 'Bob', 'local'])
        key_list        = KeyList(nicks=['Alice', 'Bob', 'local'])
        keyset          = key_list.get_keyset('alice@jabber.org')
        keyset.rx_harac = 1
        keyset.rx_key   = 32 * b'\x01'
        keyset.rx_hek   = 32 * b'\x01'
        group_list      = GroupList(groups=['testgroup'])
        settings        = Settings()
        packet_list     = PacketList(contact_list=contact_list, settings=settings)
        window_list     = WindowList(contact_list=contact_list, group_list=group_list, packet_list=packet_list, settings=settings)
        master_key      = MasterKey()

        # Test
        for p in apct_list:
            self.assertIsNone(process_message(ts, p, window_list, packet_list, contact_list, key_list, group_list, settings, master_key))

        # Teardown
        cleanup()

    def test_invalid_header(self):
        # Setup
        message         = b'testgroup'
        ts              = datetime.datetime.now()
        apct_list       = self.create_message_apct(ORIGIN_CONTACT_HEADER, message, header=b'1')
        contact_list    = ContactList(nicks=['Alice', 'Bob', 'local'])
        key_list        = KeyList(nicks=['Alice', 'Bob', 'local'])
        keyset          = key_list.get_keyset('alice@jabber.org')
        keyset.rx_harac = 1
        keyset.rx_key   = 32 * b'\x01'
        keyset.rx_hek   = 32 * b'\x01'
        group_list      = GroupList(groups=['testgroup'])
        settings        = Settings()
        packet_list     = PacketList(contact_list=contact_list, settings=settings)
        window_list     = WindowList(contact_list=contact_list, group_list=group_list, packet_list=packet_list, settings=settings)
        master_key      = MasterKey()

        # Test
        for p in apct_list:
            self.assertFR("Message from had invalid header.", process_message, ts, p, window_list, packet_list, contact_list, key_list, group_list, settings, master_key)

        # Teardown
        cleanup()

    def test_invalid_group_message_header(self):
        # Setup
        message         = b'testgroup'
        ts              = datetime.datetime.now()
        apct_list       = self.create_message_apct(ORIGIN_CONTACT_HEADER, message, header=GROUP_MESSAGE_HEADER)
        contact_list    = ContactList(nicks=['Alice', 'Bob', 'local'])
        key_list        = KeyList(nicks=['Alice', 'Bob', 'local'])
        keyset          = key_list.get_keyset('alice@jabber.org')
        keyset.rx_harac = 1
        keyset.rx_key   = 32 * b'\x01'
        keyset.rx_hek   = 32 * b'\x01'
        group_list      = GroupList(groups=['testgroup'])
        settings        = Settings()
        packet_list     = PacketList(contact_list=contact_list, settings=settings)
        window_list     = WindowList(contact_list=contact_list, group_list=group_list, packet_list=packet_list, settings=settings)
        master_key      = MasterKey()

        # Test
        for p in apct_list:
            self.assertFR("Received an invalid group message.", process_message,
                          ts, p, window_list, packet_list, contact_list, key_list, group_list, settings, master_key)

    def test_invalid_group_timestamp_header_raises_fr(self):
        # Setup
        message         = b'testgroup'
        ts              = datetime.datetime.now()
        header          = GROUP_MESSAGE_HEADER + US_BYTE
        apct_list       = self.create_message_apct(ORIGIN_CONTACT_HEADER, message, header=header)
        contact_list    = ContactList(nicks=['Alice', 'Bob', 'local'])
        key_list        = KeyList(nicks=['Alice', 'Bob', 'local'])
        keyset          = key_list.get_keyset('alice@jabber.org')
        keyset.rx_harac = 1
        keyset.rx_key   = 32 * b'\x01'
        keyset.rx_hek   = 32 * b'\x01'
        group_list      = GroupList(groups=['testgroup'])
        settings        = Settings()
        packet_list     = PacketList(contact_list=contact_list, settings=settings)
        window_list     = WindowList(contact_list=contact_list, group_list=group_list, packet_list=packet_list, settings=settings)
        master_key      = MasterKey()

        # Test
        for p in apct_list:
            self.assertFR("Received an invalid group message.", process_message,
                          ts, p, window_list, packet_list, contact_list, key_list, group_list, settings, master_key)

        # Teardown
        cleanup()

    def test_invalid_window_raises_fr(self):
        # Setup
        message         = b'testgroup'
        ts              = datetime.datetime.now()
        timestamp       = double_to_bytes(time.time() * 1000)
        header          = GROUP_MESSAGE_HEADER + timestamp + b'test_group' + US_BYTE
        apct_list       = self.create_message_apct(ORIGIN_CONTACT_HEADER, message, header=header)
        contact_list    = ContactList(nicks=['Alice', 'Bob', 'local'])
        key_list        = KeyList(nicks=['Alice', 'Bob', 'local'])
        keyset          = key_list.get_keyset('alice@jabber.org')
        keyset.rx_harac = 1
        keyset.rx_key   = 32 * b'\x01'
        keyset.rx_hek   = 32 * b'\x01'
        group_list      = GroupList(groups=['testgroup'])
        settings        = Settings()
        packet_list     = PacketList(contact_list=contact_list, settings=settings)
        window_list     = WindowList(contact_list=contact_list, group_list=group_list, packet_list=packet_list, settings=settings)
        master_key      = MasterKey()

        # Test
        for p in apct_list:
            self.assertFR("Received message to unknown group.", process_message,
                          ts, p, window_list, packet_list, contact_list, key_list, group_list, settings, master_key)

        # Teardown
        cleanup()

    def test_normal_msg_from_user(self):
        # Setup
        ts              = datetime.datetime.now()
        apct_list       = self.create_message_apct(ORIGIN_USER_HEADER, b'testmessage')
        contact_list    = ContactList(nicks=['Alice', 'Bob', 'local'])
        key_list        = KeyList(nicks=['Alice', 'Bob', 'local'])
        keyset          = key_list.get_keyset('alice@jabber.org')
        keyset.tx_harac = 1
        keyset.tx_key   = 32 * b'\x01'
        keyset.tx_hek   = 32 * b'\x01'
        group_list      = GroupList(groups=['testgroup'])
        settings        = Settings()
        packet_list     = PacketList(contact_list=contact_list, settings=settings)
        window_list     = WindowList(contact_list=contact_list, group_list=group_list, packet_list=packet_list, settings=settings)
        master_key      = MasterKey()

        # Test
        for p in apct_list:
            self.assertIsNone(process_message(ts, p, window_list, packet_list, contact_list, key_list, group_list, settings, master_key))

        # Teardown
        cleanup()

    def test_group_msg(self):
        # Setup
        ts                 = datetime.datetime.now()
        apct_list          = self.create_message_apct(ORIGIN_CONTACT_HEADER, b'testmessage', group_name=b'testgroup')
        contact_list       = ContactList(nicks=['Alice', 'Bob', 'local'])
        key_list           = KeyList(nicks=['Alice', 'Bob', 'local'])
        keyset             = key_list.get_keyset('alice@jabber.org')
        keyset.rx_harac    = 1
        keyset.rx_key      = 32 * b'\x01'
        keyset.rx_hek      = 32 * b'\x01'
        group_list         = GroupList(groups=['testgroup'])
        group              = group_list.get_group('testgroup')
        group.log_messages = True
        settings           = Settings()
        packet_list        = PacketList(contact_list=contact_list, settings=settings)
        window_list        = WindowList(contact_list=contact_list, group_list=group_list, packet_list=packet_list, settings=settings)
        master_key         = MasterKey()

        # Test
        for p in apct_list:
            self.assertIsNone(process_message(ts, p, window_list, packet_list, contact_list, key_list, group_list, settings, master_key))

        # Teardown
        cleanup()

    def test_file(self):
        # Setup
        ts              = datetime.datetime.now()
        apct_list       = self.create_file_apct()
        contact_list    = ContactList(nicks=['Alice', 'Bob', 'local'])
        key_list        = KeyList(nicks=['Alice', 'Bob', 'local'])
        keyset          = key_list.get_keyset('alice@jabber.org')
        keyset.rx_harac = 1
        keyset.rx_key   = 32 * b'\x01'
        keyset.rx_hek   = 32 * b'\x01'
        group_list      = GroupList(groups=['testgroup'])
        settings        = Settings()
        packet_list     = PacketList(contact_list=contact_list, settings=settings)
        window_list     = WindowList(contact_list=contact_list, group_list=group_list, packet_list=packet_list, settings=settings)
        master_key      = MasterKey()

        # Test
        for p in apct_list:
            self.assertIsNone(process_message(ts, p, window_list, packet_list, contact_list, key_list, group_list, settings, master_key))

        # Teardown
        shutil.rmtree('received_files/')


if __name__ == '__main__':
    unittest.main(exit=False)
