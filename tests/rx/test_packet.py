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
import builtins
import os
import shutil
import time
import unittest
import zlib

from src.common.statics  import *
from src.common.crypto   import encrypt_and_sign, byte_padding, hash_chain
from src.common.encoding import double_to_bytes, int_to_bytes
from src.common.misc     import split_byte_string
from src.rx.packet       import decrypt_assembly_packet, Packet, PacketList

from tests.mock_classes  import create_contact, ContactList, KeyList, Settings, WindowList
from tests.utils         import TFCTestCase


class TestDecryptAssemblyPacket(TFCTestCase):

    def test_invalid_origin_header_raises_fr(self):
        # Setup
        invalid_origin_header = b'e'
        mock_data             = 344 * b'a'
        packet                = MESSAGE_PACKET_HEADER + mock_data + invalid_origin_header

        # Test
        self.assertFR("Received packet had an invalid origin-header.", decrypt_assembly_packet, packet, None, None, None)

    def test_missing_rx_psk_raises_fr(self):
        # Setup
        packet        = MESSAGE_PACKET_HEADER + 344 * b'a' + ORIGIN_CONTACT_HEADER + b'alice@jabber.org'
        window_list   = WindowList(nicks=['Alice', 'local'])
        contact_list  = ContactList(nicks=['Alice', 'local'])
        key_list      = KeyList(nicks=['Alice', 'local'])
        keyset        = key_list.get_keyset('alice@jabber.org')
        keyset.rx_hek = bytes(32)  # Set to identify missing PSK

        # Test
        self.assertFR("Warning! Received packet from Alice but no PSK exists.", decrypt_assembly_packet, packet, window_list, contact_list, key_list)


    def test_invalid_harac_ct_raises_fr(self):
        # Setup
        packet        = MESSAGE_PACKET_HEADER + 344 * b'a' + ORIGIN_CONTACT_HEADER + b'alice@jabber.org'
        window_list   = WindowList(nicks=['Alice', 'local'])
        contact_list  = ContactList(nicks=['Alice', 'local'])
        key_list      = KeyList(nicks=['Alice', 'local'])

        # Test
        self.assertFR("Warning! Received packet from Alice had an invalid hash ratchet MAC.", decrypt_assembly_packet, packet, window_list, contact_list, key_list)

    def test_invalid_harac_raises_fr(self):
        # Setup
        encrypted_message = encrypt_and_sign(PRIVATE_MESSAGE_HEADER + byte_padding(b'test'), 32 * b'\x01')
        harac_in_bytes    = int_to_bytes(3)
        encrypted_harac   = encrypt_and_sign(harac_in_bytes, 32 * b'\x02')
        packet            = MESSAGE_PACKET_HEADER + encrypted_harac + encrypted_message + ORIGIN_CONTACT_HEADER + b'alice@jabber.org'

        window_list       = WindowList(nicks=['Alice', 'local'])
        contact_list      = ContactList(nicks=['Alice', 'local'])
        key_list          = KeyList(nicks=['Alice', 'local'])
        keyset            = key_list.get_keyset('alice@jabber.org')
        keyset.rx_harac   = 3

        # Test
        self.assertFR("Warning! Received packet from Alice had an invalid hash ratchet MAC.", decrypt_assembly_packet, packet, window_list, contact_list, key_list)

    def test_expired_harac_raises_fr(self):
        # Setup
        encrypted_message = encrypt_and_sign(PRIVATE_MESSAGE_HEADER + byte_padding(b'test'), 32 * b'\x01')
        harac_in_bytes    = int_to_bytes(1)
        encrypted_harac   = encrypt_and_sign(harac_in_bytes, 32 * b'\x01')
        packet            = MESSAGE_PACKET_HEADER + encrypted_harac + encrypted_message + ORIGIN_CONTACT_HEADER + b'alice@jabber.org'

        window_list       = WindowList(nicks=['Alice', 'local'])
        contact_list      = ContactList(nicks=['Alice', 'local'])
        key_list          = KeyList(nicks=['Alice', 'local'])
        keyset            = key_list.get_keyset('alice@jabber.org')
        keyset.rx_harac   = 3

        # Test
        self.assertFR("Warning! Received packet from Alice had an expired hash ratchet counter.", decrypt_assembly_packet, packet, window_list, contact_list, key_list)

    def test_harac_dos_can_be_interrupted(self):
        # Setup
        encrypted_message = encrypt_and_sign(PRIVATE_MESSAGE_HEADER + byte_padding(b'test'), 32 * b'\x01')
        harac_in_bytes    = int_to_bytes(10000)
        encrypted_harac   = encrypt_and_sign(harac_in_bytes, 32 * b'\x01')
        packet            = MESSAGE_PACKET_HEADER + encrypted_harac + encrypted_message + ORIGIN_CONTACT_HEADER + b'alice@jabber.org'
        o_input           = builtins.input
        builtins.input    = lambda x: 'No'

        window_list       = WindowList(nicks=['Alice', 'local'])
        contact_list      = ContactList(nicks=['Alice', 'local'])
        key_list          = KeyList(nicks=['Alice', 'local'])
        keyset            = key_list.get_keyset('alice@jabber.org')
        keyset.rx_harac   = 3

        # Test
        self.assertFR("Dropped packet from Alice.", decrypt_assembly_packet, packet, window_list, contact_list, key_list)

        # Teardown
        builtins.input = o_input

    def test_invalid_packet_ct_raises_fr(self):
        # Setup
        encrypted_message = encrypt_and_sign(PRIVATE_MESSAGE_HEADER + byte_padding(b'test'), 32 * b'\x01')
        harac_in_bytes    = int_to_bytes(5)
        encrypted_harac   = encrypt_and_sign(harac_in_bytes, 32 * b'\x01')
        packet            = MESSAGE_PACKET_HEADER + encrypted_harac + encrypted_message + ORIGIN_CONTACT_HEADER + b'alice@jabber.org'

        window_list       = WindowList(nicks=['Alice', 'local'])
        contact_list      = ContactList(nicks=['Alice', 'local'])
        key_list          = KeyList(nicks=['Alice', 'local'])
        keyset            = key_list.get_keyset('alice@jabber.org')
        keyset.rx_harac   = 3

        # Test
        self.assertFR("Warning! Received packet from Alice had an invalid MAC.", decrypt_assembly_packet, packet, window_list, contact_list, key_list)

    def test_successful_packet_decryption(self):
        # Setup
        message           = PRIVATE_MESSAGE_HEADER + byte_padding(b'test')
        encrypted_message = encrypt_and_sign(message, 32 * b'\x01')
        harac_in_bytes    = int_to_bytes(1)
        encrypted_harac   = encrypt_and_sign(harac_in_bytes, 32 * b'\x01')
        packet            = MESSAGE_PACKET_HEADER + encrypted_harac + encrypted_message + ORIGIN_CONTACT_HEADER + b'alice@jabber.org'

        window_list       = WindowList(nicks=['Alice', 'local'])
        contact_list      = ContactList(nicks=['Alice', 'local'])
        key_list          = KeyList(nicks=['Alice', 'local'])
        keyset            = key_list.get_keyset('alice@jabber.org')
        keyset.rx_harac   = 1

        # Test
        assembly_pt, account, origin = decrypt_assembly_packet(packet, window_list, contact_list, key_list)

        self.assertEqual(assembly_pt, message)
        self.assertEqual(account, 'alice@jabber.org')
        self.assertEqual(origin, ORIGIN_CONTACT_HEADER)

    def test_successful_packet_decryption_with_offset(self):
        # Setup
        message           = PRIVATE_MESSAGE_HEADER + byte_padding(b'test')
        encrypted_message = encrypt_and_sign(message, hash_chain(32 * b'\x01'))
        harac_in_bytes    = int_to_bytes(2)
        encrypted_harac   = encrypt_and_sign(harac_in_bytes, 32 * b'\x01')
        packet            = MESSAGE_PACKET_HEADER + encrypted_harac + encrypted_message + ORIGIN_CONTACT_HEADER + b'alice@jabber.org'

        window_list       = WindowList(nicks=['Alice', 'local'])
        contact_list      = ContactList(nicks=['Alice', 'local'])
        key_list          = KeyList(nicks=['Alice', 'local'])
        keyset            = key_list.get_keyset('alice@jabber.org')
        keyset.rx_harac   = 1

        # Test
        assembly_pt, account, origin = decrypt_assembly_packet(packet, window_list, contact_list, key_list)

        self.assertEqual(assembly_pt, message)
        self.assertEqual(account, 'alice@jabber.org')
        self.assertEqual(origin, ORIGIN_CONTACT_HEADER)

    def test_successful_command_decryption(self):
        # Setup
        command           = byte_padding(b'test')
        encrypted_message = encrypt_and_sign(command, 32 * b'\x01')
        harac_in_bytes    = int_to_bytes(1)
        encrypted_harac   = encrypt_and_sign(harac_in_bytes, 32 * b'\x01')
        packet            = COMMAND_PACKET_HEADER + encrypted_harac + encrypted_message

        window_list       = WindowList(nicks=['Alice', 'local'])
        contact_list      = ContactList(nicks=['Alice', 'local'])
        key_list          = KeyList(nicks=['Alice', 'local'])
        keyset            = key_list.get_keyset('local')
        keyset.tx_harac   = 1

        # Test
        assembly_pt, account, origin = decrypt_assembly_packet(packet, window_list, contact_list, key_list)

        self.assertEqual(assembly_pt, command)
        self.assertEqual(account, 'local')
        self.assertEqual(origin, ORIGIN_USER_HEADER)

class TestPacket(TFCTestCase):

    @staticmethod
    def mock_message_preprocessor(message, header=b'', group=False):
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

    @staticmethod
    def mock_file_preprocessor(payload):
        if len(payload) < 255:
            padded = byte_padding(payload)
            packet_list = [F_S_HEADER + padded]
        else:
            payload = bytes(8) + payload
            padded  = byte_padding(payload)
            p_list  = split_byte_string(padded, item_len=255)

            packet_list = ([F_L_HEADER + int_to_bytes(len(p_list)) + p_list[0][8:]] +
                           [F_A_HEADER + p for p in p_list[1:-1]] +
                           [F_E_HEADER + p_list[-1]])
        return packet_list

    @staticmethod
    def mock_command_preprocessor(command):
        payload = zlib.compress(command, level=9)
        if len(payload) < 255:
            padded      = byte_padding(payload)
            packet_list = [C_S_HEADER + padded]
        else:
            payload += hash_chain(payload)
            padded   = byte_padding(payload)
            p_list   = split_byte_string(padded, item_len=255)
            packet_list = ([C_L_HEADER + p_list[0]] +
                           [C_A_HEADER + p for p in p_list[1:-1]] +
                           [C_E_HEADER + p_list[-1]])
        return packet_list

    def test_missing_start_packet_raises_fr(self):
        account  = 'alice@jabber.org'
        contact  = create_contact('Alice')
        origin   = ORIGIN_USER_HEADER
        type_    = 'message'
        settings = Settings()
        packet   = Packet(account, contact, origin, type_, settings)

        self.assertFR('Missing start packet.', packet.add_packet, (M_A_HEADER + bytes(254)))
        self.assertFR('Missing start packet.', packet.add_packet, (M_E_HEADER + bytes(254)))

    def test_short_message(self):
        # Setup
        account  = 'alice@jabber.org'
        contact  = create_contact('Alice')
        origin   = ORIGIN_USER_HEADER
        type_    = 'message'
        settings = Settings()
        packet   = Packet(account, contact, origin, type_, settings)
        message  = "Lorem ipsum dolor sit amet, consectetur adipiscing elit"
        packets  = self.mock_message_preprocessor(message)

        # Test
        for p in packets:
            packet.add_packet(p)

        message = packet.assemble_message_packet()
        message = message[1:].decode()
        self.assertEqual(message, message)

    def test_compression_error_raises_fr(self):
        # Setup
        account  = 'alice@jabber.org'
        contact  = create_contact('Alice')
        origin   = ORIGIN_USER_HEADER
        type_    = 'message'
        settings = Settings()
        packet   = Packet(account, contact, origin, type_, settings)
        message  = "Lorem ipsum dolor sit amet, consectetur adipiscing elit"

        plaintext   = message.encode()
        payload     = zlib.compress(plaintext, level=9)
        if payload[:-1] == b'a':  # Remove false positives
            payload = payload[-1:] + b'c'
        else:
            payload = payload[-1:] + b'a'
        padded      = byte_padding(payload)
        packet_list = [M_S_HEADER + padded]

        # Test
        for p in packet_list:
            packet.add_packet(p)

        self.assertFR('Decompression of long message failed.', packet.assemble_message_packet)

    def test_long_message(self):
        # Setup
        account  = 'alice@jabber.org'
        contact  = create_contact('Alice')
        origin   = ORIGIN_USER_HEADER
        type_    = 'message'
        settings = Settings()
        packet   = Packet(account, contact, origin, type_, settings)

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

        packets = self.mock_message_preprocessor(long_msg)

        # Test
        for p in packets:
            packet.add_packet(p)

        message = packet.assemble_message_packet()
        message = message[1:].decode()
        self.assertEqual(message, long_msg)

    def test_decryption_error_raises_fr(self):
        # Setup
        account  = 'alice@jabber.org'
        contact  = create_contact('Alice')
        origin   = ORIGIN_USER_HEADER
        type_    = 'message'
        settings = Settings()
        packet   = Packet(account, contact, origin, type_, settings)

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

        plaintext = long_msg.encode()
        payload   = zlib.compress(plaintext, level=9)

        msg_key  = bytes(32)
        payload  = encrypt_and_sign(payload, msg_key)
        if payload[:-1] == b'a':  # Remove false positives
            payload = payload[-1:] + b'c'
        else:
            payload = payload[-1:] + b'a'
        payload += msg_key
        padded   = byte_padding(payload)
        p_list   = split_byte_string(padded, item_len=255)
        packet_list = ([M_L_HEADER + p_list[0]] +
                       [M_A_HEADER + p for p in p_list[1:-1]] +
                       [M_E_HEADER + p_list[-1]])

        # Test
        for p in packet_list:
            packet.add_packet(p)

        self.assertFR('Decryption of long message failed.', packet.assemble_message_packet)

    def test_short_file(self):
        # Setup
        account    = 'alice@jabber.org'
        contact    = create_contact('Alice')
        origin     = ORIGIN_CONTACT_HEADER
        type_      = 'file'
        settings   = Settings()
        packet     = Packet(account, contact, origin, type_, settings)
        file_data  = b'abcdefghijk'
        compressed = zlib.compress(file_data, level=9)
        file_key   = os.urandom(32)
        encrypted  = encrypt_and_sign(compressed, key=file_key)
        encrypted += file_key
        encoded    = base64.b85encode(encrypted)
        file_data  = US_BYTE.join([b'testfile.txt', b'11.0B', b'00d 00h 00m 00s', encoded])
        packets    = self.mock_file_preprocessor(file_data)

        # Test
        for p in packets:
            packet.add_packet(p)
        self.assertIsNone(packet.assemble_and_store_file())

        for p in packets:
            packet.add_packet(p)
        self.assertIsNone(packet.assemble_and_store_file())

        self.assertTrue(os.path.isfile('received_files/Alice/testfile.txt'))
        self.assertTrue(os.path.isfile('received_files/Alice/testfile.txt.1'))

        # Teardown
        shutil.rmtree('received_files/')

    def test_short_file_from_user_raises_fr(self):
        # Setup
        account    = 'alice@jabber.org'
        contact    = create_contact('Alice')
        origin     = ORIGIN_USER_HEADER
        type_      = 'file'
        settings   = Settings()
        packet     = Packet(account, contact, origin, type_, settings)
        file_data  = b'abcdefghijk'
        compressed = zlib.compress(file_data, level=9)
        file_key   = os.urandom(32)
        encrypted  = encrypt_and_sign(compressed, key=file_key)
        encrypted += file_key
        encoded    = base64.b85encode(encrypted)
        file_data  = US_BYTE.join([b'testfile.txt', b'11.0B', b'00d 00h 00m 00s', encoded])
        packets    = self.mock_file_preprocessor(file_data)

        # Test
        for p in packets:
            self.assertFR("Ignored short file from user.", packet.add_packet, p)

    def test_unauthorized_file_from_contact_raises_fr(self):
        # Setup
        account                = 'alice@jabber.org'
        contact                = create_contact('Alice')
        contact.file_reception = False
        origin                 = ORIGIN_CONTACT_HEADER
        type_                  = 'file'
        settings               = Settings()
        packet                 = Packet(account, contact, origin, type_, settings)
        file_data              = b'abcdefghijk'
        compressed             = zlib.compress(file_data, level=9)
        file_key               = os.urandom(32)
        encrypted              = encrypt_and_sign(compressed, key=file_key)
        encrypted             += file_key
        encoded                = base64.b85encode(encrypted)
        file_data              = US_BYTE.join([b'testfile.txt', b'11.0B', b'00d 00h 00m 00s', encoded])
        packets                = self.mock_file_preprocessor(file_data)

        # Test
        for p in packets:
            self.assertFR("Unauthorized short file from contact.", packet.add_packet, p)

    def test_empty_file_raises_fr(self):
        # Setup
        account    = 'alice@jabber.org'
        contact    = create_contact('Alice')
        origin     = ORIGIN_CONTACT_HEADER
        type_      = 'file'
        settings   = Settings()
        packet     = Packet(account, contact, origin, type_, settings)

        file_data  = b''
        compressed = zlib.compress(file_data, level=9)
        file_key   = os.urandom(32)
        encrypted  = encrypt_and_sign(compressed, key=file_key)
        encrypted += file_key
        encoded    = base64.b85encode(encrypted)

        file_data  = US_BYTE.join([b'testfile.txt', b'11.0B', b'00d 00h 00m 00s', encoded])
        packets    = self.mock_file_preprocessor(file_data)

        # Test
        for p in packets:
            packet.add_packet(p)
        self.assertFR('Received file did not contain data.', packet.assemble_and_store_file)

    def test_long_file(self):
        # Setup
        account    = 'alice@jabber.org'
        contact    = create_contact('Alice')
        origin     = ORIGIN_CONTACT_HEADER
        type_      = 'file'
        settings   = Settings()
        packet     = Packet(account, contact, origin, type_, settings)

        file_data  = os.urandom(10000)
        compressed = zlib.compress(file_data, level=9)
        file_key   = os.urandom(32)
        encrypted  = encrypt_and_sign(compressed, key=file_key)
        encrypted += file_key
        encoded    = base64.b85encode(encrypted)

        file_data  = US_BYTE.join([b'testfile.txt', b'11.0B', b'00d 00h 00m 00s', encoded])
        packets    = self.mock_file_preprocessor(file_data)

        # Test
        for p in packets:
            packet.add_packet(p)
        self.assertIsNone(packet.assemble_and_store_file())

        self.assertTrue(os.path.isfile('received_files/Alice/testfile.txt'))
        self.assertEqual(os.path.getsize('received_files/Alice/testfile.txt'), 10000)

        # Teardown
        shutil.rmtree('received_files/')

    def test_long_file_from_user_raises_fr(self):
        # Setup
        account    = 'alice@jabber.org'
        contact    = create_contact('Alice')
        origin     = ORIGIN_USER_HEADER
        type_      = 'file'
        settings   = Settings()
        packet     = Packet(account, contact, origin, type_, settings)

        file_data  = os.urandom(10000)
        compressed = zlib.compress(file_data, level=9)
        file_key   = os.urandom(32)
        encrypted  = encrypt_and_sign(compressed, key=file_key)
        encrypted += file_key
        encoded    = base64.b85encode(encrypted)

        file_data  = US_BYTE.join([b'testfile.txt', b'11.0B', b'00d 00h 00m 00s', encoded])
        packets    = self.mock_file_preprocessor(file_data)

        # Test
        self.assertFR("Ignored long file from user.", packet.add_packet, packets[0])

    def test_unauthorized_long_file_raises_fr(self):
        # Setup
        account                = 'alice@jabber.org'
        contact                = create_contact('Alice')
        contact.file_reception = False
        origin                 = ORIGIN_CONTACT_HEADER
        type_                  = 'file'
        settings               = Settings()
        packet                 = Packet(account, contact, origin, type_, settings)
        file_data              = os.urandom(10000)
        compressed             = zlib.compress(file_data, level=9)
        file_key               = os.urandom(32)
        encrypted              = encrypt_and_sign(compressed, key=file_key)
        encrypted             += file_key
        encoded                = base64.b85encode(encrypted)
        file_data              = US_BYTE.join([b'testfile.txt', b'11.0B', b'00d 00h 00m 00s', encoded])
        packets                = self.mock_file_preprocessor(file_data)

        # Test
        self.assertFR("Unauthorized long file from contact.", packet.add_packet, packets[0])

    def test_invalid_long_file_header_raises_fr(self):
        # Setup
        account    = 'alice@jabber.org'
        contact    = create_contact('Alice')
        origin     = ORIGIN_CONTACT_HEADER
        type_      = 'file'
        settings   = Settings()
        packet     = Packet(account, contact, origin, type_, settings)
        file_data  = os.urandom(10000)
        compressed = zlib.compress(file_data, level=9)
        file_key   = os.urandom(32)
        encrypted  = encrypt_and_sign(compressed, key=file_key)
        encrypted += file_key
        encoded    = base64.b85encode(encrypted)
        file_data  = US_BYTE.join([b'testfile.txt', b'11.0B', encoded])
        packets    = self.mock_file_preprocessor(file_data)

        # Test
        self.assertFR("Received packet had an invalid header.", packet.add_packet, packets[0])


    def test_contact_canceled_file(self):
        # Setup
        account    = 'alice@jabber.org'
        contact    = create_contact('Alice')
        origin     = ORIGIN_CONTACT_HEADER
        type_      = 'file'
        settings   = Settings()
        packet     = Packet(account, contact, origin, type_, settings)
        file_data  = os.urandom(10000)
        compressed = zlib.compress(file_data, level=9)
        file_key   = os.urandom(32)
        encrypted  = encrypt_and_sign(compressed, key=file_key)
        encrypted += file_key
        encoded    = base64.b85encode(encrypted)
        file_data  = US_BYTE.join([b'testfile.txt', b'11.0B', b'00d 00h 00m 00s', encoded])
        packets    = self.mock_file_preprocessor(file_data)
        packets    = packets[:20]
        packets.append(byte_padding(F_C_HEADER))  # Add cancel packet

        # Test
        for p in packets:
            packet.add_packet(p)
        self.assertEqual(len(packet.assembly_pt_list), 0)  # Cancel packet empties packet list
        self.assertFalse(packet.lt_active)
        self.assertFalse(packet.is_complete)

    def test_short_command(self):
        # Setup
        account  = 'local'
        contact  = create_contact('local')
        origin   = ORIGIN_CONTACT_HEADER
        type_    = 'command'
        settings = Settings()
        packet   = Packet(account, contact, origin, type_, settings)
        command  = b'testcommand'
        packets  = self.mock_command_preprocessor(command)

        # Test
        for p in packets:
            packet.add_packet(p)

        purp_cmd = packet.assemble_command_packet()
        self.assertEqual(purp_cmd, command)

    def test_long_command(self):
        # Setup
        account  = 'local'
        contact  = create_contact('local')
        origin   = ORIGIN_CONTACT_HEADER
        type_    = 'command'
        settings = Settings()
        packet   = Packet(account, contact, origin, type_, settings)
        command  = os.urandom(500)
        packets  = self.mock_command_preprocessor(command)

        # Test
        for p in packets:
            packet.add_packet(p)

        purp_cmd = packet.assemble_command_packet()
        self.assertEqual(purp_cmd, command)

    def test_long_command_hash_mismatch_raises_fr(self):
        # Setup
        account  = 'local'
        contact  = create_contact('local')
        origin   = ORIGIN_CONTACT_HEADER
        type_    = 'command'
        settings = Settings()
        packet   = Packet(account, contact, origin, type_, settings)
        command  = os.urandom(500) + b'a'
        packets  = self.mock_command_preprocessor(command)
        packets  = [p.replace(b'a', b'c') for p in packets]

        # Test
        for p in packets:
            packet.add_packet(p)

        self.assertFR('Received an invalid command.', packet.assemble_command_packet)


class TestPacketList(unittest.TestCase):

    def test_class(self):
        # Setup
        contact_list = ContactList(nicks=['Alice', 'Bob'])
        settings     = Settings()
        packet_list  = PacketList(contact_list, settings)
        packet       = packet_list.get_packet('alice@jabber.org', ORIGIN_CONTACT_HEADER, 'message')

        # Test
        self.assertEqual(packet.account, 'alice@jabber.org')
        self.assertTrue(packet_list.has_packet('alice@jabber.org', ORIGIN_CONTACT_HEADER, 'message'))
        self.assertFalse(packet_list.has_packet('alice@jabber.org', ORIGIN_USER_HEADER, 'message'))
        self.assertEqual(len(packet_list), 1)
        for p in packet_list:
            self.assertIsInstance(p, Packet)


if __name__ == '__main__':
    unittest.main(exit=False)
