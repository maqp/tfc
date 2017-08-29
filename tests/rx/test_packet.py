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
import binascii
import builtins
import os
import shutil
import unittest
import zlib

from src.common.crypto   import byte_padding, encrypt_and_sign, hash_chain, rm_padding_bytes
from src.common.encoding import int_to_bytes
from src.common.misc     import split_byte_string
from src.common.statics  import *

from src.tx.packet import split_to_assembly_packets

from src.rx.packet import decrypt_assembly_packet, Packet, PacketList

from tests.mock_classes import create_contact, ContactList, KeyList, Settings, WindowList
from tests.utils        import ignored, TFCTestCase


class TestDecryptAssemblyPacket(TFCTestCase):

    def setUp(self):
        self.o_input      = builtins.input
        self.window_list  = WindowList( nicks=['Alice', LOCAL_ID])
        self.contact_list = ContactList(nicks=['Alice', LOCAL_ID])
        self.key_list     = KeyList(    nicks=['Alice', LOCAL_ID])
        self.keyset       = self.key_list.get_keyset('alice@jabber.org')
        self.packet       = None

    def tearDown(self):
        builtins.input = self.o_input

    def create_encrypted_packet(self, tx_harac, rx_harac, hek=KEY_LENGTH*b'\x01', key=KEY_LENGTH*b'\x01'):
        encrypted_message    = encrypt_and_sign(PRIVATE_MESSAGE_HEADER + byte_padding(b'test'), key)
        encrypted_harac      = encrypt_and_sign(int_to_bytes(tx_harac), hek)
        self.packet          = MESSAGE_PACKET_HEADER + encrypted_harac + encrypted_message + ORIGIN_CONTACT_HEADER + b'alice@jabber.org'
        self.keyset.rx_harac = rx_harac

    def test_invalid_origin_header_raises_fr(self):
        # Setup
        packet = MESSAGE_PACKET_HEADER + MESSAGE_LENGTH*b'm' + b'e'

        # Test
        self.assertFR("Error: Received packet had an invalid origin-header.",
                      decrypt_assembly_packet, packet, self.window_list, self.contact_list, self.key_list)

    def test_masqueraded_command_raises_fr(self):
        for o in [ORIGIN_USER_HEADER, ORIGIN_CONTACT_HEADER]:
            # Setup
            packet = MESSAGE_PACKET_HEADER + MESSAGE_LENGTH*b'm' + o + LOCAL_ID.encode()

            # Test
            self.assertFR("Warning! Received packet masqueraded as command.",
                          decrypt_assembly_packet, packet, self.window_list, self.contact_list, self.key_list)

    def test_invalid_harac_ct_raises_fr(self):
        # Setup
        packet = MESSAGE_PACKET_HEADER + MESSAGE_LENGTH*b'm' + ORIGIN_CONTACT_HEADER + b'alice@jabber.org'

        # Test
        self.assertFR("Warning! Received packet from Alice had an invalid hash ratchet MAC.",
                      decrypt_assembly_packet, packet, self.window_list, self.contact_list, self.key_list)

    def test_decryption_with_zero_rx_key_raises_fr(self):
        # Setup
        self.create_encrypted_packet(tx_harac=2, rx_harac=1, key=(hash_chain(KEY_LENGTH*b'\x01')))
        keyset        = self.key_list.get_keyset('alice@jabber.org')
        keyset.rx_key = bytes(KEY_LENGTH)

        # Test
        self.assertFR("Warning! Loaded zero-key for packet decryption.",
                      decrypt_assembly_packet, self.packet, self.window_list, self.contact_list, self.key_list)

    def test_decryption_with_zero_rx_hek_raises_fr(self):
        # Setup
        self.create_encrypted_packet(tx_harac=2, rx_harac=1, key=(hash_chain(KEY_LENGTH*b'\x01')))
        keyset        = self.key_list.get_keyset('alice@jabber.org')
        keyset.rx_hek = bytes(KEY_LENGTH)

        # Test
        self.assertFR("Warning! Loaded zero-key for packet decryption.",
                      decrypt_assembly_packet, self.packet, self.window_list, self.contact_list, self.key_list)

    def test_invalid_harac_raises_fr(self):
        # Setup
        self.create_encrypted_packet(tx_harac=3, rx_harac=3, hek=KEY_LENGTH*b'\x02')

        # Test
        self.assertFR("Warning! Received packet from Alice had an invalid hash ratchet MAC.",
                      decrypt_assembly_packet, self.packet, self.window_list, self.contact_list, self.key_list)

    def test_expired_harac_raises_fr(self):
        # Setup
        self.create_encrypted_packet(tx_harac=1, rx_harac=3)

        # Test
        self.assertFR("Warning! Received packet from Alice had an expired hash ratchet counter.",
                      decrypt_assembly_packet, self.packet, self.window_list, self.contact_list, self.key_list)

    def test_harac_dos_can_be_interrupted(self):
        # Setup
        self.create_encrypted_packet(tx_harac=10000, rx_harac=3)
        builtins.input = lambda _: 'No'

        # Test
        self.assertFR("Dropped packet from Alice.",
                      decrypt_assembly_packet, self.packet, self.window_list, self.contact_list, self.key_list)

    def test_invalid_packet_ct_raises_fr(self):
        # Setup
        self.create_encrypted_packet(tx_harac=5, rx_harac=3)

        # Test
        self.assertFR("Warning! Received packet from Alice had an invalid MAC.",
                      decrypt_assembly_packet, self.packet, self.window_list, self.contact_list, self.key_list)

    def test_successful_packet_decryption(self):
        # Setup
        self.create_encrypted_packet(tx_harac=1, rx_harac=1)

        # Test
        assembly_pt, account, origin = decrypt_assembly_packet(self.packet, self.window_list, self.contact_list, self.key_list)
        self.assertEqual(rm_padding_bytes(assembly_pt), PRIVATE_MESSAGE_HEADER + b'test')
        self.assertEqual(account, 'alice@jabber.org')
        self.assertEqual(origin, ORIGIN_CONTACT_HEADER)

    def test_successful_packet_decryption_with_offset(self):
        # Setup
        self.create_encrypted_packet(tx_harac=2, rx_harac=1, key=(hash_chain(KEY_LENGTH*b'\x01')))

        # Test
        assembly_pt, account, origin = decrypt_assembly_packet(self.packet, self.window_list, self.contact_list, self.key_list)
        self.assertEqual(rm_padding_bytes(assembly_pt), PRIVATE_MESSAGE_HEADER + b'test')
        self.assertEqual(account, 'alice@jabber.org')
        self.assertEqual(origin, ORIGIN_CONTACT_HEADER)

    def test_successful_command_decryption(self):
        # Setup
        command           = byte_padding(b'test')
        encrypted_message = encrypt_and_sign(command, KEY_LENGTH*b'\x01')
        encrypted_harac   = encrypt_and_sign(int_to_bytes(1), KEY_LENGTH*b'\x01')
        packet            = COMMAND_PACKET_HEADER + encrypted_harac + encrypted_message
        keyset            = self.key_list.get_keyset(LOCAL_ID)
        keyset.tx_harac   = 1

        # Test
        assembly_pt, account, origin = decrypt_assembly_packet(packet, self.window_list, self.contact_list, self.key_list)
        self.assertEqual(assembly_pt, command)
        self.assertEqual(account, LOCAL_ID)
        self.assertEqual(origin, ORIGIN_USER_HEADER)


class TestPacket(TFCTestCase):

    def setUp(self):
        self.msg = ("Lorem ipsum dolor sit amet, consectetur adipiscing elit. Aenean condimentum consectetur purus quis"
                    " dapibus. Fusce venenatis lacus ut rhoncus faucibus. Cras sollicitudin commodo sapien, sed bibendu"
                    "m velit maximus in. Aliquam ac metus risus. Sed cursus ornare luctus. Integer aliquet lectus id ma"
                    "ssa blandit imperdiet. Ut sed massa eget quam facilisis rutrum. Mauris eget luctus nisl. Sed ut el"
                    "it iaculis, faucibus lacus eget, sodales magna. Nunc sed commodo arcu. In hac habitasse platea dic"
                    "tumst. Integer luctus aliquam justo, at vestibulum dolor iaculis ac. Etiam laoreet est eget odio r"
                    "utrum, vel malesuada lorem rhoncus. Cras finibus in neque eu euismod. Nulla facilisi. Nunc nec ali"
                    "quam quam, quis ullamcorper leo. Nunc egestas lectus eget est porttitor, in iaculis felis sceleris"
                    "que. In sem elit, fringilla id viverra commodo, sagittis varius purus. Pellentesque rutrum loborti"
                    "s neque a facilisis. Mauris id tortor placerat, aliquam dolor ac, venenatis arcu.")

        self.contact  = create_contact()
        self.settings = Settings(logfile_masking=True)

        compressed = zlib.compress(b'abcdefghijk', level=COMPRESSION_LEVEL)
        file_key   = os.urandom(KEY_LENGTH)
        encrypted  = encrypt_and_sign(compressed, key=file_key)
        encrypted += file_key
        encoded    = base64.b85encode(encrypted)

        self.short_f_data = (int_to_bytes(1) + int_to_bytes(2) + b'testfile.txt' + US_BYTE + encoded)

    def tearDown(self):
        with ignored(FileNotFoundError):
            shutil.rmtree(DIR_RX_FILES)

    def test_invalid_assembly_packet_header_raises_fr(self):
        # Setup
        packet    = Packet('alice@jabber.org', self.contact, ORIGIN_USER_HEADER, MESSAGE, self.settings)
        plaintext = "Lorem ipsum dolor sit amet, consectetur adipiscing elit".encode()
        packets   = split_to_assembly_packets(plaintext, MESSAGE)

        # Test
        self.assertFR("Error: Received packet had an invalid assembly packet header.",
                      packet.add_packet, b'i' + packets[0][1:])
        self.assertEqual(packet.log_masking_ctr, 1)

    def test_missing_start_packet_raises_fr(self):
        packet = Packet('alice@jabber.org', self.contact, ORIGIN_USER_HEADER, MESSAGE, self.settings)

        for header in [M_A_HEADER, M_E_HEADER]:
            self.assertFR("Missing start packet.", packet.add_packet, header + bytes(PADDING_LEN))
        self.assertEqual(packet.log_masking_ctr, 2)

    def test_short_message(self):
        # Setup
        packet    = Packet('alice@jabber.org', self.contact, ORIGIN_USER_HEADER, MESSAGE, self.settings)
        plaintext = "Lorem ipsum dolor sit amet, consectetur adipiscing elit".encode()
        packets   = split_to_assembly_packets(plaintext, MESSAGE)

        for p in packets:
            packet.add_packet(p)

        # Test
        self.assertEqual(packet.assemble_message_packet(), plaintext)

    def test_compression_error_raises_fr(self):
        # Setup
        packet      = Packet('alice@jabber.org', self.contact, ORIGIN_USER_HEADER, MESSAGE, self.settings)
        payload     = zlib.compress(b"Lorem ipsum", level=COMPRESSION_LEVEL)[::-1]
        packet_list = [M_S_HEADER + byte_padding(payload)]

        for p in packet_list:
            packet.add_packet(p)

        # Test
        self.assertFR("Error: Decompression of message failed.", packet.assemble_message_packet)

    def test_long_message(self):
        # Setup
        packet  = Packet('alice@jabber.org', self.contact, ORIGIN_USER_HEADER, MESSAGE, self.settings)
        packets = split_to_assembly_packets(self.msg.encode(), MESSAGE)

        for p in packets:
            packet.add_packet(p)

        # Test
        message = packet.assemble_message_packet()
        self.assertEqual(message.decode(), self.msg)

    def test_decryption_error_raises_fr(self):
        # Setup
        packet      = Packet('alice@jabber.org', self.contact, ORIGIN_USER_HEADER, MESSAGE, self.settings)
        payload     = zlib.compress(self.msg.encode(), level=COMPRESSION_LEVEL)
        msg_key     = bytes(KEY_LENGTH)
        payload     = encrypt_and_sign(payload, msg_key)[::-1]
        payload    += msg_key
        padded      = byte_padding(payload)
        p_list      = split_byte_string(padded, item_len=PADDING_LEN)
        packet_list = ([M_L_HEADER + p_list[0]] +
                       [M_A_HEADER + p for p in p_list[1:-1]] +
                       [M_E_HEADER + p_list[-1]])

        for p in packet_list:
            packet.add_packet(p)

        # Test
        self.assertFR("Error: Decryption of message failed.", packet.assemble_message_packet)

    def test_short_file(self):
        # Setup
        packets = split_to_assembly_packets(self.short_f_data, FILE)

        # Test
        self.assertFalse(os.path.isfile(f'{DIR_RX_FILES}Alice/testfile.txt'))
        self.assertFalse(os.path.isfile(f'{DIR_RX_FILES}Alice/testfile.txt.1'))

        packet             = Packet('alice@jabber.org', self.contact, ORIGIN_CONTACT_HEADER, FILE, self.settings)
        packet.long_active = True

        for p in packets:
            packet.add_packet(p)
        self.assertIsNone(packet.assemble_and_store_file())
        self.assertTrue(os.path.isfile(f'{DIR_RX_FILES}Alice/testfile.txt'))

        for p in packets:
            packet.add_packet(p)
        self.assertIsNone(packet.assemble_and_store_file())
        self.assertTrue(os.path.isfile(f'{DIR_RX_FILES}Alice/testfile.txt.1'))

        # Teardown
        shutil.rmtree(DIR_RX_FILES)

    def test_short_file_from_user_raises_fr(self):
        # Setup
        packet  = Packet('alice@jabber.org', self.contact, ORIGIN_USER_HEADER, FILE, self.settings)
        packets = split_to_assembly_packets(self.short_f_data, FILE)

        # Test
        for p in packets:
            self.assertFR("Ignored file from user.", packet.add_packet, p)
        self.assertEqual(packet.log_masking_ctr, 1)

    def test_unauthorized_file_from_contact_raises_fr(self):
        # Setup
        self.contact.file_reception = False

        packet  = Packet('alice@jabber.org', self.contact, ORIGIN_CONTACT_HEADER, FILE, self.settings)
        packets = split_to_assembly_packets(self.short_f_data, FILE)

        # Test
        for p in packets:
            self.assertFR("Alert! File transmission from Alice but reception is disabled.", packet.add_packet, p)
        self.assertEqual(packet.log_masking_ctr, 1)

    def test_long_file(self):
        # Setup
        packet             = Packet('alice@jabber.org', self.contact, ORIGIN_CONTACT_HEADER, FILE, self.settings)
        packet.long_active = True

        compressed = zlib.compress(os.urandom(10000), level=COMPRESSION_LEVEL)
        file_key   = os.urandom(KEY_LENGTH)
        encrypted  = encrypt_and_sign(compressed, key=file_key)
        encrypted += file_key
        encoded    = base64.b85encode(encrypted)
        file_data  = int_to_bytes(1000) + int_to_bytes(10000)+ b'testfile.txt' + US_BYTE + encoded
        packets    = split_to_assembly_packets(file_data, FILE)

        for p in packets:
            packet.add_packet(p)

        # Test
        self.assertIsNone(packet.assemble_and_store_file())
        self.assertTrue(os.path.isfile(f'{DIR_RX_FILES}Alice/testfile.txt'))
        self.assertEqual(os.path.getsize(f'{DIR_RX_FILES}Alice/testfile.txt'), 10000)


    def test_disabled_file_reception_raises_fr_with_append_packet(self):
        # Setup
        packet             = Packet('alice@jabber.org', self.contact, ORIGIN_CONTACT_HEADER, FILE, self.settings)
        packet.long_active = True

        compressed = zlib.compress(os.urandom(10000), level=COMPRESSION_LEVEL)
        file_key   = os.urandom(KEY_LENGTH)
        encrypted  = encrypt_and_sign(compressed, key=file_key)
        encrypted += file_key
        encoded    = base64.b85encode(encrypted)
        file_data  = int_to_bytes(1000) + int_to_bytes(10000)+ b'testfile.txt' + US_BYTE + encoded
        packets    = split_to_assembly_packets(file_data, FILE)

        for p in packets[:2]:
            self.assertIsNone(packet.add_packet(p))

        packet.contact.file_reception = False

        # Test
        self.assertFR("Alert! File reception disabled mid-transfer.",
                      packet.add_packet, packets[2])

        for p in packets[3:]:
            self.assertFR("Missing start packet.", packet.add_packet, p)

        self.assertEqual(packet.log_masking_ctr, len(packets))


    def test_disabled_file_reception_raises_fr_with_end_packet(self):
        # Setup
        packet             = Packet('alice@jabber.org', self.contact, ORIGIN_CONTACT_HEADER, FILE, self.settings)
        packet.long_active = True

        compressed = zlib.compress(os.urandom(10000), level=COMPRESSION_LEVEL)
        file_key   = os.urandom(KEY_LENGTH)
        encrypted  = encrypt_and_sign(compressed, key=file_key)
        encrypted += file_key
        encoded    = base64.b85encode(encrypted)
        file_data  = int_to_bytes(1000) + int_to_bytes(10000)+ b'testfile.txt' + US_BYTE + encoded
        packets    = split_to_assembly_packets(file_data, FILE)

        for p in packets[:-1]:
            self.assertIsNone(packet.add_packet(p))

        packet.contact.file_reception = False

        # Test
        for p in packets[-1:]:
            self.assertFR("Alert! File reception disabled mid-transfer.", packet.add_packet, p)
        self.assertEqual(packet.log_masking_ctr, len(packets))

    def test_long_file_from_user_raises_fr(self):
        # Setup
        packet     = Packet('alice@jabber.org', self.contact, ORIGIN_USER_HEADER, FILE, self.settings)
        compressed = zlib.compress(os.urandom(10000), level=COMPRESSION_LEVEL)
        file_key   = os.urandom(KEY_LENGTH)
        encrypted  = encrypt_and_sign(compressed, key=file_key)
        encrypted += file_key
        encoded    = base64.b85encode(encrypted)
        file_data  = int_to_bytes(1000) + int_to_bytes(10000) + b'testfile.txt' + US_BYTE + encoded
        packets    = split_to_assembly_packets(file_data, FILE)

        # Test
        self.assertFR("Ignored file from user.", packet.add_packet, packets[0])
        self.assertEqual(packet.log_masking_ctr, 1)

    def test_unauthorized_long_file_raises_fr(self):
        # Setup
        self.contact.file_reception = False

        packet     = Packet('alice@jabber.org', self.contact, ORIGIN_CONTACT_HEADER, FILE, self.settings)
        compressed = zlib.compress(os.urandom(10000), level=COMPRESSION_LEVEL)
        file_key   = os.urandom(KEY_LENGTH)
        encrypted  = encrypt_and_sign(compressed, key=file_key)
        encrypted += file_key
        encoded    = base64.b85encode(encrypted)
        file_data  = int_to_bytes(1000) + int_to_bytes(10000) + b'testfile.txt' + US_BYTE + encoded
        packets    = split_to_assembly_packets(file_data, FILE)

        # Test
        self.assertFR("Alert! File transmission from Alice but reception is disabled.", packet.add_packet, packets[0])
        self.assertEqual(packet.log_masking_ctr, 1)

    def test_invalid_long_file_header_raises_fr(self):
        # Setup
        packet     = Packet('alice@jabber.org', self.contact, ORIGIN_CONTACT_HEADER, FILE, self.settings)
        compressed = zlib.compress(os.urandom(10000), level=COMPRESSION_LEVEL)
        file_key   = os.urandom(KEY_LENGTH)
        encrypted  = encrypt_and_sign(compressed, key=file_key)
        encrypted += file_key
        encoded    = base64.b85encode(encrypted)
        file_data  = int_to_bytes(1000) + int_to_bytes(10000) + binascii.unhexlify('3f264d4189d7a091') + US_BYTE + encoded
        packets    = split_to_assembly_packets(file_data, FILE)

        # Test
        self.assertFR("Error: Received file packet had an invalid header.", packet.add_packet, packets[0])
        self.assertEqual(packet.log_masking_ctr, 1)

    def test_contact_canceled_file(self):
        # Setup
        packet     = Packet('alice@jabber.org', self.contact, ORIGIN_CONTACT_HEADER, FILE, self.settings)
        compressed = zlib.compress(os.urandom(10000), level=COMPRESSION_LEVEL)
        file_key   = os.urandom(KEY_LENGTH)
        encrypted  = encrypt_and_sign(compressed, key=file_key)
        encrypted += file_key
        encoded    = base64.b85encode(encrypted)
        file_data  = int_to_bytes(1000) + int_to_bytes(10000) + b'testfile.txt' + US_BYTE + encoded
        packets    = split_to_assembly_packets(file_data, FILE)
        packets    = packets[:20]
        packets.append(byte_padding(F_C_HEADER))  # Add cancel packet

        for p in packets:
            packet.add_packet(p)

        # Test
        self.assertEqual(len(packet.assembly_pt_list), 0)  # Cancel packet empties packet list
        self.assertFalse(packet.long_active)
        self.assertFalse(packet.is_complete)
        self.assertEqual(packet.log_masking_ctr, len(packets))

    def test_noise_packet_interrupts_file(self):
        # Setup
        packet     = Packet('alice@jabber.org', self.contact, ORIGIN_CONTACT_HEADER, FILE, self.settings)
        compressed = zlib.compress(os.urandom(10000), level=COMPRESSION_LEVEL)
        file_key   = os.urandom(KEY_LENGTH)
        encrypted  = encrypt_and_sign(compressed, key=file_key)
        encrypted += file_key
        encoded    = base64.b85encode(encrypted)
        file_data  = int_to_bytes(1000) + int_to_bytes(10000) + b'testfile.txt' + US_BYTE + encoded
        packets    = split_to_assembly_packets(file_data, FILE)
        packets    = packets[:20]
        packets.append(byte_padding(P_N_HEADER))  # Add cancel packet

        for p in packets:
            packet.add_packet(p)

        # Test
        self.assertEqual(len(packet.assembly_pt_list), 0)  # Cancel packet empties packet list
        self.assertFalse(packet.long_active)
        self.assertFalse(packet.is_complete)
        self.assertEqual(packet.log_masking_ctr, len(packets))

    def test_short_command(self):
        # Setup
        packet  = Packet(LOCAL_ID, self.contact, ORIGIN_CONTACT_HEADER, COMMAND, self.settings)
        packets = split_to_assembly_packets(b'testcommand', COMMAND)

        for p in packets:
            packet.add_packet(p)

        # Test
        self.assertEqual(packet.assemble_command_packet(), b'testcommand')
        self.assertEqual(packet.log_masking_ctr, 0)

    def test_long_command(self):
        # Setup
        packet  = Packet(LOCAL_ID, self.contact, ORIGIN_CONTACT_HEADER, COMMAND, self.settings)
        command = os.urandom(500)
        packets = split_to_assembly_packets(command, COMMAND)

        for p in packets:
            packet.add_packet(p)

        # Test
        self.assertEqual(packet.assemble_command_packet(), command)
        self.assertEqual(packet.log_masking_ctr, 0)

    def test_long_command_hash_mismatch_raises_fr(self):
        # Setup
        packet  = Packet(LOCAL_ID, self.contact, ORIGIN_CONTACT_HEADER, COMMAND, self.settings)
        command = os.urandom(500) + b'a'
        packets = split_to_assembly_packets(command, COMMAND)
        packets = [p.replace(b'a', b'c') for p in packets]

        for p in packets:
            packet.add_packet(p)

        # Test
        self.assertFR("Error: Received an invalid command.", packet.assemble_command_packet)
        self.assertEqual(packet.log_masking_ctr, 0)

    def test_long_command_compression_error_raises_fr(self):
        # Setup
        packet      = Packet(LOCAL_ID, self.contact, ORIGIN_CONTACT_HEADER, COMMAND, self.settings)
        command     = os.urandom(500) + b'a'
        payload     = zlib.compress(command, level=COMPRESSION_LEVEL)[::-1]
        payload    += hash_chain(payload)
        padded      = byte_padding(payload)
        p_list      = split_byte_string(padded, item_len=PADDING_LEN)
        packet_list = ([C_L_HEADER + p_list[0]] +
                       [C_A_HEADER + p for p in p_list[1:-1]] +
                       [C_E_HEADER + p_list[-1]])

        for p in packet_list:
            packet.add_packet(p)

        # Test
        self.assertFR("Error: Decompression of command failed.", packet.assemble_command_packet)
        self.assertEqual(packet.log_masking_ctr, 0)


class TestPacketList(unittest.TestCase):

    def setUp(self):
        self.contact_list = ContactList(nicks=['Alice', 'Bob'])
        self.settings     = Settings()
        packet            = Packet('alice@jabber.org', self.contact_list.get_contact('Alice'),
                                   ORIGIN_CONTACT_HEADER, MESSAGE, self.settings)

        self.packet_list         = PacketList(self.settings, self.contact_list)
        self.packet_list.packets = [packet]

    def test_packet_list_iterates_over_contact_objects(self):
        for p in self.packet_list:
            self.assertIsInstance(p, Packet)

    def test_len_returns_number_of_contacts(self):
        self.assertEqual(len(self.packet_list), 1)

    def test_has_packet(self):
        self.assertTrue(self.packet_list.has_packet('alice@jabber.org', ORIGIN_CONTACT_HEADER, MESSAGE))
        self.assertFalse(self.packet_list.has_packet('alice@jabber.org', ORIGIN_USER_HEADER, MESSAGE))

    def test_get_packet(self):
        packet = self.packet_list.get_packet('alice@jabber.org', ORIGIN_CONTACT_HEADER, MESSAGE)
        self.assertEqual(packet.account, 'alice@jabber.org')
        self.assertEqual(packet.origin, ORIGIN_CONTACT_HEADER)
        self.assertEqual(packet.type, MESSAGE)


if __name__ == '__main__':
    unittest.main(exit=False)
