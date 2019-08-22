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
import unittest
import zlib

from datetime import datetime
from unittest import mock

from src.common.crypto   import byte_padding, encrypt_and_sign
from src.common.encoding import int_to_bytes
from src.common.statics  import *

from src.transmitter.packet import split_to_assembly_packets

from src.receiver.packet import decrypt_assembly_packet, Packet, PacketList

from tests.mock_classes import ContactList, create_contact, KeyList, Settings, WindowList
from tests.utils        import assembly_packet_creator, cd_unit_test, cleanup, nick_to_pub_key, TFCTestCase
from tests.utils        import UNDECODABLE_UNICODE


class TestDecryptAssemblyPacket(TFCTestCase):

    def setUp(self):
        self.onion_pub_key = nick_to_pub_key("Alice")
        self.origin        = ORIGIN_CONTACT_HEADER
        self.window_list   = WindowList(nicks=['Alice', LOCAL_ID])
        self.contact_list  = ContactList(nicks=['Alice', LOCAL_ID])
        self.key_list      = KeyList(nicks=['Alice', LOCAL_ID])
        self.keyset        = self.key_list.get_keyset(nick_to_pub_key("Alice"))
        self.args          = self.onion_pub_key, self.origin, self.window_list, self.contact_list, self.key_list

    def test_decryption_with_zero_rx_key_raises_fr(self):
        # Setup
        keyset       = self.key_list.get_keyset(nick_to_pub_key("Alice"))
        keyset.rx_mk = bytes(SYMMETRIC_KEY_LENGTH)
        packet       = assembly_packet_creator(MESSAGE, payload="Test message", encrypt_packet=True)[0]

        # Test
        self.assert_fr("Warning! Loaded zero-key for packet decryption.",
                       decrypt_assembly_packet, packet, *self.args)

    def test_invalid_harac_ct_raises_fr(self):
        packet = assembly_packet_creator(MESSAGE, payload="Test message", encrypt_packet=True, tamper_harac=True)[0]
        self.assert_fr("Warning! Received packet from Alice had an invalid hash ratchet MAC.",
                       decrypt_assembly_packet, packet, *self.args)

    def test_decryption_with_zero_rx_hek_raises_fr(self):
        # Setup
        keyset       = self.key_list.get_keyset(nick_to_pub_key("Alice"))
        keyset.rx_hk = bytes(SYMMETRIC_KEY_LENGTH)
        packet       = assembly_packet_creator(MESSAGE, payload="Test message", encrypt_packet=True)[0]

        # Test
        self.assert_fr("Warning! Loaded zero-key for packet decryption.", decrypt_assembly_packet, packet, *self.args)

    def test_expired_harac_raises_fr(self):
        # Setup
        self.keyset.rx_harac = 1

        # Test
        packet = assembly_packet_creator(MESSAGE, payload="Test message", encrypt_packet=True, harac=0)[0]
        self.assert_fr("Warning! Received packet from Alice had an expired hash ratchet counter.",
                       decrypt_assembly_packet, packet, *self.args)

    @mock.patch('builtins.input', return_value='No')
    def test_harac_dos_can_be_interrupted(self, _):
        packet = assembly_packet_creator(MESSAGE, payload="Test message", encrypt_packet=True, harac=100_001)[0]
        self.assert_fr("Dropped packet from Alice.",
                       decrypt_assembly_packet, packet, *self.args)

    def test_invalid_packet_ct_raises_fr(self):
        packet = assembly_packet_creator(MESSAGE, payload="Test message", encrypt_packet=True, tamper_message=True)[0]
        self.assert_fr("Warning! Received packet from Alice had an invalid MAC.",
                       decrypt_assembly_packet, packet, *self.args)

    def test_successful_packet_decryption(self):
        packet = assembly_packet_creator(MESSAGE, payload="Test message", encrypt_packet=True)[0]
        self.assertEqual(decrypt_assembly_packet(packet, *self.args),
                         assembly_packet_creator(MESSAGE, payload="Test message")[0])

    def test_successful_packet_decryption_with_offset(self):
        packet = assembly_packet_creator(MESSAGE, payload="Test message", encrypt_packet=True, message_number=3)[0]
        self.assertEqual(decrypt_assembly_packet(packet, *self.args),
                         assembly_packet_creator(MESSAGE, payload="Test message", message_number=3)[0])

    def test_successful_command_decryption(self):
        packet = assembly_packet_creator(COMMAND, payload=b"command_data", encrypt_packet=True)[0]
        self.assertEqual(decrypt_assembly_packet(packet, *self.args),
                         assembly_packet_creator(COMMAND, payload=b"command_data")[0])


class TestPacket(TFCTestCase):

    def setUp(self):
        self.short_msg = "Lorem ipsum dolor sit amet, consectetur adipiscing elit"
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

        self.unit_test_dir  = cd_unit_test()
        self.ts             = datetime.now()
        self.contact        = create_contact('Alice')
        self.settings       = Settings(log_file_masking=True)
        self.onion_pub_key  = nick_to_pub_key('Alice')
        self.window_list    = WindowList()
        self.whisper_header = b'\x00'

        compressed        = zlib.compress(b'file_data', level=COMPRESSION_LEVEL)
        file_key          = os.urandom(SYMMETRIC_KEY_LENGTH)
        encrypted         = encrypt_and_sign(compressed, key=file_key)
        encrypted        += file_key
        self.short_f_data = (int_to_bytes(1) + int_to_bytes(2) + b'testfile.txt' + US_BYTE + encrypted)

    def tearDown(self):
        cleanup(self.unit_test_dir)

    def test_invalid_assembly_packet_header_raises_fr(self):
        # Setup
        packet   = Packet(self.onion_pub_key, ORIGIN_CONTACT_HEADER, MESSAGE, self.contact, self.settings)
        a_packet = assembly_packet_creator(MESSAGE, payload=self.short_msg, s_header_override=b'i')[0]

        # Test
        self.assert_fr("Error: Received packet had an invalid assembly packet header.", packet.add_packet, a_packet)
        self.assertEqual(packet.log_masking_ctr, 1)

    def test_missing_start_packet_raises_fr(self):
        # Setup
        packet = Packet(self.onion_pub_key, ORIGIN_USER_HEADER, MESSAGE, self.contact, self.settings)

        # Test
        for header in [M_A_HEADER, M_E_HEADER]:
            self.assert_fr("Missing start packet.", packet.add_packet, header + bytes(PADDING_LENGTH))
        self.assertEqual(packet.log_masking_ctr, 2)

    def test_short_message(self):
        # Setup
        packet      = Packet(self.onion_pub_key, ORIGIN_USER_HEADER, MESSAGE, self.contact, self.settings)
        packet_list = assembly_packet_creator(MESSAGE, self.short_msg)

        for p in packet_list:
            packet.add_packet(p, packet_ct=b'test_ct')

        # Test
        self.assertEqual(packet.assemble_message_packet(),
                         self.whisper_header + PRIVATE_MESSAGE_HEADER + self.short_msg.encode())
        self.assertEqual(packet.log_ct_list, [b'test_ct'])

    def test_compression_error_raises_fr(self):
        # Setup
        packet      = Packet(self.onion_pub_key, ORIGIN_USER_HEADER, MESSAGE, self.contact, self.settings)
        packet_list = assembly_packet_creator(MESSAGE, self.short_msg, tamper_compression=True)

        for p in packet_list:
            packet.add_packet(p)

        # Test
        self.assert_fr("Error: Decompression of message failed.", packet.assemble_message_packet)

    def test_long_message(self):
        # Setup
        packet      = Packet(self.onion_pub_key, ORIGIN_USER_HEADER, MESSAGE, self.contact, self.settings)
        packet_list = assembly_packet_creator(MESSAGE, self.msg)

        for p in packet_list:
            packet.add_packet(p, packet_ct=b'test_ct')

        # Test
        message = packet.assemble_message_packet()
        self.assertEqual(message,  self.whisper_header + PRIVATE_MESSAGE_HEADER + self.msg.encode())
        self.assertEqual(packet.log_ct_list, 3 * [b'test_ct'])

    def test_decryption_error_raises_fr(self):
        # Setup
        packet      = Packet(self.onion_pub_key, ORIGIN_USER_HEADER, MESSAGE, self.contact, self.settings)
        packet_list = assembly_packet_creator(MESSAGE, self.msg, tamper_ciphertext=True)

        for p in packet_list:
            packet.add_packet(p)

        # Test
        self.assert_fr("Error: Decryption of message failed.", packet.assemble_message_packet)

    def test_short_file(self):
        # Setup
        packets = split_to_assembly_packets(self.short_f_data, FILE)

        # Test
        self.assertFalse(os.path.isfile(f'{DIR_RECV_FILES}Alice/testfile.txt'))
        self.assertFalse(os.path.isfile(f'{DIR_RECV_FILES}Alice/testfile.txt.1'))

        packet             = Packet(self.onion_pub_key, ORIGIN_CONTACT_HEADER, FILE, self.contact, self.settings)
        packet.long_active = True

        for p in packets:
            packet.add_packet(p)
        self.assertIsNone(packet.assemble_and_store_file(self.ts, self.onion_pub_key, self.window_list))
        self.assertTrue(os.path.isfile(f'{DIR_RECV_FILES}Alice/testfile.txt'))

        for p in packets:
            packet.add_packet(p)
        self.assertIsNone(packet.assemble_and_store_file(self.ts, self.onion_pub_key, self.window_list))
        self.assertTrue(os.path.isfile(f'{DIR_RECV_FILES}Alice/testfile.txt.1'))

    def test_short_file_from_user_raises_fr(self):
        # Setup
        packet  = Packet(self.onion_pub_key, ORIGIN_USER_HEADER, FILE, self.contact, self.settings)
        packets = split_to_assembly_packets(self.short_f_data, FILE)

        # Test
        for p in packets:
            self.assert_fr("Ignored file from the user.", packet.add_packet, p)
        self.assertEqual(packet.log_masking_ctr, 1)

    def test_unauthorized_file_from_contact_raises_fr(self):
        # Setup
        self.contact.file_reception = False

        packet  = Packet(self.onion_pub_key, ORIGIN_CONTACT_HEADER, FILE, self.contact, self.settings)
        packets = split_to_assembly_packets(self.short_f_data, FILE)

        # Test
        for p in packets:
            self.assert_fr("Alert! File transmission from Alice but reception is disabled.", packet.add_packet, p)
        self.assertEqual(packet.log_masking_ctr, 1)

    def test_long_file(self):
        # Setup
        packet             = Packet(self.onion_pub_key, ORIGIN_CONTACT_HEADER, FILE, self.contact, self.settings)
        packet.long_active = True
        packet_list        = assembly_packet_creator(FILE)

        for p in packet_list:
            packet.add_packet(p)

        # Test
        self.assertIsNone(packet.assemble_and_store_file(self.ts, self.onion_pub_key, self.window_list))
        self.assertEqual(os.path.getsize(f'{DIR_RECV_FILES}Alice/test_file.txt'), 10000)

    def test_disabled_file_reception_raises_fr_with_append_packet(self):
        # Setup
        packet             = Packet(self.onion_pub_key, ORIGIN_CONTACT_HEADER, FILE, self.contact, self.settings)
        packet.long_active = True
        packet_list        = assembly_packet_creator(FILE)

        for p in packet_list[:2]:
            self.assertIsNone(packet.add_packet(p))

        packet.contact.file_reception = False

        # Test
        self.assert_fr("Alert! File reception disabled mid-transfer.", packet.add_packet, packet_list[2])

        for p in packet_list[3:]:
            self.assert_fr("Missing start packet.", packet.add_packet, p)

        self.assertEqual(packet.log_masking_ctr, len(packet_list))

    def test_disabled_file_reception_raises_fr_with_end_packet(self):
        # Setup
        packet             = Packet(self.onion_pub_key, ORIGIN_CONTACT_HEADER, FILE, self.contact, self.settings)
        packet.long_active = True
        packet_list        = assembly_packet_creator(FILE)

        for p in packet_list[:-1]:
            self.assertIsNone(packet.add_packet(p))

        packet.contact.file_reception = False

        # Test
        for p in packet_list[-1:]:
            self.assert_fr("Alert! File reception disabled mid-transfer.", packet.add_packet, p)
        self.assertEqual(packet.log_masking_ctr, len(packet_list))

    def test_long_file_from_user_raises_fr(self):
        # Setup
        packet      = Packet(self.onion_pub_key, ORIGIN_USER_HEADER, FILE, self.contact, self.settings)
        packet_list = assembly_packet_creator(FILE)

        # Test
        self.assert_fr("Ignored file from the user.", packet.add_packet, packet_list[0])
        self.assertEqual(packet.log_masking_ctr, 1)

    def test_unauthorized_long_file_raises_fr(self):
        # Setup
        self.contact.file_reception = False

        packet      = Packet(self.onion_pub_key, ORIGIN_CONTACT_HEADER, FILE, self.contact, self.settings)
        packet_list = assembly_packet_creator(FILE)

        # Test
        self.assert_fr("Alert! File transmission from Alice but reception is disabled.",
                       packet.add_packet, packet_list[0])
        self.assertEqual(packet.log_masking_ctr, 1)

    def test_invalid_long_file_header_raises_fr(self):
        # Setup
        packet      = Packet(self.onion_pub_key, ORIGIN_CONTACT_HEADER, FILE, self.contact, self.settings)
        packet_list = assembly_packet_creator(FILE, file_name=UNDECODABLE_UNICODE)

        # Test
        self.assert_fr("Error: Received file packet had an invalid header.", packet.add_packet, packet_list[0])
        self.assertEqual(packet.log_masking_ctr, 1)

    def test_contact_canceled_file(self):
        # Setup
        packet      = Packet(self.onion_pub_key, ORIGIN_CONTACT_HEADER, FILE, self.contact, self.settings)
        packet_list = assembly_packet_creator(FILE)[:20]
        packet_list.append(byte_padding(F_C_HEADER))  # Add cancel packet

        for p in packet_list:
            packet.add_packet(p)

        # Test
        self.assertEqual(len(packet.assembly_pt_list), 0)  # Cancel packet empties packet list
        self.assertFalse(packet.long_active)
        self.assertFalse(packet.is_complete)
        self.assertEqual(packet.log_masking_ctr, len(packet_list))

    def test_noise_packet_interrupts_file(self):
        # Setup
        packet      = Packet(self.onion_pub_key, ORIGIN_CONTACT_HEADER, FILE, self.contact, self.settings)
        packet_list = assembly_packet_creator(FILE)[:20]
        packet_list.append(byte_padding(P_N_HEADER))  # Add noise packet

        for p in packet_list:
            packet.add_packet(p)

        # Test
        self.assertEqual(len(packet.assembly_pt_list), 0)  # Noise packet empties packet list
        self.assertFalse(packet.long_active)
        self.assertFalse(packet.is_complete)
        self.assertEqual(packet.log_masking_ctr, len(packet_list))

    def test_short_command(self):
        # Setup
        packet  = Packet(LOCAL_ID, ORIGIN_CONTACT_HEADER, COMMAND, self.contact, self.settings)
        packets = assembly_packet_creator(COMMAND, b'test_command')

        for p in packets:
            packet.add_packet(p)

        # Test
        self.assertEqual(packet.assemble_command_packet(), b'test_command')
        self.assertEqual(packet.log_masking_ctr, 0)

    def test_long_command(self):
        # Setup
        packet  = Packet(LOCAL_ID, ORIGIN_CONTACT_HEADER, COMMAND, self.contact, self.settings)
        command = 500*b'test_command'
        packets = assembly_packet_creator(COMMAND, command)

        for p in packets:
            packet.add_packet(p)

        # Test
        self.assertEqual(packet.assemble_command_packet(), command)
        self.assertEqual(packet.log_masking_ctr, 0)

    def test_long_command_hash_mismatch_raises_fr(self):
        # Setup
        packet      = Packet(LOCAL_ID, ORIGIN_CONTACT_HEADER, COMMAND, self.contact, self.settings)
        packet_list = assembly_packet_creator(COMMAND, os.urandom(500), tamper_cmd_hash=True)

        for p in packet_list:
            packet.add_packet(p)

        # Test
        self.assert_fr("Error: Received an invalid command.", packet.assemble_command_packet)
        self.assertEqual(packet.log_masking_ctr, 0)

    def test_long_command_compression_error_raises_fr(self):
        # Setup
        packet      = Packet(LOCAL_ID, ORIGIN_CONTACT_HEADER, COMMAND, self.contact, self.settings)
        packet_list = assembly_packet_creator(COMMAND, os.urandom(500), tamper_compression=True)

        for p in packet_list:
            packet.add_packet(p)

        # Test
        self.assert_fr("Error: Decompression of command failed.", packet.assemble_command_packet)
        self.assertEqual(packet.log_masking_ctr, 0)


class TestPacketList(unittest.TestCase):

    def setUp(self):
        self.contact_list  = ContactList(nicks=['Alice', 'Bob'])
        self.settings      = Settings()
        self.onion_pub_key = nick_to_pub_key('Alice')
        packet             = Packet(self.onion_pub_key, ORIGIN_CONTACT_HEADER, MESSAGE,
                                    self.contact_list.get_contact_by_address_or_nick('Alice'), self.settings)

        self.packet_list         = PacketList(self.settings, self.contact_list)
        self.packet_list.packets = [packet]

    def test_packet_list_iterates_over_contact_objects(self):
        for p in self.packet_list:
            self.assertIsInstance(p, Packet)

    def test_len_returns_number_of_contacts(self):
        self.assertEqual(len(self.packet_list), 1)

    def test_has_packet(self):
        self.assertTrue(self.packet_list.has_packet(self.onion_pub_key, ORIGIN_CONTACT_HEADER, MESSAGE))
        self.assertFalse(self.packet_list.has_packet(self.onion_pub_key, ORIGIN_USER_HEADER, MESSAGE))

    def test_get_packet(self):
        packet = self.packet_list.get_packet(self.onion_pub_key, ORIGIN_CONTACT_HEADER, MESSAGE)
        self.assertEqual(packet.onion_pub_key, self.onion_pub_key)
        self.assertEqual(packet.origin, ORIGIN_CONTACT_HEADER)
        self.assertEqual(packet.type, MESSAGE)

        packet = self.packet_list.get_packet(self.onion_pub_key, ORIGIN_CONTACT_HEADER, MESSAGE)
        self.assertEqual(packet.onion_pub_key, self.onion_pub_key)
        self.assertEqual(packet.origin, ORIGIN_CONTACT_HEADER)
        self.assertEqual(packet.type, MESSAGE)


if __name__ == '__main__':
    unittest.main(exit=False)
