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

import hashlib
import os
import threading
import time
import unittest

from datetime import datetime
from unittest import mock

from src.common.encoding     import int_to_bytes
from src.common.reed_solomon import RSCodec
from src.common.statics      import (BLAKE2_DIGEST_LENGTH, COMMAND_DATAGRAM_HEADER, DST_COMMAND_QUEUE,
                                     DST_MESSAGE_QUEUE, EXIT, FILE_DATAGRAM_HEADER, GATEWAY_QUEUE, GROUP_ID_LENGTH,
                                     GROUP_MSG_EXIT_GROUP_HEADER, GROUP_MSG_INVITE_HEADER, GROUP_MSG_JOIN_HEADER,
                                     GROUP_MSG_MEMBER_ADD_HEADER, GROUP_MSG_MEMBER_REM_HEADER,
                                     LOCAL_KEY_DATAGRAM_HEADER, MESSAGE_DATAGRAM_HEADER, PUBLIC_KEY_DATAGRAM_HEADER,
                                     RELAY_BUFFER_OUTGOING_F_DIR, RELAY_BUFFER_OUTGOING_FILE,
                                     RELAY_BUFFER_OUTGOING_M_DIR, RELAY_BUFFER_OUTGOING_MESSAGE, SRC_TO_RELAY_QUEUE,
                                     SYMMETRIC_KEY_LENGTH, TFC_PUBLIC_KEY_LENGTH, TX_BUF_KEY_QUEUE,
                                     UNENCRYPTED_DATAGRAM_HEADER, UNIT_TEST_QUEUE)

from src.relay.tcb import dst_outgoing, src_incoming, buffer_to_flask

from tests.mock_classes import Gateway, nick_to_pub_key, Settings
from tests.utils        import cd_unit_test, cleanup, gen_queue_dict, tear_queues, TFCTestCase


class TestSRCIncoming(unittest.TestCase):

    def setUp(self) -> None:
        """Pre-test actions."""
        self.settings      = Settings()
        self.unit_test_dir = cd_unit_test()
        self.gateway       = Gateway()
        self.rs            = RSCodec(2 * self.gateway.settings.serial_error_correction)
        self.ts            = datetime.now()
        self.queues        = gen_queue_dict()
        self.args          = self.queues, self.gateway
        self.queues[TX_BUF_KEY_QUEUE].put(SYMMETRIC_KEY_LENGTH*b'a')

    def tearDown(self) -> None:
        """Post-test actions."""
        tear_queues(self.queues)
        cleanup(self.unit_test_dir)

    def create_packet(self, packet: bytes):
        """Create Reed-Solomon encoded packet"""
        return self.rs.encode(packet)

    def test_unencrypted_datagram(self) -> None:
        # Setup
        packet = self.create_packet(UNENCRYPTED_DATAGRAM_HEADER + b'test')
        self.queues[GATEWAY_QUEUE].put((self.ts, 640 * b'a'))
        self.queues[GATEWAY_QUEUE].put((self.ts, packet))

        # Test
        self.assertIsNone(src_incoming(*self.args, unit_test=True))
        self.assertEqual(self.queues[SRC_TO_RELAY_QUEUE].qsize(), 1)

    def test_local_key_datagram(self) -> None:
        # Setup
        packet = self.create_packet(LOCAL_KEY_DATAGRAM_HEADER + b'test')

        def queue_delayer() -> None:
            """Place packet into queue after delay."""
            time.sleep(0.01)
            self.queues[GATEWAY_QUEUE].put((self.ts, packet))

        threading.Thread(target=queue_delayer).start()

        # Test
        self.assertIsNone(src_incoming(*self.args, unit_test=True))
        self.assertEqual(self.queues[DST_COMMAND_QUEUE].qsize(), 1)

    def test_command_datagram(self) -> None:
        # Setup
        packet = self.create_packet(COMMAND_DATAGRAM_HEADER + b'test')
        self.queues[GATEWAY_QUEUE].put((self.ts, packet))

        # Test
        self.assertIsNone(src_incoming(*self.args, unit_test=True))
        self.assertEqual(self.queues[DST_COMMAND_QUEUE].qsize(), 1)

    def test_message_datagram(self) -> None:
        # Setup
        packet = self.create_packet(MESSAGE_DATAGRAM_HEADER + 344 * b'a' + nick_to_pub_key('bob'))
        self.queues[GATEWAY_QUEUE].put((self.ts, packet))
        self.queues[TX_BUF_KEY_QUEUE].put(SYMMETRIC_KEY_LENGTH*b'a')

        # Test
        self.assertIsNone(src_incoming(*self.args, unit_test=True))
        self.assertEqual(self.queues[DST_MESSAGE_QUEUE].qsize(), 1)

    def test_public_key_datagram(self) -> None:
        # Setup
        packet = self.create_packet(PUBLIC_KEY_DATAGRAM_HEADER + nick_to_pub_key('bob') + TFC_PUBLIC_KEY_LENGTH * b'a')
        self.queues[GATEWAY_QUEUE].put((self.ts, packet))

        # Test
        self.assertIsNone(src_incoming(*self.args, unit_test=True))

    def test_file_datagram(self) -> None:
        # Setup
        packet = self.create_packet(FILE_DATAGRAM_HEADER
                                    + int_to_bytes(2)
                                    + nick_to_pub_key('Alice')
                                    + nick_to_pub_key('Bob')
                                    + 200 * b'a')
        self.queues[GATEWAY_QUEUE].put((self.ts, packet))

        # Test
        self.assertIsNone(src_incoming(*self.args, unit_test=True))
        self.assertEqual(self.queues[DST_MESSAGE_QUEUE].qsize(), 0)

    def test_group_invitation_datagram(self) -> None:
        # Setup
        packet = self.create_packet(GROUP_MSG_INVITE_HEADER
                                    + bytes(GROUP_ID_LENGTH)
                                    + nick_to_pub_key('Alice')
                                    + nick_to_pub_key('Bob'))
        self.queues[GATEWAY_QUEUE].put((self.ts, packet))

        # Test
        self.assertIsNone(src_incoming(*self.args, unit_test=True))
        self.assertEqual(self.queues[DST_MESSAGE_QUEUE].qsize(), 0)

    def test_group_join_datagram(self) -> None:
        # Setup
        packet = self.create_packet(GROUP_MSG_JOIN_HEADER
                                    + bytes(GROUP_ID_LENGTH)
                                    + nick_to_pub_key('Alice')
                                    + nick_to_pub_key('Bob'))
        self.queues[GATEWAY_QUEUE].put((self.ts, packet))

        # Test
        self.assertIsNone(src_incoming(*self.args, unit_test=True))
        self.assertEqual(self.queues[DST_MESSAGE_QUEUE].qsize(), 0)

    def test_group_add_datagram(self) -> None:
        # Setup
        packet = self.create_packet(GROUP_MSG_MEMBER_ADD_HEADER
                                    + bytes(GROUP_ID_LENGTH)
                                    + int_to_bytes(1)
                                    + nick_to_pub_key('Alice')
                                    + nick_to_pub_key('Bob'))
        self.queues[GATEWAY_QUEUE].put((self.ts, packet))

        # Test
        self.assertIsNone(src_incoming(*self.args, unit_test=True))
        self.assertEqual(self.queues[DST_MESSAGE_QUEUE].qsize(), 0)

    def test_group_remove_datagram(self) -> None:
        # Setup
        packet = self.create_packet(GROUP_MSG_MEMBER_REM_HEADER
                                    + bytes(GROUP_ID_LENGTH)
                                    + int_to_bytes(2)
                                    + nick_to_pub_key('Alice')
                                    + nick_to_pub_key('Bob'))
        self.queues[GATEWAY_QUEUE].put((self.ts, packet))

        # Test
        self.assertIsNone(src_incoming(*self.args, unit_test=True))
        self.assertEqual(self.queues[DST_MESSAGE_QUEUE].qsize(), 0)

    def test_group_exit_datagram(self) -> None:
        # Setup
        packet = self.create_packet(GROUP_MSG_EXIT_GROUP_HEADER
                                    + bytes(GROUP_ID_LENGTH)
                                    + nick_to_pub_key('Alice')
                                    + nick_to_pub_key('Bob'))
        self.queues[GATEWAY_QUEUE].put((self.ts, packet))

        # Test
        self.assertIsNone(src_incoming(*self.args, unit_test=True))
        self.assertEqual(self.queues[DST_MESSAGE_QUEUE].qsize(), 0)


class TestBufferToFlask(TFCTestCase):

    def setUp(self) -> None:
        self.unittest_dir = cd_unit_test()

    def tearDown(self) -> None:
        cleanup(self.unittest_dir)

    def test_missing_buf_key_raises_soft_error(self) -> None:
        # Setup
        packet        = 500 * b'a'
        onion_pub_key = nick_to_pub_key('Alice')
        ts            = datetime.now()
        header        = MESSAGE_DATAGRAM_HEADER
        buf_key       = None

        # Test
        self.assert_se("Error: No buffer key available for packet buffering.",
                       buffer_to_flask, packet, onion_pub_key, ts, header, buf_key, False)

    def test_buffering_of_unique_messages(self) -> None:
        # Setup
        packet        = 500 * b'a'
        onion_pub_key = nick_to_pub_key('Alice')
        ts            = datetime.now()
        header        = MESSAGE_DATAGRAM_HEADER
        buf_key       = SYMMETRIC_KEY_LENGTH * b'a'
        sub_dir       = hashlib.blake2b(onion_pub_key, key=buf_key, digest_size=BLAKE2_DIGEST_LENGTH).hexdigest()
        # Test
        self.assertIsNone(buffer_to_flask(packet, onion_pub_key, ts, header, buf_key, False))
        self.assertIsNone(buffer_to_flask(packet, onion_pub_key, ts, header, buf_key, False))

        self.assertTrue(os.path.isdir(f"{RELAY_BUFFER_OUTGOING_M_DIR}/{sub_dir}"))
        self.assertTrue(os.path.isfile(f"{RELAY_BUFFER_OUTGOING_M_DIR}/{sub_dir}/{RELAY_BUFFER_OUTGOING_MESSAGE}.0"))
        self.assertTrue(os.path.isfile(f"{RELAY_BUFFER_OUTGOING_M_DIR}/{sub_dir}/{RELAY_BUFFER_OUTGOING_MESSAGE}.1"))

    def test_buffering_of_unique_files(self) -> None:
        # Setup
        packet        = 500 * b'a'
        onion_pub_key = nick_to_pub_key('Alice')
        ts            = datetime.now()
        header        = MESSAGE_DATAGRAM_HEADER
        buf_key       = SYMMETRIC_KEY_LENGTH * b'a'
        sub_dir       = hashlib.blake2b(onion_pub_key, key=buf_key, digest_size=BLAKE2_DIGEST_LENGTH).hexdigest()
        # Test
        self.assertIsNone(buffer_to_flask(packet, onion_pub_key, ts, header, buf_key, True))
        self.assertIsNone(buffer_to_flask(packet, onion_pub_key, ts, header, buf_key, True))

        self.assertTrue(os.path.isdir(f"{RELAY_BUFFER_OUTGOING_F_DIR}/{sub_dir}"))
        self.assertTrue(os.path.isfile(f"{RELAY_BUFFER_OUTGOING_F_DIR}/{sub_dir}/{RELAY_BUFFER_OUTGOING_FILE}.0"))
        self.assertTrue(os.path.isfile(f"{RELAY_BUFFER_OUTGOING_F_DIR}/{sub_dir}/{RELAY_BUFFER_OUTGOING_FILE}.1"))


class TestDSTOutGoing(unittest.TestCase):

    def test_loop(self) -> None:
        # Setup
        packet  = b'test_packet'
        queues  = gen_queue_dict()
        gateway = Gateway()

        def queue_delayer() -> None:
            """Place packets into queue after delay."""
            time.sleep(0.015)
            queues[DST_COMMAND_QUEUE].put(packet)
            time.sleep(0.015)
            queues[DST_MESSAGE_QUEUE].put(packet)
            time.sleep(0.015)
            queues[UNIT_TEST_QUEUE].put(EXIT)

        threading.Thread(target=queue_delayer).start()

        # Test
        side_effects = [EOFError, KeyboardInterrupt, None] + [None] * 100_000
        with unittest.mock.patch('time.sleep', side_effect=side_effects):
            self.assertIsNone(dst_outgoing(queues, gateway, unit_test=True))
        self.assertEqual(packet, gateway.packets[0])

        # Teardown
        tear_queues(queues)


if __name__ == '__main__':
    unittest.main(exit=False)
