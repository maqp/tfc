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

import threading
import time
import unittest

from datetime import datetime
from unittest import mock

from src.common.encoding     import int_to_bytes
from src.common.reed_solomon import RSCodec
from src.common.statics      import *

from src.relay.tcb import dst_outgoing, src_incoming

from tests.mock_classes import Gateway, nick_to_pub_key, Settings
from tests.utils        import cd_unit_test, cleanup, gen_queue_dict, tear_queues


class TestSRCIncoming(unittest.TestCase):

    def setUp(self):
        self.settings      = Settings()
        self.unit_test_dir = cd_unit_test()
        self.gateway       = Gateway()
        self.rs            = RSCodec(2 * self.gateway.settings.serial_error_correction)
        self.ts            = datetime.now()
        self.queues        = gen_queue_dict()
        self.args          = self.queues, self.gateway

    def tearDown(self):
        tear_queues(self.queues)
        cleanup(self.unit_test_dir)

    def create_packet(self, packet: bytes):
        """Create Reed-Solomon encoded packet"""
        return self.rs.encode(packet)

    def test_unencrypted_datagram(self):
        # Setup
        packet = self.create_packet(UNENCRYPTED_DATAGRAM_HEADER + b'test')
        self.queues[GATEWAY_QUEUE].put((self.ts, 640 * b'a'))
        self.queues[GATEWAY_QUEUE].put((self.ts, packet))

        # Test
        self.assertIsNone(src_incoming(*self.args, unit_test=True))
        self.assertEqual(self.queues[SRC_TO_RELAY_QUEUE].qsize(), 1)

    def test_local_key_datagram(self):
        # Setup
        packet = self.create_packet(LOCAL_KEY_DATAGRAM_HEADER + b'test')

        def queue_delayer():
            """Place packet into queue after delay."""
            time.sleep(0.01)
            self.queues[GATEWAY_QUEUE].put((self.ts, packet))

        threading.Thread(target=queue_delayer).start()

        # Test
        self.assertIsNone(src_incoming(*self.args, unit_test=True))
        self.assertEqual(self.queues[DST_COMMAND_QUEUE].qsize(), 1)

    def test_command_datagram(self):
        # Setup
        packet = self.create_packet(COMMAND_DATAGRAM_HEADER + b'test')
        self.queues[GATEWAY_QUEUE].put((self.ts, packet))

        # Test
        self.assertIsNone(src_incoming(*self.args, unit_test=True))
        self.assertEqual(self.queues[DST_COMMAND_QUEUE].qsize(), 1)

    def test_message_datagram(self):
        # Setup
        packet = self.create_packet(MESSAGE_DATAGRAM_HEADER + 344 * b'a' + nick_to_pub_key('bob'))
        self.queues[GATEWAY_QUEUE].put((self.ts, packet))

        # Test
        self.assertIsNone(src_incoming(*self.args, unit_test=True))
        self.assertEqual(self.queues[M_TO_FLASK_QUEUE].qsize(),  1)
        self.assertEqual(self.queues[DST_MESSAGE_QUEUE].qsize(), 1)

    def test_public_key_datagram(self):
        # Setup
        packet = self.create_packet(PUBLIC_KEY_DATAGRAM_HEADER + nick_to_pub_key('bob') + TFC_PUBLIC_KEY_LENGTH * b'a')
        self.queues[GATEWAY_QUEUE].put((self.ts, packet))

        # Test
        self.assertIsNone(src_incoming(*self.args, unit_test=True))
        self.assertEqual(self.queues[M_TO_FLASK_QUEUE].qsize(), 1)

    def test_file_datagram(self):
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
        self.assertEqual(self.queues[F_TO_FLASK_QUEUE].qsize(),  2)

    def test_group_invitation_datagram(self):
        # Setup
        packet = self.create_packet(GROUP_MSG_INVITE_HEADER
                                    + bytes(GROUP_ID_LENGTH)
                                    + nick_to_pub_key('Alice')
                                    + nick_to_pub_key('Bob'))
        self.queues[GATEWAY_QUEUE].put((self.ts, packet))

        # Test
        self.assertIsNone(src_incoming(*self.args, unit_test=True))
        self.assertEqual(self.queues[DST_MESSAGE_QUEUE].qsize(), 0)
        self.assertEqual(self.queues[M_TO_FLASK_QUEUE].qsize(),  2)

    def test_group_join_datagram(self):
        # Setup
        packet = self.create_packet(GROUP_MSG_JOIN_HEADER
                                    + bytes(GROUP_ID_LENGTH)
                                    + nick_to_pub_key('Alice')
                                    + nick_to_pub_key('Bob'))
        self.queues[GATEWAY_QUEUE].put((self.ts, packet))

        # Test
        self.assertIsNone(src_incoming(*self.args, unit_test=True))
        self.assertEqual(self.queues[DST_MESSAGE_QUEUE].qsize(), 0)
        self.assertEqual(self.queues[M_TO_FLASK_QUEUE].qsize(),  2)

    def test_group_add_datagram(self):
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
        self.assertEqual(self.queues[M_TO_FLASK_QUEUE].qsize(),  2)

    def test_group_remove_datagram(self):
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
        self.assertEqual(self.queues[M_TO_FLASK_QUEUE].qsize(),  2)

    def test_group_exit_datagram(self):
        # Setup
        packet = self.create_packet(GROUP_MSG_EXIT_GROUP_HEADER
                                    + bytes(GROUP_ID_LENGTH)
                                    + nick_to_pub_key('Alice')
                                    + nick_to_pub_key('Bob'))
        self.queues[GATEWAY_QUEUE].put((self.ts, packet))

        # Test
        self.assertIsNone(src_incoming(*self.args, unit_test=True))
        self.assertEqual(self.queues[DST_MESSAGE_QUEUE].qsize(), 0)
        self.assertEqual(self.queues[M_TO_FLASK_QUEUE].qsize(),  2)


class TestDSTOutGoing(unittest.TestCase):

    def test_loop(self):
        # Setup
        packet  = b'test_packet'
        queues  = gen_queue_dict()
        gateway = Gateway()

        def queue_delayer():
            """Place packets into queue after delay."""
            time.sleep(0.01)
            queues[DST_COMMAND_QUEUE].put(packet)
            queues[DST_MESSAGE_QUEUE].put(packet)
            time.sleep(0.01)
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
