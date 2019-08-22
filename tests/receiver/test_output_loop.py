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

import base64
import datetime
import threading
import time
import unittest

from typing        import Tuple
from unittest      import mock
from unittest.mock import MagicMock

from src.common.crypto   import blake2b, encrypt_and_sign
from src.common.encoding import b58encode, bool_to_bytes, int_to_bytes, str_to_bytes
from src.common.statics  import *

from src.transmitter.packet import split_to_assembly_packets

from src.receiver.output_loop import output_loop

from tests.mock_classes import ContactList, Gateway, GroupList, KeyList, MasterKey, nick_to_pub_key, Settings
from tests.utils        import gen_queue_dict, tear_queues


def rotate_key(key: bytes, harac: int) -> Tuple[bytes, int]:
    """Move to next key in hash ratchet."""
    return blake2b(key + int_to_bytes(harac), digest_size=SYMMETRIC_KEY_LENGTH), harac + 1


class TestOutputLoop(unittest.TestCase):

    def setUp(self):
        self.o_sleep = time.sleep
        time.sleep   = lambda _: None

    def tearDown(self):
        time.sleep = self.o_sleep

    @mock.patch('tkinter.Tk',     return_value=MagicMock())
    @mock.patch('os.system',      return_value=None)
    @mock.patch('builtins.input', side_effect=[b58encode(SYMMETRIC_KEY_LENGTH*b'a'),
                                               bytes(CONFIRM_CODE_LENGTH).hex(),
                                               b58encode(SYMMETRIC_KEY_LENGTH*b'a', public_key=True)])
    def test_loop(self, *_):
        # Setup
        queues     = gen_queue_dict()
        kek        = SYMMETRIC_KEY_LENGTH * b'a'
        conf_code  = bytes(1)
        tx_pub_key = nick_to_pub_key('Bob')
        o_sleep    = self.o_sleep
        test_delay = 0.1

        def queue_packet(mk, hk, tx_harac, packet, onion_pub_key=None):
            """Create encrypted datagram."""
            if onion_pub_key is None:
                header = b''
                queue  = queues[COMMAND_DATAGRAM_HEADER]
                packet = split_to_assembly_packets(packet, COMMAND)[0]
            else:
                header = onion_pub_key + ORIGIN_CONTACT_HEADER
                queue  = queues[MESSAGE_DATAGRAM_HEADER]
                packet = split_to_assembly_packets(packet, MESSAGE)[0]

            encrypted_harac   = encrypt_and_sign(int_to_bytes(tx_harac), hk)
            encrypted_message = encrypt_and_sign(packet,                 mk)
            encrypted_packet  = header + encrypted_harac + encrypted_message
            queue.put((datetime.datetime.now(), encrypted_packet))

        def queue_delayer():
            """Place datagrams into queue after delay."""
            o_sleep(test_delay)
            local_harac = INITIAL_HARAC
            tx_harac    = INITIAL_HARAC
            local_hek   = SYMMETRIC_KEY_LENGTH * b'a'
            file_key    = SYMMETRIC_KEY_LENGTH * b'b'
            local_key   = SYMMETRIC_KEY_LENGTH * b'a'
            tx_mk       = SYMMETRIC_KEY_LENGTH * b'a'
            tx_hk       = SYMMETRIC_KEY_LENGTH * b'a'

            # Queue local key packet
            local_key_packet = encrypt_and_sign(local_key + local_hek + conf_code, key=kek)
            queues[LOCAL_KEY_DATAGRAM_HEADER].put((datetime.datetime.now(), local_key_packet))
            o_sleep(test_delay)

            # Select file window
            command = WIN_SELECT + WIN_UID_FILE
            queue_packet(local_key, tx_hk, local_harac, command)
            local_key, local_harac = rotate_key(local_key, local_harac)
            o_sleep(test_delay)

            # Select local window
            command = WIN_SELECT + WIN_UID_LOCAL
            queue_packet(local_key, tx_hk, local_harac, command)
            local_key, local_harac = rotate_key(local_key, local_harac)
            o_sleep(test_delay)

            # A message that goes to buffer
            queue_packet(tx_mk, tx_hk, tx_harac, bool_to_bytes(False) + PRIVATE_MESSAGE_HEADER + b'Hi Bob', tx_pub_key)
            tx_mk, tx_harac = rotate_key(tx_mk, tx_harac)

            # ECDHE keyset for Bob
            command = KEY_EX_ECDHE + nick_to_pub_key("Bob") + (4 * SYMMETRIC_KEY_LENGTH * b'a') + str_to_bytes('Bob')
            queue_packet(local_key, tx_hk, local_harac, command)
            local_key, local_harac = rotate_key(local_key, local_harac)
            o_sleep(test_delay)

            # Message for Bob
            queue_packet(tx_mk, tx_hk, tx_harac, bool_to_bytes(False) + PRIVATE_MESSAGE_HEADER + b'Hi Bob', tx_pub_key)
            tx_mk, tx_harac = rotate_key(tx_mk, tx_harac)
            o_sleep(test_delay)

            # Enable file reception for Bob
            command = CH_FILE_RECV + ENABLE.upper() + US_BYTE
            queue_packet(local_key, tx_hk, local_harac, command)
            o_sleep(test_delay)

            # File packet from Bob
            ct     = encrypt_and_sign(b'test', file_key)
            f_hash = blake2b(ct)
            packet = nick_to_pub_key('Bob') + ORIGIN_CONTACT_HEADER + ct
            queues[FILE_DATAGRAM_HEADER].put((datetime.datetime.now(), packet))
            o_sleep(test_delay)

            # File key packet from Bob
            queue_packet(tx_mk, tx_hk, tx_harac, bool_to_bytes(False)
                         + FILE_KEY_HEADER + base64.b85encode(f_hash + file_key), tx_pub_key)
            o_sleep(test_delay)

            # Queue exit message to break the loop
            o_sleep(0.5)
            queues[UNIT_TEST_QUEUE].put(EXIT)
            o_sleep(test_delay)

        threading.Thread(target=queue_delayer).start()

        # Test
        self.assertIsNone(output_loop(queues, Gateway(), Settings(), ContactList(), KeyList(),
                                      GroupList(), MasterKey(), stdin_fd=1, unit_test=True))

        # Teardown
        tear_queues(queues)


if __name__ == '__main__':
    unittest.main(exit=False)
