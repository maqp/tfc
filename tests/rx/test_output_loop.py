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
import datetime
import shutil
import threading
import time
import unittest
import zlib

from multiprocessing import Queue

from src.common.crypto   import encrypt_and_sign, hash_chain
from src.common.encoding import b58encode, int_to_bytes, str_to_bytes
from src.common.statics  import *

from src.tx.packet import split_to_assembly_packets

from src.rx.output_loop import output_loop

from tests.mock_classes import ContactList, GroupList, KeyList, MasterKey, Settings
from tests.utils        import ignored


class TestOutputLoop(unittest.TestCase):

    def setUp(self):
        self.o_input = builtins.input

    def tearDown(self):
        builtins.input = self.o_input

        with ignored(FileNotFoundError):
            shutil.rmtree(DIR_IMPORTED)

    def test_loop(self):
        # Setup
        queues = {LOCAL_KEY_PACKET_HEADER:  Queue(),
                  PUBLIC_KEY_PACKET_HEADER: Queue(),
                  MESSAGE_PACKET_HEADER:    Queue(),
                  COMMAND_PACKET_HEADER:    Queue(),
                  EXIT_QUEUE:               Queue(),
                  IMPORTED_FILE_HEADER:     Queue(),
                  GATEWAY_QUEUE:            Queue(),
                  UNITTEST_QUEUE:           Queue()}

        local_key = KEY_LENGTH * b'a'
        local_hek = KEY_LENGTH * b'a'
        kek       = KEY_LENGTH * b'a'
        fdk       = KEY_LENGTH * b'a'
        tx_key    = KEY_LENGTH * b'a'
        tx_hek    = KEY_LENGTH * b'a'
        conf_code = bytes(1)

        input_list     = [b58encode(kek),
                          conf_code.hex(),
                          b58encode(fdk, file_key=True)]
        gen            = iter(input_list)
        builtins.input = lambda _: next(gen)

        def queue_packet(key, hek, tx_harac, packet, rx_account=None):
            if rx_account is None:
                header  = COMMAND_PACKET_HEADER
                trailer = b''
                queue   = queues[COMMAND_PACKET_HEADER]
                packet  = split_to_assembly_packets(packet, COMMAND)[0]

            else:
                header  = MESSAGE_PACKET_HEADER
                trailer = ORIGIN_CONTACT_HEADER + rx_account
                queue   = queues[MESSAGE_PACKET_HEADER]
                packet  = split_to_assembly_packets(packet, MESSAGE)[0]

            encrypted_harac   = encrypt_and_sign(int_to_bytes(tx_harac), hek)
            encrypted_message = encrypt_and_sign(packet,                 key)
            encrypted_packet  = header + encrypted_harac + encrypted_message + trailer
            queue.put((datetime.datetime.now(), encrypted_packet))
            time.sleep(0.1)

        def queue_delayer():
            time.sleep(0.1)

            # Queue local key packet
            local_key_packet = LOCAL_KEY_PACKET_HEADER + encrypt_and_sign(local_key + local_hek + conf_code, key=kek)
            queues[LOCAL_KEY_PACKET_HEADER].put((datetime.datetime.now(), local_key_packet))
            time.sleep(0.1)

            # Queue screen clearing command
            queue_packet(tx_key, tx_hek, INITIAL_HARAC, CLEAR_SCREEN_HEADER)

            # Queue message that goes to buffer
            queue_packet(tx_key, tx_hek, INITIAL_HARAC, PRIVATE_MESSAGE_HEADER + b'Hi Bob', b'bob@jabber.org')

            # Queue public key for Bob
            public_key_packet = PUBLIC_KEY_PACKET_HEADER + KEY_LENGTH * b'a' + ORIGIN_CONTACT_HEADER + b'bob@jabber.org'
            queues[PUBLIC_KEY_PACKET_HEADER].put((datetime.datetime.now(), public_key_packet))
            time.sleep(0.1)

            # Queue X25519 keyset for Bob
            command = KEY_EX_X25519_HEADER + 4 * (KEY_LENGTH * b'a') + b'bob@jabber.org' + US_BYTE + b'Bob'
            queue_packet(hash_chain(tx_key), tx_hek, INITIAL_HARAC+1, command)

            # Queue window selection packet
            command = WINDOW_SELECT_HEADER + b'bob@jabber.org'
            queue_packet(hash_chain(hash_chain(tx_key)), tx_hek, INITIAL_HARAC+2, command)

            # Queue message that is displayed directly
            packet = b'Hi again, Bob'
            queue_packet(tx_key, tx_hek, INITIAL_HARAC, packet, b'bob@jabber.org')

            # Queue file window selection command
            command = WINDOW_SELECT_HEADER + WIN_TYPE_FILE.encode()
            queue_packet(hash_chain(hash_chain(hash_chain(tx_key))), tx_hek, INITIAL_HARAC+3, command)

            # Queue imported file packet
            file_data  = str_to_bytes('testfile') + 500*b'a'
            compressed = zlib.compress(file_data, level=COMPRESSION_LEVEL)
            packet     = IMPORTED_FILE_HEADER + encrypt_and_sign(compressed, key=fdk)
            queues[IMPORTED_FILE_HEADER].put((datetime.datetime.now(), packet))
            time.sleep(0.1)

            # Queue exit message to break loop
            queues[UNITTEST_QUEUE].put(EXIT)
            time.sleep(0.1)

        threading.Thread(target=queue_delayer).start()

        # Test
        self.assertIsNone(output_loop(queues, Settings(), ContactList(), KeyList(),
                                      GroupList(), MasterKey(), stdin_fd=1, unittest=True))

        # Teardown
        for key_ in queues:
            while not queues[key_].empty():
                queues[key_].get()
            time.sleep(0.1)
            queues[key_].close()


if __name__ == '__main__':
    unittest.main(exit=False)
