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
import threading
import time
import unittest

from src.common.crypto  import X448, encrypt_and_sign
from src.common.misc    import ensure_dir
from src.common.statics import (BLAKE2_DIGEST_LENGTH, CONTACT_REQ_QUEUE, URL_TOKEN_QUEUE, RX_BUF_KEY_QUEUE,
                                RELAY_BUFFER_OUTGOING_M_DIR, RELAY_BUFFER_OUTGOING_MESSAGE,
                                RELAY_BUFFER_OUTGOING_F_DIR, RELAY_BUFFER_OUTGOING_FILE, SYMMETRIC_KEY_LENGTH)

from src.relay.server import flask_server

from tests.utils import cd_unit_test, cleanup, gen_queue_dict, nick_to_onion_address, nick_to_pub_key, tear_queues


class TestFlaskServer(unittest.TestCase):

    def setUp(self) -> None:
        self.test_dir = cd_unit_test()

    def tearDown(self) -> None:
        cleanup(self.test_dir)

    @staticmethod
    def store_test_packet(plaintext: bytes, file_dir: str, file_name: str, key: bytes):
        with open(f"{file_dir}/{file_name}", 'wb+') as f:
            f.write(encrypt_and_sign(plaintext, key))

    def test_flask_server(self) -> None:
        # Setup
        queues                = gen_queue_dict()
        url_token_private_key = X448.generate_private_key()
        url_token_public_key  = X448.derive_public_key(url_token_private_key).hex()
        url_token             = 'a450987345098723459870234509827340598273405983274234098723490285'
        url_token_old         = 'a450987345098723459870234509827340598273405983274234098723490286'
        url_token_invalid     = 'ääääääääääääääääääääääääääääääääääääääääääääääääääääääääääääääää'
        onion_pub_key         = nick_to_pub_key('Alice')
        onion_address         = nick_to_onion_address('Alice')
        packet1               = b"packet1"
        packet2               = b"packet2"
        packet3               = b"packet3"
        test_key              = SYMMETRIC_KEY_LENGTH * b'a'

        sub_dir = hashlib.blake2b(onion_pub_key, key=test_key, digest_size=BLAKE2_DIGEST_LENGTH).hexdigest()

        buf_dir_m = f"{RELAY_BUFFER_OUTGOING_M_DIR}/{sub_dir}"
        buf_dir_f = f"{RELAY_BUFFER_OUTGOING_F_DIR}/{sub_dir}"

        ensure_dir(f"{buf_dir_m}/")
        ensure_dir(f"{buf_dir_f}/")

        packet_list = [packet1, packet2]

        for i, packet in enumerate(packet_list):
            TestFlaskServer.store_test_packet(packet,
                                              buf_dir_m,
                                              RELAY_BUFFER_OUTGOING_MESSAGE + f".{i}",
                                              test_key)

        TestFlaskServer.store_test_packet(packet3,
                                          buf_dir_f,
                                          RELAY_BUFFER_OUTGOING_FILE + '.0',
                                          test_key)

        def queue_delayer() -> None:
            """Place buffer key to queue after a delay."""
            time.sleep(0.1)
            queues[RX_BUF_KEY_QUEUE].put(test_key)

        threading.Thread(target=queue_delayer).start()

        # Test
        app = flask_server(queues, url_token_public_key, unit_test=True)

        # Test valid URL token returns all queued messages
        queues[URL_TOKEN_QUEUE].put((onion_pub_key, url_token_old))
        queues[URL_TOKEN_QUEUE].put((onion_pub_key, url_token))

        with app.test_client() as c:
            # Test root domain returns public key of server.
            resp = c.get('/')
            self.assertEqual(resp.data, url_token_public_key.encode())

            resp = c.get(f'/contact_request/{onion_address}')
            self.assertEqual(b'OK', resp.data)
            self.assertEqual(queues[CONTACT_REQ_QUEUE].qsize(), 1)

            # Test invalid URL token returns empty response
            resp = c.get(f'/{url_token_invalid}/messages/')
            self.assertEqual(b'', resp.data)
            resp = c.get(f'/{url_token_invalid}/files/')
            self.assertEqual(b'', resp.data)

        with app.test_client() as c:
            resp = c.get(f'/{url_token}/messages/')
            self.assertEqual(b'packet1\npacket2', resp.data)

        with app.test_client() as c:
            resp = c.get(f'/{url_token}/files/')
            self.assertEqual(b'packet3', resp.data)

        # Test valid URL token returns nothing as buffers are empty
        with app.test_client() as c:
            resp = c.get(f'/{url_token}/messages/')
            self.assertEqual(b'', resp.data)

        with app.test_client() as c:
            resp = c.get(f'/{url_token}/files/')
            self.assertEqual(b'', resp.data)

        # Teardown
        tear_queues(queues)


if __name__ == '__main__':
    unittest.main(exit=False)
