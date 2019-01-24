#!/usr/bin/env python3.6
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

import unittest

from src.common.crypto  import X448
from src.common.statics import *

from src.relay.server import flask_server

from tests.utils import gen_queue_dict, nick_to_onion_address, nick_to_pub_key


class TestFlaskServer(unittest.TestCase):

    def test_flask_server(self):
        # Setup
        queues                = gen_queue_dict()
        url_token_private_key = X448.generate_private_key()
        url_token_public_key  = X448.derive_public_key(url_token_private_key).hex()
        url_token             = 'a450987345098723459870234509827340598273405983274234098723490285'
        url_token_old         = 'a450987345098723459870234509827340598273405983274234098723490286'
        url_token_invalid     = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
        onion_pub_key         = nick_to_pub_key('Alice')
        onion_address         = nick_to_onion_address('Alice')
        packet1               = "packet1"
        packet2               = "packet2"
        packet3               = b"packet3"

        # Test
        app = flask_server(queues, url_token_public_key, unittest=True)

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

        # Test valid URL token returns all queued messages
        queues[URL_TOKEN_QUEUE].put((onion_pub_key, url_token_old))
        queues[URL_TOKEN_QUEUE].put((onion_pub_key, url_token))
        queues[M_TO_FLASK_QUEUE].put((packet1, onion_pub_key))
        queues[M_TO_FLASK_QUEUE].put((packet2, onion_pub_key))
        queues[F_TO_FLASK_QUEUE].put((packet3, onion_pub_key))

        with app.test_client() as c:
            resp = c.get(f'/{url_token}/messages/')
            self.assertEqual(b'packet1\npacket2', resp.data)

        with app.test_client() as c:
            resp = c.get(f'/{url_token}/files/')
            self.assertEqual(b'packet3', resp.data)

        # Test valid URL token returns nothing as queues are empty
        with app.test_client() as c:
            resp = c.get(f'/{url_token}/messages/')
            self.assertEqual(b'', resp.data)

        with app.test_client() as c:
            resp = c.get(f'/{url_token}/files/')
            self.assertEqual(b'', resp.data)


if __name__ == '__main__':
    unittest.main(exit=False)
