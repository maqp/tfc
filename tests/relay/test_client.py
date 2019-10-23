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
import threading
import time
import unittest

from unittest import mock
from typing   import Any

import requests

from src.common.crypto   import X448
from src.common.db_onion import pub_key_to_onion_address, pub_key_to_short_address
from src.common.statics  import (CONTACT_MGMT_QUEUE, CONTACT_REQ_QUEUE, C_REQ_MGMT_QUEUE, C_REQ_STATE_QUEUE,
                                 DST_MESSAGE_QUEUE, EXIT, GROUP_ID_LENGTH, GROUP_MGMT_QUEUE,
                                 GROUP_MSG_EXIT_GROUP_HEADER, GROUP_MSG_INVITE_HEADER, GROUP_MSG_JOIN_HEADER,
                                 GROUP_MSG_MEMBER_ADD_HEADER, GROUP_MSG_MEMBER_REM_HEADER, GROUP_MSG_QUEUE,
                                 MESSAGE_DATAGRAM_HEADER, ONION_SERVICE_PUBLIC_KEY_LENGTH, PUBLIC_KEY_DATAGRAM_HEADER,
                                 RP_ADD_CONTACT_HEADER, RP_REMOVE_CONTACT_HEADER, TFC_PUBLIC_KEY_LENGTH, TOR_DATA_QUEUE,
                                 UNIT_TEST_QUEUE, URL_TOKEN_QUEUE)

from src.relay.client import c_req_manager, client, client_scheduler, g_msg_manager, get_data_loop

from tests.mock_classes import Gateway
from tests.utils        import gen_queue_dict, nick_to_onion_address, nick_to_pub_key, tear_queues


class TestClient(unittest.TestCase):

    url_token_private_key = X448.generate_private_key()
    url_token_public_key  = X448.derive_public_key(url_token_private_key)
    url_token             = X448.shared_key(url_token_private_key, url_token_public_key).hex()

    class MockResponse(object):
        """Mock Response object."""
        def __init__(self, text):
            """Create new MockResponse object."""
            self.text    = text
            self.content = text

    class MockSession(object):
        """Mock Session object."""

        def __init__(self):
            """Create new MockSession object."""
            self.proxies = dict()
            self.timeout = None
            self.url     = None
            self.test_no = 0

        def get(self, url, timeout=0, stream=False):
            """Mock .get() method."""

            self.timeout = timeout

            # When we reach `get_data_loop` that loads stream, throw exception to close the test.
            if stream:
                (_ for _ in ()).throw(requests.exceptions.RequestException)

            if url.startswith("http://hpcrayuxhrcy2wtpfwgwjibderrvjll6azfr4tqat3eka2m2gbb55bid.onion/"):

                if self.test_no == 0:
                    self.test_no += 1
                    (_ for _ in ()).throw(requests.exceptions.RequestException)

                if self.test_no == 1:
                    self.test_no += 1
                    return TestClient.MockResponse('OK')

                # Test function recovers from RequestException.
                if self.test_no == 2:
                    self.test_no += 1
                    (_ for _ in ()).throw(requests.exceptions.RequestException)

                # Test function recovers from invalid public key.
                if self.test_no == 3:
                    self.test_no += 1
                    return TestClient.MockResponse(((ONION_SERVICE_PUBLIC_KEY_LENGTH-1)*b'a').hex())

                # Test client prints online/offline messages.
                elif self.test_no < 10:
                    self.test_no += 1
                    return TestClient.MockResponse('')

                # Test valid public key moves function to `get_data_loop`.
                elif self.test_no == 10:
                    self.test_no += 1
                    return TestClient.MockResponse(TestClient.url_token_public_key.hex())

    @staticmethod
    def mock_session():
        """Return MockSession object."""
        return TestClient.MockSession()

    def setUp(self):
        """Pre-test actions."""
        self.o_session   = requests.session
        self.queues      = gen_queue_dict()
        requests.session = TestClient.mock_session

    def tearDown(self):
        """Post-test actions."""
        requests.session = self.o_session
        tear_queues(self.queues)

    @mock.patch('time.sleep', return_value=None)
    def test_client(self, _):
        onion_pub_key = nick_to_pub_key('Alice')
        onion_address = nick_to_onion_address('Alice')
        tor_port      = '1337'
        settings      = Gateway()
        sk            = TestClient.url_token_private_key
        self.assertIsNone(client(onion_pub_key, self.queues, sk, tor_port, settings, onion_address, unit_test=True))
        self.assertEqual(self.queues[URL_TOKEN_QUEUE].get(), (onion_pub_key, TestClient.url_token))


class TestGetDataLoop(unittest.TestCase):

    url_token_private_key_user   = X448.generate_private_key()
    url_token_public_key_user    = X448.derive_public_key(url_token_private_key_user)
    url_token_public_key_contact = X448.derive_public_key(X448.generate_private_key())
    url_token                    = X448.shared_key(url_token_private_key_user, url_token_public_key_contact).hex()

    class MockResponse(object):
        """Mock Response object."""
        def __init__(self):
            self.test_no = 0

        def iter_lines(self):
            """Return data depending test number."""
            self.test_no += 1
            message = b''

            # Empty message
            if self.test_no == 1:
                pass

            # Invalid message
            elif self.test_no == 2:
                message = MESSAGE_DATAGRAM_HEADER + b'\x1f'

            # Valid message
            elif self.test_no == 3:
                message = MESSAGE_DATAGRAM_HEADER    + base64.b85encode(b'test') + b'\n'

            # Invalid public key
            elif self.test_no == 4:
                message = PUBLIC_KEY_DATAGRAM_HEADER + base64.b85encode((TFC_PUBLIC_KEY_LENGTH-1) * b'\x01')

            # Valid public key
            elif self.test_no == 5:
                message = PUBLIC_KEY_DATAGRAM_HEADER + base64.b85encode(TFC_PUBLIC_KEY_LENGTH * b'\x01')

            # Group management headers
            elif self.test_no == 6:
                message = GROUP_MSG_INVITE_HEADER

            elif self.test_no == 7:
                message = GROUP_MSG_JOIN_HEADER

            elif self.test_no == 8:
                message = GROUP_MSG_MEMBER_ADD_HEADER

            elif self.test_no == 9:
                message = GROUP_MSG_MEMBER_REM_HEADER

            elif self.test_no == 10:
                message = GROUP_MSG_EXIT_GROUP_HEADER

            # Invalid header
            elif self.test_no == 11:
                message = b'\x1f'

            # RequestException (no remaining data)
            elif self.test_no == 12:
                (_ for _ in ()).throw(requests.exceptions.RequestException)

            return message.split(b'\n')

    class MockFileResponse(object):
        """MockFileResponse object."""

        def __init__(self, content):
            self.content = content

    class Session(object):
        """Mock session object."""

        def __init__(self) -> None:
            """Create new Session object."""
            self.proxies   = dict()
            self.timeout   = None
            self.url       = None
            self.stream    = False
            self.test_no   = 0
            self.response  = TestGetDataLoop.MockResponse()
            self.url_token = TestGetDataLoop.url_token
            self.onion_url = 'http://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaam2dqd.onion'

        def get(self, url: str, timeout: int = 0, stream: bool = False) -> Any:
            """Return data depending on what test is in question."""

            self.stream  = stream
            self.timeout = timeout

            if url == f"{self.onion_url}/{self.url_token}/messages":

                # Test function recovers from RequestException.
                if self.test_no == 1:
                    self.test_no += 1
                    (_ for _ in ()).throw(requests.exceptions.RequestException)

                if self.test_no >= 2:
                    self.test_no += 1
                    return self.response

            elif url == f"{self.onion_url}/{self.url_token}/files":

                # Test file data is received
                if self.test_no == 0:
                    self.test_no += 1
                    return TestGetDataLoop.MockFileResponse(b'test')

                # Test function recovers from RequestException.
                if self.test_no > 1:
                    (_ for _ in ()).throw(requests.exceptions.RequestException)

    @staticmethod
    def mock_session() -> Session:
        """Return mock Session object."""
        return TestGetDataLoop.Session()

    def setUp(self):
        """Pre-test actions."""
        self.o_session   = requests.session
        self.queues      = gen_queue_dict()
        requests.session = TestGetDataLoop.mock_session

    def tearDown(self):
        """Post-test actions."""
        requests.session = self.o_session
        tear_queues(self.queues)

    def test_get_data_loop(self):

        onion_pub_key = bytes(ONION_SERVICE_PUBLIC_KEY_LENGTH)
        settings      = Gateway()
        onion_addr    = pub_key_to_onion_address(bytes(ONION_SERVICE_PUBLIC_KEY_LENGTH))
        short_addr    = pub_key_to_short_address(bytes(ONION_SERVICE_PUBLIC_KEY_LENGTH))
        url_token     = TestGetDataLoop.url_token
        session       = TestGetDataLoop.mock_session()

        self.assertIsNone(get_data_loop(onion_addr, url_token, short_addr,
                                        onion_pub_key, self.queues, session, settings))

        self.assertIsNone(get_data_loop(onion_addr, url_token, short_addr,
                                        onion_pub_key, self.queues, session, settings))

        self.assertEqual(self.queues[DST_MESSAGE_QUEUE].qsize(), 2)  # Message and file
        self.assertEqual(self.queues[GROUP_MSG_QUEUE].qsize(),   5)  # 5 group management messages


class TestGroupManager(unittest.TestCase):

    def test_group_manager(self):

        queues = gen_queue_dict()

        def queue_delayer():
            """Place messages to queue one at a time."""
            time.sleep(0.1)

            # Test function recovers from incorrect group ID size
            queues[GROUP_MSG_QUEUE].put((
                GROUP_MSG_EXIT_GROUP_HEADER,
                bytes((GROUP_ID_LENGTH - 1)),
                pub_key_to_short_address(bytes(ONION_SERVICE_PUBLIC_KEY_LENGTH))
                ))

            # Test group invite for added and removed contacts
            queues[GROUP_MGMT_QUEUE].put((RP_ADD_CONTACT_HEADER, nick_to_pub_key('Alice') + nick_to_pub_key('Bob')))
            queues[GROUP_MGMT_QUEUE].put((RP_REMOVE_CONTACT_HEADER, nick_to_pub_key('Alice')))

            for header in [GROUP_MSG_INVITE_HEADER,     GROUP_MSG_JOIN_HEADER,
                           GROUP_MSG_MEMBER_ADD_HEADER, GROUP_MSG_MEMBER_REM_HEADER]:
                queues[GROUP_MSG_QUEUE].put(
                    (header,
                     bytes(GROUP_ID_LENGTH) + nick_to_pub_key('Bob') + nick_to_pub_key('Charlie'),
                     pub_key_to_short_address(bytes(ONION_SERVICE_PUBLIC_KEY_LENGTH))
                     ))

            queues[GROUP_MSG_QUEUE].put(
                (GROUP_MSG_EXIT_GROUP_HEADER,
                 bytes(GROUP_ID_LENGTH),
                 pub_key_to_short_address(bytes(ONION_SERVICE_PUBLIC_KEY_LENGTH))
                 ))

            # Exit test
            time.sleep(0.2)
            queues[UNIT_TEST_QUEUE].put(EXIT)
            queues[GROUP_MSG_QUEUE].put(
                (GROUP_MSG_EXIT_GROUP_HEADER,
                 bytes(GROUP_ID_LENGTH),
                 pub_key_to_short_address(bytes(ONION_SERVICE_PUBLIC_KEY_LENGTH))
                 ))

        # Test
        threading.Thread(target=queue_delayer).start()
        self.assertIsNone(g_msg_manager(queues, unit_test=True))
        tear_queues(queues)


class TestClientScheduler(unittest.TestCase):

    def test_client_scheduler(self):
        queues             = gen_queue_dict()
        gateway            = Gateway()
        server_private_key = X448.generate_private_key()

        def queue_delayer():
            """Place messages to queue one at a time."""
            time.sleep(0.1)
            queues[TOR_DATA_QUEUE].put(
                ('1234', nick_to_onion_address('Alice')))
            queues[CONTACT_MGMT_QUEUE].put(
                (RP_ADD_CONTACT_HEADER, b''.join([nick_to_pub_key('Alice'), nick_to_pub_key('Bob')]), True))
            time.sleep(0.1)
            queues[CONTACT_MGMT_QUEUE].put(
                (RP_REMOVE_CONTACT_HEADER, b''.join([nick_to_pub_key('Alice'), nick_to_pub_key('Bob')]), True))
            time.sleep(0.1)
            queues[UNIT_TEST_QUEUE].put(EXIT)
            time.sleep(0.1)
            queues[CONTACT_MGMT_QUEUE].put((EXIT, EXIT, EXIT))

        threading.Thread(target=queue_delayer).start()

        self.assertIsNone(client_scheduler(queues, gateway, server_private_key, unit_test=True))
        tear_queues(queues)


class TestContactRequestManager(unittest.TestCase):

    def test_contact_request_manager(self):

        queues = gen_queue_dict()

        def queue_delayer():
            """Place messages to queue one at a time."""
            time.sleep(0.1)
            queues[C_REQ_MGMT_QUEUE].put(
                (RP_ADD_CONTACT_HEADER, b''.join(list(map(nick_to_pub_key, ['Alice', 'Bob'])))))
            time.sleep(0.1)

            # Test that request from Alice does not appear
            queues[CONTACT_REQ_QUEUE].put((nick_to_onion_address('Alice')))
            time.sleep(0.1)

            # Test that request from Charlie appears
            queues[CONTACT_REQ_QUEUE].put((nick_to_onion_address('Charlie')))
            time.sleep(0.1)

            # Test that another request from Charlie does not appear
            queues[CONTACT_REQ_QUEUE].put((nick_to_onion_address('Charlie')))
            time.sleep(0.1)

            # Remove Alice
            queues[C_REQ_MGMT_QUEUE].put((RP_REMOVE_CONTACT_HEADER, nick_to_pub_key('Alice')))
            time.sleep(0.1)

            # Load settings from queue
            queues[C_REQ_STATE_QUEUE].put(False)
            queues[C_REQ_STATE_QUEUE].put(True)

            # Test that request from Alice is accepted
            queues[CONTACT_REQ_QUEUE].put((nick_to_onion_address('Alice')))
            time.sleep(0.1)

            # Exit test
            queues[UNIT_TEST_QUEUE].put(EXIT)
            queues[CONTACT_REQ_QUEUE].put(nick_to_pub_key('Charlie'))

        threading.Thread(target=queue_delayer).start()
        self.assertIsNone(c_req_manager(queues, unit_test=True))
        tear_queues(queues)


if __name__ == '__main__':
    unittest.main(exit=False)
