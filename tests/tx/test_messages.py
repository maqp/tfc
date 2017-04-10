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

import binascii
import os
import unittest
import time

from multiprocessing    import Queue

from src.common.statics import *
from src.tx.messages    import Message, queue_message

from tests.mock_classes import create_contact, create_group, Settings, UserInput, Window


class TestMessageStub(unittest.TestCase):

    def test_stub(self):
        # Setup
        message = Message('test_plaintext')

        # Test
        self.assertEqual(message.plaintext, 'test_plaintext')
        self.assertEqual(message.type,      'message')

class TestQueueMessage(unittest.TestCase):

    def test_normal_contact(self):
        # Setup
        settings = Settings()
        m_queue  = Queue()
        window   = Window(type='contact',
                          window_contacts=[create_contact('Alice')],
                          uid='alice@jabber.org')

        # Short messages
        user_input = UserInput(plaintext=binascii.hexlify(os.urandom(125)).decode())
        self.assertIsNone(queue_message(user_input, window, settings, m_queue))

        p, s, ra, ta, ls, wu = m_queue.get()
        self.assertIsInstance(p, bytes)
        self.assertEqual(len(p), 256)

        self.assertIsInstance(s, Settings)
        self.assertEqual(ra, 'alice@jabber.org')
        self.assertEqual(ta, 'user@jabber.org')
        self.assertEqual(ls, True)
        self.assertEqual(wu, 'alice@jabber.org')

        # Long messages
        user_input = UserInput(plaintext=binascii.hexlify(os.urandom(250)).decode())
        self.assertIsNone(queue_message(user_input, window, settings, m_queue))
        self.assertEqual(m_queue.qsize(), 2)

        while not m_queue.empty():
            p, s, ra, ta, ls, wu = m_queue.get()
            self.assertIsInstance(p, bytes)
            self.assertEqual(len(p), 256)

            self.assertIsInstance(s, Settings)
            self.assertEqual(ra, 'alice@jabber.org')
            self.assertEqual(ta, 'user@jabber.org')
            self.assertEqual(ls, True)
            self.assertEqual(wu, 'alice@jabber.org')

        # Teardown
        time.sleep(0.2)
        m_queue.close()

    def test_group_trickle(self):
        # Setup
        settings = Settings(session_trickle=True)
        m_queue  = Queue()
        contact  = create_contact('Alice')
        group    = create_group('test_group', ['Alice'])
        window   = Window(name='test_group',
                          type='group',
                          group=group,
                          window_contacts=[contact])

        # Short messages
        user_input = UserInput(plaintext=binascii.hexlify(os.urandom(125)).decode())
        self.assertIsNone(queue_message(user_input, window, settings, m_queue, header=PRIVATE_MESSAGE_HEADER))
        c_pt, log_dict = m_queue.get()
        self.assertEqual(len(c_pt), 256)
        self.assertIsInstance(log_dict, dict)

        # Long messages
        user_input = UserInput(plaintext=binascii.hexlify(os.urandom(250)).decode())
        self.assertIsNone(queue_message(user_input, window, settings, m_queue))
        self.assertEqual(m_queue.qsize(), 2)

        while not m_queue.empty():
            c_pt, log_dict = m_queue.get()
            self.assertEqual(len(c_pt), 256)
            self.assertIsInstance(log_dict, dict)

        # Teardown
        time.sleep(0.2)
        m_queue.close()


if __name__ == '__main__':
    unittest.main(exit=False)
