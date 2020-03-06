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

import time
import threading
import unittest

from typing        import Any
from unittest      import mock
from unittest.mock import MagicMock

from src.common.encoding import b58encode
from src.common.statics  import (ACCOUNT_CHECK_QUEUE, ACCOUNT_SEND_QUEUE, GUI_INPUT_QUEUE, PUB_KEY_CHECK_QUEUE,
                                 PUB_KEY_SEND_QUEUE, TFC_PUBLIC_KEY_LENGTH, USER_ACCOUNT_QUEUE)

from src.relay.diffs import account_checker, GetAccountFromUser, pub_key_checker, show_value_diffs

from tests.utils import gen_queue_dict, nick_to_pub_key, nick_to_onion_address, tear_queues, TFCTestCase


class TestGetAccountFromUser(unittest.TestCase):

    def setUp(self) -> None:
        """Pre-test actions."""
        self.queues = gen_queue_dict()

    def tearDown(self) -> None:
        """Post-test actions."""
        tear_queues(self.queues)

    @mock.patch('tkinter.Tk',        MagicMock())
    @mock.patch('tkinter.Entry.get', side_effect=[nick_to_onion_address('Alice'),
                                                  nick_to_onion_address('Bob')])
    def test_input(self, *_: Any) -> None:
        self.queue = self.queues[GUI_INPUT_QUEUE]
        app = GetAccountFromUser(self.queue, nick_to_onion_address('Alice'))
        self.assertIsNone(app.evaluate_account())
        self.assertIsNone(app.evaluate_account())
        self.assertIsNone(app.dismiss_window())
        self.assertEqual(self.queue.get(), nick_to_onion_address('Bob'))


class TestAccountChecker(unittest.TestCase):


    def setUp(self) -> None:
        """Pre-test actions."""
        self.queues = gen_queue_dict()

    def tearDown(self) -> None:
        """Post-test actions."""
        tear_queues(self.queues)

    @mock.patch('src.relay.diffs.GetAccountFromUser', return_value=MagicMock(return_value=None))
    def test_account_checker(self, *_: Any) -> None:
        # Setup
        user_account     = b58encode(nick_to_pub_key('Alice'))
        account          = b58encode(nick_to_pub_key('Bob'))
        unknown_account  = b58encode(nick_to_pub_key('Charlie'))
        invalid_account1 = account[:-1] + 'c'
        invalid_account2 = unknown_account[:-1] + 'c'

        def queue_delayer() -> None:
            """Place messages to queue one at a time."""
            time.sleep(0.05)
            self.queues[USER_ACCOUNT_QUEUE].put(user_account)
        threading.Thread(target=queue_delayer).start()

        self.queues[GUI_INPUT_QUEUE].put(unknown_account)
        self.queues[ACCOUNT_SEND_QUEUE].put(invalid_account1)
        self.queues[ACCOUNT_CHECK_QUEUE].put(account)
        self.queues[ACCOUNT_CHECK_QUEUE].put(invalid_account2)

        # Test
        with mock.patch('time.sleep', lambda _: None):
            self.assertIsNone(account_checker(self.queues, stdin_fd=1, unit_test=True))


class TestPubKeyChecker(unittest.TestCase):

    def setUp(self) -> None:
        """Pre-test actions."""
        self.queues = gen_queue_dict()

    def tearDown(self) -> None:
        """Post-test actions."""
        tear_queues(self.queues)

    @mock.patch('shutil.get_terminal_size', return_value=[200, 200])
    def test_pub_key_checker(self, _: Any) -> None:
        # Setup
        public_key         = TFC_PUBLIC_KEY_LENGTH*b'a'
        invalid_public_key = b58encode(public_key, public_key=True)[:-1] + 'a'
        account            = nick_to_pub_key('Bob')

        for local_test in [True, False]:
            self.queues[PUB_KEY_SEND_QUEUE].put((account,  public_key))
            self.queues[PUB_KEY_CHECK_QUEUE].put((account, invalid_public_key.encode()))

            # Test
            self.assertIsNone(pub_key_checker(self.queues, local_test=local_test, unit_test=True))
            self.assertIsNone(pub_key_checker(self.queues, local_test=local_test, unit_test=True))



class TestShowValueDiffs(TFCTestCase):

    @mock.patch('shutil.get_terminal_size', return_value=[110, 110])
    def test_show_public_key_diffs(self, _: Any) -> None:

        self.assert_prints("""\
           ┌──────────────────────────────────────────────────────────────────────────────────────┐           
           │                   Source Computer received an invalid public key.                    │           
           │                  See arrows below that point to correct characters.                  │           
           │                                                                                      │           
           │ 4EEue4P8vkwzjAEnxiUw9s4ibVA3YVWvzshd6tCQp67qjqda7n93SCtM8Z24tVFd8ZuS9Kt5kecghuajaneR │           
           │    ↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓ ↓↓↓↓↓↓↓ ↓↓↓↓↓↓↓↓↓↓↓↓↓ ↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓ │           
           │ 4EEjKap9yReFo8SdSKPhUgsQgsKD19nJBrhiBuDmcB7yzucbYMaGtpQF8de99KHWLqWtohzLKWtqTv9HG5Fb │           
           └──────────────────────────────────────────────────────────────────────────────────────┘           
""", show_value_diffs, 'public key',
                           b58encode(TFC_PUBLIC_KEY_LENGTH*b'a', public_key=True),
                           b58encode(TFC_PUBLIC_KEY_LENGTH*b'b', public_key=True),
                           local_test=True)

        self.assert_prints("""\
     ┌─────────────────────────────────────────────────────────────────────────────────────────────────┐      
     │                         Source Computer received an invalid public key.                         │      
     │                       See arrows below that point to correct characters.                        │      
     │                                                                                                 │      
     │    A       B       C       D       E       F       G       H       I       J       K       L    │      
     │ 4EEue4P 8vkwzjA EnxiUw9 s4ibVA3 YVWvzsh d6tCQp6 7qjqda7 n93SCtM 8Z24tVF d8ZuS9K t5kecgh uajaneR │      
     │    ↓↓↓↓ ↓↓↓↓↓↓↓ ↓↓↓↓↓↓↓ ↓↓↓↓↓↓↓ ↓↓↓↓↓↓  ↓↓↓↓↓↓↓  ↓↓↓↓↓↓ ↓↓↓↓↓↓↓  ↓↓↓↓↓↓ ↓↓↓↓↓↓↓ ↓↓↓↓↓↓↓ ↓↓↓↓↓↓↓ │      
     │ 4EEjKap 9yReFo8 SdSKPhU gsQgsKD 19nJBrh iBuDmcB 7yzucbY MaGtpQF 8de99KH WLqWtoh zLKWtqT v9HG5Fb │      
     │    A       B       C       D       E       F       G       H       I       J       K       L    │      
     └─────────────────────────────────────────────────────────────────────────────────────────────────┘      
""", show_value_diffs, 'public key',
                           b58encode(TFC_PUBLIC_KEY_LENGTH*b'a', public_key=True),
                           b58encode(TFC_PUBLIC_KEY_LENGTH*b'b', public_key=True),
                           local_test=False)

    @mock.patch('shutil.get_terminal_size', return_value=[80, 80])
    def test_show_account_diffs(self, _: Any) -> None:

        self.assert_prints("""\
          ┌──────────────────────────────────────────────────────────┐          
          │       Source Computer received an invalid account.       │          
          │    See arrows below that point to correct characters.    │          
          │                                                          │          
          │ zwp3dykiztmeils2u5eqjtdtx5x3kti5ktjthpkznku3ws5u5fq2bnad │          
          │ ↓↓↓↓↓ ↓↓↓↓↓↓↓↓↓↓↓↓↓↓ ↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓  │          
          │ hpcrayuxhrcy2wtpfwgwjibderrvjll6azfr4tqat3eka2m2gbb55bid │          
          └──────────────────────────────────────────────────────────┘          
""", show_value_diffs, 'account',
                           nick_to_onion_address('Alice'),
                           nick_to_onion_address('Bob'),
                           local_test=True)


if __name__ == '__main__':
    unittest.main(exit=False)
