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

import unittest

from unittest      import mock
from unittest.mock import MagicMock

from src.common.crypto  import blake2b
from src.common.statics import *

from src.transmitter.input_loop import input_loop

from tests.mock_classes import ContactList, Gateway, GroupList, MasterKey, OnionService, Settings
from tests.utils        import gen_queue_dict, nick_to_onion_address, nick_to_pub_key, tear_queues, VALID_ECDHE_PUB_KEY


class TestInputLoop(unittest.TestCase):

    conf_code  = blake2b(nick_to_pub_key('Alice'), digest_size=CONFIRM_CODE_LENGTH).hex()
    input_list = ['61',                            # Enter Relay confirmation code
                  '61',                            # Enter Receiver confirmation code
                  nick_to_onion_address("Alice"),  # Enter rx-account for new contact
                  'Alice',                         # Enter nick for contact
                  '',                              # Enter to default for ECDHE
                  VALID_ECDHE_PUB_KEY,             # Enter public key for contact
                  'Yes',                           # Accept key fingerprints for Alice
                  conf_code,                       # Confirmation code
                  'Alice',                         # Select Alice as the recipient
                  'Test',                          # Send test message
                  '/file',                         # Open file selection prompt
                  '',                              # Give empty string to abort
                  '/exit']                         # Enter exit command

    def setUp(self):
        self.settings      = Settings(disable_gui_dialog=True)
        self.gateway       = Gateway()
        self.contact_list  = ContactList()
        self.group_list    = GroupList()
        self.master_key    = MasterKey()
        self.onion_service = OnionService()
        self.queues        = gen_queue_dict()

    def tearDown(self):
        tear_queues(self.queues)

    @mock.patch('builtins.input',                    side_effect=input_list)
    @mock.patch('os.fdopen',                         MagicMock())
    @mock.patch('os.getrandom',                      lambda n, flags: n*b'a')
    @mock.patch('os.urandom',                        lambda n:        n*b'a')
    @mock.patch('shutil.get_terminal_size',          return_value=[200, 200])
    @mock.patch('src.transmitter.commands.exit_tfc', side_effect=SystemExit)
    @mock.patch('sys.stdin',                         MagicMock())
    @mock.patch('time.sleep',                        return_value=None)
    def test_input_loop_functions(self, *_):
        with self.assertRaises(SystemExit):
            self.assertIsNone(input_loop(self.queues, self.settings, self.gateway, self.contact_list,
                                         self.group_list, self.master_key, self.onion_service, stdin_fd=1))


if __name__ == '__main__':
    unittest.main(exit=False)
