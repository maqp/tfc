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
import os
import time
import unittest

from multiprocessing import Queue

from src.common.statics import *

import src.tx.commands
from src.tx.input_loop import input_loop

from tests.mock_classes import ContactList, Gateway, GroupList, MasterKey, Settings


class TestInputLoop(unittest.TestCase):

    def setUp(self):
        if 'TRAVIS' not in os.environ or not os.environ['TRAVIS'] == 'true':
            self.o_getrandom = os.getrandom
        self.o_input      = builtins.input
        self.o_urandom    = os.urandom
        self.gateway      = Gateway()
        self.settings     = Settings(disable_gui_dialog=True)
        self.contact_list = ContactList()
        self.group_list   = GroupList()
        self.master_key   = MasterKey()
        self.queues       = {MESSAGE_PACKET_QUEUE: Queue(),
                             FILE_PACKET_QUEUE:    Queue(),
                             COMMAND_PACKET_QUEUE: Queue(),
                             NH_PACKET_QUEUE:      Queue(),
                             LOG_PACKET_QUEUE:     Queue(),
                             EXIT_QUEUE:           Queue(),
                             NOISE_PACKET_QUEUE:   Queue(),
                             NOISE_COMMAND_QUEUE:  Queue(),
                             KEY_MANAGEMENT_QUEUE: Queue(),
                             WINDOW_SELECT_QUEUE:  Queue()}

        input_list     = ['',                           # NH Bypass start
                          '61',                         # Enter confirmation code
                          '',                           # NH Bypass end
                          'alice@jabber.org',           # Enter rx-account for new contact
                          'bob@jabber.org',             # Enter tx-account for new contact
                          '',                           # Enter for auto-nick
                          '',                           # Enter to default for X25519
                          '5JZB2s2RCtRUunKiqMbb6rAj3Z'  # Enter public key for contact
                          '7TkJwa8zknL1cfTFpWoQArd6n',
                          'Yes',                        # Accept key fingerprints for Alice
                          'Alice',                      # Select Alice as recipient
                          'Test',                       # Send test message
                          '/file',                      # Open file selection prompt
                          '',                           # Give empty string to abort
                          '/exit']                      # Enter exit command
        gen            = iter(input_list)
        builtins.input = lambda _: str(next(gen))
        if 'TRAVIS' not in os.environ or not os.environ['TRAVIS'] == 'true':
            os.getrandom = lambda n, flags: n * b'a'
        os.urandom     = lambda n:        n * b'a'

        self.o_exit_tfc          = src.tx.commands.exit_tfc
        src.tx.commands.exit_tfc = lambda *_: (_ for _ in ()).throw(SystemExit)

    def tearDown(self):
        if 'TRAVIS' not in os.environ or not os.environ['TRAVIS'] == 'true':
            os.getrandom = self.o_getrandom

        builtins.input           = self.o_input
        os.urandom               = self.o_urandom
        src.tx.commands.exit_tfc = self.o_exit_tfc

        for key in self.queues:
            while not self.queues[key].empty():
                self.queues[key].get()
            time.sleep(0.1)
            self.queues[key].close()

    def test_input_loop_functions(self):
        with self.assertRaises(SystemExit):
            self.assertIsNone(input_loop(self.queues, self.settings, self.gateway, self.contact_list,
                                         self.group_list, self.master_key, stdin_fd=1))


if __name__ == '__main__':
    unittest.main(exit=False)
