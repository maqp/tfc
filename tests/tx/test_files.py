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
import unittest
import time

from multiprocessing import Queue

from src.tx.files       import File, queue_file

from tests.mock_classes import create_contact, Gateway, Settings, Window
from tests.utils        import TFCTestCase


class TestFile(TFCTestCase):

    def test_missing_file_raises_fr(self):
        # Setup
        settings = Settings()
        window   = Window()
        gateway  = Gateway(delay=0.02)

        # Test
        self.assertFR("Error: File not found.", File, './testfile.txt', window, settings, gateway)


    def test_empty_file_raises_fr(self):
        # Setup
        with open('testfile.txt', 'wb+') as f:
            f.write(b'')

        settings = Settings()
        window   = Window()
        gateway  = Gateway(delay=0.02)

        # Test
        self.assertFR("Error: Target file is empty. No file was sent.", File, './testfile.txt', window, settings, gateway)

    def test_oversize_filename_raises_fr(self):
        # Setup
        f_name = 250 * 'a' + '.txt'
        with open(f_name, 'wb+') as f:
            f.write(b'a')

        settings = Settings()
        window   = Window()
        gateway  = Gateway(delay=0.02)

        # Test
        self.assertFR("Error: File name is too long. No file was sent.", File, f'./{f_name}', window, settings, gateway)

        # Teardown
        os.remove(f_name)

    def test_small_file(self):
        # Setup
        input_data = os.urandom(5)
        with open('testfile.txt', 'wb+') as f:
            f.write(input_data)

        settings = Settings(session_trickle=True,
                            long_packet_rand_d=True)
        window   = Window()
        gateway  = Gateway(delay=0.02)

        # Test
        file = File('./testfile.txt', window, settings, gateway)

        self.assertEqual(file.name, b'testfile.txt')
        self.assertEqual(file.size, b'5.0B')
        self.assertEqual(len(file.plaintext), 141)
        self.assertIsInstance(file.plaintext, bytes)

        # Teardown
        os.remove('testfile.txt')

    def test_large_file(self):
        # Setup
        input_data = os.urandom(2000)
        with open('testfile.txt', 'wb+') as f:
            f.write(input_data)

        settings = Settings()
        contacts = [create_contact('Alice'), create_contact('Bob')]
        window   = Window(window_contacts=contacts)
        gateway  = Gateway(delay=0.02)

        # Test
        file = File('./testfile.txt', window, settings, gateway)

        self.assertEqual(file.name, b'testfile.txt')
        self.assertEqual(file.size, b'2.0KB')
        self.assertEqual(len(file.plaintext), 2640)
        self.assertIsInstance(file.plaintext, bytes)

        # Teardown
        os.remove('testfile.txt')


class TestQueueFile(TFCTestCase):

    def test_aborted_file(self):
        # Setup
        input_data = os.urandom(5)
        with open('testfile.txt', 'wb+') as f:
            f.write(input_data)

        settings   = Settings(session_trickle=True,
                              disable_gui_dialog=True)
        window     = Window(name='Alice',
                            type='contact',
                            uid='alice@jabber.org')
        gateway    = Gateway(delay=0.02)
        f_queue    = Queue()
        input_list = ['./testfile.txt', 'No']
        gen        = iter(input_list)

        def mock_input(_):
            return str(next(gen))
        builtins.input = mock_input

        # Test
        self.assertFR("File selection aborted.", queue_file, window, settings, f_queue, gateway)

        # Teardown
        os.remove('testfile.txt')
        time.sleep(0.2)
        f_queue.close()

    def test_file_queue_short_trickle(self):
        # Setup
        input_data = os.urandom(5)
        with open('testfile.txt', 'wb+') as f:
            f.write(input_data)

        settings   = Settings(session_trickle=True,
                              disable_gui_dialog=True)
        window     = Window(name='Alice',
                            type='contact',
                            uid='alice@jabber.org')
        gateway    = Gateway(delay=0.02)
        f_queue    = Queue()
        input_list = ['./testfile.txt', 'Yes']
        gen        = iter(input_list)

        def mock_input(_):
            return str(next(gen))
        builtins.input = mock_input

        # Test
        self.assertIsNone(queue_file(window, settings, f_queue, gateway))
        time.sleep(0.5)
        self.assertEqual(f_queue.qsize(), 1)
        q_data, l_d = f_queue.get()

        self.assertIsInstance(q_data, bytes)
        self.assertIsInstance(l_d, dict)

        # Teardown
        os.remove('testfile.txt')
        time.sleep(0.2)
        f_queue.close()

    def test_file_queue_long_normal(self):
        # Setup
        input_data = os.urandom(200000)
        with open('testfile.txt', 'wb+') as f:
            f.write(input_data)

        settings   = Settings(session_trickle=False,
                              disable_gui_dialog=True,
                              confirm_sent_files=True)
        window     = Window(name='Alice',
                            type='contact',
                            uid='alice@jabber.org',
                            window_contacts=[create_contact('Alice')])
        gateway    = Gateway(delay=0.02)
        f_queue    = Queue()

        input_list = ['./testfile.txt', 'Yes']
        gen        = iter(input_list)

        def mock_input(_):
            return str(next(gen))
        builtins.input = mock_input

        # Test
        self.assertIsNone(queue_file(window, settings, f_queue, gateway))
        time.sleep(1)
        self.assertEqual(f_queue.qsize(), 982)

        while not f_queue.empty():
            p, s, ra, ta, lm, wu = f_queue.get()
            self.assertIsInstance(p, bytes)
            self.assertIsInstance(s, Settings)
            self.assertEqual(ra, 'alice@jabber.org')
            self.assertEqual(ta, 'user@jabber.org')
            self.assertEqual(wu, 'alice@jabber.org')
            self.assertTrue(lm)

        # Teardown
        os.remove('testfile.txt')
        time.sleep(0.5)
        f_queue.close()
        time.sleep(0.5)

if __name__ == '__main__':
    unittest.main(exit=False)
