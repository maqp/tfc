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

import argparse
import builtins
import os
import unittest

from src.nh.misc import box_print, c_print, clear_screen, ensure_dir, get_tty_w, graceful_exit
from src.nh.misc import phase, print_on_previous_line, process_arguments, yes


class TestMisc(unittest.TestCase):

    def test_box_print(self):
        self.assertIsNone(box_print("Test message",                          head=1, tail=1))
        self.assertIsNone(box_print(["Test message", '', "Another message"], head=1, tail=1))

        o_input        = builtins.input
        builtins.input = lambda x: ''
        self.assertIsNone(box_print("Test message", manual_proceed=True))
        builtins.input = o_input

    def test_c_print(self):
        self.assertIsNone(c_print('Test message', head=1, tail=1))

    def test_clear_screen(self):
        self.assertIsNone(clear_screen())

    def test_ensure_dir(self):
        self.assertIsNone(ensure_dir('test_dir/'))
        try:
            os.rmdir('test_dir/')
        except OSError:
            pass

    def test_get_tty_w(self):
        self.assertIsInstance(get_tty_w(), int)

    def test_graceful_exit(self):
        with self.assertRaises(SystemExit):
            graceful_exit('test message')
            graceful_exit('test message', clear=True)

    def test_phase(self):
        self.assertIsNone(phase('Entering phase'))
        self.assertIsNone(phase('Done'))
        self.assertIsNone(phase('Starting phase', head=1, offset=len("Finished")))
        self.assertIsNone(phase('Finished', done=True))

    def test_print_on_previous_line(self):
        self.assertIsNone(print_on_previous_line())
        self.assertIsNone(print_on_previous_line(reps=2, flush=True))

    def test_process_arguments(self):
        # Setup
        class MockParser(object):
            def __init__(self, *_, **__):
                pass

            def parse_args(self):
                class Args(object):
                    def __init__(self):
                        self.local_test = True
                        self.dd_sockets = True
                args = Args()
                return args

            def add_argument(self, *_, **__):
                pass

        o_argparse              = argparse.ArgumentParser
        argparse.ArgumentParser = MockParser

        # Test
        self.assertEqual(process_arguments(), (True, True))

        # Teardown
        argparse.ArgumentParser = o_argparse

    def test_yes(self):
        # Setup
        words      = ['BAD', '', 'bad', 'Y', 'YES', 'N', 'NO']
        input_list = words
        gen        = iter(input_list)

        def mock_input(_):
            return str(next(gen))

        builtins.input = mock_input

        # Test
        self.assertTrue(yes('test prompt', head=1, tail=1))
        self.assertTrue(yes('test prompt'))
        self.assertFalse(yes('test prompt', head=1, tail=1))
        self.assertFalse(yes('test prompt'))


if __name__ == '__main__':
    unittest.main(exit=False)
