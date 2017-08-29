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
import _tkinter
import unittest

from tkinter import filedialog

from src.common.path import ask_path_cli, ask_path_gui, Completer

from tests.mock_classes import Settings
from tests.utils        import ignored, TFCTestCase


class TestAskPathGui(TFCTestCase):

    def setUp(self):
        self.o_aof    = filedialog.askopenfilename
        self.o_ad     = filedialog.askdirectory
        self.o_input  = builtins.input
        self.settings = Settings()

    def tearDown(self):
        filedialog.askopenfilename = self.o_aof
        filedialog.askdirectory    = self.o_ad
        builtins.input             = self.o_input

    def test_disabled_gui_uses_cli(self):
        # Setup
        self.settings.disable_gui_dialog = True
        builtins.input                   = lambda _: '/bin/mv'

        # Test
        self.assertEqual(ask_path_gui('prompt_msg', self.settings, get_file=True), '/bin/mv')

    def test_tcl_error_falls_back_to_cli(self):
        # Setup
        builtins.input             = lambda _: '/bin/mv'
        filedialog.askopenfilename = lambda title: (_ for _ in ()).throw(_tkinter.TclError)

        # Test
        self.assertEqual(ask_path_gui('prompt_msg', self.settings, get_file=True), '/bin/mv')

    def test_get_path_to_file_gui(self):
        # Setup
        filedialog.askopenfilename = lambda title: 'test_path_to_file'

        # Test
        self.assertEqual(ask_path_gui('test message', self.settings, get_file=True), 'test_path_to_file')

    def test_no_path_to_file_raises_fr(self):
        # Setup
        filedialog.askopenfilename = lambda title: ''

        # Test
        self.assertFR("File selection aborted.", ask_path_gui, 'test message', self.settings, True)

    def test_get_path_gui(self):
        # Setup
        filedialog.askdirectory = lambda title: 'test_path'

        # Test
        self.assertEqual(ask_path_gui('test message', self.settings, get_file=False), 'test_path')

    def test_no_path_raises_fr(self):
        # Setup
        filedialog.askdirectory = lambda title: ''

        # Test
        self.assertFR("Path selection aborted.", ask_path_gui, 'test message', self.settings, False)


class TestCompleter(unittest.TestCase):

    def setUp(self):
        self.cwd = os.getcwd()
        os.chdir('/bin')

    def tearDown(self):
        os.chdir(self.cwd)

    def test_completer(self):
        # Test path
        completer = Completer(get_file=False)
        self.assertEqual(completer.complete_path('/bin/'),   [])
        self.assertEqual(completer.path_complete('/bin'),    [])
        self.assertEqual(completer.path_complete(),          [])
        self.assertEqual(completer.complete_path(''),        [])
        self.assertEqual(completer.complete_path('/bin/sh'), ['/bin/sh '])
        self.assertNotEqual(completer.listdir('/etc/'),      [])

        # Test file
        completer = Completer(get_file=True)
        self.assertTrue(len(completer.complete_path('/bin/')) > 0)
        self.assertTrue(completer.complete(0, 0))


class TestPath(TFCTestCase):

    def setUp(self):
        self.o_input   = builtins.input
        input_list     = ['/dev/zero', '/bin/mv', './testdir', './testfile']
        gen            = iter(input_list)
        builtins.input = lambda _: str(next(gen))

        with ignored(FileExistsError):
            os.mkdir('testdir/')

    def tearDown(self):
        builtins.input = self.o_input

        with ignored(OSError):
            os.remove('testfile')

        with ignored(OSError):
            os.rmdir('testdir/')

    def test_ask_path_cli(self):
        self.assertEqual(ask_path_cli('prompt_msg', get_file=True), '/bin/mv')
        self.assertEqual(ask_path_cli('prompt_msg'), 'testdir/')

        open('testfile', 'a+').close()
        self.assertEqual(ask_path_cli('prompt_msg', get_file=True), 'testfile')

        builtins.input = lambda _: ''
        self.assertFR("File selection aborted.", ask_path_cli, 'prompt_msg', True)

        builtins.input = lambda _: '/home/'
        self.assertEqual(ask_path_cli('prompt_msg'), '/home/')

        input_list     = ['/home', '/dir_that_does_not_exist', '/bin/']
        gen            = iter(input_list)
        builtins.input = lambda _: str(next(gen))

        self.assertEqual(ask_path_cli('prompt_msg'), '/home/')
        self.assertEqual(ask_path_cli('prompt_msg'), '/bin/')


if __name__ == '__main__':
    unittest.main(exit=False)
