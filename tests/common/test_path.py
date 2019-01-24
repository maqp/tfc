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

import os
import _tkinter
import unittest

from unittest      import mock
from unittest.mock import MagicMock

from src.common.path import ask_path_cli, ask_path_gui, Completer

from tests.mock_classes import Settings
from tests.utils        import ignored, TFCTestCase


class TestAskPathGui(TFCTestCase):

    file_path = '/home/user/file.txt'
    path      = '/home/user/'

    def setUp(self):
        self.settings = Settings()

    @mock.patch('os.path.isfile', return_value=True)
    @mock.patch('builtins.input', return_value=file_path)
    def test_disabled_gui_uses_cli(self, *_):
        self.settings.disable_gui_dialog = True
        self.assertEqual(ask_path_gui('prompt_msg', self.settings, get_file=True), self.file_path)

    @mock.patch('os.path.isfile',                     return_value=True)
    @mock.patch('builtins.input',                     return_value=file_path)
    @mock.patch('tkinter.filedialog.askopenfilename', side_effect=_tkinter.TclError)
    def test_tcl_error_falls_back_to_cli(self, *_):
        self.assertEqual(ask_path_gui('prompt_msg', self.settings, get_file=True), self.file_path)

    @mock.patch('tkinter.Tk',                         return_value=MagicMock())
    @mock.patch('os.path.isfile',                     return_value=True)
    @mock.patch('tkinter.filedialog.askopenfilename', return_value=file_path)
    def test_get_path_to_file_gui(self, *_):
        self.assertEqual(ask_path_gui('path to file:', self.settings, get_file=True),
                         self.file_path)

    @unittest.skipIf("TRAVIS" in os.environ and os.environ["TRAVIS"] == "true", "Skip as Travis has no $DISPLAY.")
    @mock.patch('tkinter.filedialog.askopenfilename', return_value='')
    def test_no_path_to_file_raises_fr(self, _):
        self.assert_fr("File selection aborted.", ask_path_gui, 'test message', self.settings, True)

    @unittest.skipIf("TRAVIS" in os.environ and os.environ["TRAVIS"] == "true", "Skip as Travis has no $DISPLAY.")
    @mock.patch('tkinter.filedialog.askdirectory', return_value=path)
    def test_get_path_gui(self, _):
        self.assertEqual(ask_path_gui('select path for file:', self.settings), self.path)

    @unittest.skipIf("TRAVIS" in os.environ and os.environ["TRAVIS"] == "true", "Skip as Travis has no $DISPLAY.")
    @mock.patch('tkinter.filedialog.askdirectory', return_value='')
    def test_no_path_raises_fr(self, _):
        self.assert_fr("Path selection aborted.", ask_path_gui, 'test message', self.settings, False)


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
        self.assertEqual(completer.path_complete(['/bin']),  [])
        self.assertEqual(completer.path_complete(),          [])
        self.assertEqual(completer.complete_path(''),        [])
        self.assertEqual(completer.complete_path('/bin/sh'), ['/bin/sh '])
        self.assertNotEqual(completer.listdir('/etc/'),      [])

        # Test file
        completer = Completer(get_file=True)
        self.assertTrue(len(completer.complete_path('/bin/')) > 0)
        self.assertTrue(completer.complete('', 0))


class TestPath(TFCTestCase):

    def setUp(self):
        with ignored(FileExistsError):
            os.mkdir('test_dir/')

    def tearDown(self):
        with ignored(OSError):
            os.remove('testfile')
        with ignored(OSError):
            os.rmdir('test_dir/')

    @mock.patch('time.sleep',     return_value=None)
    @mock.patch('os.path.isfile', side_effect=[False, True, True])
    @mock.patch('builtins.input', side_effect=['file1', 'file2', './test_dir', './testfile', '', '/home',
                                               '/dir_that_does_not_exist', '/bin/', KeyboardInterrupt])
    def test_ask_path_cli(self, *_):
        self.assertEqual(ask_path_cli('path to file:', get_file=True), 'file2')
        self.assertEqual(ask_path_cli('prompt_msg'), 'test_dir/')

        open('testfile', 'a+').close()
        self.assertEqual(ask_path_cli('prompt_msg', get_file=True), 'testfile')

        self.assert_fr("File selection aborted.", ask_path_cli, 'prompt_msg', True)

        self.assertEqual(ask_path_cli('prompt_msg'), '/home/')
        self.assertEqual(ask_path_cli('prompt_msg'), '/bin/')

        self.assert_fr("File path selection aborted.", ask_path_cli, 'prompt_msg', False)


if __name__ == '__main__':
    unittest.main(exit=False)
