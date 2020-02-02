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

import os
import _tkinter
import unittest

from unittest      import mock
from unittest.mock import MagicMock
from typing        import Any

from src.common.path import ask_path_cli, ask_path_gui, Completer

from tests.mock_classes import Settings
from tests.utils        import cd_unit_test, cleanup, ignored, TFCTestCase


class TestAskPathGui(TFCTestCase):

    file_path = '/home/user/file.txt'
    path      = '/home/user/'

    def setUp(self) -> None:
        """Pre-test actions."""
        self.settings = Settings()

    @mock.patch('os.path.isfile', return_value=True)
    @mock.patch('builtins.input', return_value=file_path)
    def test_disabled_gui_uses_cli(self, *_: Any) -> None:
        self.settings.disable_gui_dialog = True
        self.assertEqual(ask_path_gui('prompt_msg', self.settings, get_file=True), self.file_path)

    @mock.patch('os.path.isfile',                     return_value=True)
    @mock.patch('builtins.input',                     return_value=file_path)
    @mock.patch('tkinter.filedialog.askopenfilename', side_effect=_tkinter.TclError)
    def test_tcl_error_falls_back_to_cli(self, *_: Any) -> None:
        self.assertEqual(ask_path_gui('prompt_msg', self.settings, get_file=True), self.file_path)

    @mock.patch('tkinter.Tk',                         return_value=MagicMock())
    @mock.patch('os.path.isfile',                     return_value=True)
    @mock.patch('tkinter.filedialog.askopenfilename', return_value=file_path)
    def test_get_path_to_file_gui(self, *_: Any) -> None:
        self.assertEqual(ask_path_gui('path to file:', self.settings, get_file=True),
                         self.file_path)

    @mock.patch('tkinter.Tk',                         return_value=MagicMock())
    @mock.patch('tkinter.filedialog.askopenfilename', return_value='')
    def test_no_path_to_file_raises_se(self, *_: Any) -> None:
        self.assert_se("File selection aborted.", ask_path_gui, 'test message', self.settings, True)

    @mock.patch('tkinter.Tk',                      return_value=MagicMock())
    @mock.patch('tkinter.filedialog.askdirectory', return_value=path)
    def test_get_path_gui(self, *_: Any) -> None:
        self.assertEqual(ask_path_gui('select path for file:', self.settings), self.path)

    @mock.patch('tkinter.Tk',                      return_value=MagicMock())
    @mock.patch('tkinter.filedialog.askdirectory', return_value='')
    def test_no_path_raises_se(self, *_: Any) -> None:
        self.assert_se("Path selection aborted.", ask_path_gui, 'test message', self.settings, False)


class TestCompleter(unittest.TestCase):

    def setUp(self) -> None:
        """Pre-test actions."""
        self.cwd           = os.getcwd()
        self.unit_test_dir = cd_unit_test()

        # Create test directory structure for the completer.
        os.mkdir('outer')
        os.chdir('outer/')
        with open('file', 'w+') as f:
            f.write('text')
        os.mkdir('middle')
        os.chdir('middle/')
        os.mkdir('inner')
        os.chdir('..')
        os.chdir('..')

    def tearDown(self) -> None:
        """Post-test actions."""
        cleanup(self.unit_test_dir)
        os.chdir(self.cwd)

    def test_completer(self) -> None:
        # Test path
        completer = Completer(get_file=False)
        self.assertEqual(completer.complete_path('outer/'),       ['outer/middle/'])
        self.assertEqual(completer.path_complete(['/outer']),     [])
        self.assertEqual(completer.path_complete(),               ['./outer/'])
        self.assertEqual(completer.complete_path(''),             ['outer/'])
        self.assertEqual(completer.complete_path('outer/middle'), ['outer/middle/inner/'])
        self.assertEqual(completer.complete_path('outer/file'),   ['outer/file '])
        self.assertNotEqual(completer.listdir('outer/'),          [])

        # Test file
        completer = Completer(get_file=True)
        self.assertTrue(len(completer.complete_path('/bin/')) > 0)
        self.assertTrue(completer.complete('', 0))


class TestPath(TFCTestCase):

    def setUp(self) -> None:
        """Pre-test actions."""
        with ignored(FileExistsError):
            os.mkdir('test_dir/')

    def tearDown(self) -> None:
        """Post-test actions."""
        with ignored(OSError):
            os.remove('testfile')
        with ignored(OSError):
            os.rmdir('test_dir/')

    @mock.patch('time.sleep',     return_value=None)
    @mock.patch('os.path.isfile', side_effect=[False, True, True])
    @mock.patch('builtins.input', side_effect=['file1', 'file2', './test_dir', './testfile', '', '/home',
                                               '/dir_that_does_not_exist', '/bin/', KeyboardInterrupt])
    def test_ask_path_cli(self, *_: Any) -> None:
        self.assertEqual(ask_path_cli('path to file:', get_file=True), 'file2')
        self.assertEqual(ask_path_cli('prompt_msg'), 'test_dir/')

        open('testfile', 'a+').close()
        self.assertEqual(ask_path_cli('prompt_msg', get_file=True), 'testfile')

        self.assert_se("File selection aborted.", ask_path_cli, 'prompt_msg', True)

        self.assertEqual(ask_path_cli('prompt_msg'), '/home/')
        self.assertEqual(ask_path_cli('prompt_msg'), '/bin/')

        self.assert_se("File path selection aborted.", ask_path_cli, 'prompt_msg', False)


if __name__ == '__main__':
    unittest.main(exit=False)
