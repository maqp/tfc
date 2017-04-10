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
import unittest

from src.common.path import ask_path_cli

from tests.utils     import TFCTestCase


class TestPath(TFCTestCase):

    def test_ask_path_cli(self):
        # Setup
        o_input = builtins.input

        # Test
        input_list = ['/dev/zero', "/bin/mv"]
        gen        = iter(input_list)
        def mock_input(_):
            return str(next(gen))
        builtins.input = mock_input
        self.assertEqual(ask_path_cli('prompt_msg', get_file=True), "/bin/mv")

        builtins.input = lambda x: ''
        self.assertFR("File selection aborted.", ask_path_cli, 'prompt_msg', True)

        builtins.input = lambda x: "/home/"
        self.assertEqual(ask_path_cli('prompt_msg'), "/home/")

        builtins.input = lambda x: "/home"
        self.assertEqual(ask_path_cli('prompt_msg'), "/home/")

        input_list = ['/doesnotexist', "/bin/"]
        gen        = iter(input_list)

        def mock_input(_):
            return str(next(gen))

        builtins.input = mock_input
        self.assertEqual(ask_path_cli('prompt_msg'), "/bin/")

        # Teardown
        builtins.input = o_input


if __name__ == '__main__':
    unittest.main(exit=False)
