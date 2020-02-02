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

import unittest

from src.common.exceptions import CriticalError, SoftError, graceful_exit
from tests.mock_classes    import RxWindow


class TestCriticalError(unittest.TestCase):

    def test_critical_error(self) -> None:
        with self.assertRaises(SystemExit):
            CriticalError('test')


class TestSoftError(unittest.TestCase):

    def test_function_return(self) -> None:
        error = SoftError('test message')
        self.assertEqual(error.message, 'test message')

        error = SoftError('test message', head_clear=True)
        self.assertEqual(error.message, 'test message')

        error = SoftError('test message', tail_clear=True)
        self.assertEqual(error.message, 'test message')

        error = SoftError('test message', window=RxWindow())
        self.assertEqual(error.message, 'test message')


class TestGracefulExit(unittest.TestCase):

    def test_graceful_exit(self) -> None:
        with self.assertRaises(SystemExit):
            graceful_exit('test message')
            graceful_exit('test message', clear=False)
            graceful_exit('test message', exit_code=1)
            graceful_exit('test message', exit_code=2)


if __name__ == '__main__':
    unittest.main(exit=False)
