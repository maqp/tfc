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

import unittest

from src.common.errors import CriticalError, graceful_exit


class Window(object):

    def __init__(self):
        pass

    def print_new(self, *_):
        pass


class TestErrors(unittest.TestCase):

    def test_critical_error(self):
        with self.assertRaises(SystemExit):
            CriticalError('test')

    def test_graceful_exit(self):
        with self.assertRaises(SystemExit):
            graceful_exit('test message')
            graceful_exit('test message', clear=True)


if __name__ == '__main__':
    unittest.main(exit=False)
