#!/usr/bin/env python3.5
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
import unittest

from src.nh.misc import process_arguments

from tests.utils import TFCTestCase


class TestMisc(TFCTestCase):

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

    def setUp(self):
        self.o_argparse         = argparse.ArgumentParser
        argparse.ArgumentParser = TestMisc.MockParser

    def tearDown(self):
        argparse.ArgumentParser = self.o_argparse

    def test_process_arguments(self):
        self.assertEqual(process_arguments(), (True, True))


if __name__ == '__main__':
    unittest.main(exit=False)
