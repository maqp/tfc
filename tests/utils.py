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

import os
import unittest

from src.common.errors import FunctionReturn


class TFCTestCase(unittest.TestCase):

    def assertFR(self, msg, func, *args, **kwargs):
        """Check that FunctionReturn error is raised and specific message is displayed."""
        e_raised = False
        try:
            func(*args, **kwargs)
        except FunctionReturn as inst:
            e_raised = True
            self.assertEqual(inst.message, msg)

        self.assertTrue(e_raised)


def cleanup():
    for f in os.listdir('user_data/'):
        if f.startswith('ut'):
            os.remove(f'user_data/{f}')
