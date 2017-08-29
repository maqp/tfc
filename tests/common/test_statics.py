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

import src.common.statics


class TestStatics(unittest.TestCase):

    def test_uniqueness(self):
        variable_list = [getattr(src.common.statics, item) for item in dir(src.common.statics) if not item.startswith("__")]
        variable_list = [v for v in variable_list if (isinstance(v, str) or isinstance(v, bytes))]

        # Debugger
        for unique_variable in list(set(variable_list)):
            repeats = 0
            for variable in variable_list:
                if variable == unique_variable:
                    repeats += 1
            if repeats > 1:
                spacing = (3 - len(unique_variable)) * ' '
                print(f"Setting value '{unique_variable}'{spacing} appeared in {repeats} variables: ", end='')
                items = [i for i in dir(src.common.statics)
                         if not i.startswith("__") and getattr(src.common.statics, i) == unique_variable]
                print(', '.join(items))

        self.assertEqual(len(list(set(variable_list))), len(variable_list))


if __name__ == '__main__':
    unittest.main(exit=False)
