#!/usr/bin/env python3.7
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

import unittest

from src.common.word_list import eff_wordlist


class TestWordList(unittest.TestCase):
    def test_each_word_is_unique(self) -> None:
        self.assertEqual(len(eff_wordlist), len(set(eff_wordlist)))

    def test_word_list_length(self) -> None:
        self.assertEqual(len(eff_wordlist), 7776)


if __name__ == "__main__":
    unittest.main()
