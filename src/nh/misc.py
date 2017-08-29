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

from typing import Tuple


def process_arguments() -> Tuple[bool, bool]:
    """Define nh.py settings from arguments passed from command line."""
    parser = argparse.ArgumentParser("python3.6 nh.py",
                                     usage="%(prog)s [OPTION]",
                                     description="More options inside nh.py")

    parser.add_argument('-l',
                        action='store_true',
                        default=False,
                        dest='local_test',
                        help="Enable local testing mode")

    parser.add_argument('-d',
                        action='store_true',
                        default=False,
                        dest='dd_sockets',
                        help="Enable data diode simulator sockets")

    args = parser.parse_args()

    return args.local_test, args.dd_sockets
