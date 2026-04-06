#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
TFC - Onion-routed, endpoint secure messaging system
Copyright (C) 2013-2026  Markus Ottela

This file is part of TFC.
TFC is free software: you can redistribute it and/or modify it under the terms
of the GNU General Public License as published by the Free Software Foundation,
either version 3 of the License, or (at your option) any later version. TFC is
distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without
even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
See the GNU General Public License for more details. You should have received a
copy of the GNU General Public License along with TFC. If not, see
<https://www.gnu.org/licenses/>.
"""

import math


def human_readable_size(size: int) -> str:
    """Convert file size from bytes to a human-readable form."""
    f_size = float(size)
    for unit in ['', 'K', 'M', 'G', 'T', 'P', 'E', 'Z']:
        if abs(f_size) < 1024.0:
            return f'{f_size:3.1f}{unit}B'
        f_size /= 1024.0
    return f'{f_size:3.1f}YB'


def round_up(value: int|float) -> int:
    """Round value to next 10."""
    return int(math.ceil(value / 10.0)) * 10
