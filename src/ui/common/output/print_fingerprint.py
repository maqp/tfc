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

from typing import TYPE_CHECKING

from src.common.utils.encoding import b10encode
from src.common.utils.strings import split_string
from src.ui.common.output.print_message import print_message

if TYPE_CHECKING:
    from src.common.crypto.fingerprint import Fingerprint


def print_fingerprint(fingerprint: 'Fingerprint', msg : str = '') -> None:
    """Print a formatted message and fingerprint inside the box.

    Truncate fingerprint for clean layout with three rows that have
    five groups of five numbers, for example:

       ┌───────────────────────────────┐
       │     Fingerprint for Alice     │
       │                               │
       │ 45408 66244 60063 51146 49842 │
       │ 54936 03101 11892 94057 51231 │
       │ 59374 09637 58434 47573 71137 │
       └───────────────────────────────┘

    The resulting fingerprint has 249.15 bits of entropy which
    is more than the symmetric security of X448 (224 bits).
    """
    message_list        = [msg, ''] if msg else []
    base_10_fingerprint = b10encode(fingerprint)[:(3 * 5 * 5)]
    fingerprint_rows    = split_string(base_10_fingerprint, item_len=(5*5))
    message_list       += [' '.join(split_string(row, item_len=5)) for row in fingerprint_rows]
    print_message(message_list, box=True)
