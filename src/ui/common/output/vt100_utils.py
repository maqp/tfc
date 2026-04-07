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

import os
import sys
import time

from src.common.statics import VT100, ShellCommand


def clear_screen(delay: float = 0.0) -> None:
    """Clear the terminal window."""
    time.sleep(delay)
    sys.stdout.write(  VT100.CLEAR_ENTIRE_SCREEN.value
                     + VT100.CURSOR_LEFT_UP_CORNER.value)
    sys.stdout.flush()


def print_spacing(count: int = 0) -> None:
    """Print `count` many new-lines."""
    for _ in range(count):
        print()


def clear_previous_lines(*,
                         no_lines : int,           # Number of times to repeat the action
                         delay    : float = 0.0,   # Time to sleep before clearing lines above
                         flush    : bool  = False  # Flush stdout when true
                         ) -> None:
    """Next message is printed on upper line."""
    time.sleep(delay)

    for _ in range(no_lines):
        sys.stdout.write(VT100.CURSOR_UP_ONE_LINE.value + VT100.CLEAR_ENTIRE_LINE.value)
    if flush:
        sys.stdout.flush()


def reset_terminal() -> None:
    """Reset terminal."""
    os.system(ShellCommand.RESET)
