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

import datetime
import inspect
import sys
import time

from typing import Any

from src.common.misc    import clear_screen
from src.common.output  import c_print
from src.common.statics import *


class CriticalError(Exception):
    """A variety of errors during which Tx.py should gracefully exit."""

    def __init__(self, error_message: str) -> None:
        graceful_exit("Critical error in function '{}':\n{}"
                      .format(inspect.stack()[1][3], error_message), clear=False)


class FunctionReturn(Exception):
    """Print return message and return to exception handler function."""

    def __init__(self, return_msg: str, output: bool = True, delay: float = 0, window: Any = None) -> None:
        self.message = return_msg

        if window is None:
            if output:
                clear_screen()
                c_print(self.message, head=1, tail=1)
            time.sleep(delay)
        else:
            window.print_new(datetime.datetime.now(), return_msg)


def graceful_exit(message='', clear=True):
    """Display a message and exit Tx.py."""
    if clear:
        sys.stdout.write(CLEAR_ENTIRE_SCREEN + CURSOR_LEFT_UP_CORNER)
    if message:
        print("\n" + message)
    print("\nExiting TFC.\n")
    exit()
