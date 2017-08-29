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

import inspect
import sys
import time
import typing

from datetime import datetime

from src.common.output import c_print, clear_screen

if typing.TYPE_CHECKING:
    from src.rx.windows import RxWindow


class CriticalError(Exception):
    """A variety of errors during which TFC should gracefully exit."""

    def __init__(self, error_message: str) -> None:
        graceful_exit("Critical error in function '{}':\n{}"
                      .format(inspect.stack()[1][3], error_message), clear=False, exit_code=1)


class FunctionReturn(Exception):
    """Print return message and return to exception handler function."""

    def __init__(self,
                 message:    str,
                 output:     bool       = True,
                 delay:      float      = 0,
                 window:     'RxWindow' = None,
                 head:       int        = 1,
                 tail:       int        = 1,
                 head_clear: bool       = False,
                 tail_clear: bool       = False) -> None:
        self.message = message

        if window is None:
            if output:
                if head_clear:
                    clear_screen()
                c_print(self.message, head=head, tail=tail)
            time.sleep(delay)
            if tail_clear:
                clear_screen()
        else:
            window.add_new(datetime.now(), self.message, output=output)


def graceful_exit(message: str ='', clear: bool = True, exit_code: int = 0) -> None:
    """Display a message and exit TFC."""
    if clear:
        clear_screen()
    if message:
        print('\n' + message)
    print("\nExiting TFC.\n")

    sys.exit(exit_code)
