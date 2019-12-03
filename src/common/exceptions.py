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

import inspect
import sys
import typing

from datetime import datetime
from typing import Optional

from src.common.output import clear_screen, m_print
from src.common.statics import TFC

if typing.TYPE_CHECKING:
    from src.receiver.windows import RxWindow


class CriticalError(Exception):
    """A severe exception that requires TFC to gracefully exit."""

    def __init__(self, error_message: str, exit_code: int = 1) -> None:
        """A severe exception that requires TFC to gracefully exit."""
        graceful_exit(
            f"Critical error in function '{inspect.stack()[1][3]}':\n{error_message}",
            clear=False,
            exit_code=exit_code,
        )


class SoftError(Exception):
    """A soft exception from which TFC can automatically recover from.

    When a SoftError is raised, TFC prints a message
    and returns to the exception handler function.
    """

    def __init__(
        self,
        message: str,
        window: Optional["RxWindow"] = None,  # The window to include the message in
        output: bool = True,  # When False, doesn't print message when adding it to window
        bold: bool = False,  # When True, prints the message in bold
        head_clear: bool = False,  # When True, clears the screen before printing message
        tail_clear: bool = False,  # When True, clears the screen after message (needs delay)
        delay: float = 0,  # The delay before continuing
        head: int = 1,  # The number of new-lines to print before the message
        tail: int = 1,  # The number of new-lines to print after message
        ts: Optional["datetime"] = None,  # Datetime object
    ) -> None:
        """Print return message and return to exception handler function."""
        self.message = message

        if window is None:
            if output:
                m_print(
                    self.message,
                    bold=bold,
                    head_clear=head_clear,
                    tail_clear=tail_clear,
                    delay=delay,
                    head=head,
                    tail=tail,
                )
        else:
            ts = datetime.now() if ts is None else ts
            window.add_new(ts, self.message, output=output)


def graceful_exit(
    message: str = "",  # Exit message to print
    clear: bool = True,  # When False, does not clear screen before printing message
    exit_code: int = 0,  # Value returned to parent process
) -> None:
    """Display a message and exit TFC."""
    if clear:
        clear_screen()
    if message:
        print("\n" + message)
    print(f"\nExiting {TFC}.\n")

    sys.exit(exit_code)
