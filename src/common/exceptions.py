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

import inspect
import sys

from contextlib import contextmanager
from datetime import datetime
from typing import TYPE_CHECKING, Optional as O, Type, Iterator, Any

if TYPE_CHECKING:
    from src.ui.receiver.window_rx import RxWindow
    from src.database.db_settings import Settings


@contextmanager
def ignored(*exceptions: Type[BaseException]) -> Iterator[Any]:
    """Ignore an exception."""
    try:
        yield
    except exceptions:
        pass


class ValidationError(Exception):
    """Exception raised when a validation fails."""
    pass


class CheckInputError(Exception):
    """Exception raised when user needs to check the input from Relay Program."""
    pass


class InvalidPassword(Exception):
    """Exception raised when a password is invalid."""
    pass


class SoftError(Exception):
    """A soft exception from which TFC can automatically recover from.

    When a SoftError is raised, TFC prints a message
    and returns to the exception handler function.
    """

    def __init__(self,
                 message        : str,
                 window         : O['RxWindow'] = None,
                 output         : bool          = True,
                 bold           : bool          = False,
                 clear_before   : bool          = False,
                 clear_after    : bool          = False,
                 clear_delay    : float         = 0.0,
                 padding_top    : int           = 1,
                 padding_bottom : int           = 1,
                 ts             : O['datetime'] = None
                 ) -> None:
        """Print return message and return to exception handler function."""
        from src.ui.common.output.print_message import print_message

        # Prevent quickly disappearing messages from screen
        if clear_after: clear_delay = max(clear_delay, 0.5)

        super().__init__(message)
        self.message = message

        if window is None:
            if output:
                print_message(self.message,
                              bold           = bold,
                              clear_before   = clear_before,
                              clear_after    = clear_after,
                              clear_delay    = clear_delay,
                              padding_top    = padding_top,
                              padding_bottom = padding_bottom)
        else:
            ts = datetime.now() if ts is None else ts
            window.add_new_system_message(ts, self.message, output=output)


def raise_if_traffic_masking(settings: 'Settings', only_if: O[bool] = None) -> None:
    """Raise exception if traffic masking is enabled.

    Some commands will reveal TFC usage on Relay program.
    This function prevents those functions from being called.
    """
    # Extra conditions that need to be true for the exception to be raised
    if only_if is not None and not only_if:
        return

    if settings.traffic_masking:
        raise SoftError('Error: Command is disabled during traffic masking.', clear_before=True)


class CriticalError(Exception):

    """A severe exception that requires TFC to gracefully exit."""
    def __init__(self, error_message: str, exit_code: int = 1) -> None:
        """A severe exception that requires TFC to gracefully exit."""
        super().__init__(error_message)
        graceful_exit(f"Critical error in function '{inspect.stack()[1][3]}':\n{error_message}",
                      clear=False, exit_code=exit_code)




def graceful_exit(message   : str  = '',    # Exit message to print
                  clear     : bool = True,  # When False, does not clear screen before printing message
                  exit_code : int  = 0      # Value returned to parent process
                  ) -> None:
    """Display a message and exit TFC."""
    from src.common.statics import ProgramLiterals
    from src.ui.common.output.vt100_utils import clear_screen

    if clear:
        clear_screen()
    if message:
        print('\n' + message)
    print(f'\nExiting {ProgramLiterals.NAME.value}.\n')

    sys.exit(exit_code)

