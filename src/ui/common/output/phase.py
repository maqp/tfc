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

import time

from types import TracebackType
from typing import Callable, Optional as O, TypeAlias

from src.common.statics import StatusMsg
from src.ui.common.output.vt100_utils import print_spacing
from src.ui.common.utils import get_terminal_width


DoneMessageUpdater: TypeAlias = Callable[[str], None]


class Phase:
    """Context manager that prints a phase start and completion message."""

    def __init__(self,
                 description    : str,
                 done_message   : str   = '',
                 *,
                 padding_top    : int   = 0,
                 padding_bottom : int   = 0,
                 delay          : float = 0.5
                 ) -> None:
        self.description          = description
        self.done_message         = done_message or StatusMsg.DONE
        self.padding_top          = padding_top
        self.padding_bottom       = padding_bottom
        self.delay                = delay
        self.current_done_message = self.done_message

    def __enter__(self) -> DoneMessageUpdater:
        """Print the phase description and return a completion-message updater."""
        print_spacing(self.padding_top)
        message_when_done     = f'{self.description}... {self.current_done_message}'
        whitespace_around_msg = get_terminal_width() - len(message_when_done)
        text_indent           = (whitespace_around_msg // 2) * ' '
        print(f'{text_indent}{self.description}... ', end='', flush=True)
        return self.update_done_message

    def __exit__(self,
                 exc_type  : O[type[BaseException]],
                 exc_value : O[BaseException],
                 traceback : O[TracebackType]
                 ) -> None:
        """Print the completion message unless the phase failed."""
        if exc_type is not None:
            print('FAILED')
            return

        print(self.current_done_message)
        print_spacing(self.padding_bottom)
        time.sleep(self.delay)

    def update_done_message(self, value: str) -> None:
        """Set the completion message printed when the phase exits."""
        self.current_done_message = value


def phase(description    : str,         # Description of the phase
          done_message   : str   = '',  # The done message to use once complete.
          *,
          padding_top    : int   = 0,   # Number of inserted new lines before print
          padding_bottom : int   = 0,   # Number of inserted new lines after print
          delay          : float = 0.5  # Duration of phase completion message
          ) -> Phase:
    """Print phase and completion message around some time consuming task.

    Returns a context manager whose `as` target is a callback that can
    be used to override the completion message.

    Usage:
        with phase('Doing time consuming task', 'COMPLETE'):
            some_time_consuming_task()

        with phase('Hashing file') as update_done_message:
            digest = hash_file(path)
            update_done_message(f'COMPLETE: {digest}')
    """
    return Phase(description,
                 done_message,
                 padding_top    = padding_top,
                 padding_bottom = padding_bottom,
                 delay          = delay)
