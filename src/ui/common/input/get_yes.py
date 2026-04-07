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

from typing import Optional as O

from src.common.statics import VT100
from src.ui.common.output.vt100_utils import print_spacing, clear_previous_lines
from src.ui.common.utils import get_terminal_width, terminal_width_check


def get_yes(prompt : str,             # Question to be asked
            abort  : O[bool] = None,  # Determines the return value of ^C and ^D
            head   : int     = 0,     # Number of new lines to print before prompt
            tail   : int     = 0      # Number of new lines to print after prompt
            ) -> bool:                # True/False depending on input
    """Prompt the user a question that is answered with yes/no."""
    print_spacing(head)

    prompt      = f'{prompt} (y/n): '
    input_space = len(' yes ')

    upper_line = '┌' + (len(prompt) + input_space) * '─' + '┐'
    title_line = '│' +      prompt  + input_space  * ' ' + '│'
    lower_line = '└' + (len(prompt) + input_space) * '─' + '┘'

    terminal_w = get_terminal_width()
    upper_line = upper_line.center(terminal_w)
    title_line = title_line.center(terminal_w)
    lower_line = lower_line.center(terminal_w)

    indent = title_line.find('│')

    terminal_width_check(len(upper_line))

    print(upper_line)
    while True:
        print(title_line)
        print(lower_line)
        print(3 * VT100.CURSOR_UP_ONE_LINE)

        try:
            user_input = input(indent * ' ' + f'│ {prompt}')
        except (EOFError, KeyboardInterrupt):
            if abort is None:
                raise
            print('')
            user_input = 'y' if abort else 'n'

        clear_previous_lines(no_lines=1)

        if user_input == '':
            continue

        if user_input.lower() in ['y', 'yes']:
            print(indent * ' ' + f'│ {prompt}Yes │\n')
            print_spacing(tail)
            return True

        if user_input.lower() in ['n', 'no']:
            print(indent * ' ' + f'│ {prompt}No  │\n')
            print_spacing(tail)
            return False

    raise RuntimeError('Broke out of loop')
