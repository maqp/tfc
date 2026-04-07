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

from src.common.statics import VT100

from src.common.entities.confirm_code import ConfirmationCode
from src.ui.common.output.print_message import print_message
from src.ui.common.output.vt100_utils import clear_previous_lines
from src.ui.common.utils import get_terminal_width, terminal_width_check


def get_confirmation_code(*,
                          code_displayed_on : str  # The system the confirmation code is displayed by
                          ) -> ConfirmationCode:   # The confirmation code entered by the user
    """Get confirmation code from the user."""
    while True:
        title       = f'Enter confirmation code (from {code_displayed_on}): '
        input_space = len(' ff ')

        upper_line = '┌' + (len(title) + input_space) * '─' + '┐'
        title_line = '│' +      title  + input_space  * ' ' + '│'
        lower_line = '└' + (len(title) + input_space) * '─' + '┘'

        terminal_w = get_terminal_width()
        upper_line = upper_line.center(terminal_w)
        title_line = title_line.center(terminal_w)
        lower_line = lower_line.center(terminal_w)

        terminal_width_check(len(upper_line))

        print(upper_line)
        print(title_line)
        print(lower_line)
        print(3 * VT100.CURSOR_UP_ONE_LINE)

        indent   = title_line.find('│')
        hex_code = input(indent * ' ' + f'│ {title}')

        try:
            return ConfirmationCode.from_hex(hex_code)
        except ValueError:
            print_message('Invalid confirmation code.', padding_top=1)
            clear_previous_lines(no_lines=5, delay=1)
