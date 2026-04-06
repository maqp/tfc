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

import getpass

from src.common.statics import VT100
from src.ui.common.utils import get_terminal_width, terminal_width_check


def get_password(message : str,          # Prompt message
                 repeat  : bool = False  # When True, prints corner chars for the second box
                 ) -> str:               # Password from user
    """Prompt the user to enter a password.

    The getpass library ensures the password is not echoed on screen
    when it is typed.
    """
    l, r = ('├', '┤') if repeat else ('┌', '┐')

    terminal_w  = get_terminal_width()
    input_space = len(' c ')  # `c` is where the caret sits

    upper_line = ( l  + (len(message) + input_space) * '─' +  r ).center(terminal_w)
    title_line = ('│' +      message  + input_space  * ' ' + '│').center(terminal_w)
    lower_line = ('└' + (len(message) + input_space) * '─' + '┘').center(terminal_w)

    terminal_width_check(len(upper_line))

    print(upper_line)
    print(title_line)
    print(lower_line)
    print(3 * VT100.CURSOR_UP_ONE_LINE)

    indent     = title_line.find('│')
    user_input = getpass.getpass(indent * ' ' + f'│ {message}')

    return user_input
