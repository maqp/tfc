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

from typing import TYPE_CHECKING, Optional as O, Any, Callable

from src.common.exceptions import ValidationError
from src.common.statics import B58KeyType, B58Guide, CryptoVarLength, VT100
from src.ui.common.output.print_message import print_message
from src.ui.common.output.vt100_utils import print_spacing, clear_previous_lines
from src.ui.common.utils import get_terminal_width, terminal_width_check

if TYPE_CHECKING:
    pass

Validator = Callable[..., None]


def get_input(message        : str,                    # Input prompt message
              default        : str          = '',      # Default return value
              head           : int          = 0,       # Number of new lines to print before the input
              tail           : int          = 1,       # Number of new lines to print after input
              expected_len   : int          = 0,       # Expected length of the input
              key_type       : str          = '',      # When specified, sets input width
              guide          : bool         = False ,  # When True, prints the guide for key
              validator      : O[Validator] = None,    # Input validator function
              validator_args : Any          = None     # Arguments required by the validator
              ) -> str:                                # Input from user
    """Display boxed input prompt with a message."""
    print_spacing(head)

    terminal_width = get_terminal_width()

    if key_type:
        key_guide = {B58KeyType.B58_LOCAL_KEY:  B58Guide.B58_LOCAL_KEY_GUIDE,
                     B58KeyType.B58_PUBLIC_KEY: B58Guide.B58_PUBLIC_KEY_GUIDE}.get(B58KeyType(key_type), '')
        if guide:
            inner_spc = len(key_guide) + 2
        else:
            inner_spc = CryptoVarLength.ENCODED_B58_PUB_KEY if key_type == B58KeyType.B58_PUBLIC_KEY else CryptoVarLength.ENCODED_B58_KEK
            inner_spc += 2  # Spacing around input space
    else:
        key_guide = ''
        inner_spc = terminal_width - 2 if expected_len == 0 else expected_len + 2

    upper_line = '┌'  + inner_spc * '─'  +  '┐'
    guide_line = '│ ' + key_guide        + ' │'
    input_line = '│'  + inner_spc * ' '  +  '│'
    lower_line = '└'  + inner_spc * '─'  +  '┘'
    box_indent = (terminal_width - len(upper_line)) // 2 * ' '

    terminal_width_check(len(upper_line))

    print(box_indent + upper_line)
    if guide:
        print(box_indent + guide_line)
    print(box_indent + input_line)
    print(box_indent + lower_line)
    print((5 if guide else 4) * VT100.CURSOR_UP_ONE_LINE)
    print(box_indent + '┌─┤' + message + '├')
    if guide:
        print('')

    text_input = input(box_indent + '│ ')

    if text_input == '':
        print(2 * VT100.CURSOR_UP_ONE_LINE)
        print(box_indent + '│ ' + default)
        text_input = default

    if validator is not None:
        try:
            if validator_args is None:              validator(text_input)
            elif isinstance(validator_args, tuple): validator(text_input, *validator_args)
            else:                                   validator(text_input, validator_args)
        except ValidationError as e:
            print_message(str(e), padding_top=1)
            clear_previous_lines(no_lines=4, delay=1)
            return get_input(message, default, head, tail, expected_len, key_type, guide, validator, validator_args)

    print_spacing(tail)

    return text_input
