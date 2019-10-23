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

import getpass
import typing

from typing import Any, Callable, Optional

from src.common.encoding   import b58decode
from src.common.exceptions import CriticalError
from src.common.misc       import get_terminal_width, terminal_width_check
from src.common.output     import clear_screen, m_print, print_on_previous_line, print_spacing
from src.common.statics    import (B58_LOCAL_KEY, B58_LOCAL_KEY_GUIDE, B58_PUBLIC_KEY, B58_PUBLIC_KEY_GUIDE,
                                   CURSOR_UP_ONE_LINE, ECDHE, NC_BYPASS_START, NC_BYPASS_STOP)

if typing.TYPE_CHECKING:
    from src.common.db_settings import Settings


Validator = Callable[..., str]


def ask_confirmation_code(source: str  # The system the confirmation code is displayed by
                          ) -> str:    # The confirmation code entered by the user
    """\
    Ask the user to input confirmation code from Source Computer to
    verify local key has been installed.
    """
    title       = f"Enter confirmation code (from {source}): "
    input_space = len(' ff ')

    upper_line = ('┌' + (len(title) + input_space) * '─' + '┐')
    title_line = ('│' +      title  + input_space  * ' ' + '│')
    lower_line = ('└' + (len(title) + input_space) * '─' + '┘')

    terminal_w = get_terminal_width()
    upper_line = upper_line.center(terminal_w)
    title_line = title_line.center(terminal_w)
    lower_line = lower_line.center(terminal_w)

    terminal_width_check(len(upper_line))

    print(upper_line)
    print(title_line)
    print(lower_line)
    print(3 * CURSOR_UP_ONE_LINE)

    indent = title_line.find('│')
    return input(indent * ' ' + f'│ {title}')


def box_input(message:        str,                          # Input prompt message
              default:        str                 = '',     # Default return value
              head:           int                 = 0,      # Number of new lines to print before the input
              tail:           int                 = 1,      # Number of new lines to print after input
              expected_len:   int                 = 0,      # Expected length of the input
              key_type:       str                 = '',     # When specified, sets input width
              guide:          bool                = False,  # When True, prints the guide for key
              validator:      Optional[Validator] = None,   # Input validator function
              validator_args: Optional[Any]       = None    # Arguments required by the validator
              ) -> str:                                     # Input from user
    """Display boxed input prompt with a message."""
    print_spacing(head)

    terminal_width = get_terminal_width()

    if key_type:
        key_guide = {B58_LOCAL_KEY:  B58_LOCAL_KEY_GUIDE,
                     B58_PUBLIC_KEY: B58_PUBLIC_KEY_GUIDE}.get(key_type, '')
        if guide:
            inner_spc = len(key_guide) + 2
        else:
            inner_spc = (86 if key_type == B58_PUBLIC_KEY else 53)
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
    print((5 if guide else 4) * CURSOR_UP_ONE_LINE)
    print(box_indent + '┌─┤' + message + '├')
    if guide:
        print('')

    user_input = input(box_indent + '│ ')

    if user_input == '':
        print(2 * CURSOR_UP_ONE_LINE)
        print(box_indent + '│ ' + default)
        user_input = default

    if validator is not None:
        error_msg = validator(user_input, validator_args)
        if error_msg:
            m_print(error_msg, head=1)
            print_on_previous_line(reps=4, delay=1)
            return box_input(message, default, head, tail, expected_len, key_type, guide, validator, validator_args)

    print_spacing(tail)

    return user_input


def get_b58_key(key_type:      str,         # The type of Base58 key to be entered
                settings:      'Settings',  # Settings object
                short_address: str = ''     # The contact's short Onion address
                ) -> bytes:                 # The Base58 decoded key
    """Ask the user to input a Base58 encoded key."""
    if key_type == B58_PUBLIC_KEY:
        clear_screen()
        m_print(f"{ECDHE} key exchange", head=1, tail=1, bold=True)
        m_print("If needed, resend your public key to the contact by pressing <Enter>", tail=1)

        box_msg = f"Enter public key of {short_address} (from Relay)"
    elif key_type == B58_LOCAL_KEY:
        box_msg = "Enter local key decryption key (from Transmitter)"
    else:
        raise CriticalError("Invalid key type")

    while True:
        rx_pk = box_input(box_msg, key_type=key_type, guide=not settings.local_testing_mode)
        rx_pk = ''.join(rx_pk.split())

        if key_type == B58_PUBLIC_KEY and rx_pk == '':
            return rx_pk.encode()

        try:
            return b58decode(rx_pk, public_key=(key_type == B58_PUBLIC_KEY))
        except ValueError:
            m_print("Checksum error - Check that the entered key is correct.")
            print_on_previous_line(reps=(4 if settings.local_testing_mode else 5), delay=1)


def nc_bypass_msg(key: str, settings: 'Settings') -> None:
    """Print messages about bypassing Networked Computer.

    During ciphertext delivery of local key exchange, these bypass
    messages tell the user when to bypass and remove bypass of Networked
    Computer. Bypass of Networked Computer makes initial bootstrap more
    secure by denying remote attacker the access to the encrypted local
    key. Without the ciphertext, e.g. a visually collected local key
    decryption key is useless.
    """
    m = {NC_BYPASS_START: "Bypass Networked Computer if needed. Press <Enter> to send local key.",
         NC_BYPASS_STOP:  "Remove bypass of Networked Computer. Press <Enter> to continue."}

    if settings.nc_bypass_messages:
        m_print(m[key], manual_proceed=True, box=True, head=(1 if key == NC_BYPASS_STOP else 0))


def pwd_prompt(message: str,          # Prompt message
               repeat:  bool = False  # When True, prints corner chars for the second box
               ) -> str:              # Password from user
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
    print(3 * CURSOR_UP_ONE_LINE)

    indent     = title_line.find('│')
    user_input = getpass.getpass(indent * ' ' + f'│ {message}')

    return user_input


def yes(prompt: str,                    # Question to be asked
        abort:  Optional[bool] = None,  # Determines the return value of ^C and ^D
        head:   int = 0,                # Number of new lines to print before prompt
        tail:   int = 0                 # Number of new lines to print after prompt
        ) -> bool:                      # True/False depending on input
    """Prompt the user a question that is answered with yes/no."""
    print_spacing(head)

    prompt      = f"{prompt} (y/n): "
    input_space = len(' yes ')

    upper_line = ('┌' + (len(prompt) + input_space) * '─' + '┐')
    title_line = ('│' +      prompt  + input_space  * ' ' + '│')
    lower_line = ('└' + (len(prompt) + input_space) * '─' + '┘')

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
        print(3 * CURSOR_UP_ONE_LINE)

        try:
            user_input = input(indent * ' ' + f'│ {prompt}')
        except (EOFError, KeyboardInterrupt):
            if abort is None:
                raise
            print('')
            user_input = 'y' if abort else 'n'

        print_on_previous_line()

        if user_input == '':
            continue

        if user_input.lower() in ['y', 'yes']:
            print(indent * ' ' + f'│ {prompt}Yes │\n')
            print_spacing(tail)
            return True

        elif user_input.lower() in ['n', 'no']:
            print(indent * ' ' + f'│ {prompt}No  │\n')
            print_spacing(tail)
            return False
