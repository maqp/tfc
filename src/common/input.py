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

import getpass
import typing

from typing import Any, Callable

from src.common.encoding   import b58decode
from src.common.exceptions import CriticalError
from src.common.misc       import get_terminal_width
from src.common.output     import box_print, c_print, clear_screen, message_printer, print_on_previous_line
from src.common.statics    import *

if typing.TYPE_CHECKING:
    from src.common.db_settings import Settings


def ask_confirmation_code() -> str:
    """\
    Ask user to input confirmation code from RxM
    to verify that local key has been installed.

    Input box accommodates room for the 'resend' command.
    """
    title = "Enter confirmation code (from RxM): "
    space = len(' resend ')

    upper_line = ('┌' + (len(title) + space) * '─' + '┐')
    title_line = ('│' +      title  + space  * ' ' + '│')
    lower_line = ('└' + (len(title) + space) * '─' + '┘')

    terminal_w = get_terminal_width()
    upper_line = upper_line.center(terminal_w)
    title_line = title_line.center(terminal_w)
    lower_line = lower_line.center(terminal_w)

    print(upper_line)
    print(title_line)
    print(lower_line)
    print(3 * CURSOR_UP_ONE_LINE)

    indent = title_line.find('│')
    return input(indent * ' ' + '│ {}'.format(title))


def box_input(message:        str,
              default:        str      = '',
              head:           int      = 0,
              tail:           int      = 1,
              expected_len:   int      = 0,
              validator:      Callable = None,
              validator_args: Any      = None,
              key_input:      bool     = False) -> str:
    """Display boxed input prompt with title.

    :param message:        Input prompt message
    :param default:        Default return value
    :param head:           Number of new lines to print before input
    :param tail:           Number of new lines to print after input
    :param expected_len    Expected length of input
    :param validator:      Input validator function
    :param validator_args: Arguments required by the validator
    :param key_input:      When True, prints key input position guide
    :return:               Input from user
    """
    for _ in range(head):
        print('')

    terminal_w = get_terminal_width()
    input_len  = terminal_w - 2 if expected_len == 0 else expected_len + 2

    if key_input:
        input_len += 2

    input_top_line = '┌'   + input_len * '─'                 +   '┐'
    key_pos_guide  = '│  ' + '   '.join('ABCDEFGHIJKLMNOPQ') + '  │'
    input_line     = '│'   + input_len * ' '                 +   '│'
    input_bot_line = '└'   + input_len * '─'                 +   '┘'

    input_line_indent = (terminal_w - len(input_line)) // 2
    input_box_indent  = input_line_indent * ' '

    print(input_box_indent + input_top_line)
    if key_input:
        print(input_box_indent + key_pos_guide)
    print(input_box_indent + input_line)
    print(input_box_indent + input_bot_line)
    print((5 if key_input else 4) * CURSOR_UP_ONE_LINE)
    print(input_box_indent + '┌─┤' + message + '├')
    if key_input:
        print('')

    user_input = input(input_box_indent + '│ ')

    if user_input == '':
        print(2 * CURSOR_UP_ONE_LINE)
        print(input_box_indent + '│ {}'.format(default))
        user_input = default

    if validator is not None:
        error_msg = validator(user_input, validator_args)
        if error_msg:
            c_print("Error: {}".format(error_msg), head=1)
            print_on_previous_line(reps=4, delay=1.5)
            return box_input(message, default, head, tail, expected_len, validator, validator_args)

    for _ in range(tail):
        print('')

    return user_input


def get_b58_key(key_type: str, settings: 'Settings') -> bytes:
    """Ask user to input Base58 encoded public key from RxM.

    For file keys, use testnet address format instead to
    prevent file injected via import from accidentally
    being decrypted with public key from adversary.
    """
    if key_type == B58_PUB_KEY:
        clear_screen()
        c_print("Import public key from RxM", head=1, tail=1)
        c_print("WARNING")
        message_printer("Outside specific requests TxM (this computer) "
                        "makes, you must never copy any data from "
                        "NH/RxM to TxM. Doing so could infect TxM, that "
                        "could then later covertly transmit private "
                        "keys/messages to attacker.", head=1, tail=1)
        message_printer("You can resend your public key by typing 'resend'", tail=1)
        box_msg = "Enter contact's public key from RxM"
    elif key_type == B58_LOCAL_KEY:
        box_msg = "Enter local key decryption key from TxM"
    elif key_type == B58_FILE_KEY:
        box_msg = "Enter file decryption key"
    else:
        raise CriticalError("Invalid key type")

    while True:
        if settings.local_testing_mode or key_type == B58_FILE_KEY:
            pub_key = box_input(box_msg, expected_len=51)
            small   = True
        else:
            pub_key = box_input(box_msg, expected_len=65, key_input=True)
            small   = False
        pub_key = ''.join(pub_key.split())

        if key_type == B58_PUB_KEY and pub_key == RESEND:
            return pub_key.encode()

        try:
            return b58decode(pub_key, file_key=(key_type==B58_FILE_KEY))
        except ValueError:
            c_print("Checksum error - Check that entered key is correct.", head=1)
            print_on_previous_line(reps=5 if small else 6, delay=1.5)


def nh_bypass_msg(key: str, settings: 'Settings') -> None:
    """Print messages about bypassing NH.

    During ciphertext delivery of local key exchange, NH bypass messages
    tell user when to bypass and remove bypass of NH. This makes initial
    key bootstrap more secure in case key decryption key input is not safe.
    """
    m = {NH_BYPASS_START: "Bypass NH if needed. Press <Enter> to send local key.",
         NH_BYPASS_STOP:  "Remove bypass of NH. Press <Enter> to continue."}

    if settings.nh_bypass_messages:
        box_print(m[key], manual_proceed=True, head=(1 if key == NH_BYPASS_STOP else 0))


def pwd_prompt(message: str, second: bool = False) -> str:
    """Prompt user to enter a password.

    :param message: Prompt message
    :param second:  When True, prints corner chars for second box
    :return:        Password from user
    """
    l, r = {False: ('┌', '┐'),
            True:  ('├', '┤')}[second]

    upper_line = ( l  + (len(message) + 3) * '─' +  r )
    title_line = ('│' +      message  + 3  * ' ' + '│')
    lower_line = ('└' + (len(message) + 3) * '─' + '┘')

    terminal_w = get_terminal_width()
    upper_line = upper_line.center(terminal_w)
    title_line = title_line.center(terminal_w)
    lower_line = lower_line.center(terminal_w)

    print(upper_line)
    print(title_line)
    print(lower_line)
    print(3 * CURSOR_UP_ONE_LINE)

    indent     = title_line.find('│')
    user_input = getpass.getpass(indent * ' ' + '│ {}'.format(message))

    return user_input


def yes(prompt: str, head: int = 0, tail: int = 0) -> bool:
    """Prompt user a question that is answered with yes / no.

    :param prompt: Question to be asked
    :param head:   Number of new lines to print before prompt
    :param tail:   Number of new lines to print after prompt
    :return:       True if user types 'y' or 'yes'
                   False if user types 'n' or 'no'
    """
    for _ in range(head):
        print('')

    prompt     = "{} (y/n): ".format(prompt)
    upper_line = ('┌' + (len(prompt) + 5) * '─' + '┐')
    title_line = ('│' +       prompt + 5  * ' ' + '│')
    lower_line = ('└' + (len(prompt) + 5) * '─' + '┘')

    terminal_w = get_terminal_width()
    upper_line = upper_line.center(terminal_w)
    title_line = title_line.center(terminal_w)
    lower_line = lower_line.center(terminal_w)

    indent = title_line.find('│')

    print(upper_line)
    while True:
        print(title_line)
        print(lower_line)
        print(3 * CURSOR_UP_ONE_LINE)
        user_input = input(indent * ' ' + '│ {}'.format(prompt))
        print_on_previous_line()

        if user_input == '':
            continue

        if user_input.lower() in ['y', 'yes']:
            print(indent * ' ' + '│ {}Yes │\n'.format(prompt))
            for _ in range(tail):
                print('')
            return True

        elif user_input.lower() in ['n', 'no']:
            print(indent * ' ' + '│ {}No  │\n'.format(prompt))
            for _ in range(tail):
                print('')
            return False
