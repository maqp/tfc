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

from src.common.encoding import b58decode
from src.common.errors   import CriticalError
from src.common.misc     import clear_screen, get_tty_w
from src.common.output   import box_print, c_print, message_printer, print_on_previous_line
from src.common.statics  import *

if typing.TYPE_CHECKING:
    from src.common.db_settings import Settings


def box_input(title:          str,
              default:        str      = '',
              head:           int      = 0,
              tail:           int      = 0,
              expected_len:   int      = 0,
              validator:      Callable = None,
              validator_args: Any      = None) -> str:
    """Display boxed prompt for user with title.

    :param title:          Title for data to prompt
    :param default:        Default return value
    :param head:           Number of new lines to print before input
    :param tail:           Number of new lines to print after input
    :param expected_len    Expected length of input
    :param validator:      Input validator function
    :param validator_args: Arguments required by the validator
    :return:               Input from user
    """
    for _ in range(head):
        print('')

    tty_w     = get_tty_w()
    input_len = tty_w - 2 if expected_len == 0 else expected_len + 2

    input_top_line = '┌' + input_len * '─' + '┐'
    input_line     = '│' + input_len * ' ' + '│'
    input_bot_line = '└' + input_len * '─' + '┘'

    input_line_indent = (tty_w - len(input_line)) // 2
    input_box_indent  = input_line_indent * ' '

    print(input_box_indent + input_top_line)
    print(input_box_indent + input_line)
    print(input_box_indent + input_bot_line)
    print(4 * CURSOR_UP_ONE_LINE)
    print(input_box_indent + '┌─┤' + title + '├')

    user_input = input(input_box_indent + '│ ')

    if user_input == '':
        print(2 * CURSOR_UP_ONE_LINE)
        print(input_box_indent + f'│ {default}')
        user_input = default

    if validator is not None:
        success, error_msg = validator(user_input, validator_args)
        if not success:
            c_print("Error: {}".format(error_msg), head=1)
            print_on_previous_line(reps=4, delay=1.5)
            return box_input(title, default, head, tail, expected_len, validator, validator_args)

    for _ in range(tail):
        print('')

    return user_input


def get_b58_key(k_type: str) -> bytes:
    """Ask user to input Base58 encoded public key from RxM."""
    if k_type == 'pubkey':
        clear_screen()
        c_print("Import public key from RxM", head=1, tail=1)
        c_print("WARNING")
        message_printer("Key exchange will break the HW separation. "
                        "Outside specific requests TxM (this computer) "
                        "makes, you must never copy any data from "
                        "NH/RxM to TxM. Doing so could infect TxM, that "
                        "could then later covertly transmit private "
                        "keys/messages to adversary on NH.", head=1, tail=1)
        box_msg = "Enter contact's public key from RxM"
    elif k_type == 'localkey':
        box_msg = "Enter local key decryption key from TxM"
    elif k_type == 'imported_file':
        box_msg = "Enter file decryption key"
    else:
        raise CriticalError("Invalid key type")

    while True:
        pub_key = box_input(box_msg, expected_len=59)
        pub_key = ''.join(pub_key.split())

        try:
            return b58decode(pub_key)
        except ValueError:
            c_print("Checksum error - Check that entered key is correct.", head=1)
            print_on_previous_line(reps=4, delay=1.5)


def nh_bypass_msg(key: str, settings: 'Settings') -> None:
    """Print messages about bypassing NH."""
    m = dict(start ="Bypass NH if needed. Press <Enter> to send local key.",
             finish="Remove bypass of NH. Press <Enter> to continue.")

    if settings.nh_bypass_messages:
        box_print(m[key], manual_proceed=True)


def pwd_prompt(message: str, lc: str, rc: str) -> str:
    """Prompt user to enter a password.

    :param message: Prompt message
    :param lc:      Upper-left corner box character
    :param rc:      Upper-right corner box character
    :return:        Password from user
    """
    upper_line = (lc  + (len(message) + 3) * '─' +  rc)
    title_line = ('│' +      message  + 3  * ' ' + '│')
    lower_line = ('└' + (len(message) + 3) * '─' + '┘')

    upper_line = upper_line.center(get_tty_w())
    title_line = title_line.center(get_tty_w())
    lower_line = lower_line.center(get_tty_w())

    print(upper_line)
    print(title_line)
    print(lower_line)
    print(3 * CURSOR_UP_ONE_LINE)

    indent     = title_line.find('│')
    user_input = getpass.getpass(indent * ' ' + f'│ {message}')

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
    tty_w      = get_tty_w()
    upper_line = ('┌' + (len(prompt) + 5) * '─' + '┐')
    title_line = ('│' +       prompt + 5  * ' ' + '│')
    lower_line = ('└' + (len(prompt) + 5) * '─' + '┘')

    upper_line = upper_line.center(tty_w)
    title_line = title_line.center(tty_w)
    lower_line = lower_line.center(tty_w)

    indent = title_line.find('│')
    print(upper_line)
    print(title_line)
    print(lower_line)
    print(3 * CURSOR_UP_ONE_LINE)

    while True:
        print(title_line)
        print(lower_line)
        print(3 * CURSOR_UP_ONE_LINE)
        answer = input(indent * ' ' + f'│ {prompt}')
        print_on_previous_line()

        if answer == '':
            continue

        if answer.lower() in 'yes':
            print(indent * ' ' + f'│ {prompt}Yes │\n')
            for _ in range(tail):
                print('')
            return True

        elif answer.lower() in 'no':
            print(indent * ' ' + f'│ {prompt}No  │\n')
            for _ in range(tail):
                print('')
            return False

        else:
            continue
