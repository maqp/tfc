#!/usr/bin/env python3.5
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

import argparse
import os
import shutil
import sys
import time

from typing import Tuple, Union

from src.common.statics import *


def box_print(msg_list:       Union[str, list],
              manual_proceed: bool = False,
              head:           int  = 0,
              tail:           int  = 0) -> None:
    """Print message inside a box.

    :param msg_list:       List of lines to print
    :param manual_proceed: Wait for user input before continuing
    :param head:           Number of new lines to print before box
    :param tail:           Number of new lines to print after box
    :return:               None
    """
    for _ in range(head):
        print('')

    if isinstance(msg_list, str):
        msg_list = [msg_list]

    tty_w  = get_tty_w()
    widest = max(msg_list, key=len)

    msg_list = ['{:^{}}'.format(m, len(widest)) for m in msg_list]

    top_line = '┌' + (len(msg_list[0]) + 2) * '─' + '┐'
    bot_line = '└' + (len(msg_list[0]) + 2) * '─' + '┘'
    msg_list = ['│ {} │'.format(m) for m in msg_list]

    top_line = top_line.center(tty_w)
    msg_list = [m.center(tty_w) for m in msg_list]
    bot_line = bot_line.center(tty_w)

    print(top_line)
    for m in msg_list:
        print(m)
    print(bot_line)

    for _ in range(tail):
        print('')

    if manual_proceed:
        input('')
        print_on_previous_line()


def c_print(string: str, head: int = 0, tail: int = 0) -> None:
    """Print string to center of screen.

    :param string: String to print
    :param head:   Number of new lines to print before string
    :param tail:   Number of new lines to print after string
    :return:       None
    """
    for _ in range(head):
        print('')

    print(string.center(get_tty_w()))

    for _ in range(tail):
        print('')


def clear_screen(delay: int = 0) -> None:
    """Clear terminal window."""
    time.sleep(delay)
    sys.stdout.write(CLEAR_ENTIRE_SCREEN + CURSOR_LEFT_UP_CORNER)
    sys.stdout.flush()


def ensure_dir(directory: str) -> None:
    """Ensure directory exists."""
    name = os.path.dirname(directory)
    if not os.path.exists(name):
        os.makedirs(name)


def get_tty_w() -> int:
    """Return width of terminal TFC is running in."""
    return shutil.get_terminal_size()[0]


def graceful_exit(message: str = '', clear: bool = True) -> None:
    """Display a message and exit Tx.py."""
    if clear:
        sys.stdout.write(CLEAR_ENTIRE_SCREEN + CURSOR_LEFT_UP_CORNER)
    if message:
        print("\n{}".format(message))
    print("\nExiting TFC.\n")
    exit()


def phase(string: str,
          done:   bool = False,
          head:   int = 0,
          offset: int = 2) -> None:
    """Print name of next phase.

    Message about completion will be printed on same line.

    :param string: String to be printed
    :param done:   Notify with custom message
    :param head:   N.o. inserted new lines before print
    :param offset: Offset of message from center to left
    :return:       None
    """
    for _ in range(head):
        print('')

    if string == 'Done' or done:
        print(string)
        time.sleep(0.5)
    else:
        string = '{}... '.format(string)
        indent = ((get_tty_w() - (len(string) + offset)) // 2) * ' '

        print(indent + string, end='', flush=True)


def print_on_previous_line(reps:  int = 1,
                           delay: float = 0.0,
                           flush: bool = False) -> None:
    """Next message will be printed on upper line.

    :param reps:  Number of times to repeat function
    :param delay: Time to sleep before clearing lines above
    :param flush: Flush stdout when true
    :return:      None
    """
    time.sleep(delay)

    for _ in range(reps):
        sys.stdout.write(CURSOR_UP_ONE_LINE + CLEAR_ENTIRE_LINE)
    if flush:
        sys.stdout.flush()


def process_arguments() -> Tuple[bool, bool]:
    """Define NH.py settings from arguments passed from command line."""
    parser = argparse.ArgumentParser("python NH.py",
                                     usage="%(prog)s [OPTION]",
                                     description="More options inside NH.py")

    parser.add_argument("-l",
                        action="store_true",
                        default=False,
                        dest="local_test",
                        help="Enable local testing mode")

    parser.add_argument("-d",
                        action="store_true",
                        default=False,
                        dest="dd_sockets",
                        help="Enable data diode simulator sockets")

    args = parser.parse_args()

    return args.local_test, args.dd_sockets


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
        answer = input(indent * ' ' + '│ {}'.format(prompt))
        print_on_previous_line()

        if answer == '':
            continue

        if answer.lower() in 'yes':
            print(indent * ' ' + '│ {}Yes │\n'.format(prompt))
            for _ in range(tail):
                print('')
            return True

        elif answer.lower() in 'no':
            print(indent * ' ' + '│ {}No  │\n'.format(prompt))
            for _ in range(tail):
                print('')
            return False

        else:
            continue
