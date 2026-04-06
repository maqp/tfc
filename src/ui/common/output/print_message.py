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

import textwrap
import time

from src.common.statics import VT100
from src.ui.common.output.vt100_utils import clear_screen, print_spacing, clear_previous_lines
from src.ui.common.utils import get_terminal_width

MsgListType = str | list[str]


def print_message(msg_list       : str | list[str],  # List of lines to print
                  manual_proceed : bool  = False,    # Wait for user input before continuing
                  bold           : bool  = False,    # When True, prints the message in bold style
                  center         : bool  = True,     # When False, does not center message
                  box            : bool  = False,    # When True, prints a box around the message
                  clear_before   : bool  = False,    # When True, clears screen before printing message
                  clear_after    : bool  = False,    # When True, clears screen after printing message (requires delay)
                  clear_delay    : float = 0,        # Delay before continuing
                  max_width      : int   = 0,        # Maximum width of message
                  padding_top    : int   = 0,        # Number of new lines to print before the message
                  padding_bottom : int   = 0,        # Number of new lines to print after the message
                  ) -> None:
    """Print message to screen.

    The message is automatically wrapped if the
    terminal is too narrow to display the message.
    """
    if isinstance(msg_list, str):
        msg_list = [msg_list]

    terminal_width           = get_terminal_width()
    len_widest_msg, msg_list = split_too_wide_messages(box, max_width, msg_list, terminal_width)

    if box or center:
        # Insert whitespace around every line to make them equally long
        msg_list = [f'{m:^{len_widest_msg}}' for m in msg_list]

    if box:
        # Add box chars around the message
        msg_list = [f'│ {m} │' for m in msg_list]
        msg_list.insert(0, '┌' + (len_widest_msg + 2) * '─' + '┐')
        msg_list.append(   '└' + (len_widest_msg + 2) * '─' + '┘')

    # Print the message
    if clear_before:
        clear_screen()
    print_spacing(padding_top)

    for message in msg_list:
        if center:
            message = message.center(terminal_width)
        if bold:
            message = VT100.BOLD_ON.value + message + VT100.NORMAL_TEXT.value
        print(message)

    print_spacing(padding_bottom)
    time.sleep(clear_delay)
    if clear_after:
        clear_screen()

    # Check if message needs to be manually dismissed
    if manual_proceed:
        input()
        clear_previous_lines(no_lines=1)


def split_too_wide_messages(box            : bool,
                            max_width      : int,
                            msg_list       : 'MsgListType',
                            terminal_width : int
                            ) -> tuple[int, 'MsgListType']:
    """Split too wide messages to multiple lines."""
    len_widest_msg = max(len(m) for m in msg_list)
    spc_around_msg = 4 if box else 2
    max_msg_width  = terminal_width - spc_around_msg

    if max_width:
        max_msg_width = min(max_width, max_msg_width)

    if len_widest_msg > max_msg_width:
        new_msg_list = []
        for msg in msg_list:
            if len(msg) > max_msg_width:
                new_msg_list.extend(textwrap.fill(msg, max_msg_width).split('\n'))
            else:
                new_msg_list.append(msg)

        msg_list       = new_msg_list
        len_widest_msg = max(len(m) for m in msg_list)

    return len_widest_msg, msg_list
