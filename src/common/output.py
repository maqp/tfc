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

import binascii
import textwrap
import time
import typing
import sys

from typing import List, Union

from src.common.misc    import get_tty_w, split_string
from src.common.statics import *

if typing.TYPE_CHECKING:
    from src.common.db_contacts import ContactList


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


def message_printer(message: str, head: int = 0, tail: int = 0) -> None:
    """Print long message in the middle of the screen.

    :param message: Message to print
    :param head:    Number of new lines to print before message
    :param tail:    Number of new lines to print after message
    :return:        None
    """
    for _ in range(head):
        print('')

    line_list = (textwrap.fill(message, min(49, (get_tty_w() - 6))).split('\n'))
    for l in line_list:
        c_print(l)

    for _ in range(tail):
        print('')


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


def print_fingerprints(fp: bytes, msg: str = '') -> None:
    """Print fingerprints of contact and user.

    :param fp:  Contact's fingerprint
    :param msg: Title message
    :return:    None
    """

    def base10encode(fingerprint: bytes) -> str:
        """Encode fingerprint to decimals for distinct communication.

        Base64 has 75% efficiency but encoding is bad as user might
               confuse upper case I with lower case l, 0 with O etc.

        Base58 has 73% efficiency and removes the problem of Base64
               explained above, but works only when manually typing
               strings because user has to take time to explain which
               letters were capitalized etc.

        Base16 has 50% efficiency and removes the capitalisation problem
               with Base58 but the choice is bad as '3', 'b', 'c', 'd'
               and 'e' are hard to distinguish in English language
               (fingerprints are usually read aloud over off band call).

        Base10 has 41% efficiency but as languages have evolved in a
               way that makes clear distinction between the way different
               numbers are pronounced: reading them is faster and less
               error prone. Compliments to OWS/WA developers for
               discovering this.

        Truncate fingerprint for clean layout with three rows that each
        have five groups of five numbers. The resulting fingerprint has
        249.15 bits of entropy.
        """
        hex_representation = binascii.hexlify(fingerprint)
        dec_representation = str(int(hex_representation, base=16))
        return dec_representation[:75]

    p_lst  = [msg, ''] if msg else []
    parts  = split_string(base10encode(fp), item_len=25)
    p_lst += [' '.join(p[i:i + 5] for i in range(0, len(p), 5)) for p in parts]

    box_print(p_lst)


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


def g_mgmt_print(key:          str,
                 members:      List[str],
                 contact_list: 'ContactList',
                 g_name:       str = '') -> None:
    """Lists members at different parts of group management."""
    m = dict(new_g="Created new group '{}' with following members:".format(g_name),
             add_m="Added following accounts to group '{}':".format(g_name),
             add_a="Following accounts were already in group '{}':".format(g_name),
             rem_m="Removed following members from group '{}':".format(g_name),
             rem_n="Following accounts were not in group '{}':".format(g_name),
             unkwn="Following unknown accounts were ignored:")[key]

    if members:
        m_list  = []  # type: List[str]
        m_list += [contact_list.get_contact(m).nick for m in members if contact_list.has_contact(m)]
        m_list += [m for m in members if not contact_list.has_contact(m)]

        just_len  = len(max(m_list, key=len))
        justified = [m] + ["  * {}".format(m.ljust(just_len)) for m in m_list]
        box_print(justified, head=1, tail=1)
