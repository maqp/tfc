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

from src.common.encoding import b58encode
from src.common.misc     import get_terminal_width, split_string
from src.common.statics  import *

if typing.TYPE_CHECKING:
    from src.common.db_contacts import ContactList
    from src.common.db_settings import Settings


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

    len_widest = max(len(m) for m in msg_list)
    msg_list   = ['{:^{}}'.format(m, len_widest) for m in msg_list]

    top_line = '┌' + (len(msg_list[0]) + 2) * '─' + '┐'
    bot_line = '└' + (len(msg_list[0]) + 2) * '─' + '┘'
    msg_list = ['│ {} │'.format(m) for m in msg_list]

    terminal_w = get_terminal_width()
    top_line   = top_line.center(terminal_w)
    msg_list   = [m.center(terminal_w) for m in msg_list]
    bot_line   = bot_line.center(terminal_w)

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

    print(string.center(get_terminal_width()))

    for _ in range(tail):
        print('')


def clear_screen(delay: float = 0.0) -> None:
    """Clear terminal window."""
    time.sleep(delay)
    sys.stdout.write(CLEAR_ENTIRE_SCREEN + CURSOR_LEFT_UP_CORNER)
    sys.stdout.flush()


def group_management_print(key:          str,
                           members:      List[str],
                           contact_list: 'ContactList',
                           group_name:   str = '') -> None:
    """List purported member status during group management."""
    m = {NEW_GROUP:        "Created new group '{}' with following members:".format(group_name),
         ADDED_MEMBERS:    "Added following accounts to group '{}':"       .format(group_name),
         ALREADY_MEMBER:   "Following accounts were already in group '{}':".format(group_name),
         REMOVED_MEMBERS:  "Removed following members from group '{}':"    .format(group_name),
         NOT_IN_GROUP:     "Following accounts were not in group '{}':"    .format(group_name),
         UNKNOWN_ACCOUNTS: "Following unknown accounts were ignored:"}[key]

    if members:
        m_list = ([contact_list.get_contact(m).nick for m in members if contact_list.has_contact(m)]
                  + [m for m in members if not contact_list.has_contact(m)])

        just_len  = max(len(m) for m in m_list)
        justified = [m] + ["  * {}".format(m.ljust(just_len)) for m in m_list]
        box_print(justified, head=1, tail=1)


def message_printer(message: str, head: int = 0, tail: int = 0) -> None:
    """Print long message in the middle of the screen.

    :param message: Message to print
    :param head:    Number of new lines to print before message
    :param tail:    Number of new lines to print after message
    :return:        None
    """
    for _ in range(head):
        print('')

    line_list = (textwrap.fill(message, min(49, (get_terminal_width() - 6))).split('\n'))
    for l in line_list:
        c_print(l)

    for _ in range(tail):
        print('')


def phase(string: str,
          done:   bool = False,
          head:   int  = 0,
          offset: int  = 2) -> None:
    """Print name of next phase.

    Message about completion will be printed on same line.

    :param string: String to be printed
    :param done:   When True, allows custom string to notify completion
    :param head:   Number of inserted new lines before print
    :param offset: Offset of message from center to left
    :return:       None
    """
    for _ in range(head):
        print('')

    if string == DONE or done:
        print(string)
        time.sleep(0.5)
    else:
        string = '{}... '.format(string)
        indent = ((get_terminal_width() - (len(string) + offset)) // 2) * ' '

        print(indent + string, end='', flush=True)


def print_fingerprint(fp: bytes, msg: str = '') -> None:
    """Print formatted message and fingerprint inside box.

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


def print_key(message:   str,
              key_bytes: bytes,
              settings:  'Settings',
              no_split:  bool = False,
              file_key:  bool = False) -> None:
    """Print symmetric key.

    If local testing is not enabled, this function will add spacing in the
    middle of the key to help user keep track of typing progress. The ideal
    substring length in Cowan's `focus of attention` is four digits:

        https://en.wikipedia.org/wiki/Working_memory#Working_memory_as_part_of_long-term_memory

    The 51 char KDK is however not divisible by 4, and remembering which
    symbols are letters and if they are capitalized is harder than remembering
    just digits. 51 is divisible by 3. The 17 segments are displayed with guide
    letter A..Q to help keep track when typing:

         A   B   C   D   E   F   G   H   I   J   K   L   M   N   O   P   Q
        5Ka 52G yNz vjF nM4 2jw Duu rWo 7di zgi Y8g iiy yGd 78L cCx mwQ mWV

    :param message:   Message to print
    :param key_bytes: Decryption key
    :param settings:  Settings object
    :param no_split:  When True, does not split decryption key to chunks
    :param file_key   When True, uses testnet address format
    :return:          None
    """
    b58key = b58encode(key_bytes, file_key)
    if settings.local_testing_mode or no_split:
        box_print([message, b58key])
    else:
        box_print([message,
                   '   '.join('ABCDEFGHIJKLMNOPQ'),
                   ' '.join(split_string(b58key, item_len=3))])


def print_on_previous_line(reps:  int   = 1,
                           delay: float = 0.0,
                           flush: bool  = False) -> None:
    """Next message will be printed on upper line.

    :param reps:  Number of times to repeat action
    :param delay: Time to sleep before clearing lines above
    :param flush: Flush stdout when true
    :return:      None
    """
    time.sleep(delay)

    for _ in range(reps):
        sys.stdout.write(CURSOR_UP_ONE_LINE + CLEAR_ENTIRE_LINE)
    if flush:
        sys.stdout.flush()
