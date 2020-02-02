#!/usr/bin/env python3.7
# -*- coding: utf-8 -*-

"""
TFC - Onion-routed, endpoint secure messaging system
Copyright (C) 2013-2020  Markus Ottela

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

import textwrap
import time
import typing
import sys

from datetime import datetime
from typing   import List, Optional, Tuple, Union

from src.common.encoding import b10encode, b58encode, pub_key_to_onion_address
from src.common.misc     import get_terminal_width, split_string
from src.common.statics  import (ADDED_MEMBERS, ALREADY_MEMBER, B58_LOCAL_KEY_GUIDE, B58_PUBLIC_KEY_GUIDE, BOLD_ON,
                                 CLEAR_ENTIRE_LINE, CLEAR_ENTIRE_SCREEN, CURSOR_LEFT_UP_CORNER, CURSOR_UP_ONE_LINE,
                                 DONE, NC, NEW_GROUP, NORMAL_TEXT, NOT_IN_GROUP, RECEIVER, RELAY, REMOVED_MEMBERS, RX,
                                 TFC, TRANSMITTER, TX, UNKNOWN_ACCOUNTS, VERSION)

if typing.TYPE_CHECKING:
    from src.common.db_contacts import ContactList
    from src.common.db_settings import Settings
    from src.common.gateway     import GatewaySettings as GWSettings

    MsgListType = Union[str, List[str]]


def clear_screen(delay: float = 0.0) -> None:
    """Clear the terminal window."""
    time.sleep(delay)
    sys.stdout.write(CLEAR_ENTIRE_SCREEN + CURSOR_LEFT_UP_CORNER)
    sys.stdout.flush()


def group_management_print(key:          str,            # Group management message identifier
                           members:      List[bytes],    # List of members' Onion public keys
                           contact_list: 'ContactList',  # ContactList object
                           group_name:   str = ''        # Name of the group
                           ) -> None:
    """Print group management command results."""
    m = {NEW_GROUP:        "Created new group '{}' with following members:".format(group_name),
         ADDED_MEMBERS:    "Added following accounts to group '{}':"       .format(group_name),
         ALREADY_MEMBER:   "Following accounts were already in group '{}':".format(group_name),
         REMOVED_MEMBERS:  "Removed following members from group '{}':"    .format(group_name),
         NOT_IN_GROUP:     "Following accounts were not in group '{}':"    .format(group_name),
         UNKNOWN_ACCOUNTS: "Following unknown accounts were ignored:"}[key]

    if members:
        m_list = ([contact_list.get_nick_by_pub_key(m) for m in members if     contact_list.has_pub_key(m)]
                  + [pub_key_to_onion_address(m)       for m in members if not contact_list.has_pub_key(m)])

        just_len  = max(len(m) for m in m_list)
        justified = [m] + [f"  * {m.ljust(just_len)}" for m in m_list]
        m_print(justified, box=True)


def m_print(msg_list:       Union[str, List[str]],  # List of lines to print
            manual_proceed: bool  = False,          # Wait for user input before continuing
            bold:           bool  = False,          # When True, prints the message in bold style
            center:         bool  = True,           # When False, does not center message
            box:            bool  = False,          # When True, prints a box around the message
            head_clear:     bool  = False,          # When True, clears screen before printing message
            tail_clear:     bool  = False,          # When True, clears screen after printing message (requires delay)
            delay:          float = 0,              # Delay before continuing
            max_width:      int   = 0,              # Maximum width of message
            head:           int   = 0,              # Number of new lines to print before the message
            tail:           int   = 0,              # Number of new lines to print after the message
            ) -> None:
    """Print message to screen.

    The message automatically wraps if the terminal is too narrow to
    display the message.
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
    if head_clear:
        clear_screen()
    print_spacing(head)

    for message in msg_list:
        if center:
            message = message.center(terminal_width)
        if bold:
            message = BOLD_ON + message + NORMAL_TEXT
        print(message)

    print_spacing(tail)
    time.sleep(delay)
    if tail_clear:
        clear_screen()

    # Check if message needs to be manually dismissed
    if manual_proceed:
        input('')
        print_on_previous_line()


def split_too_wide_messages(box:            bool,
                            max_width:      int,
                            msg_list:       'MsgListType',
                            terminal_width: int
                            ) -> Tuple[int, 'MsgListType']:
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
                new_msg_list.extend(textwrap.fill(msg, max_msg_width).split("\n"))
            else:
                new_msg_list.append(msg)

        msg_list = new_msg_list
        len_widest_msg = max(len(m) for m in msg_list)

    return len_widest_msg, msg_list


def phase(string: str,            # Description of the phase
          done:   bool  = False,  # When True, uses string as the phase completion message
          head:   int   = 0,      # Number of inserted new lines before print
          tail:   int   = 0,      # Number of inserted new lines after print
          offset: int   = 4,      # Offset of phase string from center to left
          delay:  float = 0.5     # Duration of phase completion message
          ) -> None:
    """Print the name of the next phase.

    The notification of completion of the phase is printed on the same
    line as the phase message.
    """
    print_spacing(head)

    if string == DONE or done:
        print(string)
        time.sleep(delay)
    else:
        string += '... '
        indent  = ((get_terminal_width() - (len(string) + offset)) // 2) * ' '

        print(indent + string, end='', flush=True)

    print_spacing(tail)


def print_fingerprint(fp:  bytes,    # Contact's fingerprint
                      msg: str = ''  # Title message
                      ) -> None:
    """Print a formatted message and fingerprint inside the box.

    Truncate fingerprint for clean layout with three rows that have
    five groups of five numbers. The resulting fingerprint has
    249.15 bits of entropy which is more than the symmetric security
    of X448.
    """
    p_lst  = [msg, ''] if msg else []
    b10fp  = b10encode(fp)[:(3*5*5)]
    parts  = split_string(b10fp, item_len=(5*5))
    p_lst += [' '.join(split_string(p, item_len=5)) for p in parts]

    m_print(p_lst, box=True)


def print_key(message:    str,                              # Instructive message
              key_bytes:  bytes,                            # 32-byte key to be displayed
              settings:   Union['Settings', 'GWSettings'],  # Settings object
              public_key: bool = False                      # When True, uses Testnet address WIF format
              ) -> None:
    """Print a symmetric key in WIF format.

    If local testing is not enabled, this function adds spacing in the
    middle of the key, as well as guide letters to help the user keep
    track of typing progress:

    Local key encryption keys:

         A   B   C   D   E   F   G   H   I   J   K   L   M   N   O   P   Q
        5Ka 52G yNz vjF nM4 2jw Duu rWo 7di zgi Y8g iiy yGd 78L cCx mwQ mWV

    X448 public keys:

           A       B       C       D       E       F       H       H       I       J       K       L
        4EcuqaD ddsdsuc gBX2PY2 qR8hReA aeSN2oh JB9w5Cv q6BQjDa PPgzSvW 932aHio sT42SKJ Gu2PpS1 Za3Xrao
    """
    b58key = b58encode(key_bytes, public_key)
    if settings.local_testing_mode:
        m_print([message, b58key], box=True)
    else:
        guide, chunk_length = (B58_PUBLIC_KEY_GUIDE, 7) if public_key else (B58_LOCAL_KEY_GUIDE, 3)

        key = ' '.join(split_string(b58key, item_len=chunk_length))
        m_print([message, guide, key], box=True)


def print_title(operation: str) -> None:
    """Print the TFC title."""
    operation_name = {TX: TRANSMITTER, RX: RECEIVER, NC: RELAY}[operation]
    m_print(f"{TFC} - {operation_name} {VERSION}", bold=True, head_clear=True, head=1, tail=1)


def print_on_previous_line(reps:  int   = 1,     # Number of times to repeat the action
                           delay: float = 0.0,   # Time to sleep before clearing lines above
                           flush: bool  = False  # Flush stdout when true
                           ) -> None:
    """Next message is printed on upper line."""
    time.sleep(delay)

    for _ in range(reps):
        sys.stdout.write(CURSOR_UP_ONE_LINE + CLEAR_ENTIRE_LINE)
    if flush:
        sys.stdout.flush()


def print_spacing(count: int = 0) -> None:
    """Print `count` many new-lines."""
    for _ in range(count):
        print()


def rp_print(message: str,                          # Message to print
             ts:      Optional['datetime'] = None,  # Timestamp for displayed event
             bold:    bool                 = False  # When True, prints the message in bold style
             ) -> None:
    """Print an event in Relay Program."""
    if ts is None:
        ts = datetime.now()
    ts_fmt = ts.strftime('%b %d - %H:%M:%S.%f')[:-4]

    if bold:
        print(f"{BOLD_ON}{ts_fmt} - {message}{NORMAL_TEXT}")
    else:
        print(f"{ts_fmt} - {message}")
