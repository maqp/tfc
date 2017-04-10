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

import argparse
import shutil
import math
import os
import re
import sys
import time
import typing

from typing import Any, Callable, List, Tuple, Union

from src.common.statics import *

if typing.TYPE_CHECKING:
    from src.common.db_contacts import ContactList
    from src.common.db_groups   import GroupList
    from src.common.db_settings import Settings


def clear_screen(delay: float = 0.0) -> None:
    """Clear terminal window."""
    time.sleep(delay)
    sys.stdout.write(CLEAR_ENTIRE_SCREEN + CURSOR_LEFT_UP_CORNER)
    sys.stdout.flush()


def ensure_dir(directory: str) -> None:
    """Ensure directory exists."""
    name = os.path.dirname(directory)
    if not os.path.exists(name):
        os.makedirs(name)


def get_tab_complete_list(contact_list: 'ContactList',
                          group_list:   'GroupList',
                          settings:     'Settings') -> List[str]:
    """Return a list of tab-complete words."""
    tc_list  = ['about', 'add ', 'all', 'clear', 'cmd', 'create ', 'exit', 'export ',
               'false', 'file', 'fingerprints', 'group ', 'help', 'history ', 'localkey',
               'logging ', 'msg ', 'names', 'nick ', 'notify ', 'passwd ', 'psk',
               'reset', 'rm ', 'set ', 'settings', 'store ', 'true', 'unread']

    tc_list  += [(c + ' ') for c in contact_list.get_list_of_accounts()]
    tc_list  += [(n + ' ') for n in contact_list.get_list_of_nicks()]
    tc_list  += [(u + ' ') for u in contact_list.get_list_of_users_accounts()]
    tc_list  += [(g + ' ') for g in group_list.get_list_of_group_names()]
    tc_list  += [(s + ' ') for s in settings.key_list]

    return tc_list


def get_tab_completer(contact_list: 'ContactList',
                      group_list:   'GroupList',
                      settings:     'Settings') -> Callable:
    """Return tab completer object."""

    def tab_complete(text, state):
        """Return tab_complete options."""
        tab_complete_list = get_tab_complete_list(contact_list, group_list, settings)
        options           = [t for t in tab_complete_list if t.startswith(text)]
        try:
            return options[state]
        except IndexError:
            pass

    return tab_complete


def get_tty_w() -> int:
    """Return width of terminal TFC is running in."""
    return shutil.get_terminal_size()[0]


def process_arguments() -> Tuple[str, bool, bool]:
    """Define Tx.py settings from arguments passed from command line."""
    parser = argparse.ArgumentParser('python tfc.py',
                                     usage='%(prog)s [OPTION]',
                                     description='')

    parser.add_argument('-rx',
                        action='store_true',
                        default=False,
                        dest='operation',
                        help="Run RxM side program")

    parser.add_argument('-l',
                        action='store_true',
                        default=False,
                        dest='local_test',
                        help="Enable local testing mode")

    parser.add_argument('-d',
                        action='store_true',
                        default=False,
                        dest='dd_sockets',
                        help="Data diode simulator socket configuration for local testing")

    args       = parser.parse_args()
    operation  = 'rx' if args.operation else 'tx'
    local_test = args.local_test
    dd_sockets = args.dd_sockets

    return operation, local_test, dd_sockets


def resize_terminal(height: int, width: int) -> None:
    """Resize Terminal to specified size.

    :param height: Terminal height in chars
    :param width:  Terminal width in chars
    :return:       None
    """
    sys.stdout.write('\x1b[8;{};{}t\n'.format(height, width))
    time.sleep(0.1)


def round_up(x: Union[int, float]) -> int:
    """Round value to next 10."""
    return int(math.ceil(x / 10.0)) * 10


def split_string(string: str, item_len: int) -> List[str]:
    """Split string into list of specific length substrings.

    :param string:   String to split
    :param item_len: Length of list items
    :return:         String split to list
    """
    return [string[i:i + item_len] for i in range(0, len(string), item_len)]


def split_byte_string(string: bytes, item_len: int) -> List[bytes]:
    """Split byte string into list of specific length substrings.

    :param string:   String to split
    :param item_len: Length of list items
    :return:         String split to list
    """
    return [string[i:i + item_len] for i in range(0, len(string), item_len)]


def validate_account(account: str, *_: Any) -> Tuple[bool, str]:
    """Validate account name."""
    error_msg = ''

    # Length limited by database's unicode padding
    if len(account) > 254:
        error_msg = "Account must be shorter than 255 chars."

    if not re.match(ACCOUNT_FORMAT, account):
        error_msg = "Invalid account format."

    # Avoid delimiter char collision in output packets
    if not account.isprintable():
        error_msg = "Account must be printable."

    if error_msg:
        return False, error_msg

    return True, ''


def validate_key_exchange(key_ex: str, *_: Any) -> Tuple[bool, str]:
    """Validate specified key exchange."""
    if key_ex.lower() in ['e', 'ecdhe']:
        return True, ''
    elif key_ex.lower() in ['p', 'psk']:
        return True, ''
    else:
        return False, "Invalid key exchange selection."


def validate_nick(nick: str, args: Tuple['ContactList', 'GroupList', str]) -> Tuple[bool, str]:
    """Validate nickname for account.

    :param nick: Nick to validate
    :param args: Contact list and group list databases
    :return:     True if nick is valid, else False
    """
    contact_list, group_list, account = args

    error_msg = ''

    # Length limited by database's unicode padding
    if len(nick) > 254:
        error_msg = "Nick must be shorter than 255 chars."

    # Avoid delimiter char collision in output packets
    if not nick.isprintable():
        error_msg = "Nick must be printable."

    if nick == '':
        error_msg = "Nick can't be empty."

    # RxM displays sent messages under "Me"
    if nick.lower() == 'me':
        error_msg = "'Me' is a reserved nick."

    # RxM displays system notifications under nick '-!-'.
    if nick.lower() == '-!-':
        error_msg = "'-!-' is a reserved nick."

    # Ensure that nicks, accounts and group names are UIDs in recipient selection
    if nick == 'local':
        error_msg = "Nick can't refer to local keyfile."

    if re.match(ACCOUNT_FORMAT, nick):
        error_msg = "Nick can't have format of an account."

    if nick in contact_list.get_list_of_nicks():
        error_msg = "Nick already in use."

        # Allow if nick matches the account the key is being re-exchanged for.
        if contact_list.has_contact(account):
            if nick == contact_list.get_contact(account).nick:
                error_msg = ''

    if nick in group_list.get_list_of_group_names():
        error_msg = "Nick can't be a group name."

    if error_msg:
        return False, error_msg

    return True, ''
