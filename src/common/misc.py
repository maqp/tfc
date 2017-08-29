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
import math
import os
import re
import shutil
import typing

from contextlib import contextmanager
from typing     import Any, Callable, Generator, List, Tuple, Union

from src.common.reed_solomon import RSCodec
from src.common.statics      import *

if typing.TYPE_CHECKING:
    from src.common.db_contacts import ContactList
    from src.common.db_groups   import GroupList
    from src.common.db_settings import Settings
    from src.nh.settings        import Settings as NHSettings


def calculate_race_condition_delay(settings: Union['Settings', 'NHSettings'], txm: bool = False) -> float:
    """Calculate NH race condition delay.

    This value is the max time it takes for NH to deliver
    command received from TxM all the way to RxM.

    :param settings: Settings object
    :param txm:      When True, allocate time for command delivery from TxM to NH
    :return:         Time to wait to prevent race condition
    """
    rs                 = RSCodec(2 * settings.session_serial_error_correction)
    max_account_length = 254
    max_message_length = PACKET_LENGTH + 2 * max_account_length
    command_length     = 365*2 if txm else 365
    max_bytes          = (len(rs.encode(os.urandom(max_message_length)))
                          + len(rs.encode(os.urandom(command_length))))

    return (max_bytes * BAUDS_PER_BYTE) / settings.serial_baudrate


def calculate_serial_delays(session_serial_baudrate: int) -> Tuple[float, float]:
    """Calculate transmission delay and receive timeout."""
    bytes_per_sec = session_serial_baudrate / BAUDS_PER_BYTE
    byte_travel_t = 1 / bytes_per_sec

    rxm_receive_timeout    = max(2 * byte_travel_t, 0.02)
    txm_inter_packet_delay = 2 * rxm_receive_timeout

    return rxm_receive_timeout, txm_inter_packet_delay


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
                'false', 'file', 'fingerprints', 'group ', 'help', 'history ', 'join ', 'localkey',
                'logging ', 'msg ', 'names', 'nick ', 'notify ', 'passwd ', 'psk', 'reset',
                'rm', 'rmlogs ', 'set ', 'settings', 'store ', 'true', 'unread', 'whisper ']

    tc_list += [(c + ' ') for c in contact_list.get_list_of_accounts()]
    tc_list += [(n + ' ') for n in contact_list.get_list_of_nicks()]
    tc_list += [(u + ' ') for u in contact_list.get_list_of_users_accounts()]
    tc_list += [(g + ' ') for g in group_list.get_list_of_group_names()]
    tc_list += [(s + ' ') for s in settings.key_list]

    return tc_list


def get_tab_completer(contact_list: 'ContactList',
                      group_list:   'GroupList',
                      settings:     'Settings') -> Callable:
    """Return tab completer object."""

    def tab_complete(text, state) -> List[str]:
        """Return tab_complete options."""
        tab_complete_list = get_tab_complete_list(contact_list, group_list, settings)
        options           = [t for t in tab_complete_list if t.startswith(text)]
        with ignored(IndexError):
            return options[state]

    return tab_complete


def get_terminal_height() -> int:
    """Return height of terminal."""
    return int(shutil.get_terminal_size()[1])


def get_terminal_width() -> int:
    """Return width of terminal."""
    return shutil.get_terminal_size()[0]


@contextmanager
def ignored(*exceptions: Any) -> Generator:
    """Ignore exception."""
    try:
        yield
    except exceptions:
        pass


def process_arguments() -> Tuple[str, bool, bool]:
    """Load TxM/RxM startup settings from command line arguments."""
    parser = argparse.ArgumentParser('python3.6 tfc.py',
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
    operation  = RX if args.operation else TX
    local_test = args.local_test
    dd_sockets = args.dd_sockets

    return operation, local_test, dd_sockets


def readable_size(size: int) -> str:
    """Convert file size from bytes to human readable form."""
    f_size = float(size)
    for unit in ['', 'K', 'M', 'G', 'T', 'P', 'E', 'Z']:
        if abs(f_size) < 1024.0:
            return '{:3.1f}{}B'.format(f_size, unit)
        f_size /= 1024.0
    return '{:3.1f}YB'.format(f_size)


def round_up(value: Union[int, float]) -> int:
    """Round value to next 10."""
    return int(math.ceil(value / 10.0)) * 10


def split_byte_string(string: bytes, item_len: int) -> List[bytes]:
    """Split byte string into list of specific length substrings.

    :param string:   String to split
    :param item_len: Length of list items
    :return:         String split to list
    """
    return [string[i:i + item_len] for i in range(0, len(string), item_len)]


def split_string(string: str, item_len: int) -> List[str]:
    """Split string into list of specific length substrings.

    :param string:   String to split
    :param item_len: Length of list items
    :return:         String split to list
    """
    return [string[i:i + item_len] for i in range(0, len(string), item_len)]


def validate_account(account: str, *_: Any) -> str:
    """Validate account name.

    :param account: Account name to validate
    :param _:       Unused arguments
    :return:        Error message if validation failed, else empty string
    """
    error_msg = ''

    # Length limited by database's unicode padding
    if len(account) >= PADDING_LEN:
        error_msg = "Account must be shorter than {} chars.".format(PADDING_LEN)

    if not re.match(ACCOUNT_FORMAT, account):
        error_msg = "Invalid account format."

    # Avoid delimiter char collision in output packets
    if not account.isprintable():
        error_msg = "Account must be printable."

    return error_msg


def validate_key_exchange(key_ex: str, *_: Any) -> str:
    """Validate specified key exchange.

    :param key_ex: Key exchange selection to validate
    :param _:      Unused arguments
    :return:       Error message if validation failed, else empty string
    """
    error_msg = ''

    if key_ex.lower() not in ['x', 'x25519', 'p', 'psk']:
        error_msg = "Invalid key exchange selection."

    return error_msg


def validate_nick(nick: str, args: Tuple['ContactList', 'GroupList', str]) -> str:
    """Validate nickname for account.

    :param nick: Nick to validate
    :param args: Contact list and group list databases
    :return:     Error message if validation failed, else empty string
    """
    contact_list, group_list, account = args

    error_msg = ''

    # Length limited by database's unicode padding
    if len(nick) >= PADDING_LEN:
        error_msg = "Nick must be shorter than {} chars.".format(PADDING_LEN)

    # Avoid delimiter char collision in output packets
    if not nick.isprintable():
        error_msg = "Nick must be printable."

    if nick == '':
        error_msg = "Nick can't be empty."

    # RxM displays sent messages under 'Me'
    if nick.lower() == 'me':
        error_msg = "'Me' is a reserved nick."

    # RxM displays system notifications under '-!-'
    if nick.lower() == '-!-':
        error_msg = "'-!-' is a reserved nick."

    # Ensure that nicks, accounts and group names are UIDs in recipient selection
    if nick == 'local':
        error_msg = "Nick can't refer to local keyfile."

    if re.match(ACCOUNT_FORMAT, nick):
        error_msg = "Nick can't have format of an account."

    if nick in contact_list.get_list_of_nicks():
        error_msg = "Nick already in use."

        # Allow if nick matches the account the key is being re-exchanged for
        if contact_list.has_contact(account):
            if nick == contact_list.get_contact(account).nick:
                error_msg = ''

    if nick in group_list.get_list_of_group_names():
        error_msg = "Nick can't be a group name."

    return error_msg
