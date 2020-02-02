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

import argparse
import base64
import binascii
import hashlib
import math
import os
import random
import shutil
import subprocess
import sys
import time
import threading
import typing
import zlib

from contextlib      import contextmanager
from typing          import Any, Callable, Dict, Iterator, List, Optional, Tuple, Type, Union
from multiprocessing import Process

from src.common.reed_solomon import RSCodec
from src.common.statics      import (BAUDS_PER_BYTE, COMMAND_LENGTH, CURSOR_UP_ONE_LINE, DIR_RECV_FILES, DIR_USER_DATA,
                                     DUMMY_CONTACT, DUMMY_GROUP, DUMMY_MEMBER, ECDHE, EVENT, EXIT, EXIT_QUEUE, LOCAL_ID,
                                     LOCAL_PUBKEY, ME, ONION_ADDRESS_CHECKSUM_ID, ONION_ADDRESS_CHECKSUM_LENGTH,
                                     ONION_ADDRESS_LENGTH, ONION_SERVICE_PUBLIC_KEY_LENGTH, PACKET_LENGTH,
                                     PADDING_LENGTH, POWEROFF, PSK, RESET, RX, STATIC, TAILS, TRAFFIC_MASKING, TX, WIPE)

if typing.TYPE_CHECKING:
    from multiprocessing        import Queue
    from src.common.db_contacts import ContactList
    from src.common.db_groups   import GroupList
    from src.common.db_settings import Settings
    from src.common.gateway     import Gateway


def calculate_race_condition_delay(serial_error_correction: int,
                                   serial_baudrate:         int
                                   ) -> float:
    """\
    Calculate the delay required to prevent Relay Program race condition.

    When Transmitter Program outputs a command to exit or wipe data,
    Relay program will also receive a copy of the command. If Relay
    Program acts on the command too early, Receiver Program will not
    receive the exit/wipe command at all.

    This program calculates the delay Transmitter Program should wait
    before outputting command for Relay Program, to ensure Receiver
    Program has received the encrypted command.
    """
    rs             = RSCodec(2 * serial_error_correction)
    message_length = PACKET_LENGTH + ONION_ADDRESS_LENGTH
    enc_msg_length = len(rs.encode(os.urandom(message_length)))
    enc_cmd_length = len(rs.encode(os.urandom(COMMAND_LENGTH)))
    max_bytes      = enc_msg_length + (2 * enc_cmd_length)

    return (max_bytes * BAUDS_PER_BYTE) / serial_baudrate


def decompress(data:     bytes,  # Data to be decompressed
               max_size: int     # The maximum size of decompressed data.
               ) -> bytes:       # Decompressed data
    """Decompress received data.

    The decompressed data has a maximum size, designed to prevent zip
    bombs from filling the drive of an unsuspecting user.
    """
    from src.common.exceptions import SoftError  # Avoid circular import

    dec  = zlib.decompressobj()
    data = dec.decompress(data, max_size)
    if dec.unconsumed_tail:
        raise SoftError("Error: Decompression aborted due to possible zip bomb.")
    del dec

    return data


def ensure_dir(directory: str) -> None:
    """Ensure directory exists.

    This function is run before checking a database exists in the
    specified directory, or before storing data into a directory.
    It prevents errors in case user has for some reason removed
    the directory.
    """
    name = os.path.dirname(directory)
    if not os.path.exists(name):
        with ignored(FileExistsError):
            os.makedirs(name)


def get_tab_complete_list(contact_list: 'ContactList',
                          group_list:   'GroupList',
                          settings:     'Settings',
                          gateway:      'Gateway'
                          ) -> List[str]:
    """Return a list of tab-complete words."""
    commands = ['about',
                'add ',
                'clear',
                'cmd',
                'connect',
                'exit',
                'export ',
                'file',
                'group ',
                'help',
                'history ',
                'localkey',
                'logging ',
                'msg ',
                'names',
                'nick ',
                'notify ',
                'passwd ',
                'psk',
                'reset',
                'rmlogs ',
                'set ',
                'settings',
                'store ',
                'unread',
                'verify',
                'whisper ',
                'whois ']

    tc_list  = ['all', 'create ', 'false', 'False', 'join ', 'true', 'True']
    tc_list += commands
    tc_list += [(a + ' ') for a in contact_list.get_list_of_addresses()]
    tc_list += [(n + ' ') for n in contact_list.get_list_of_nicks()]
    tc_list += [(g + ' ') for g in group_list.get_list_of_group_names()]
    tc_list += [(i + ' ') for i in group_list.get_list_of_hr_group_ids()]
    tc_list += [(s + ' ') for s in settings.key_list]
    tc_list += [(s + ' ') for s in gateway.settings.key_list]

    return tc_list


def get_tab_completer(contact_list: 'ContactList',
                      group_list:   'GroupList',
                      settings:     'Settings',
                      gateway:      'Gateway'
                      ) -> Optional[Callable[[str, Any], Any]]:
    """Return the tab completer object."""

    def tab_complete(text: str, state: Any) -> List[str]:
        """Return tab-complete options."""
        tab_complete_list = get_tab_complete_list(contact_list, group_list, settings, gateway)
        options           = [t for t in tab_complete_list if t.startswith(text)]  # type: List[str]
        with ignored(IndexError):
            tc = options[state]  # type: List[str]
            return tc

    return tab_complete


def get_terminal_height() -> int:
    """Return the height of the terminal."""
    return shutil.get_terminal_size()[1]


def get_terminal_width() -> int:
    """Return the width of the terminal."""
    return shutil.get_terminal_size()[0]


class HideRunTime(object):
    """Runtime hiding time context manager.

    By joining a thread that sleeps for a longer time than it takes for
    the function to run, this context manager hides the actual running
    time of the function.

    Note that random.SystemRandom() uses the Kernel CSPRNG (/dev/urandom),
    not Python's weak PRNG based on Mersenne Twister:
        https://docs.python.org/2/library/random.html#random.SystemRandom
    """

    def __init__(self,
                 settings:   Optional['Settings'] = None,
                 delay_type: str                  = STATIC,
                 duration:   float                = 0.0
                 ) -> None:

        if delay_type == TRAFFIC_MASKING and settings is not None:
            self.length = settings.tm_static_delay
            self.length += random.SystemRandom().uniform(0, settings.tm_random_delay)

        elif delay_type == STATIC:
            self.length = duration

    def __enter__(self) -> None:
        self.timer = threading.Thread(target=time.sleep, args=(self.length,))
        self.timer.start()

    def __exit__(self,
                 exc_type:  Any,
                 exc_value: Any,
                 traceback: Any
                 ) -> None:
        self.timer.join()


@contextmanager
def ignored(*exceptions: Type[BaseException]) -> Iterator[Any]:
    """Ignore an exception."""
    try:
        yield
    except exceptions:
        pass


def monitor_processes(process_list:       List[Process],
                      software_operation: str,
                      queues:             Dict[bytes, 'Queue[bytes]'],
                      error_exit_code:    int = 1
                      ) -> None:
    """Monitor the status of `process_list` and EXIT_QUEUE.

    This function monitors a list of processes. If one of them dies, it
    terminates the rest and closes TFC with exit code 1.

    If EXIT or WIPE signal is received to EXIT_QUEUE, the function
    terminates running processes and closes the program with exit code 0
    or overwrites existing user data and powers the system off.
    """
    while True:
        with ignored(EOFError, KeyboardInterrupt):
            time.sleep(0.1)

            if not all([p.is_alive() for p in process_list]):
                for p in process_list:
                    p.terminate()
                sys.exit(error_exit_code)

            if queues[EXIT_QUEUE].qsize() > 0:
                command = queues[EXIT_QUEUE].get()

                for p in process_list:
                    p.terminate()

                if command == EXIT:
                    sys.exit(0)

                if command == WIPE:
                    with open('/etc/os-release') as f:
                        data = f.read()
                    if TAILS not in data:
                        shred_databases(software_operation)
                    power_off_system()


def power_off_system() -> None:
    """Power off system."""
    os.system(POWEROFF)


def process_arguments() -> Tuple[str, bool, bool]:
    """Load program-specific settings from command line arguments.

    The arguments are determined by the desktop entries and in the
    Terminator configuration file for local testing. The descriptions
    here are provided for the sake of completeness.
    """
    parser = argparse.ArgumentParser(f'python3.7 {sys.argv[0]}',
                                     usage='%(prog)s [OPTION]',
                                     epilog='Full documentation at: <https://github.com/maqp/tfc/wiki>')

    parser.add_argument('-r',
                        action='store_true',
                        default=False,
                        dest='operation',
                        help="run Receiver instead of Transmitter Program")

    parser.add_argument('-l',
                        action='store_true',
                        default=False,
                        dest='local_test',
                        help="enable local testing mode")

    parser.add_argument('-d',
                        action='store_true',
                        default=False,
                        dest='data_diode_sockets',
                        help="use data diode simulator sockets during local testing mode")

    args      = parser.parse_args()
    operation = RX if args.operation else TX

    return operation, args.local_test, args.data_diode_sockets


def readable_size(size: int) -> str:
    """Convert file size from bytes to a human-readable form."""
    f_size = float(size)
    for unit in ['', 'K', 'M', 'G', 'T', 'P', 'E', 'Z']:
        if abs(f_size) < 1024.0:
            return f'{f_size:3.1f}{unit}B'
        f_size /= 1024.0
    return f'{f_size:3.1f}YB'


def reset_terminal() -> None:
    """Reset terminal."""
    os.system(RESET)


def round_up(value: Union[int, float]) -> int:
    """Round value to next 10."""
    return int(math.ceil(value / 10.0)) * 10


def shred_databases(software_operation: str) -> None:
    """Shred TFC databases and remove directories."""
    if software_operation == RX:
        subprocess.Popen("find {} -type f -exec shred -n 3 -z -u {{}} \\;".format(DIR_RECV_FILES), shell=True).wait()

    subprocess.Popen("find {} -name '{}*' -type f -exec shred -n 3 -z -u {{}} \\;"
                     .format(DIR_USER_DATA, software_operation), shell=True).wait()

    for d in [DIR_USER_DATA, DIR_RECV_FILES]:
        with ignored(FileNotFoundError):
            shutil.rmtree(d)


def split_byte_string(bytestring: bytes,  # Bytestring to split
                      item_len: int       # Length of each substring
                      ) -> List[bytes]:   # List of substrings
    """Split a bytestring into a list of specific length substrings."""
    return [bytestring[i:i + item_len] for i in range(0, len(bytestring), item_len)]


def split_string(string:   str,   # String to split
                 item_len: int    # Length of each substring
                 ) -> List[str]:  # List of substrings
    """Split a string into a list of specific length substrings."""
    return [string[i:i + item_len] for i in range(0, len(string), item_len)]


def separate_header(bytestring:    bytes,      # Bytestring to slice
                    header_length: int         # Number of header bytes to separate
                    ) -> Tuple[bytes, bytes]:  # Header and payload
    """Separate `header_length` first bytes from a bytestring."""
    return bytestring[:header_length], bytestring[header_length:]


def separate_headers(bytestring:         bytes,      # Bytestring to slice
                     header_length_list: List[int],  # List of header lengths
                     ) -> List[bytes]:               # Header and payload
    """Separate a list of headers from bytestring.

    Length of each header is determined in the `header_length_list`.
    """
    fields = []
    for header_length in header_length_list:
        field, bytestring = separate_header(bytestring, header_length)
        fields.append(field)
    fields.append(bytestring)

    return fields


def separate_trailer(bytestring:     bytes,     # Bytestring to slice
                     trailer_length: int        # Number of trailer bytes to separate
                     ) -> Tuple[bytes, bytes]:  # Payload and trailer
    """Separate `trailer_length` last bytes from a bytestring.

    This saves space and makes trailer separation more readable.
    """
    return bytestring[:-trailer_length], bytestring[-trailer_length:]


def split_to_substrings(bytestring: bytes, length: int) -> List[bytes]:
    """Split byte string into all it's possible `length` long substrings."""
    substrings = []
    for i in range(0, len(bytestring) - length + 1):
        substrings.append(bytestring[i:length + i])

    return substrings


def terminal_width_check(minimum_width: int) -> None:
    """Wait until user re-sizes their terminal to specified width. """
    if get_terminal_width() < minimum_width:
        print("Please make the terminal wider.")
        while get_terminal_width() < minimum_width:
            time.sleep(0.1)
        time.sleep(0.1)
        print(2*CURSOR_UP_ONE_LINE)


def validate_onion_addr(onion_address_contact: str,      # String to slice
                        onion_address_user:    str = ''  # Number of header chars to separate
                        ) -> str:                        # Payload and trailer
    """Validate a v3 Onion Service address."""
    error_msg = ''

    if len(onion_address_contact) != ONION_ADDRESS_LENGTH:
        return "Error: Invalid account length."

    # Together with length check this should make accidental export local key decryption keys hard enough.
    if any(c.isupper() for c in onion_address_contact):
        return "Error: Account must be in lower case."

    try:
        decoded = base64.b32decode(onion_address_contact.upper())

        public_key, checksum, version \
            = separate_headers(decoded, [ONION_SERVICE_PUBLIC_KEY_LENGTH, ONION_ADDRESS_CHECKSUM_LENGTH])

        if checksum != hashlib.sha3_256(ONION_ADDRESS_CHECKSUM_ID
                                        + public_key
                                        + version
                                        ).digest()[:ONION_ADDRESS_CHECKSUM_LENGTH]:
            error_msg = "Checksum error - Check that the entered account is correct."

    except (binascii.Error, ValueError):
        return "Error: Invalid account format."

    if onion_address_contact in (LOCAL_ID, DUMMY_CONTACT, DUMMY_MEMBER) or public_key == LOCAL_PUBKEY:
        error_msg = "Error: Can not add reserved account."

    if onion_address_user and onion_address_contact == onion_address_user:
        error_msg = "Error: Can not add own account."

    return error_msg


def validate_group_name(group_name:   str,            # Name of the group
                        contact_list: 'ContactList',  # ContactList object
                        group_list:   'GroupList'     # GroupList object
                        ) -> str:                     # Error message if validation failed, else empty string
    """Validate the specified group name."""
    error_msg = ''

    # Avoids collision with delimiters
    if not group_name.isprintable():
        error_msg = "Error: Group name must be printable."

    # Length is limited by database's Unicode padding
    if len(group_name) >= PADDING_LENGTH:
        error_msg = f"Error: Group name must be less than {PADDING_LENGTH} chars long."

    if group_name == DUMMY_GROUP:
        error_msg = "Error: Group name cannot use the name reserved for database padding."

    if not validate_onion_addr(group_name):
        error_msg = "Error: Group name cannot have the format of an account."

    if group_name in contact_list.get_list_of_nicks():
        error_msg = "Error: Group name cannot be a nick of contact."

    if group_name in group_list.get_list_of_group_names():
        error_msg = f"Error: Group with name '{group_name}' already exists."

    return error_msg


def validate_key_exchange(key_ex: str,  # Key exchange selection to validate
                          *_: Any       # Unused arguments
                          ) -> str:     # Error message if validation failed, else empty string
    """Validate the specified key exchange."""
    error_msg = ''

    if key_ex.upper() not in [ECDHE, ECDHE[:1], PSK, PSK[:1]]:
        error_msg = "Invalid key exchange selection."

    return error_msg


def validate_nick(nick: str,                                      # Nick to validate
                  args: Tuple['ContactList', 'GroupList', bytes]  # Contact list and group list databases
                  ) -> str:                                       # Error message if validation failed, else ''
    """Validate the specified nickname."""
    contact_list, group_list, onion_pub_key = args

    error_msg = ''

    # Length is limited by database's Unicode padding
    if len(nick) >= PADDING_LENGTH:
        error_msg = f"Error: Nick must be shorter than {PADDING_LENGTH} chars."

    # Avoid delimiter char collision in output packets
    if not nick.isprintable():
        error_msg = "Error: Nick must be printable."

    if nick == '':
        error_msg = "Error: Nick cannot be empty."

    # Receiver displays sent messages under 'Me'
    if nick.lower() == ME.lower():
        error_msg = f"Error: '{ME}' is a reserved nick."

    # Receiver displays system notifications under reserved notification symbol
    if nick == EVENT:
        error_msg = f"Error: '{EVENT}' is a reserved nick."

    # Ensure that nicks, accounts and group names are UIDs in recipient selection
    if validate_onion_addr(nick) == '':  # If no error message was received, nick had format of account
        error_msg = "Error: Nick cannot have the format of an account."

    if nick in (LOCAL_ID, DUMMY_CONTACT, DUMMY_MEMBER):
        error_msg = "Error: Nick cannot have the format of an account."

    if nick in contact_list.get_list_of_nicks():
        error_msg = same_contact_check(onion_pub_key, nick, contact_list)

    if nick in group_list.get_list_of_group_names():
        error_msg = "Error: Nick cannot be a group name."

    return error_msg


def same_contact_check(onion_pub_key: bytes,
                       nick:          str,
                       contact_list:  'ContactList'
                       ) -> str:
    """Check if nick matches the account being replaced."""
    error_msg = "Error: Nick already in use."

    if contact_list.has_pub_key(onion_pub_key):
        if nick == contact_list.get_nick_by_pub_key(onion_pub_key):
            error_msg = ''

    return error_msg
