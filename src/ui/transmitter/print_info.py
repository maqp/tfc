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

from typing import TYPE_CHECKING

from src.common.entities.group_id import GroupID
from src.common.entities.group_name import GroupName
from src.common.exceptions import SoftError

from src.common.statics import ProgramLiterals
from src.ui.common.output.print_message import print_message
from src.ui.common.output.vt100_utils import clear_screen
from src.ui.common.output.print_tables import print_contacts, print_groups, print_gateway_settings, print_system_settings
from src.ui.common.utils import get_terminal_width
from src.common.utils.validators import validate_second_field

if TYPE_CHECKING:
    from src.common.gateway import Gateway
    from src.database.db_contacts import ContactList
    from src.database.db_groups import GroupList
    from src.database.db_settings import Settings
    from src.ui.transmitter.user_input import UserInput


def print_recipients(contact_list: 'ContactList', group_list: 'GroupList') -> None:
    """Print the list of contacts and groups."""
    print_contacts(contact_list)
    print_groups(group_list)


def print_settings(settings: 'Settings', gateway: 'Gateway') -> None:
    """Print settings and gateway settings."""
    print_system_settings(settings)
    print_gateway_settings(gateway.settings)


def print_about() -> None:
    """Print URLs that direct to TFC's project site and documentation."""
    clear_screen()
    print(f'\n Tinfoil Chat {ProgramLiterals.VERSION}\n\n'
          ' Website:     https://github.com/maqp/tfc/\n'
          ' Wikipage:    https://github.com/maqp/tfc/wiki\n')


def print_help(settings: 'Settings') -> None:
    """Print the list of commands."""

    def help_printer(tuple_list: list[tuple[str, str, bool]]) -> None:
        """Print list of commands and their descriptions.

        Style in which commands are printed depends on terminal width.
        Depending on whether traffic masking is enabled, some commands
        are either displayed or hidden.
        """
        len_longest_command = max(len(t[0]) for t in tuple_list) + 1  # Add one for spacing
        wrapper             = textwrap.TextWrapper(width=max(1, terminal_width - len_longest_command))

        for help_cmd, description, display in tuple_list:
            if not display:
                continue

            desc_lines  = wrapper.fill(description).split('\n')
            desc_indent = (len_longest_command - len(help_cmd)) * ' '

            print(help_cmd + desc_indent + desc_lines[0])

            # Print wrapped description lines with indent
            if len(desc_lines) > 1:
                for line in desc_lines[1:]:
                    print(len_longest_command * ' ' + line)
                print('')

    # ------------------------------------------------------------------------------------------------------------------

    y_tm = settings.traffic_masking
    n_tm = not y_tm

    common_commands = [("/about",                    "Show links to project resources",                     True),
                       ("/add",                      "Add new contact",                                     n_tm),
                       ("/cc",                       "Clear replay ciphertext caches on Transmitter, Relay and Receiver", n_tm),
                       ("/cf",                       "Cancel file transmission to active contact/group",    y_tm),
                       ("/cm",                       "Cancel message transmission to active contact/group", True),
                       ("/clear, '  '",              "Clear TFC screens",                                   True),
                       ("/cmd, '//'",                "Display command window on Receiver",                  True),
                       ("/connect",                  "Resend Onion Service data to Relay",                  True),
                       ("/exit",                     "Exit TFC on all three computers",                     True),
                       ("/export (n)",               "Export (n) messages from recipient's log file",       True),
                       ("/file",                     "Send file to active contact/group",                   True),
                       ("/fw",                       "Display file reception window on Receiver",           y_tm),
                       ("/help",                     "Display this list of commands",                       True),
                       ("/history (n)",              "Print (n) messages from recipient's log file",        True),
                       ("/localkey",                 "Generate new local key pair",                         n_tm),
                       ("/logging {on,off}(' all')", "Change message log setting (for all contacts)",       True),
                       ("/msg {A,N,G}",              "Change recipient to Account, Nick, or Group",         n_tm),
                       ("/names",                    "List contacts and groups",                            True),
                       ("/nick N",                   "Change nickname of active recipient/group to N",      True),
                       ("/notify {on,off} (' all')", "Change notification settings (for all contacts)",     True),
                       ("/passwd {tx,rx}",           "Change master password on target system",             n_tm),
                       ("/psk",                      "Open PSK import dialog on Receiver",                  n_tm),
                       ("/reset",                    "Reset ephemeral session log for active window",       True),
                       ("/rm {A,N}",                 "Remove contact specified by account A or nick N",     n_tm),
                       ("/rf a",                     "Resend cached Relay file ciphertext with id a",       n_tm),
                       ("/rmlogs {A,N}",             "Remove log entries for account A or nick N",          True),
                       ("/rr P₁..Pₙ",                "Resend cached Relay packet numbers P₁..Pₙ",           n_tm),
                       ("/rt P₁..Pₙ",                "Resend cached Transmitter packet numbers P₁..Pₙ",     True),
                       ("/set S V",                  "Change setting S to value V",                         True),
                       ("/settings",                 "List setting names, values and descriptions",         True),
                       ("/store {on,off} (' all')",  "Change file reception (for all contacts)",            True),
                       ("/unread, ' '",              "List windows with unread messages on Receiver",       True),
                       ("/verify",                   "Verify fingerprints with active contact",             True),
                       ("/whisper M",                "Send message M, asking it not to be logged",          True),
                       ("/whois {A,N}",              "Check which A corresponds to N or vice versa",        True),
                       ("/wipe",                     "Wipe all TFC user data and power off systems",        True),
                       ("Shift + PgUp/PgDn",         "Scroll terminal up/down",                             True)]

    group_commands  = [("/group create G A₁..Aₙ",    "Create group G and add accounts A₁..Aₙ",              n_tm),
                       ("/group join ID G A₁..Aₙ",   "Join group ID, call it G and add accounts A₁..Aₙ",    n_tm),
                       ("/group add G A₁..Aₙ",       "Add accounts A₁..Aₙ to group G",                      n_tm),
                       ("/group rm G A₁..Aₙ",        "Remove accounts A₁..Aₙ from group G",                 n_tm),
                       ("/group rm G",               "Remove group G",                                      n_tm)]

    terminal_width = get_terminal_width()

    clear_screen()

    print(textwrap.fill('List of commands:', width=terminal_width))
    print('')
    help_printer(common_commands)
    print(terminal_width * '─')

    if settings.traffic_masking:
        print('')
    else:
        print(textwrap.fill('Group management:', width=terminal_width))
        print('')
        help_printer(group_commands)
        print(terminal_width * '─' + '\n')


def whois(contact_list : 'ContactList',
          group_list   : 'GroupList',
          user_input   : 'UserInput',
          ) -> None:
    """Do a lookup for a contact or group selector."""
    selector = validate_second_field(user_input, 'account or nick')

    # Contacts
    if selector in contact_list.get_list_of_addresses():
        print_message([f"Nick of '{selector}' is ",
                 f'{contact_list.get_contact_by_address_or_nick(selector).nick}'], bold=True)

    elif selector in contact_list.get_list_of_nick_strings():
        print_message([f"Account of '{selector}' is",
                 f'{contact_list.get_contact_by_address_or_nick(selector).onion_address}'], bold=True)

    # Groups
    elif selector in group_list.get_list_of_group_names():
        print_message([f"Group ID of group '{selector}' is",
                 f'{group_list.get_group(GroupName(selector)).group_id.hr_value}'], bold=True)

    elif selector in group_list.get_list_of_hr_group_ids():
        print_message([f"Name of group with ID '{selector}' is",
                 f'{group_list.get_group_by_id(GroupID.from_string(selector)).group_name}'], bold=True)

    else:
        raise SoftError('Error: Unknown selector.', clear_before=True)
