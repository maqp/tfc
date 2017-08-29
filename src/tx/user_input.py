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

import typing

from src.common.output  import print_on_previous_line
from src.common.statics import *

if typing.TYPE_CHECKING:
    from src.common.db_settings import Settings
    from src.tx.windows         import TxWindow


def process_aliases(plaintext: str, settings: 'Settings', window: 'TxWindow') -> str:
    """Check if plaintext is an alias for another command."""
    aliases = [(' ',  '/unread'                                           ),
               ('  ', '/exit' if settings.double_space_exits else '/clear'),
               ('//', '/cmd'                                              )]

    for a in aliases:
        if plaintext == a[0]:
            plaintext = a[1]
            print_on_previous_line()
            print(f"Msg to {window.type_print} {window.name}: {plaintext}")
            break

    return plaintext


def get_input(window: 'TxWindow', settings: 'Settings') -> 'UserInput':
    """Read and process input from user."""
    while True:
        try:
            plaintext = input(f"Msg to {window.type_print} {window.name}: ")
            if plaintext in ['', '/']:
                raise EOFError
        except (EOFError, KeyboardInterrupt):
            print('')
            print_on_previous_line()
            continue

        plaintext = process_aliases(plaintext, settings, window)

        # Determine plaintext type
        pt_type = MESSAGE
        if plaintext == '/file':
            pt_type = FILE
        elif plaintext.startswith('/'):
            plaintext = plaintext[1:]
            pt_type   = COMMAND

        # Check if group was empty
        if pt_type in [MESSAGE, FILE] and window.type == WIN_TYPE_GROUP and not window.group.has_members():
            print_on_previous_line()
            print(f"Msg to {window.type_print} {window.name}: Error: Group is empty.")
            print_on_previous_line(delay=0.5)
            continue

        return UserInput(plaintext, pt_type)


class UserInput(object):
    """UserInput objects are messages, files or commands.

    The type of created UserInput object is determined based on input
    by user. Commands start with slash, but as files are a special case
    of command, /file commands are interpreted as file type. The 'type'
    attribute allows tx_loop to determine what function should process
    the user input.
    """

    def __init__(self, plaintext: str, type_: str) -> None:
        """Create a new UserInput object."""
        self.plaintext = plaintext
        self.type      = type_
