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

from src.common.output import print_on_previous_line

if typing.TYPE_CHECKING:
    from src.common.db_settings import Settings
    from src.tx.windows         import Window


class UserInput(object):
    """UserInput objects are messages, files or commands.

    The type of created object is determined based on input by user. Commands
    start with slash, but as files are a special case of command, commands
    starting with /file are interpreted as file type. The type allows tx_loop
    to determine what function should process the user input.
    """

    def __init__(self,
                 window:   'Window',
                 settings: 'Settings') -> None:
        """Create a new UserInput object."""
        self.window    = window
        self.settings  = settings
        self.w_type    = 'group ' if window.type == 'group' else ''
        self.plaintext = self.get_input()
        self.process_aliases()
        self.type      = self.detect_input_type()
        self.check_empty_group()

    def get_input(self) -> str:
        """Get message/command from user."""
        try:
            plaintext = input(f"Msg to {self.w_type}{self.window.name}: ")

            # Ignore empty inputs
            if plaintext in ['', '/']:
                print_on_previous_line()
                return self.get_input()

            return plaintext

        except (KeyboardInterrupt, EOFError):
            print('')
            print_on_previous_line()
            return self.get_input()

    def process_aliases(self) -> None:
        """Check if input was an alias for existing command."""
        aliases = [(' ',  '/unread'),
                   ('  ', '/exit' if self.settings.double_space_exits else '/clear'),
                   ('//', '/cmd')]

        for a in aliases:
            if self.plaintext == a[0]:
                self.plaintext = a[1]
                print_on_previous_line()
                print(f"Msg to {self.w_type}{self.window.name}: {self.plaintext}")

    def detect_input_type(self) -> str:
        """Detect type of input to process."""
        if self.plaintext == '/file':
            return 'file'
        elif self.plaintext.startswith('/'):
            self.plaintext = self.plaintext[1:]
            return 'command'
        else:
            return 'message'

    def check_empty_group(self) -> None:
        """Notify the user if group was empty."""
        if self.type == 'message' and self.window.type == 'group' and len(self.window.window_contacts) == 0:
            print_on_previous_line()
            print(f"Msg to {self.w_type}{self.window.name}: Error: Group is empty.")
            print_on_previous_line(delay=0.5)
            self.__init__(self.window, self.settings)
