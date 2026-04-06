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

from typing import TYPE_CHECKING

from src.common.types_custom import BoolIsWhisperedMessage, StrPlaintextMessage
from src.common.statics import PayloadType
from src.common.utils.encoding import bool_to_bytes
from src.ui.common.output.vt100_utils import clear_previous_lines

if TYPE_CHECKING:
    from src.database.db_settings import Settings
    from src.ui.transmitter.window_tx import TxWindow


class GetUserInput:
    """CLI UI object that reads input from user."""

    def __init__(self,
                 settings : 'Settings',
                 window   : 'TxWindow'
                 ) -> None:
        """Create a new GetUserInput object."""
        self.__settings = settings
        self.__window   = window

    @property
    def target(self) -> str:
        """Get to whom message is being sent."""
        return f'{self.__window.window_type_hr} {self.__window.window_name}'

    def get_input(self) -> 'UserInput':
        """Read and process input from the user and determine its type."""
        while True:
            try:
                plaintext = input(f'Msg to {self.__window.window_type_hr} {self.__window.window_name}: ')
                if plaintext in ['', '/']:
                    raise ValueError
            except (EOFError, KeyboardInterrupt, ValueError):
                print('')
                clear_previous_lines(no_lines=1)
                continue

            plaintext = self.process_aliases(plaintext)

            # Determine plaintext type
            pt_type = PayloadType.MESSAGE

            if plaintext == '/file':
                pt_type = PayloadType.FILE

            elif plaintext.startswith('/'):
                plaintext = plaintext[1:]
                pt_type   = PayloadType.COMMAND

            # Prevent sending messages/files to empty group
            if self.__window.is_empty_group_window and pt_type != PayloadType.COMMAND:
                clear_previous_lines(no_lines=1)
                print(f'{pt_type} to {self.target}: Error: The group is empty.')
                clear_previous_lines(no_lines=1, delay=0.5)
                continue

            return UserInput(StrPlaintextMessage(plaintext), pt_type)

        raise RuntimeError('Broke out of loop')

    def process_aliases(self, orig_message : str) -> str:
        """Check if plaintext is an alias for another command."""
        if   orig_message == ' ':  message = '/unread'
        elif orig_message == '//': message = '/cmd'
        elif orig_message == '  ': message = '/exit' if self.__settings.double_space_exits else '/clear'
        else:                      message = orig_message

        if message != orig_message:
            # Replace what the user typed
            clear_previous_lines(no_lines=1)
            print(f'Msg to {self.__window.window_type_hr} {self.__window.window_name}: {message}')

        return message


class UserInput:
    """\
    UserInput is a wrapper for the given input that carries
    the main data type (message, file, or command) with it.

    The type of created UserInput object is determined based on input
    by the user. Commands start with a slash, but as files are a special
    case of a command, /file commands are interpreted as the file type.
    The 'type' attribute allows `input_process()` to determine what function
    should process the user input.
    """

    def __init__(self,
                 plaintext   : StrPlaintextMessage,
                 packet_type : PayloadType,
                 is_whisper  : BoolIsWhisperedMessage = BoolIsWhisperedMessage(False)
                 ) -> None:
        """Create a new UserInput object."""
        self.__plaintext  = plaintext
        self.__type       = packet_type
        self.__is_whisper = is_whisper

    @property
    def is_message(self) -> bool:
        """Return True if this user input is a message."""
        return self.__type == PayloadType.MESSAGE

    @property
    def is_file(self) -> bool:
        """Return True if this user input is a file."""
        return self.__type == PayloadType.FILE

    @property
    def is_command(self) -> bool:
        """Return True if this user input is a command."""
        return self.__type == PayloadType.COMMAND

    @property
    def whisper_bytes(self) -> bytes:
        """Return bytes representation about if the message is whispered.

        This means that it requests the Receiver
        Program of contact to not log the message.

        Note: This behavior can not be guaranteed as
        the user can just take screenshots, edit the
        source code of their TFC endpoint etc.
        """
        return bool_to_bytes(self.__is_whisper)

    @property
    def plaintext(self) -> str:
        """Return the plaintext of the user input."""
        return self.__plaintext

    @property
    def plaintext_bytes(self) -> bytes:
        """Return the plaintext message."""
        return self.__plaintext.encode()
