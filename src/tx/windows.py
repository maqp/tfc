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

from typing import Dict, Generator, Iterable, List, Sized

from src.common.exceptions import FunctionReturn
from src.common.output     import clear_screen
from src.common.statics    import *

from src.tx.packet import queue_command

if typing.TYPE_CHECKING:
    from multiprocessing        import Queue
    from src.common.db_contacts import Contact, ContactList
    from src.common.db_groups   import Group, GroupList
    from src.common.db_settings import Settings
    from src.tx.user_input      import UserInput


class MockWindow(Iterable):
    """Mock window simplifies queueing of message assembly packets."""

    def __init__(self, uid: str, contacts: List['Contact']) -> None:
        """Create new mock window."""
        self.uid             = uid
        self.window_contacts = contacts
        self.log_messages    = self.window_contacts[0].log_messages
        self.type            = WIN_TYPE_CONTACT
        self.group           = None  # type: Group
        self.name            = None  # type: str

    def __iter__(self) -> Generator:
        """Iterate over contact objects in window."""
        yield from self.window_contacts


class TxWindow(Iterable, Sized):
    """
    TxWindow objects manages ephemeral communications
    data associated with selected contact or group.
    """

    def __init__(self,
                 contact_list: 'ContactList',
                 group_list:   'GroupList') -> None:
        """Create a new TxWindow object."""
        self.contact_list    = contact_list
        self.group_list      = group_list
        self.window_contacts = []    # type: List[Contact]
        self.group           = None  # type: Group
        self.contact         = None  # type: Contact
        self.name            = None  # type: str
        self.type            = None  # type: str
        self.type_print      = None  # type: str
        self.uid             = None  # type: str
        self.imc_name        = None  # type: str
        self.log_messages    = None  # type: bool

    def __iter__(self) -> Generator:
        """Iterate over Contact objects in window."""
        yield from self.window_contacts

    def __len__(self) -> int:
        """Return the number of contacts in window."""
        return len(self.window_contacts)

    def select_tx_window(self,
                         settings:  'Settings',
                         queues:    Dict[bytes, 'Queue'],
                         selection: str  = None,
                         cmd:       bool = False) -> None:
        """Select specified window or ask the user to specify one."""
        if selection is None:
            self.contact_list.print_contacts()
            self.group_list.print_groups()
            selection = input("Select recipient: ").strip()

        if selection in self.group_list.get_list_of_group_names():
            if cmd and settings.session_traffic_masking and selection != self.uid:
                raise FunctionReturn("Error: Can't change window during traffic masking.")

            self.group           = self.group_list.get_group(selection)
            self.window_contacts = self.group.members
            self.name            = self.group.name
            self.uid             = self.name
            self.log_messages    = self.group.log_messages
            self.type            = WIN_TYPE_GROUP
            self.type_print      = 'group'

            if self.window_contacts:
                self.imc_name = self.window_contacts[0].rx_account

        elif selection in self.contact_list.contact_selectors():
            if cmd and settings.session_traffic_masking:
                contact = self.contact_list.get_contact(selection)
                if contact.rx_account != self.uid:
                    raise FunctionReturn("Error: Can't change window during traffic masking.")

            self.contact         = self.contact_list.get_contact(selection)
            self.window_contacts = [self.contact]
            self.name            = self.contact.nick
            self.uid             = self.contact.rx_account
            self.imc_name        = self.contact.rx_account
            self.log_messages    = self.contact.log_messages
            self.type            = WIN_TYPE_CONTACT
            self.type_print      = 'contact'

        else:
            raise FunctionReturn("Error: No contact/group was found.")

        if settings.session_traffic_masking and not cmd:
            queues[WINDOW_SELECT_QUEUE].put((self.window_contacts, self.log_messages))

        packet = WINDOW_SELECT_HEADER + self.uid.encode()
        queue_command(packet, settings, queues[COMMAND_PACKET_QUEUE])

        clear_screen()

    def deselect_window(self) -> None:
        """Deselect active window."""
        self.window_contacts = []
        self.group           = None  # type: Group
        self.contact         = None  # type: Contact
        self.name            = None  # type: str
        self.type            = None  # type: str
        self.uid             = None  # type: str
        self.imc_name        = None  # type: str

    def is_selected(self) -> bool:
        """Return True if window is selected, else False."""
        return self.name is not None

    def update_log_messages(self) -> None:
        """Update window's logging setting."""
        if self.type == WIN_TYPE_CONTACT:
            self.log_messages = self.contact.log_messages
        if self.type == WIN_TYPE_GROUP:
            self.log_messages = self.group.log_messages

    def update_group_win_members(self, group_list: 'GroupList') -> None:
        """Update window's group members list."""
        if self.type == WIN_TYPE_GROUP:
            if group_list.has_group(self.name):
                self.group           = group_list.get_group(self.name)
                self.window_contacts = self.group.members
                if self.window_contacts:
                    self.imc_name = self.window_contacts[0].rx_account
            else:
                self.deselect_window()


def select_window(user_input: 'UserInput',
                  window:     'TxWindow',
                  settings:   'Settings',
                  queues:     Dict[bytes, 'Queue']) -> None:
    """Select new window to send messages/files to."""
    try:
        selection = user_input.plaintext.split()[1]
    except (IndexError, TypeError):
        raise FunctionReturn("Error: Invalid recipient.")

    window.select_tx_window(settings, queues, selection, cmd=True)
