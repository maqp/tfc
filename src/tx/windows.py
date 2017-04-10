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

from typing import Dict, List

from src.common.errors  import FunctionReturn
from src.common.misc    import clear_screen
from src.common.statics import *
from src.tx.packet      import queue_command

if typing.TYPE_CHECKING:
    from multiprocessing        import Queue
    from src.common.db_contacts import Contact, ContactList
    from src.common.db_groups   import Group, GroupList
    from src.common.db_settings import Settings
    from src.tx.user_input      import UserInput


class Window(object):
    """
    Window objects manages ephemeral communications
    data associated with selected contact or group.
    """

    def __init__(self,
                 contact_list: 'ContactList',
                 group_list:   'GroupList') -> None:
        """Create a new window object."""
        self.contact_list    = contact_list
        self.group_list      = group_list
        self.window_contacts = []    # type: List[Contact]
        self.group           = None  # type: Group
        self.contact         = None  # type: Contact
        self.name            = None  # type: str
        self.type            = None  # type: str
        self.uid             = None  # type: str
        self.imc_name        = None  # type: str

    def __iter__(self) -> 'Contact':
        """Iterate over contact objects in window."""
        for c in self.window_contacts:
            yield c

    def __len__(self) -> int:
        """Return the number of contacts in current window."""
        return len(self.window_contacts)

    def is_selected(self) -> bool:
        """Return True if a window is selected, else False."""
        return self.name is not None

    def deselect(self) -> None:
        """Deselect active window."""
        self.window_contacts = []
        self.group           = None  # type: Group
        self.contact         = None  # type: Contact
        self.name            = None  # type: str
        self.type            = None  # type: str
        self.uid             = None  # type: str
        self.imc_name        = None  # type: str

    def update_group_win_members(self, group_list: 'GroupList') -> None:
        """Update window's group members list."""
        if self.type == 'group':
            if group_list.has_group(self.name):
                self.group = group_list.get_group(self.name)
                self.window_contacts = self.group.members
                if self.window_contacts:
                    self.imc_name = self.window_contacts[0].rx_account
            else:
                self.deselect()

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
            if cmd and settings.session_trickle and selection != self.uid:
                raise FunctionReturn("Can't change window during trickle connection.")

            self.group           = self.group_list.get_group(selection)
            self.window_contacts = self.group.members
            self.name            = self.group.name
            self.uid             = self.name
            self.type            = 'group'

            if self.window_contacts:
                self.imc_name = self.window_contacts[0].rx_account

        elif selection in self.contact_list.contact_selectors():

            if cmd and settings.session_trickle:
                contact = self.contact_list.get_contact(selection)
                if self.uid != contact.rx_account:
                    raise FunctionReturn("Can't change window during trickle connection.")

            self.contact         = self.contact_list.get_contact(selection)
            self.window_contacts = [self.contact]
            self.name            = self.contact.nick
            self.uid             = self.contact.rx_account
            self.imc_name        = self.contact.rx_account
            self.type            = 'contact'

        else:
            raise FunctionReturn("Error: No contact/group was found.")

        if settings.session_trickle and not cmd:
            queues[WINDOW_SELECT_QUEUE].put(self.window_contacts)

        packet = WINDOW_CHANGE_HEADER + self.uid.encode()
        queue_command(packet, settings, queues[COMMAND_PACKET_QUEUE])

        clear_screen()


def select_window(user_input: 'UserInput',
                  window:     'Window',
                  settings:   'Settings',
                  queues:     Dict[bytes, 'Queue']) -> None:
    """Select new window for messages."""
    try:
        selection = user_input.plaintext.split()[1]
    except (IndexError, TypeError):
        raise FunctionReturn("Invalid recipient.")

    window.select_tx_window(settings, queues, selection, cmd=True)
