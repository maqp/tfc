#!/usr/bin/env python3.7
# -*- coding: utf-8 -*-

"""
TFC - Onion-routed, endpoint secure messaging system
Copyright (C) 2013-2019  Markus Ottela

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

import typing

from typing import Any, Dict, Iterable, Iterator, List, Optional, Sized

from src.common.db_contacts import Contact
from src.common.exceptions import SoftError
from src.common.input import yes
from src.common.output import clear_screen
from src.common.statics import (
    KEX_STATUS_PENDING,
    WINDOW_SELECT_QUEUE,
    WIN_SELECT,
    WIN_TYPE_CONTACT,
    WIN_TYPE_GROUP,
)

from src.transmitter.contact import add_new_contact
from src.transmitter.key_exchanges import export_onion_service_data, start_key_exchange
from src.transmitter.packet import queue_command

if typing.TYPE_CHECKING:
    from multiprocessing import Queue
    from src.common.db_contacts import ContactList
    from src.common.db_groups import Group, GroupList
    from src.common.db_onion import OnionService
    from src.common.db_settings import Settings
    from src.common.gateway import Gateway
    from src.transmitter.user_input import UserInput

    QueueDict = Dict[bytes, Queue[Any]]


class TxWindow(Iterable[Contact], Sized):
    """\
    TxWindow object contains data about the active recipient (contact or
    group).
    """

    def __init__(self, contact_list: "ContactList", group_list: "GroupList") -> None:
        """Create a new TxWindow object."""
        self.contact_list = contact_list
        self.group_list = group_list
        self.window_contacts = []  # type: List[Contact]
        self.contact = None  # type: Optional[Contact]
        self.group = None  # type: Optional[Group]
        self.name = ""  # type: str
        self.uid = b""  # type: bytes
        self.group_id = None  # type: Optional[bytes]
        self.log_messages = None  # type: Optional[bool]
        self.type = ""  # type: str
        self.type_print = None  # type: Optional[str]

    def __iter__(self) -> Iterator[Contact]:
        """Iterate over Contact objects in the window."""
        yield from self.window_contacts

    def __len__(self) -> int:
        """Return the number of contacts in the window."""
        return len(self.window_contacts)

    def select_tx_window(
        self,
        settings: "Settings",  # Settings object
        queues: "QueueDict",  # Dictionary of Queues
        onion_service: "OnionService",  # OnionService object
        gateway: "Gateway",  # Gateway object
        selection: Optional[str] = None,  # Selector for window
        cmd: bool = False,  # True when `/msg` command is used to switch window
    ) -> None:
        """Select specified window or ask the user to specify one."""
        if selection is None:
            selection = self.select_recipient()

        if selection in self.group_list.get_list_of_group_names():
            self.select_group(selection, cmd, settings)

        elif selection in self.contact_list.contact_selectors():
            self.select_contact(selection, cmd, queues, settings)

        elif selection.startswith("/"):
            self.window_selection_command(
                selection, settings, queues, onion_service, gateway
            )

        else:
            raise SoftError("Error: No contact/group was found.")

        if settings.traffic_masking:
            queues[WINDOW_SELECT_QUEUE].put(self.window_contacts)

        packet = WIN_SELECT + self.uid
        queue_command(packet, settings, queues)

        clear_screen()

    def select_recipient(self) -> str:
        """Select recipient."""
        self.contact_list.print_contacts()
        self.group_list.print_groups()

        if self.contact_list.has_only_pending_contacts():
            print(
                "\n'/connect'   sends Onion Service/contact data to Relay"
                "\n'/add'       adds another contact."
                "\n'/rm <Nick>' removes an existing contact.\n"
            )

        selection = input("Select recipient: ").strip()

        return selection

    def select_contact(
        self, selection: str, cmd: bool, queues: "QueueDict", settings: "Settings"
    ) -> None:
        """Select contact."""
        if cmd and settings.traffic_masking:
            contact = self.contact_list.get_contact_by_address_or_nick(selection)
            if contact.onion_pub_key != self.uid:
                raise SoftError(
                    "Error: Can't change window during traffic masking.",
                    head_clear=True,
                )

        self.contact = self.contact_list.get_contact_by_address_or_nick(selection)

        if self.contact.kex_status == KEX_STATUS_PENDING:
            start_key_exchange(
                self.contact.onion_pub_key,
                self.contact.nick,
                self.contact_list,
                settings,
                queues,
            )

        self.group = None
        self.group_id = None
        self.window_contacts = [self.contact]
        self.name = self.contact.nick
        self.uid = self.contact.onion_pub_key
        self.log_messages = self.contact.log_messages
        self.type = WIN_TYPE_CONTACT
        self.type_print = "contact"

    def select_group(self, selection: str, cmd: bool, settings: "Settings") -> None:
        """Select group."""
        if cmd and settings.traffic_masking and selection != self.name:
            raise SoftError(
                "Error: Can't change window during traffic masking.", head_clear=True
            )

        self.contact = None
        self.group = self.group_list.get_group(selection)
        self.window_contacts = self.group.members
        self.name = self.group.name
        self.uid = self.group.group_id
        self.group_id = self.group.group_id
        self.log_messages = self.group.log_messages
        self.type = WIN_TYPE_GROUP
        self.type_print = "group"

    def window_selection_command(
        self,
        selection: str,
        settings: "Settings",
        queues: "QueueDict",
        onion_service: "OnionService",
        gateway: "Gateway",
    ) -> None:
        """Commands for adding and removing contacts from contact selection menu.

        In situations where only pending contacts are available and
        those contacts are not online, these commands prevent the user
        from not being able to add new contacts.
        """
        if selection == "/add":
            add_new_contact(
                self.contact_list, self.group_list, settings, queues, onion_service
            )
            raise SoftError("New contact added.", output=False)

        if selection == "/connect":
            export_onion_service_data(
                self.contact_list, settings, onion_service, gateway
            )

        elif selection.startswith("/rm"):
            try:
                selection = selection.split()[1]
            except IndexError:
                raise SoftError("Error: No account specified.", delay=1)

            if not yes(f"Remove contact '{selection}'?", abort=False, head=1):
                raise SoftError("Removal of contact aborted.", head=0, delay=1)

            if selection in self.contact_list.contact_selectors():
                onion_pub_key = self.contact_list.get_contact_by_address_or_nick(
                    selection
                ).onion_pub_key
                self.contact_list.remove_contact_by_pub_key(onion_pub_key)
                self.contact_list.store_contacts()
                raise SoftError(f"Removed contact '{selection}'.", delay=1)

            raise SoftError(f"Error: Unknown contact '{selection}'.", delay=1)

        else:
            raise SoftError("Error: Invalid command.", delay=1)

    def deselect(self) -> None:
        """Deselect active window."""
        self.window_contacts = []
        self.contact = None
        self.group = None
        self.name = ""
        self.uid = b""
        self.log_messages = None
        self.type = ""
        self.type_print = None

    def is_selected(self) -> bool:
        """Return True if a window is selected, else False."""
        return self.name != ""

    def update_log_messages(self) -> None:
        """Update window's logging setting."""
        if self.type == WIN_TYPE_CONTACT and self.contact is not None:
            self.log_messages = self.contact.log_messages
        if self.type == WIN_TYPE_GROUP and self.group is not None:
            self.log_messages = self.group.log_messages

    def update_window(self, group_list: "GroupList") -> None:
        """Update window.

        Since previous input may have changed the window data, reload
        window data before prompting for UserInput.
        """
        if self.type == WIN_TYPE_GROUP:
            if self.group_id is not None and group_list.has_group_id(self.group_id):
                self.group = group_list.get_group_by_id(self.group_id)
                self.window_contacts = self.group.members
                self.name = self.group.name
                self.uid = self.group.group_id
            else:
                self.deselect()

        elif self.type == WIN_TYPE_CONTACT:
            if self.contact is not None and self.contact_list.has_pub_key(
                self.contact.onion_pub_key
            ):
                # Reload window contact in case keys were re-exchanged.
                self.contact = self.contact_list.get_contact_by_pub_key(
                    self.contact.onion_pub_key
                )
                self.window_contacts = [self.contact]


def select_window(
    user_input: "UserInput",
    window: "TxWindow",
    settings: "Settings",
    queues: "QueueDict",
    onion_service: "OnionService",
    gateway: "Gateway",
) -> None:
    """Select a new window to send messages/files."""
    try:
        selection = user_input.plaintext.split()[1]
    except (IndexError, TypeError):
        raise SoftError("Error: Invalid recipient.", head_clear=True)

    window.select_tx_window(
        settings, queues, onion_service, gateway, selection=selection, cmd=True
    )
