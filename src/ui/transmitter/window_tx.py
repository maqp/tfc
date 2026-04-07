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

from typing import TYPE_CHECKING, Iterator, Optional as O, Iterable

from src.common.entities.serialized_command import SerializedCommand
from src.common.entities.window_name import WindowName
from src.common.entities.window_uid import WindowUID
from src.common.types_custom import BoolLogMessages, BoolSelectWinByCmd, BytesWindowUID
from src.common.utils.validators import validate_second_field
from src.common.exceptions import SoftError, CriticalError
from src.datagrams.relay.command.contact_remove import DatagramRelayRemoveContact
from src.ui.common.input.get_yes import get_yes
from src.ui.common.output.vt100_utils import clear_screen
from src.common.statics import KexStatus, RxCommand, WindowType
from src.common.entities.group_name import GroupName

from src.transmitter.key_exchanges.add_contact import add_new_contact
from src.transmitter.key_exchanges.onion_service import export_onion_service_data
from src.transmitter.key_exchanges.x448 import start_key_exchange
from src.transmitter.queue_packet.queue_packet import queue_command
from src.ui.common.output.print_tables import print_contacts, print_groups

if TYPE_CHECKING:
    from src.common.entities.contact import Contact
    from src.common.entities.group import Group
    from src.common.entities.group_id import GroupID
    from src.common.gateway import Gateway
    from src.common.queues import TxQueue
    from src.database.db_contacts import ContactList
    from src.database.db_groups import GroupList
    from src.database.db_local_key import LocalKeyDB
    from src.database.db_masterkey import MasterKey
    from src.database.db_onion import OnionService
    from src.database.db_settings import Settings


class TxWindow:
    """TxWindow object contains data about the active recipient (contact or group)."""

    def __init__(self,
                 contact_list : 'ContactList',
                 group_list   : 'GroupList',
                 ) -> None:
        """Create a new TxWindow object."""
        self.contact_list = contact_list
        self.group_list   = group_list

        self.contact : O['Contact'] = None
        self.group   : O['Group']   = None

    # ┌───────────────┐
    # │ Window Status │
    # └───────────────┘

    def __len__(self) -> int:
        """Return the number of recipients in the selected window."""
        if   self.contact is     None and self.group is     None: return 0
        elif self.contact is not None and self.group is     None: return 1
        elif self.contact is     None and self.group is not None: return len(self.group)
        else: raise CriticalError('Contact and Group can not be selected at the same time.')

    @property
    def is_selected(self) -> bool:
        """Return True if a contact or group is currently selected."""
        return self.contact is not None or self.group is not None

    @property
    def is_empty_group_window(self) -> bool:
        """Return True if the window represents an empty group window."""
        if self.group is not None:
            return self.group.empty()
        return False

    # ┌───────────┐
    # │ Iteration │
    # └───────────┘

    def __iter__(self) -> Iterator['Contact']:
        """Iterate over contact or group members."""
        if self.contact is not None:
            return iter((self.contact,))
        if self.group is not None:
            return iter(self.group)
        return iter(())

    @property
    def window_contacts(self) -> list['Contact']:
        """Get the window contacts as list"""
        return [contact for contact in self]

    # ┌─────────────┐
    # │ Window Type │
    # └─────────────┘

    @property
    def is_contact_window(self) -> bool:
        """Return True if the window is a contact window."""
        return self.contact is not None and self.group is    None

    @property
    def is_group_window(self) -> bool:
        """Return True if the window is a group window."""
        return self.contact is    None and self.group is not None

    @property
    def window_type(self) -> WindowType:
        """Return the window type."""
        return WindowType.GROUP if self.is_group_window else WindowType.CONTACT

    @property
    def window_type_hr(self) -> str:
        """Return printable string for the window type."""
        return self.window_type.value

    # ┌─────────────┐
    # │ Identifiers │
    # └─────────────┘

    @property
    def window_uid(self) -> WindowUID:
        """Get the unique window identifier."""
        if   self.contact is not None: return WindowUID.for_contact(self.contact)
        elif self.group   is not None: return WindowUID.for_group(self.group)
        else: raise CriticalError('Unable to determine WindowUID.')

    @property
    def uid_bytes(self) -> bytes:
        """Return the WindowUID in its bytes form."""
        return self.window_uid.raw_bytes

    @property
    def uid_tbytes(self) -> BytesWindowUID:
        """Return the type-safe UID bytes for the window"""
        return BytesWindowUID(self.uid_bytes)

    @property
    def group_id(self) -> O['GroupID']:
        """Get the group ID for the window."""
        return None if self.group is None else self.group.group_id

    @property
    def window_name(self) -> WindowName:
        """Get window name."""
        if   self.contact is not None: return WindowName(self.contact.nick.value)
        elif self.group   is not None: return WindowName(self.group.group_name.value)
        else: raise CriticalError('Unable to determine WindowName.')


    # ┌──────────┐
    # │ Settings │
    # └──────────┘

    @property
    def log_messages(self) -> bool:
        """Return True if logging of messages is enabled for the window."""
        if   self.contact is not None: return self.contact.log_messages
        elif self.group   is not None: return self.group.log_messages
        else: raise CriticalError('Unable to determine message logging setting.')

    @property
    def log_messages_tbytes(self) -> BoolLogMessages:
        """Return type-safe boolean for message logging."""
        return BoolLogMessages(self.log_messages)

    # ┌────────────────────┐
    # │ Window Deselection │
    # └────────────────────┘

    def deselect(self) -> None:
        """Deselect active window."""
        self.contact = None
        self.group   = None

    # ┌──────────────────┐
    # │ Window Selection │
    # └──────────────────┘

    def get_input_from_user(self) -> str:
        """Get input from user."""
        print_contacts(self.contact_list)
        print_groups(self.group_list)

        if self.contact_list.has_only_pending_contacts():
            print("\n'/connect'   Sends Onion Service/contact data to Relay"
                  "\n'/add'       Adds another contact"
                  "\n'/rm <Nick>' Removes an existing contact\n")

        selection = input('Select recipient: ').strip()

        return selection

    def select_tx_window(self,
                         settings      : 'Settings',
                         queues        : 'TxQueue',
                         master_key    : 'MasterKey',
                         local_key_db  : 'LocalKeyDB',
                         onion_service : 'OnionService',
                         gateway       : 'Gateway',
                         selection     : O[str] = None,
                         via_command   : BoolSelectWinByCmd = BoolSelectWinByCmd(False)
                         ) -> None:
        """Select specified window or ask the user to specify one."""
        selection_ = self.get_input_from_user() if selection is None else selection

        # Contacts
        if selection_ in self.contact_list.get_contact_selectors():
            self.select_contact(settings, queues, master_key, local_key_db, selection_, via_command)

        # Groups
        elif selection_ in [group_name.value for group_name in self.group_list.get_list_of_group_names()]:
            self.select_group(GroupName(selection_), via_command, settings)

        elif selection_ in self.group_list.get_list_of_hr_group_ids():
            group_name = self.group_list.get_group_by_id(GroupID.from_string(selection_)).group_name
            self.select_group(group_name, via_command, settings)

        # Available commands
        elif selection_.startswith('/'):
            self.process_win_select_command(settings, queues, gateway, onion_service, master_key, local_key_db, selection_)

        else:
            raise SoftError('Error: No contact/group was found.')

        if settings.traffic_masking:
            # Lock traffic masking mode on sender process to selected window
            queues.tm_recipient_list.put([member for member in self])

        # Send window selection to Receiver Program
        queue_command(settings, queues, SerializedCommand(RxCommand.WIN_SELECT, self.window_uid.raw_bytes))

        clear_screen()

    def select_contact(self,
                       settings     : 'Settings',
                       queues       : 'TxQueue',
                       master_key   : 'MasterKey',
                       local_key_db : 'LocalKeyDB',
                       selection    : str,
                       via_command  : BoolSelectWinByCmd,
                       ) -> None:
        """Select contact."""
        if via_command and settings.traffic_masking:
            contact = self.contact_list.get_contact_by_address_or_nick(selection)

            if contact.onion_pub_key.public_bytes_raw != self.window_uid.raw_bytes:
                raise SoftError("Error: Can't change window during traffic masking.", clear_before=True)

        self.contact = self.contact_list.get_contact_by_address_or_nick(selection)
        self.group   = None
        clear_screen()

        assert self.contact is not None

        if self.contact.kex_status == KexStatus.KEX_STATUS_PENDING:
            start_key_exchange(self.contact.onion_pub_key, self.contact.nick, self.contact_list, settings, local_key_db, master_key, queues)

    def select_group(self,
                     group_name : GroupName,
                     cmd        : 'BoolSelectWinByCmd',
                     settings   : 'Settings'
                     ) -> None:
        """Select group."""
        if cmd and settings.traffic_masking and group_name.value != self.window_name.value:
            raise SoftError("Error: Can't change window during traffic masking.", clear_before=True)

        self.contact = None
        self.group   = self.group_list.get_group(group_name)
        clear_screen()

    def process_win_select_command(self,
                                   settings      : 'Settings',
                                   queues        : 'TxQueue',
                                   gateway       : 'Gateway',
                                   onion_service : 'OnionService',
                                   master_key    : 'MasterKey',
                                   local_key_db  : 'LocalKeyDB',
                                   selection     : str,
                                   ) -> None:
        """Commands for contact management and Onion Service export from the selection menu.

        In situations where only pending contacts are available and
        those contacts are not online, these commands prevent the user
        from not being able to add new contacts.
        """
        if selection == '/add':
            add_new_contact(settings, queues, self.contact_list, self.group_list, master_key, local_key_db, onion_service)
            raise SoftError('New contact added.', output=False)

        if selection == '/connect':
            export_onion_service_data(settings, self.contact_list, onion_service, gateway)
            raise SoftError('Onion Service data export complete.', output=False)

        if selection.startswith('/group'):
            from src.transmitter.commands.management.manage_groups import process_group_command
            from src.ui.transmitter.user_input import UserInput
            from src.common.types_custom import StrPlaintextMessage
            from src.common.statics import PayloadType

            process_group_command(settings,
                                  queues,
                                  self.contact_list,
                                  self.group_list,
                                  UserInput(StrPlaintextMessage(selection[1:]), PayloadType.COMMAND),
                                  master_key)
            raise SoftError('', output=False)

        elif selection.startswith('/rm'):
            selection = validate_second_field(selection, key='account')

            if selection in self.contact_list.get_contact_selectors():
                if not get_yes(f"Remove contact '{selection}'?", abort=False, head=1):
                    raise SoftError('Removal of contact aborted.', padding_top=0, clear_delay=1)

                onion_pub_key = self.contact_list.get_contact_by_address_or_nick(selection).onion_pub_key
                queues.relay_packet.put(DatagramRelayRemoveContact(onion_pub_key))
                self.contact_list.remove_contact(onion_pub_key)
                self.contact_list.store_contacts()
                raise SoftError(f"Removed contact '{selection}'.", clear_delay=1)
            else:
                raise SoftError(f"Error: Unknown contact '{selection}'.", clear_delay=1)

        else:
            raise SoftError('Error: Invalid window select command.', clear_delay=1)

    def update_window(self, group_list: 'GroupList') -> None:
        """Update window.

        Since previous input may have changed the window members,
        reload window data before prompting for UserInput.

        Window contact is reloaded in case keys were re-exchanged.
        """

        if self.is_group_window:
            if self.group_id is not None and group_list.has_group_id(self.group_id):
                self.group = group_list.get_group_by_id(self.group_id)
            else:
                self.deselect()
        else:
            if self.contact is not None and self.contact_list.has_onion_pub_key(self.contact.onion_pub_key):
                self.contact = self.contact_list.get_contact_by_pub_key(self.contact.onion_pub_key)
            else:
                self.deselect()


class MockWindow(Iterable['Contact']):
    """\
    Mock window simplifies queueing of message assembly packets for
    automatically generated group management and key delivery messages.
    """

    def __init__(self, window_uid: WindowUID, contacts: list['Contact']) -> None:
        """Create a new MockWindow object."""
        self.window_uid      = window_uid
        self.window_contacts = contacts

        self.type    = WindowType.CONTACT
        self.group   = None  # type: O[Group]
        self.contact = self.window_contacts[0]
        self.name    = None  # type: O[str]

    def __iter__(self) -> Iterator['Contact']:
        """Iterate over contact objects in the window."""
        yield from self.window_contacts

    @property
    def is_contact_window(self) -> bool:
        """Return True if the window is a contact window."""
        return self.contact is not None and self.group is    None

    @property
    def is_group_window(self) -> bool:
        """Return True if the window is a group window."""
        return self.contact is    None and self.group is not None

    @property
    def window_type(self) -> WindowType:
        """Return the window type."""
        return WindowType.GROUP if self.is_group_window else WindowType.CONTACT

    @property
    def uid_bytes(self) -> bytes:
        """Return the WindowUID in its bytes form."""
        return self.window_uid.raw_bytes

    @property
    def uid_tbytes(self) -> BytesWindowUID:
        """Return the type-safe UID bytes for the window"""
        return BytesWindowUID(self.uid_bytes)

    @property
    def log_messages(self) -> bool:
        """Return True if logging of messages is enabled for the window."""
        return self.window_contacts[0].log_messages

    @property
    def log_messages_tbytes(self) -> BoolLogMessages:
        """Return type-safe boolean for message logging."""
        return BoolLogMessages(self.log_messages)
