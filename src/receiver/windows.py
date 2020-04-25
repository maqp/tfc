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

import os
import sys
import textwrap
import typing

from datetime import datetime
from typing   import Any, Dict, Iterable, Iterator, List, Optional, Tuple

from src.common.encoding   import b58encode, pub_key_to_onion_address, pub_key_to_short_address
from src.common.exceptions import SoftError
from src.common.misc       import get_terminal_width
from src.common.output     import clear_screen, m_print, print_on_previous_line
from src.common.statics    import (BOLD_ON, EVENT, FILE, FILE_TRANSFER_INDENT, GROUP_ID_LENGTH, GROUP_MSG_ID_LENGTH, ME,
                                   NORMAL_TEXT, ONION_SERVICE_PUBLIC_KEY_LENGTH, ORIGIN_CONTACT_HEADER,
                                   ORIGIN_USER_HEADER, WIN_TYPE_COMMAND, WIN_TYPE_CONTACT, WIN_TYPE_FILE,
                                   WIN_TYPE_GROUP, WIN_UID_FILE, WIN_UID_COMMAND)

if typing.TYPE_CHECKING:
    from src.common.db_contacts import Contact, ContactList
    from src.common.db_groups   import GroupList
    from src.common.db_settings import Settings
    from src.receiver.packet    import Packet, PacketList

MsgTuple = Tuple[datetime, str, bytes, bytes, bool, bool]


class RxWindow(Iterable[MsgTuple]):
    """RxWindow is an ephemeral message log for contact or group.

    In addition, command history and file transfers have
    their own windows, accessible with separate commands.
    """

    def __init__(self,
                 uid:          bytes,
                 contact_list: 'ContactList',
                 group_list:   'GroupList',
                 settings:     'Settings',
                 packet_list:  'PacketList'
                 ) -> None:
        """Create a new RxWindow object."""
        self.uid          = uid
        self.contact_list = contact_list
        self.group_list   = group_list
        self.settings     = settings
        self.packet_list  = packet_list

        self.is_active    = False
        self.contact      = None
        self.group        = None
        self.group_msg_id = os.urandom(GROUP_MSG_ID_LENGTH)

        self.window_contacts = []      # type: List[Contact]
        self.message_log     = []      # type: List[MsgTuple]
        self.handle_dict     = dict()  # type: Dict[bytes, str]
        self.previous_msg_ts = datetime.now()
        self.unread_messages = 0

        if self.uid == WIN_UID_COMMAND:
            self.type            = WIN_TYPE_COMMAND  # type: str
            self.name            = self.type         # type: str
            self.window_contacts = []

        elif self.uid == WIN_UID_FILE:
            self.type        = WIN_TYPE_FILE
            self.packet_list = packet_list

        elif self.uid in self.contact_list.get_list_of_pub_keys():
            self.type            = WIN_TYPE_CONTACT
            self.contact         = self.contact_list.get_contact_by_pub_key(uid)
            self.name            = self.contact.nick
            self.window_contacts = [self.contact]

        elif self.uid in self.group_list.get_list_of_group_ids():
            self.type            = WIN_TYPE_GROUP
            self.group           = self.group_list.get_group_by_id(self.uid)
            self.name            = self.group.name
            self.window_contacts = self.group.members

        else:
            if len(uid) == ONION_SERVICE_PUBLIC_KEY_LENGTH:
                hr_uid = pub_key_to_onion_address(uid)
            elif len(uid) == GROUP_ID_LENGTH:
                hr_uid = b58encode(uid)
            else:
                hr_uid = "<unable to encode>"

            raise SoftError(f"Invalid window '{hr_uid}'.")

    def __iter__(self) -> Iterator[MsgTuple]:
        """Iterate over window's message log."""
        yield from self.message_log

    def __len__(self) -> int:
        """Return number of message tuples in the message log."""
        return len(self.message_log)

    def add_contacts(self, pub_keys: List[bytes]) -> None:
        """Add contact objects to the window."""
        self.window_contacts += [self.contact_list.get_contact_by_pub_key(k) for k in pub_keys
                                 if not self.has_contact(k) and self.contact_list.has_pub_key(k)]

    def remove_contacts(self, pub_keys: List[bytes]) -> None:
        """Remove contact objects from the window."""
        to_remove = set(pub_keys) & set([m.onion_pub_key for m in self.window_contacts])
        if to_remove:
            self.window_contacts = [c for c in self.window_contacts if c.onion_pub_key not in to_remove]

    def reset_window(self) -> None:
        """Reset the ephemeral message log of the window."""
        self.message_log = []

    def has_contact(self, onion_pub_key: bytes) -> bool:
        """\
        Return True if contact with the specified public key is in the
        window, else False.
        """
        return any(onion_pub_key == c.onion_pub_key for c in self.window_contacts)

    def update_handle_dict(self, pub_key: bytes) -> None:
        """Update handle for public key in `handle_dict`."""
        if self.contact_list.has_pub_key(pub_key):
            self.handle_dict[pub_key] = self.contact_list.get_nick_by_pub_key(pub_key)
        else:
            self.handle_dict[pub_key] = pub_key_to_short_address(pub_key)

    def create_handle_dict(self, message_log: Optional[List[MsgTuple]] = None) -> None:
        """Pre-generate {account: handle} dictionary.

        Pre-generation allows `self.print()` to indent accounts and
        nicks without having to loop over the entire message list for
        every message to determine the amount of require indent.
        """
        pub_keys = set(c.onion_pub_key for c in self.window_contacts)
        if message_log is not None:
            pub_keys |= set(tup[2] for tup in message_log)
        for k in pub_keys:
            self.update_handle_dict(k)

    def get_handle(self,
                   time_stamp:    'datetime',    # Timestamp of message to be printed
                   onion_pub_key: bytes,         # Onion Service public key of contact (used as lookup for handles)
                   origin:        bytes,         # Determines whether to use "Me" or nick of contact as handle
                   whisper:       bool = False,  # When True, displays (whisper) specifier next to handle
                   event_msg:     bool = False   # When True, sets handle to "-!-"
                   ) -> str:                     # Handle to use
        """Returns indented handle complete with headers and trailers."""
        time_stamp_str = time_stamp.strftime('%H:%M:%S.%f')[:-4]

        if onion_pub_key == WIN_UID_COMMAND or event_msg:
            handle = EVENT
            ending = ' '
        else:
            handle  = self.handle_dict[onion_pub_key] if origin == ORIGIN_CONTACT_HEADER else ME
            handles = list(self.handle_dict.values()) + [ME]
            indent  = max(len(v) for v in handles) - len(handle) if self.is_active else 0
            handle  = indent * ' ' + handle

            # Handle specifiers for messages to inactive window
            if not self.is_active:
                handle += {WIN_TYPE_GROUP:   f" (group {self.name})",
                           WIN_TYPE_CONTACT:  " (private message)"}.get(self.type, '')
            if whisper:
                handle += " (whisper)"

            ending = ': '

        handle = f"{time_stamp_str} {handle}{ending}"

        return handle

    def print(self, msg_tuple: MsgTuple, file: Any = None) -> None:
        """Print a new message to the window."""

        # Unpack tuple
        ts, message, onion_pub_key, origin, whisper, event_msg = msg_tuple

        # Determine handle
        handle = self.get_handle(ts, onion_pub_key, origin, whisper, event_msg)

        # Check if message content needs to be changed to privacy-preserving notification
        if not self.is_active and not self.settings.new_message_notify_preview and self.uid != WIN_UID_COMMAND:
            trailer = 's' if self.unread_messages > 0 else ''
            message = BOLD_ON + f"{self.unread_messages + 1} unread message{trailer}" + NORMAL_TEXT

        # Wrap message
        wrapper = textwrap.TextWrapper(width=get_terminal_width(),
                                       initial_indent=handle,
                                       subsequent_indent=len(handle)*' ')
        wrapped = wrapper.fill(message)
        if wrapped == '':
            wrapped = handle

        # Add bolding unless export file is provided
        bold_on, bold_off, f_name = (BOLD_ON, NORMAL_TEXT, sys.stdout) if file is None else ('', '', file)
        wrapped                   = bold_on + wrapped[:len(handle)] + bold_off + wrapped[len(handle):]

        if self.is_active:
            if self.previous_msg_ts.date() != ts.date():
                print(bold_on + f"00:00 -!- Day changed to {str(ts.date())}" + bold_off, file=f_name)
            print(wrapped, file=f_name)

        else:
            if onion_pub_key != WIN_UID_COMMAND:
                self.unread_messages += 1

            if (self.type == WIN_TYPE_CONTACT and self.contact is not None and self.contact.notifications) \
            or (self.type == WIN_TYPE_GROUP   and self.group   is not None and self.group.notifications) \
            or (self.type == WIN_TYPE_COMMAND):

                lines = wrapped.split('\n')
                if len(lines) > 1:
                    print(lines[0][:-1] + '…')  # Preview only first line of the long message
                else:
                    print(wrapped)
                print_on_previous_line(delay=self.settings.new_message_notify_duration, flush=True)

        self.previous_msg_ts = ts

    def add_new(self,
                timestamp:     'datetime',                  # The timestamp of the received message
                message:       str,                         # The content of the message
                onion_pub_key: bytes = WIN_UID_COMMAND,     # The Onion Service public key of associated contact
                origin:        bytes = ORIGIN_USER_HEADER,  # The direction of the message
                output:        bool  = False,               # When True, displays message while adding it to message_log
                whisper:       bool  = False,               # When True, displays message as whisper message
                event_msg:     bool  = False                # When True, uses "-!-" as message handle
                ) -> None:
        """Add message tuple to message log and optionally print it."""
        self.update_handle_dict(onion_pub_key)

        msg_tuple = (timestamp, message, onion_pub_key, origin, whisper, event_msg)
        self.message_log.append(msg_tuple)
        if output:
            self.print(msg_tuple)

    def redraw(self, file: Any = None) -> None:
        """Print all messages received to the window."""
        old_messages         = len(self.message_log) - self.unread_messages
        self.unread_messages = 0

        if file is None:
            clear_screen()

        if self.message_log:
            self.previous_msg_ts = self.message_log[-1][0]
            self.create_handle_dict(self.message_log)
            for i, msg_tuple in enumerate(self.message_log):
                if i == old_messages:
                    print('\n' + ' Unread Messages '.center(get_terminal_width(), '-') + '\n')
                self.print(msg_tuple, file)
        else:
            m_print(f"This window for {self.name} is currently empty.", bold=True, head=1, tail=1)

    def redraw_file_win(self) -> None:
        """Draw file transmission window progress bars."""
        # Initialize columns
        c1 = ['File name']
        c2 = ['Size']
        c3 = ['Sender']
        c4 = ['Complete']

        # Populate columns with file transmission status data
        for p in self.packet_list:  # type: Packet

            if p.type == FILE and len(p.assembly_pt_list) > 0:

                if (    p.name is not None and p.assembly_pt_list is not None
                    and p.size is not None and p.packets          is not None):

                    c1.append(p.name)
                    c2.append(p.size)
                    c3.append(p.contact.nick)
                    c4.append(f"{len(p.assembly_pt_list) / p.packets * 100:.2f}%")

        if len(c1) <= 1:
            m_print("No file transmissions currently in progress.", bold=True, head=1, tail=1)
            print_on_previous_line(reps=3, delay=0.1)
            return None

        # Calculate column widths
        c1w, c2w, c3w, c4w = [max(len(v) for v in column) + FILE_TRANSFER_INDENT for column in [c1, c2, c3, c4]]

        # Align columns by adding whitespace between fields of each line
        lines = [f'{f1:{c1w}}{f2:{c2w}}{f3:{c3w}}{f4:{c4w}}' for f1, f2, f3, f4 in zip(c1, c2, c3, c4)]

        # Add a terminal-wide line between the column names and the data
        lines.insert(1, get_terminal_width() * '─')

        # Print the file transfer list
        print('\n' + '\n'.join(lines) + '\n')
        print_on_previous_line(reps=len(lines)+2, delay=0.1)


class WindowList(Iterable[RxWindow]):
    """WindowList manages a list of Window objects."""

    def __init__(self,
                 settings:     'Settings',
                 contact_list: 'ContactList',
                 group_list:   'GroupList',
                 packet_list:  'PacketList'
                 ) -> None:
        """Create a new WindowList object."""
        self.settings     = settings
        self.contact_list = contact_list
        self.group_list   = group_list
        self.packet_list  = packet_list

        self.active_win = None  # type: Optional[RxWindow]
        self.windows    = [RxWindow(uid, self.contact_list, self.group_list, self.settings, self.packet_list)
                           for uid in ([WIN_UID_COMMAND, WIN_UID_FILE]
                                       + self.contact_list.get_list_of_pub_keys()
                                       + self.group_list.get_list_of_group_ids())]

        if self.contact_list.has_local_contact():
            self.set_active_rx_window(WIN_UID_COMMAND)

    def __iter__(self) -> Iterator[RxWindow]:
        """Iterate over window list."""
        yield from self.windows

    def __len__(self) -> int:
        """Return number of windows in the window list."""
        return len(self.windows)

    def has_window(self, uid: bytes) -> bool:
        """Return True if a window with matching UID exists, else False."""
        return any(w.uid == uid for w in self.windows)

    def remove_window(self, uid: bytes) -> None:
        """Remove window based on its UID."""
        for i, w in enumerate(self.windows):
            if uid == w.uid:
                del self.windows[i]
                break

    def get_group_windows(self) -> List[RxWindow]:
        """Return list of group windows."""
        return [w for w in self.windows if w.type == WIN_TYPE_GROUP]

    def get_window(self, uid: bytes) -> 'RxWindow':
        """Return window that matches the specified UID.

        Create window if it does not exist.
        """
        if not self.has_window(uid):
            self.windows.append(RxWindow(uid, self.contact_list, self.group_list, self.settings, self.packet_list))

        return next(w for w in self.windows if w.uid == uid)

    def refresh_file_window_check(self) -> None:
        """Check if file window needs to be refreshed."""
        if self.active_win is not None and self.active_win.uid == WIN_UID_FILE:
            self.active_win.redraw_file_win()

    def get_command_window(self) -> 'RxWindow':
        """Return command window."""
        return self.get_window(WIN_UID_COMMAND)

    def set_active_rx_window(self, uid: bytes) -> None:
        """Select new active window."""
        if self.active_win is not None:
            self.active_win.is_active = False
        self.active_win           = self.get_window(uid)
        self.active_win.is_active = True

        if self.active_win.uid == WIN_UID_FILE:
            self.active_win.redraw_file_win()
        else:
            self.active_win.redraw()
