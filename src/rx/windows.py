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

import os
import sys
import textwrap
import typing

from datetime import datetime
from typing   import Dict, Generator, Iterable, List, Tuple

from src.common.exceptions import FunctionReturn
from src.common.misc       import get_terminal_width
from src.common.output     import c_print, clear_screen, print_on_previous_line
from src.common.statics    import *

if typing.TYPE_CHECKING:
    from src.common.db_contacts import Contact, ContactList
    from src.common.db_groups   import GroupList
    from src.common.db_settings import Settings
    from src.rx.packet          import PacketList


class RxWindow(Iterable):
    """RxWindow is an ephemeral message log for contact or group.

    In addition, command history and file transfers have
    their own windows, accessible with separate commands.
    """

    def __init__(self,
                 uid:          str,
                 contact_list: 'ContactList',
                 group_list:   'GroupList',
                 settings:     'Settings',
                 packet_list:  'PacketList' = None) -> None:
        """Create a new RxWindow object."""
        self.uid          = uid
        self.contact_list = contact_list
        self.group_list   = group_list
        self.settings     = settings
        self.packet_list  = packet_list

        self.is_active    = False
        self.group_msg_id = os.urandom(GROUP_MSG_ID_LEN)

        self.window_contacts = []      # type: List[Contact]
        self.message_log     = []      # type: List[Tuple[datetime, str, str, bytes, bool]]
        self.handle_dict     = dict()  # type: Dict[str, str]
        self.previous_msg_ts = datetime.now()
        self.unread_messages = 0

        if self.uid == LOCAL_ID:
            self.type            = WIN_TYPE_COMMAND
            self.type_print      = 'system messages'
            self.window_contacts = [self.contact_list.get_contact(LOCAL_ID)]
            self.name            = self.type_print

        elif self.uid == WIN_TYPE_FILE:
            self.type        = WIN_TYPE_FILE
            self.packet_list = packet_list

        elif self.uid in self.contact_list.get_list_of_accounts():
            self.type            = WIN_TYPE_CONTACT
            self.type_print      = 'contact'
            self.window_contacts = [self.contact_list.get_contact(uid)]
            self.name            = self.contact_list.get_contact(uid).nick

        elif self.uid in self.group_list.get_list_of_group_names():
            self.type            = WIN_TYPE_GROUP
            self.type_print      = 'group'
            self.window_contacts = self.group_list.get_group_members(self.uid)
            self.name            = self.group_list.get_group(self.uid).name

        else:
            raise FunctionReturn(f"Invalid window '{uid}'")

    def __len__(self) -> int:
        """Return number of message tuples in message log."""
        return len(self.message_log)

    def __iter__(self) -> Generator:
        """Iterate over window's message log."""
        yield from self.message_log

    def add_contacts(self, accounts: List[str]) -> None:
        """Add contact objects to window."""
        self.window_contacts += [self.contact_list.get_contact(a) for a in accounts
                                 if not self.has_contact(a) and self.contact_list.has_contact(a)]

    def remove_contacts(self, accounts: List[str]) -> None:
        """Remove contact objects from window."""
        to_remove = set(accounts) & set([m.rx_account for m in self.window_contacts])
        if to_remove:
            self.window_contacts = [c for c in self.window_contacts if c.rx_account not in to_remove]

    def reset_window(self) -> None:
        """Reset window."""
        self.message_log = []

    def has_contact(self, account: str) -> bool:
        """Return True if contact with specified account is in window, else False."""
        return any(c.rx_account == account for c in self.window_contacts)

    def create_handle_dict(self, message_log: List[Tuple['datetime', str, str, bytes, bool]] = None) -> None:
        """Pre-generate {account: handle} dictionary.

        This allows `self.print()` to indent accounts and nicks without
        having to loop over entire message list for every message.
        """
        accounts = set(c.rx_account for c in self.window_contacts)
        if message_log is not None:
            accounts |= set(a for ts, ma, a, o, w in message_log)
        for a in accounts:
            self.handle_dict[a] = self.contact_list.get_contact(a).nick if self.contact_list.has_contact(a) else a

    def get_handle(self, time_stamp: 'datetime', account: str, origin: bytes, whisper: bool=False) -> str:
        """Returns indented handle complete with headers and trailers."""
        if self.type == WIN_TYPE_COMMAND:
            handle = "-!- "
        else:
            handle  = self.handle_dict[account] if origin == ORIGIN_CONTACT_HEADER else "Me"
            handles = list(self.handle_dict.values()) + ["Me"]
            indent  = len(max(handles, key=len)) - len(handle) if self.is_active else 0
            handle  = indent * ' ' + handle

        handle = time_stamp.strftime('%H:%M') + ' ' + handle

        if not self.is_active:
            handle += {WIN_TYPE_GROUP:   f" (group {self.name})",
                       WIN_TYPE_CONTACT: f" (private message)"  }.get(self.type, '')

        if self.type != WIN_TYPE_COMMAND:
            if whisper:
                handle += " (whisper)"
            handle += ": "

        return handle

    def print(self, msg_tuple: Tuple['datetime', str, str, bytes, bool], file=None) -> None:
        """Print new message to window."""
        bold_on, bold_off, f_name             = (BOLD_ON, NORMAL_TEXT, sys.stdout) if file is None else ('', '', file)
        ts, message, account, origin, whisper = msg_tuple

        if not self.is_active and not self.settings.new_message_notify_preview and self.type != WIN_TYPE_COMMAND:
            message = BOLD_ON + f"{self.unread_messages + 1} unread message{'s' if self.unread_messages > 1 else ''}" + NORMAL_TEXT

        handle  = self.get_handle(ts, account, origin, whisper)
        wrapper = textwrap.TextWrapper(get_terminal_width(), initial_indent=handle, subsequent_indent=len(handle)*' ')
        wrapped = wrapper.fill(message)
        if wrapped == '':
            wrapped = handle
        wrapped = bold_on + wrapped[:len(handle)] + bold_off + wrapped[len(handle):]

        if self.is_active:
            if self.previous_msg_ts.date() != ts.date():
                print(bold_on + f"00:00 -!- Day changed to {str(ts.date())}" + bold_off, file=f_name)
            print(wrapped, file=f_name)

        else:
            self.unread_messages += 1
            if (self.type == WIN_TYPE_CONTACT and self.contact_list.get_contact(account).notifications) \
            or (self.type == WIN_TYPE_GROUP   and self.group_list.get_group(self.uid).notifications) \
            or (self.type == WIN_TYPE_COMMAND):

                if len(wrapped.split('\n')) > 1:
                    # Preview only first line of long message
                    print(wrapped.split('\n')[0][:-3] + "...")
                else:
                    print(wrapped)
                print_on_previous_line(delay=self.settings.new_message_notify_duration, flush=True)

        self.previous_msg_ts = ts

    def add_new(self,
                timestamp: 'datetime',
                message:   str,
                account:   str   = LOCAL_ID,
                origin:    bytes = ORIGIN_USER_HEADER,
                output:    bool  = False,
                whisper:   bool  = False) -> None:
        """Add message tuple to message log and optionally print it."""
        msg_tuple = (timestamp, message, account, origin, whisper)
        self.message_log.append(msg_tuple)

        self.handle_dict[account] = (self.contact_list.get_contact(account).nick
                                     if self.contact_list.has_contact(account) else account)
        if output:
            self.print(msg_tuple)

    def redraw(self, file=None) -> None:
        """Print all messages received to window."""
        self.unread_messages = 0

        if file is None:
            clear_screen()

        if self.message_log:
            self.previous_msg_ts = self.message_log[0][0]
            self.create_handle_dict(self.message_log)
            for msg_tuple in self.message_log:
                self.print(msg_tuple, file)
        else:
            c_print(f"This window for {self.name} is currently empty.", head=1, tail=1)

    def redraw_file_win(self) -> None:
        """Draw file transmission window progress bars."""
        # Columns
        c1 = ['File name']
        c2 = ['Size']
        c3 = ['Sender']
        c4 = ['Complete']

        for i, p in enumerate(self.packet_list):
            if p.type == FILE and len(p.assembly_pt_list) > 0:
                c1.append(p.name)
                c2.append(p.size)
                c3.append(p.contact.nick)
                c4.append(f"{len(p.assembly_pt_list) / p.packets * 100:.2f}%")

        if not len(c1) > 1:
            c_print("No file transmissions currently in progress.", head=1, tail=1)
            print_on_previous_line(reps=3, delay=0.1)
            return None

        lst = []
        for name, size, sender, percent, in zip(c1, c2, c3, c4):
            lst.append('{0:{1}} {2:{3}} {4:{5}} {6:{7}}'.format(
                name,    max(len(v) for v in c1) + CONTACT_LIST_INDENT,
                size,    max(len(v) for v in c2) + CONTACT_LIST_INDENT,
                sender,  max(len(v) for v in c3) + CONTACT_LIST_INDENT,
                percent, max(len(v) for v in c4) + CONTACT_LIST_INDENT))

        lst.insert(1, get_terminal_width() * '─')

        print('\n' + '\n'.join(lst) + '\n')
        print_on_previous_line(reps=len(lst)+2, delay=0.1)


class WindowList(Iterable):
    """WindowList manages a list of Window objects."""

    def __init__(self,
                 settings:     'Settings',
                 contact_list: 'ContactList',
                 group_list:   'GroupList',
                 packet_list:  'PacketList') -> None:
        """Create a new WindowList object."""
        self.settings     = settings
        self.contact_list = contact_list
        self.group_list   = group_list
        self.packet_list  = packet_list

        self.active_win = None  # type: RxWindow
        self.windows    = [RxWindow(uid, self.contact_list, self.group_list, self.settings, self.packet_list)
                           for uid in ([WIN_TYPE_FILE]
                                       + self.contact_list.get_list_of_accounts()
                                       + self.group_list.get_list_of_group_names())]

        if self.contact_list.has_local_contact():
            self.select_rx_window(LOCAL_ID)

    def __len__(self) -> int:
        """Return number of windows in window list."""
        return len(self.windows)

    def __iter__(self) -> Generator:
        """Iterate over window list."""
        yield from self.windows

    def get_group_windows(self) -> List[RxWindow]:
        """Return list of group windows."""
        return [w for w in self.windows if w.type == WIN_TYPE_GROUP]

    def has_window(self, uid: str) -> bool:
        """Return True if window with matching UID exists, else False."""
        return uid in [w.uid for w in self.windows]

    def remove_window(self, uid: str) -> None:
        """Remove window based on it's UID."""
        for i, w in enumerate(self.windows):
            if uid == w.uid:
                del self.windows[i]
                break

    def select_rx_window(self, uid: str) -> None:
        """Select new active window."""
        if self.active_win is not None:
            self.active_win.is_active = False
        self.active_win           = self.get_window(uid)
        self.active_win.is_active = True

        if self.active_win.type == WIN_TYPE_FILE:
            self.active_win.redraw_file_win()
        else:
            self.active_win.redraw()

    def get_local_window(self) -> 'RxWindow':
        """Return command window."""
        return self.get_window(LOCAL_ID)

    def get_window(self, uid: str) -> 'RxWindow':
        """Return window that matches the specified UID.

        Create window if it does not exist.
        """
        if not self.has_window(uid):
            self.windows.append(RxWindow(uid, self.contact_list, self.group_list, self.settings, self.packet_list))

        return next(w for w in self.windows if w.uid == uid)
