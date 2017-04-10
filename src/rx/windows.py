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

import datetime
import os
import textwrap
import time
import typing

from typing import Iterable, List, Tuple, Union

from src.common.misc    import clear_screen, get_tty_w
from src.common.output  import c_print, print_on_previous_line
from src.common.statics import *

if typing.TYPE_CHECKING:
    from src.common.db_contacts import Contact, ContactList
    from src.common.db_groups   import GroupList
    from src.common.db_settings import Settings
    from src.rx.packet          import PacketList


class FileWindow(object):
    """FileWindow is a graphical display of ongoing file transmissions."""

    def __init__(self, uid: str, packet_list: 'PacketList') -> None:
        """Create a new file window object."""
        self.uid             = uid
        self.packet_list     = packet_list
        self.unread_messages = 0
        self.is_active       = False

    def redraw(self):
        """Draw file window frame."""
        ft_found      = False
        line_ctr      = 0
        longest_title = 0
        tty_w         = get_tty_w()

        for p in self.packet_list:
            if p.type == 'file' and len(p.assembly_pt_list) > 0:
                title         = "{} ({}) from {} ".format(p.f_name, p.f_size, p.contact.nick)
                longest_title = max(longest_title, len(title))

        for p in self.packet_list:
            if p.type == 'file' and len(p.assembly_pt_list) > 0:
                line_ctr += 1
                ft_found  = True
                title     = "{} ({}) from {} ".format(p.f_name, p.f_size, p.contact.nick)
                title    += (longest_title - len(title)) * ' '

                bar_len   = max(tty_w - (4 + len(title)), 1)
                ready     = int((len(p.assembly_pt_list) / p.f_packets) * bar_len)
                missing   = bar_len - ready
                bar       = title + '[' + (ready - 1) * '=' + '>' + missing * ' ' + ']'
                print(bar)

        print_on_previous_line(reps=line_ctr)

        if not ft_found:
            c_print("No file transmissions currently in progress.", head=1, tail=1)
            print_on_previous_line(reps=3)


class Window(object):
    """Window is an ephemeral message log for contact or group."""

    def __init__(self,
                 uid:          str,
                 contact_list: 'ContactList',
                 group_list:   'GroupList',
                 settings:     'Settings') -> None:
        """Create a new window object."""
        self.uid             = uid
        self.contact_list    = contact_list
        self.group_list      = group_list
        self.settings        = settings

        self.type            = None  # type: str
        self.is_active       = False
        self.group_timestamp = time.time() * 1000

        self.window_contacts = []  # type: List[Contact]
        self.message_log     = []  # type: List[Tuple[datetime.datetime, str, str, bytes]]
        self.unread_messages = 0

        if self.uid == 'local':
            self.type            = 'command'
            self.window_contacts = [contact_list.get_contact('local')]
            self.name            = 'system messages'

        elif self.uid in self.contact_list.get_list_of_accounts():
            self.type            = 'contact'
            self.window_contacts = [self.contact_list.get_contact(uid)]
            self.name            = self.contact_list.get_contact(uid).nick

        elif self.uid in self.group_list.get_list_of_group_names():
            self.type            = 'group'
            self.window_contacts = self.group_list.get_group_members(self.uid)
            self.name            = self.group_list.get_group(self.uid).name

        else:
            raise ValueError(f"Invalid window UID {uid}.")

        # This attribute is a helper that remembers the timestamp of previous
        # message. It is updated by print_to_window after every printed message
        # so the function knows when to display notification about date changing.
        self.previous_msg_ts = datetime.datetime.now()

    def __len__(self) -> int:
        """Return number of messages."""
        return len(self.message_log)

    def __iter__(self) -> Iterable:
        """Iterate over message log."""
        for m in self.message_log:
            yield m

    def remove_contacts(self, accounts: List[str]) -> None:
        """Remove contact objects from window."""
        for account in accounts:
            for i, m in enumerate(self.window_contacts):
                if account == m.rx_account:
                    del self.window_contacts[i]

    def add_contacts(self, accounts: List[str]) -> None:
        """Add contact objects to window."""
        for a in accounts:
            if not self.has_contact(a) and self.contact_list.has_contact(a):
                self.window_contacts.append(self.contact_list.get_contact(a))

    def reset_window(self) -> None:
        """Reset window."""
        self.message_log = []
        os.system('reset')

    @staticmethod
    def clear_window() -> None:
        """Clear window."""
        clear_screen()

    def has_contact(self, account: str) -> bool:
        """Return true if contact with specified account is in window."""
        return any(c.rx_account == account for c in self.window_contacts)

    def print(self, msg_tuple: Tuple['datetime.datetime', str, str, bytes]) -> None:
        """Print new message to window."""
        ts, message, account, origin = msg_tuple

        if self.type == 'command':
            nick = '-!-'
        else:
            window_nicks   = [c.nick for c in self.window_contacts] + ['Me']
            len_of_longest = len(max(window_nicks, key=len))
            nick           = 'Me' if origin == ORIGIN_USER_HEADER else self.contact_list.get_contact(account).nick
            indent         = len_of_longest - len(nick)
            nick           = indent * ' ' + nick + ':'

        if self.previous_msg_ts.date() != ts.date():
            print(f"00:00 -!- Day changed to {str(ts.date())}")
        self.previous_msg_ts = ts

        timestamp = ts.strftime('%H:%M')
        ts_nick   = f"{timestamp} {nick} "

        if not self.is_active and self.type == 'group':
            ts_nick += f"(group {self.name}) "

        wrapper = textwrap.TextWrapper(initial_indent=ts_nick, subsequent_indent=(len(ts_nick)) * ' ', width=get_tty_w())
        wrapped = wrapper.fill(message)

        # Add bold-effect after wrapping so length of injected VT100 codes does not affect wrapping.
        wrapped = BOLD_ON + wrapped[:len(ts_nick)] + BOLD_OFF + wrapped[len(ts_nick):]

        if self.is_active:
            print(wrapped)
        else:
            self.unread_messages += 1
            if self.contact_list.get_contact(account).notifications:
                # Preview only first line of long message
                if len(wrapped.split('\n')) > 1:
                    print(wrapped.split('\n')[0][:-3] + '...')
                else:
                    print(wrapped)
                print_on_previous_line(delay=self.settings.new_msg_notify_dur, flush=True)

    def print_new(self,
                  timestamp: 'datetime.datetime',
                  message:   str,
                  account:   str   = 'local',
                  origin:    bytes = ORIGIN_USER_HEADER,
                  print_:    bool  = True) -> None:
        """Add message tuple to list (and usually print it)."""
        msg_tuple = (timestamp, message, account, origin)
        self.message_log.append(msg_tuple)
        if print_:
            self.print(msg_tuple)

    def redraw(self) -> None:
        """Print all messages received to window."""
        self.clear_window()
        self.unread_messages = 0
        if self.message_log:
            self.previous_msg_ts = self.message_log[0][0]
        else:
            c_print(f"This window for {self.name} is currently empty.", head=1, tail=1)

        for msg_tuple in self.message_log:
            self.print(msg_tuple)


class WindowList(object):
    """WindowList manages a list of window objects."""

    def __init__(self,
                 contact_list: 'ContactList',
                 group_list:   'GroupList',
                 packet_list:  'PacketList',
                 settings:     'Settings') -> None:
        """Create a new window list object."""
        self.contact_list = contact_list
        self.group_list   = group_list
        self.packet_list  = packet_list
        self.settings     = settings
        self.windows      = []  # type: List[Union[Window, FileWindow]]
        self.active_win   = None  # type: Union[Window, FileWindow]

        for rx_acco in self.contact_list.get_list_of_accounts():
            self.windows.append(Window(rx_acco, self.contact_list, self.group_list, self.settings))

        for name in self.group_list.get_list_of_group_names():
            self.windows.append(Window(name,    self.contact_list, self.group_list, self.settings))

    def __len__(self) -> int:
        """Return number of windows."""
        return len(self.windows)

    def __iter__(self) -> 'WindowList':
        """Iterate over window list."""
        for w in self.windows:
            yield w

    def select_rx_window(self, name: str) -> None:
        """Select new active window."""
        if self.active_win is not None:
            self.active_win.is_active = False
        self.active_win           = self.get_window(name)
        self.active_win.is_active = True
        self.active_win.redraw()

    def has_window(self, name: str) -> bool:
        """Return True if window exists, else False."""
        return name in self.get_list_of_window_names()

    def get_list_of_window_names(self) -> List[str]:
        """Return list of window names."""
        return [w.uid for w in self.windows]

    def get_local_window(self) -> 'Window':
        """Return command window."""
        return self.get_window('local')

    def get_window(self, name: str) -> 'Window':
        """Return window that matches the specified name."""
        if not self.has_window(name):
            if name == FILE_R_WIN_ID_BYTES.decode():
                self.windows.append(FileWindow(name, self.packet_list))
            else:
                self.windows.append(Window(name, self.contact_list, self.group_list, self.settings))

        return next(w for w in self.windows if w.uid == name)
