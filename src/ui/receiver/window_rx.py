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

import os
import sys

from datetime import datetime
from textwrap import TextWrapper
from typing import Any, Iterable, Iterator, Optional as O, TYPE_CHECKING

from src.common.entities.window_name import WindowName
from src.common.entities.window_uid import WindowUID
from src.common.entities.group_id import GroupID
from src.common.exceptions import CriticalError
from src.common.types_custom import BoolIsWhisperedMessage
from src.ui.common.output.print_message import print_message
from src.ui.common.output.vt100_utils import clear_screen, clear_previous_lines
from src.ui.common.utils import get_terminal_width
from src.common.statics import (CLIIndentLiterals, WindowType, WinSelectHeader, Origin, SpecialHandle,
                                FieldLength, CryptoVarLength)
from src.common.utils.strings import s, bold

if TYPE_CHECKING:
    from src.common.crypto.keys.onion_service_keys import OnionPublicKeyContact
    from src.common.entities.contact import Contact
    from src.common.entities.group import Group
    from src.common.entities.payload_buffer import PayloadBuffer
    from src.database.db_contacts import ContactList
    from src.database.db_groups import GroupList
    from src.database.db_settings import Settings


class Message:
    """Message represents a received message"""

    def __init__(self,
                 timestamp    : datetime,
                 contact      : 'Contact',
                 msg_origin   : Origin,
                 msg_content  : str,
                 is_whispered : BoolIsWhisperedMessage,
                 is_event_msg : bool,  # Events displayed among chat logs, like notifications about files being received.
                 ) -> None:
        """Create new Message object"""
        self.contact      = contact
        self.msg_origin   = msg_origin
        self.timestamp    = timestamp
        self.msg_content  = msg_content
        self.is_whispered = is_whispered
        self.is_event_msg = is_event_msg

    @property
    def handle(self) -> str:
        """Determine the handle of the creator of the message"""
        if   self.is_event_msg: return SpecialHandle.EVENT
        elif self.is_from_user: return SpecialHandle.USER.value
        else:                   return self.contact.nick.value

    @property
    def is_system_message(self) -> bool:
        """Return True if the message is system message"""
        return False

    @property
    def is_from_user(self) -> bool:
        """Return True if the message is from the user."""
        return self.msg_origin == Origin.USER

    @property
    def is_from_contact(self) -> bool:
        """Return True if the message is from the contact."""
        return self.msg_origin == Origin.CONTACT


class SystemMessage:
    """SystemMessage represents a system message in RxSystemMsgWindow"""

    def __init__(self,
                 timestamp    : datetime,
                 msg_content  : str,
                 ) -> None:
        """Create new SystemMessage object"""
        self.timestamp    = timestamp
        self.msg_content  = msg_content
        self.is_whispered = False
        self.is_event_msg = False
    @property
    def handle(self) -> str:
        """Determine the handle of the creator of the message"""
        return SpecialHandle.SYSTEM_MESSAGE

    @property
    def is_system_message(self) -> bool:
        """Return True if the message is system message"""
        return True


class RxWindow:
    """RxWindow is an ephemeral message log for contact or group.

    Command history and file transfers have their
    own windows, accessible with separate commands.
    """

    def __init__(self,
                 settings     : 'Settings',
                 contact_list : 'ContactList',
                 group_list   : 'GroupList',
                 payload_buffer: 'PayloadBuffer',
                 window_uid   : WindowUID
                 ) -> None:
        """Create a new RxWindow object."""
        self.contact_list   = contact_list
        self.group_list     = group_list
        self.settings       = settings
        self.payload_buffer = payload_buffer
        self.window_uid     = window_uid

        self.contact : O['Contact'] = None
        self.group   : O['Group']   = None

        self.is_active    = False
        self.group_msg_id = os.urandom(FieldLength.GROUP_MSG_ID)

        self.message_log : dict[datetime, Message|SystemMessage] = {}
        self.handle_dict : 'dict[OnionPublicKeyContact, str]'    = {}

        self.last_read_msg_timestamp = datetime.now()

    def refresh_window_selection(self) -> None:
        """Resolve the window UID to the current contact or group object."""
        self.contact = None
        self.group   = None

        raw_uid = self.window_uid.raw_bytes

        if raw_uid in [WinSelectHeader.SYSTEM_MESSAGES, WinSelectHeader.FILE_TRANSFERS]:
            return

        if len(raw_uid) == FieldLength.GROUP_ID.value:
            group_id = GroupID(raw_uid)
            if self.group_list.has_group_id(group_id):
                self.group = self.group_list.get_group_by_id(group_id)
            return

        if len(raw_uid) == CryptoVarLength.ONION_SERVICE_PUBLIC_KEY.value:
            try:
                self.contact = self.contact_list.get_contact_by_raw_pub_key(raw_uid)
            except (KeyError, ValueError):
                return

    # ┌───────────────┐
    # │ Window Status │
    # └───────────────┘

    def __len__(self) -> int:
        """Return number of message tuples in the message log."""
        return len(self.message_log)

    @property
    def no_unread_msgs(self) -> int:
        """Get the number of unread messages in the message log."""
        unread_messages = 0
        for ts in reversed(tuple(self.message_log)):
            if ts <= self.last_read_msg_timestamp:
                break
            unread_messages += 1
        return unread_messages

    @property
    def len_longest_handle(self) -> int:
        """Return the length of the longest handle of the window."""
        return max([len(SpecialHandle.USER.value),
                    *(len(handle) for handle in self.handle_dict.values())])

    @property
    def ts_most_recent_message(self) -> datetime:
        """Get the timestamp of the most recent message."""
        return max(self.message_log)


    # ┌───────────┐
    # │ Iteration │
    # └───────────┘

    def __iter__(self) -> 'Iterator[Message|SystemMessage]':
        """Iterate over window's message log."""
        yield from self.message_log.values()

    @property
    def window_contacts(self) -> list['Contact']:
        """Get the window contacts as a list."""
        self.refresh_window_selection()
        if self.contact is not None:
            return [self.contact]
        if self.group is not None:
            return list(self.group)
        return []

    # ┌─────────────┐
    # │ Window Type │
    # └─────────────┘

    @property
    def is_contact_window(self) -> bool:
        """Return True if the window is a contact window."""
        self.refresh_window_selection()
        return self.contact is not None and self.group is    None

    @property
    def is_group_window(self) -> bool:
        """Return True if the window is a group window."""
        self.refresh_window_selection()
        return self.contact is    None and self.group is not None

    @property
    def is_chat_window(self) -> bool:
        """Return True if the window is a chat window."""
        return self.is_contact_window or self.is_group_window

    @property
    def is_system_msg_window(self) -> bool:
        """Return True if the window is for system messages."""
        return self.window_uid == WindowUID.system_messages()

    @property
    def is_file_transfer_window(self) -> bool:
        """Return True if the window is for file transfer tracking."""
        return self.window_uid == WindowUID.file_transfers()

    @property
    def window_type(self) -> WindowType:
        """Return the window type."""
        if   self.is_system_msg_window:    return WindowType.SYSTEM_MESSAGES
        elif self.is_file_transfer_window: return WindowType.FILE_TRANSFERS
        elif self.is_contact_window:       return WindowType.CONTACT
        elif self.is_group_window:         return WindowType.GROUP
        else: raise CriticalError('Unable to determine window type.')

    @property
    def window_type_hr(self) -> str:
        """Return printable string for the window type."""
        return self.window_type.value

    # ┌─────────────┐
    # │ Identifiers │
    # └─────────────┘

    @property
    def window_name(self) -> WindowName:
        """Get window name."""
        self.refresh_window_selection()
        if   self.is_system_msg_window:    return WindowName(WindowType.SYSTEM_MESSAGES.capitalize())
        elif self.is_file_transfer_window: return WindowName(WindowType.FILE_TRANSFERS.capitalize())
        elif self.contact is not None:     return WindowName(self.contact.nick.value)
        elif self.group   is not None:     return WindowName(self.group.group_name.value)
        else: raise CriticalError('Unable to determine window name.')

    # ┌──────────┐
    # │ Settings │
    # └──────────┘

    @property
    def log_messages(self) -> bool:
        """Return True if logging of messages is enabled for the window."""
        self.refresh_window_selection()
        if   self.group   is not None: return self.group.log_messages
        elif self.contact is not None: return self.contact.log_messages
        else: raise CriticalError('Invalid window to fetch message logging setting value.')

    @property
    def show_notifications(self) -> bool:
        """Return True if user has enabled notifications from this window."""
        self.refresh_window_selection()

        if   self.contact is not None:     return self.contact.notifications
        elif self.group   is not None:     return self.group.notifications
        elif self.is_system_msg_window:    return False
        elif self.is_file_transfer_window: return False
        else: raise CriticalError('Invalid window to fetch notification setting value.')

    # ┌─────────────┐
    # │ Message Log │
    # └─────────────┘

    def clear_message_log(self) -> None:
        """Clear the window's ephemeral message log."""
        self.message_log = {}

    def add_new_message(self,
                        timestamp   : 'datetime',
                        contact     : 'Contact',
                        origin      : Origin,
                        msg_content : str,
                        whisper     : BoolIsWhisperedMessage = BoolIsWhisperedMessage(False),
                        output      : bool = False,
                        event_msg   : bool = False
                        ) -> None:
        """Add message tuple to message log and optionally print it."""
        self.update_handle_dict(contact.onion_pub_key)
        self.message_log[timestamp] = message = Message(timestamp, contact, origin, msg_content, whisper, event_msg)
        if output: self.print_message(message)

    def add_new_system_message(self,
                               timestamp   : 'datetime',
                               msg_content : str,
                               output      : bool = False,
                               ) -> None:
        """Add message tuple to message log and optionally print it."""
        self.message_log[timestamp] = message = SystemMessage(timestamp, msg_content)
        if output: self.print_message(message, force_output=True)

    # ┌───────────────────┐
    # │ Handle Management │
    # └───────────────────┘

    def update_handle_dict(self, onion_pub_key: 'OnionPublicKeyContact') -> None:
        """Update handle for public key in `handle_dict`."""
        if self.contact_list.has_pub_key(onion_pub_key):
            self.handle_dict[onion_pub_key] = self.contact_list.get_nick_by_pub_key(onion_pub_key).value
        else:
            self.handle_dict[onion_pub_key] = onion_pub_key.short_address

    def reload_handles(self) -> None:
        """Reload the handle dict for this window."""
        handle_dict = {}
        for message in self.message_log.values():
            if isinstance(message, SystemMessage):
                continue
            pub_key = message.contact.onion_pub_key
            if self.contact_list.has_pub_key(pub_key):
                handle_dict[pub_key] = self.contact_list.get_nick_by_pub_key(pub_key).value
            else:
                handle_dict[pub_key] = message.contact.nick.value

        self.handle_dict = handle_dict

    def get_handle(self, message: 'Message|SystemMessage') -> str:
        """Returns indented handle complete with headers and trailers."""
        time_stamp_str = message.timestamp.strftime('%H:%M:%S.%f')[:-4]

        if message.is_system_message or message.is_event_msg:
            handle = message.handle
            ending = ' '
        else:
            len_indent = self.len_longest_handle - len(message.handle) if self.is_active else 0
            handle     = f'{len_indent * ' '}{message.handle}'

            if not self.is_active:
                if   self.is_contact_window: handle += f' (private message)'
                elif self.is_group_window:   handle += f' (group {self.window_name})'

            if message.is_whispered:
                handle += ' (whisper)'

            ending = ': '

        handle = f'{time_stamp_str} {handle}{ending}'

        return handle

    # ┌──────────────────┐
    # │ Window Rendering │
    # └──────────────────┘

    def print_message(self,
                      message      : 'Message|SystemMessage',
                      file         : Any  = None,
                      force_output : bool = False
                      ) -> None:
        """Print a message to the window."""
        write_to_file = file is not None
        output_file   = file if write_to_file else sys.stdout

        handle = self.get_handle(message)

        message_str = message.msg_content
        if not self.is_active and not self.settings.new_message_notify_preview and not self.is_system_msg_window:
            message_str = bold(f'{self.no_unread_msgs} unread message{s(self.no_unread_msgs)}')

        wrapper = TextWrapper(width=get_terminal_width(), initial_indent=handle, subsequent_indent=len(handle)*' ')
        wrapped = wrapper.fill(message_str)
        wrapped = wrapped if wrapped else handle

        date_changed    = self.last_read_msg_timestamp.date() != message.timestamp.date()
        date_change_msg = f'00:00 -!- Date changed to {str(message.timestamp.date())}' if date_changed else None

        if not write_to_file and date_change_msg is not None: date_change_msg = bold(date_change_msg)
        if not write_to_file: wrapped = bold(wrapped, bold_first_n=len(handle))

        if self.is_active or force_output:
            if date_changed: print(date_change_msg, file=output_file)
            print(wrapped, file=output_file)
            self.last_read_msg_timestamp = message.timestamp

        elif self.show_notifications:
            lines   = wrapped.split('\n')
            preview = wrapped if len(lines) <= 1 else lines[0][:-1] + '…'
            print(preview)
            clear_previous_lines(no_lines=1, delay=self.settings.new_message_notify_duration, flush=True)

    def redraw(self, file: Any = None, show_unread_marker: bool = True) -> None:
        """Re-draw the message window."""
        self.reload_handles()
        previous_last_read_msg_timestamp = self.last_read_msg_timestamp
        output_file            = file if file is not None else sys.stdout
        first_unread_timestamp = next((ts for ts in self.message_log if ts > previous_last_read_msg_timestamp), None)

        if file is None: clear_screen()

        if not self.message_log:
            print_message(f'This window for {self.window_name} is currently empty.', bold=True, padding_top=1, padding_bottom=1)
            return

        for timestamp, message in self.message_log.items():
            if show_unread_marker and timestamp == first_unread_timestamp:
                print('\n' + ' Unread Messages '.center(get_terminal_width(), '-') + '\n', file=output_file)

            self.print_message(message, file)

        self.last_read_msg_timestamp = self.ts_most_recent_message

    @staticmethod
    def render_progress_bar(percent: float, width: int) -> str:
        """Render an apt-style ASCII progress bar."""
        filled = round(percent * width)
        filled = max(0, min(width, filled))
        return '[' + ('#' * filled) + ('.' * (width - filled)) + ']'

    def redraw_file_win(self) -> None:
        """Draw file transmission window progress bars."""
        min_progress_bar_width = 10
        max_progress_bar_width = 36

        # Initialize columns
        c1 = ['File name']
        c2 = ['Size']
        c3 = ['Sender']
        c4 = ['Complete']

        rows = []  # type: list[tuple[str, str, str, str, float]]

        # Populate columns with file transmission status data
        for onion_pub_key, payload in self.payload_buffer.iter_contact_file_payloads():
            metadata = payload.transfer_metadata
            if metadata is None:
                continue
            if not self.contact_list.has_pub_key(onion_pub_key):
                continue

            file_name, file_size, packet_total = metadata
            contact = self.contact_list.get_contact_by_pub_key(onion_pub_key)
            percent = len(payload) / packet_total

            c1.append(file_name)
            c2.append(file_size)
            c3.append(contact.nick.value)
            c4.append(f'{percent * 100:6.2f}%')
            rows.append((file_name, file_size, contact.nick.value, f'{percent * 100:6.2f}%', percent))

        if len(c1) <= 1:
            print_message('No file transmissions currently in progress.', bold=True, padding_top=1, padding_bottom=1)
            clear_previous_lines(no_lines=3, delay=0.1)
            return None

        # Calculate column widths
        c1w, c2w, c3w, c4w = [max(len(v) for v in column) + CLIIndentLiterals.FILE_TRANSFER_INDENT for column in [c1, c2, c3, c4]]

        terminal_width = get_terminal_width()
        fixed_width    = c1w + c2w + c3w + c4w
        raw_bar_width  = terminal_width - fixed_width - len('Progress') - CLIIndentLiterals.FILE_TRANSFER_INDENT - 2
        bar_width      = max(min_progress_bar_width, min(max_progress_bar_width, raw_bar_width))
        c5w            = max(len('Progress'), bar_width + 2) + CLIIndentLiterals.FILE_TRANSFER_INDENT

        # Align columns by adding whitespace between fields of each line
        lines = [f'{'File name':{c1w}}{'Size':{c2w}}{'Sender':{c3w}}{'Complete':{c4w}}{'Progress':{c5w}}']
        lines.extend(f'{name:{c1w}}{size:{c2w}}{sender:{c3w}}{complete:{c4w}}{self.render_progress_bar(percent, bar_width):{c5w}}'
                     for name, size, sender, complete, percent in rows)

        # Add a terminal-wide line between the column names and the data
        lines.insert(1, terminal_width * '─')

        # Print the file transfer list
        print('\n' + '\n'.join(lines) + '\n')
        clear_previous_lines(no_lines=len(lines) + 2, delay=0.1)
        return None


class WindowList(Iterable[RxWindow]):
    """WindowList manages a list of Window objects."""

    def __init__(self,
                 settings       : 'Settings',
                 contact_list   : 'ContactList',
                 group_list     : 'GroupList',
                 payload_buffer : 'PayloadBuffer',
                 window_uid     : O[WindowUID]=None
                 ) -> None:
        """Create a new WindowList object."""
        self.settings       = settings
        self.contact_list   = contact_list
        self.group_list     = group_list
        self.payload_buffer = payload_buffer
        self.window_uid     = window_uid

        self.windows = [RxWindow(settings, contact_list, group_list, payload_buffer, uid) for uid in self.window_selectors]

        self.active_win : O[RxWindow] = None

        self.set_active_rx_window(WindowUID(WinSelectHeader.SYSTEM_MESSAGES))

    def __iter__(self) -> 'Iterator[RxWindow]':
        """Iterate over window list."""
        yield from self.windows

    def __len__(self) -> int:
        """Return number of windows in the window list."""
        return len(self.windows)

    @property
    def sys_msg_win(self) -> RxWindow:
        """Return the system message window."""
        return self.get_or_create_window(WindowUID.system_messages())

    @property
    def file_transfer_win(self) -> RxWindow:
        """Return the file transfer window."""
        return self.get_or_create_window(WindowUID.file_transfers())

    @property
    def window_selectors(self) -> list[WindowUID]:
        """Return list of WindowSelector objects."""
        return ([WindowUID.system_messages(), WindowUID.file_transfers()]
                + self.contact_list.get_list_of_win_uids()
                + self.group_list.get_list_of_win_uids()
                )

    def has_window(self, window_uid: WindowUID,) -> bool:
        """Return True if a window with matching UID exists, else False."""
        return any(w.window_uid == window_uid for w in self.windows)

    def remove_window(self, window_uid: WindowUID) -> None:
        """Remove window based on its UID."""
        for i, w in enumerate(self.windows):
            if window_uid == w.window_uid:
                del self.windows[i]
                break

    def get_or_create_window(self, window_uid: WindowUID) -> 'RxWindow':
        """Return window that matches the specified UID.

        Create window if it does not exist.
        """
        if not self.has_window(window_uid):
            self.windows.append(RxWindow(self.settings, self.contact_list, self.group_list, self.payload_buffer, window_uid))

        return next(w for w in self.windows if w.window_uid == window_uid)

    def refresh_file_window_check(self) -> None:
        """Check if file window needs to be refreshed."""
        if self.active_win is not None and self.active_win.is_file_transfer_window:
            self.active_win.redraw_file_win()

    def set_active_rx_window(self, window_uid: WindowUID) -> None:
        """Select new active window."""
        if self.active_win is not None:
            self.active_win.is_active = False

        self.active_win           = self.get_or_create_window(window_uid)
        self.active_win.is_active = True

        if self.active_win.is_file_transfer_window:
            self.active_win.redraw_file_win()
        else:
            self.active_win.redraw()
