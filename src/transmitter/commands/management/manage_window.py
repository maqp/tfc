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

from src.common.entities.nick_name import Nick
from src.common.entities.serialized_command import SerializedCommand
from src.common.exceptions import SoftError, ValidationError
from src.common.statics import WindowType, RxCommand, WinSelectHeader
from src.common.types_custom import BoolSelectWinByCmd, StrWindowName
from src.common.utils.validators import validate_nick, validate_second_field
from src.transmitter.commands.management.manage_groups import group_rename
from src.transmitter.queue_packet.queue_packet import queue_command
from src.ui.common.output.print_message import print_message
from src.ui.common.output.vt100_utils import clear_previous_lines

if TYPE_CHECKING:
    from src.common.crypto.keys.onion_service_keys import OnionPublicKeyContact
    from src.common.gateway import Gateway
    from src.common.queues import TxQueue
    from src.database.db_contacts import ContactList
    from src.database.db_groups import GroupList
    from src.database.db_local_key import LocalKeyDB
    from src.database.db_masterkey import MasterKey
    from src.database.db_onion import OnionService
    from src.database.db_settings import Settings
    from src.ui.transmitter.user_input import UserInput
    from src.ui.transmitter.window_tx import TxWindow


def deselect_window_if_necessary(onion_pub_key : 'OnionPublicKeyContact',
                                 window        : 'TxWindow',
                                 group_list    : 'GroupList'
                                 ) -> None:
    """\
    Check if the window should be deselected after contact is removed.
    """
    if window.window_type == WindowType.CONTACT and window.contact is not None:
        if onion_pub_key == window.contact.onion_pub_key:
            window.deselect()

    if window.window_type == WindowType.GROUP:
        for c in window:
            if c.onion_pub_key == onion_pub_key:
                window.update_window(group_list)

                # If the last member of the group is removed, deselect
                # the group. Deselection is not done in
                # `TxWindow.update_window()` because it would prevent
                # selecting the empty group for group related commands
                # such as notifications.
                if not window.window_contacts:
                    window.deselect()


def change_win_handle(settings     : 'Settings',
                      queues       : 'TxQueue',
                      window       : 'TxWindow',
                      contact_list : 'ContactList',
                      group_list   : 'GroupList',
                      user_input   : 'UserInput',
                      ) -> None:
    """Change the window handle, i.e., nick of contact or name of group."""
    win_name = StrWindowName(validate_second_field(user_input, key='name'))

    if window.window_type == WindowType.GROUP:
        group_rename(win_name, window, contact_list, group_list, settings, queues)
        return None

    if window.contact is None:
        raise SoftError('Error: The window does not have contact.')

    onion_pub_key = window.contact.onion_pub_key

    try:
        validate_nick(win_name, contact_list, group_list, onion_pub_key)
    except ValidationError as e:
        raise SoftError(str(e), clear_before=True)

    window.contact.nick = Nick(win_name)
    contact_list.store_contacts()

    serialized_fields = onion_pub_key.serialize() + win_name.encode()
    queue_command(settings, queues, SerializedCommand(RxCommand.CH_NICKNAME, serialized_fields))
    return None


def select_window(settings      : 'Settings',
                  queues        : 'TxQueue',
                  window        : 'TxWindow',
                  user_input    : 'UserInput',
                  master_key    : 'MasterKey',
                  local_key_db  : 'LocalKeyDB',
                  onion_service : 'OnionService',
                  gateway       : 'Gateway'
                  ) -> None:
    """Select a new window to send messages/files."""
    selection = validate_second_field(user_input, 'recipient')

    window.select_tx_window(settings,
                            queues,
                            master_key,
                            local_key_db,
                            onion_service,
                            gateway,
                            selection   = selection,
                            via_command = BoolSelectWinByCmd(True))


def rxp_show_sys_win(settings   : 'Settings',
                     queues     : 'TxQueue',
                     window     : 'TxWindow',
                     user_input : 'UserInput',
                     ) -> None:
    """\
    Display a system window on Receiver Program until the user presses
    Enter.

    Receiver Program has a dedicated window, WIN_UID_LOCAL, for system
    messages that shows information about received commands, status
    messages etc.

    Receiver Program also has another window, WIN_UID_FILE, that shows
    progress of file transmission from contacts that have traffic
    masking enabled.
    """
    cmd     = user_input.plaintext.split()[0]
    win_uid = dict(cmd=WinSelectHeader.SYSTEM_MESSAGES, fw=WinSelectHeader.FILE_TRANSFERS)[cmd]

    queue_command(settings, queues, SerializedCommand(RxCommand.WIN_SELECT, win_uid))

    try:
        print_message(f"<Enter> returns Receiver to {window.window_name}'s window", manual_proceed=True, box=True)
    except (EOFError, KeyboardInterrupt):
        pass

    clear_previous_lines(no_lines=4, flush=True)

    queue_command(settings, queues, SerializedCommand(RxCommand.WIN_SELECT, window.uid_bytes))


def rxp_display_unread(settings: 'Settings', queues: 'TxQueue') -> None:
    """\
    Display the list of windows that contain unread messages on Receiver
    Program.
    """
    queue_command(settings, queues, SerializedCommand(RxCommand.WIN_ACTIVITY))
