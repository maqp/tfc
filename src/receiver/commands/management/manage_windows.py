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

from src.common.entities.window_uid import WindowUID
from src.ui.common.output.print_message import print_message
from src.ui.common.output.vt100_utils import clear_screen, clear_previous_lines

if TYPE_CHECKING:
    from src.common.entities.serialized_command import SerializedCommand
    from src.ui.receiver.window_rx import WindowList


def win_activity(window_list: 'WindowList') -> None:
    """Show number of unread messages in each window."""
    unread_wins = [w for w in window_list if w.no_unread_msgs > 0]
    print_list  = ['Window activity'] if unread_wins else ['No window activity']
    print_list += [f'{w.window_name}: {w.no_unread_msgs}' for w in unread_wins]

    print_message(print_list, box=True)
    clear_previous_lines(no_lines=(len(print_list) + 2), delay=1)


def win_select(ser_cmd     : 'SerializedCommand',
               window_list : 'WindowList'
               ) -> None:
    """Select window specified by the Transmitter Program."""
    window_uid = WindowUID(ser_cmd.command_bytes)

    if window_uid == WindowUID.file_transfers:
        clear_screen()
    window_list.set_active_rx_window(window_uid)
