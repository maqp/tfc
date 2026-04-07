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
from src.ui.common.output.vt100_utils import reset_terminal

if TYPE_CHECKING:
    from src.common.entities.serialized_command import SerializedCommand
    from src.ui.receiver.window_rx import WindowList


def reset_screen(ser_cmd     : 'SerializedCommand',
                 window_list : 'WindowList'
                 ) -> None:
    """Reset window specified by the Transmitter Program."""
    window_uid = WindowUID(ser_cmd.command_bytes)
    window     = window_list.get_or_create_window(window_uid)

    window.clear_message_log()
    reset_terminal()
