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

import readline

from typing import TYPE_CHECKING

from src.common.entities.serialized_command import SerializedCommand
from src.common.statics import ShellCommand, RxCommand
from src.ui.common.output.vt100_utils import clear_screen, reset_terminal
from src.datagrams.relay.command.command_security import (DatagramRelayCommandScreenClear,
                                                          DatagramRelayCommandScreenReset)
from src.transmitter.queue_packet.queue_packet import queue_command

if TYPE_CHECKING:
    from src.common.queues import TxQueue
    from src.database.db_settings import Settings
    from src.ui.transmitter.user_input import UserInput
    from src.ui.transmitter.window_tx import TxWindow


def clear_screens(settings   : 'Settings',
                  queues     : 'TxQueue',
                  window     : 'TxWindow',
                  user_input : 'UserInput',
                  ) -> None:
    """Clear/reset screen of Source, Destination, and Networked Computer.

    Only send an unencrypted command to Networked Computer if traffic
    masking is disabled.

    With clear command, sending only the command header is enough.
    However, as reset command removes the ephemeral message log on
    Receiver Program, Transmitter Program must define the window to
    reset (in case, e.g., previous window selection command packet
    dropped, and active window state is inconsistent between the
    TCB programs).
    """
    clear = user_input.plaintext.split()[0] == ShellCommand.CLEAR

    if clear: command = SerializedCommand(RxCommand.CLEAR_SCREEN)
    else:     command = SerializedCommand(RxCommand.RESET_SCREEN, window.uid_bytes)

    queue_command(settings, queues, command)
    clear_screen()

    if not settings.traffic_masking:
        if clear: queues.relay_packet.put( DatagramRelayCommandScreenClear() )
        else:     queues.relay_packet.put( DatagramRelayCommandScreenReset() )

    if not clear:
        readline.clear_history()
        reset_terminal()
