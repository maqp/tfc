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

from src.common.exceptions import SoftError
from src.common.statics import PayloadType
from src.common.types_custom import BoolIsWhisperedMessage, BoolLogAsPlaceHolder, StrPlaintextMessage
from src.transmitter.queue_packet.queue_packet import queue_message
from src.ui.transmitter.user_input import UserInput

if TYPE_CHECKING:
    from src.common.queues import TxQueue
    from src.database.db_settings import Settings
    from src.ui.transmitter.window_tx import TxWindow


def whisper(settings   : 'Settings',
            queues     : 'TxQueue',
            window     : 'TxWindow',
            user_input : UserInput,
            ) -> None:
    """\
    Send a message to the active window that overrides the recipient's
    enabled logging
    setting for that message.

    The functionality of this feature is impossible to enforce, but if
    the recipient can be trusted, and they do not modify their client,
    this feature can be used to send the message off-the-record.
    """
    try:
        _command, message = user_input.plaintext.strip().split(' ', 1)
    except IndexError:
        raise SoftError('Error: No whisper message specified.', clear_before=True)

    user_input = UserInput(StrPlaintextMessage(message),
                           PayloadType.MESSAGE,
                           BoolIsWhisperedMessage(True))

    queue_message(user_input = user_input,
                  window     = window,
                  settings   = settings,
                  queues     = queues,
                  log_as_ph  = BoolLogAsPlaceHolder(True))
