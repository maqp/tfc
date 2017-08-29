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

import time
import typing

from datetime import datetime
from typing   import Dict

from src.common.misc         import ignored
from src.common.output       import box_print
from src.common.reed_solomon import ReedSolomonError, RSCodec
from src.common.statics      import *

if typing.TYPE_CHECKING:
    from multiprocessing        import Queue
    from src.common.db_settings import Settings


def receiver_loop(queues:   Dict[bytes, 'Queue'],
                  settings: 'Settings',
                  unittest: bool = False) -> None:
    """Decode received packets and forward them to packet queues.

    This function also determines the timestamp for received message.
    """
    rs       = RSCodec(2 * settings.session_serial_error_correction)
    gw_queue = queues[GATEWAY_QUEUE]

    while True:
        with ignored(EOFError, KeyboardInterrupt):
            if gw_queue.qsize() == 0:
                time.sleep(0.01)

            packet    = gw_queue.get()
            timestamp = datetime.now()

            try:
                packet = bytes(rs.decode(packet))
            except ReedSolomonError:
                box_print("Error: Failed to correct errors in received packet.", head=1, tail=1)
                continue

            p_header = packet[:1]
            if p_header in [PUBLIC_KEY_PACKET_HEADER, MESSAGE_PACKET_HEADER,
                            LOCAL_KEY_PACKET_HEADER, COMMAND_PACKET_HEADER,
                            IMPORTED_FILE_HEADER]:
                queues[p_header].put((timestamp, packet))

            if unittest:
                break
