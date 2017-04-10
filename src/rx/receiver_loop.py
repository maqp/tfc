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
import time
import typing

from typing import Dict

from src.common.output       import box_print
from src.common.reed_solomon import ReedSolomonError, RSCodec
from src.common.statics      import *

if typing.TYPE_CHECKING:
    from multiprocessing        import Queue
    from src.common.db_settings import Settings


def receiver_loop(settings: 'Settings', queues: Dict[bytes, 'Queue']) -> None:
    """Decode and queue received packets."""
    rs       = RSCodec(2 * settings.session_ec_ratio)
    gw_queue = queues[GATEWAY_QUEUE]

    while True:
        try:
            if gw_queue.empty():
                time.sleep(0.001)

            packet = gw_queue.get()
            ts     = datetime.datetime.now()

            try:
                packet = bytes(rs.decode(bytearray(packet)))
            except ReedSolomonError:
                box_print(["Warning! Failed to correct errors in received packet."], head=1, tail=1)
                continue

            p_header = packet[:1]
            if p_header in [PUBLIC_KEY_PACKET_HEADER, MESSAGE_PACKET_HEADER,
                             LOCAL_KEY_PACKET_HEADER, COMMAND_PACKET_HEADER,
                             IMPORTED_FILE_CT_HEADER]:
                queues[p_header].put((ts, packet))

        except (KeyboardInterrupt, EOFError):
            pass
