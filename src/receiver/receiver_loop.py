#!/usr/bin/env python3.7
# -*- coding: utf-8 -*-

"""
TFC - Onion-routed, endpoint secure messaging system
Copyright (C) 2013-2020  Markus Ottela

This file is part of TFC.

TFC is free software: you can redistribute it and/or modify it under the terms
of the GNU General Public License as published by the Free Software Foundation,
either version 3 of the License, or (at your option) any later version.

TFC is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with TFC. If not, see <https://www.gnu.org/licenses/>.
"""

import struct
import time
import typing

from datetime import datetime
from typing   import Any, Dict

from src.common.encoding   import bytes_to_int
from src.common.exceptions import SoftError
from src.common.misc       import ignored, separate_headers
from src.common.output     import m_print
from src.common.statics    import (COMMAND_DATAGRAM_HEADER, DATAGRAM_HEADER_LENGTH, DATAGRAM_TIMESTAMP_LENGTH,
                                   FILE_DATAGRAM_HEADER, GATEWAY_QUEUE, LOCAL_KEY_DATAGRAM_HEADER,
                                   MESSAGE_DATAGRAM_HEADER)

if typing.TYPE_CHECKING:
    from multiprocessing    import Queue
    from src.common.gateway import Gateway


def receiver_loop(queues:    Dict[bytes, 'Queue[Any]'],
                  gateway:   'Gateway',
                  unit_test: bool = False
                  ) -> None:
    """Decode received packets and forward them to packet queues."""
    gateway_queue = queues[GATEWAY_QUEUE]

    while True:
        with ignored(EOFError, KeyboardInterrupt):
            if gateway_queue.qsize() == 0:
                time.sleep(0.01)

            _, packet = gateway_queue.get()

            try:
                packet = gateway.detect_errors(packet)
            except SoftError:
                continue

            header, ts_bytes, payload = separate_headers(packet, [DATAGRAM_HEADER_LENGTH, DATAGRAM_TIMESTAMP_LENGTH])

            try:
                ts = datetime.strptime(str(bytes_to_int(ts_bytes)), "%Y%m%d%H%M%S%f")
            except (ValueError, struct.error):
                m_print("Error: Failed to decode timestamp in the received packet.", head=1, tail=1)
                continue

            if header in [MESSAGE_DATAGRAM_HEADER, FILE_DATAGRAM_HEADER,
                          COMMAND_DATAGRAM_HEADER, LOCAL_KEY_DATAGRAM_HEADER]:
                queues[header].put((ts, payload))

            if unit_test:
                break
