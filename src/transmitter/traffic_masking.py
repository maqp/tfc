#!/usr/bin/env python3.7
# -*- coding: utf-8 -*-

"""
TFC - Onion-routed, endpoint secure messaging system
Copyright (C) 2013-2019  Markus Ottela

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

import time
import typing

from typing import Any, Dict, Optional, Tuple, Union

from src.common.misc import ignored
from src.common.statics import (
    C_N_HEADER,
    NOISE_PACKET_BUFFER,
    PADDING_LENGTH,
    P_N_HEADER,
    TM_NOISE_COMMAND_QUEUE,
    TM_NOISE_PACKET_QUEUE,
)

if typing.TYPE_CHECKING:
    from multiprocessing import Queue
    from src.common.db_contacts import ContactList

    QueueDict = Dict[bytes, Queue[Any]]


def noise_loop(
    queues: "QueueDict",
    contact_list: Optional["ContactList"] = None,
    unit_test: bool = False,
) -> None:
    """Generate noise packets for traffic masking.

    This process ensures noise packet / noise command queue always has
    noise assembly packets available.
    """
    log_messages = True  # This setting is ignored: settings.log_file_masking controls logging of noise packets.
    log_as_ph = True

    header = C_N_HEADER if contact_list is None else P_N_HEADER
    noise_assembly_packet = header + bytes(PADDING_LENGTH)

    if contact_list is None:
        # Noise command
        queue = queues[TM_NOISE_COMMAND_QUEUE]
        content = noise_assembly_packet  # type: Union[bytes, Tuple[bytes, bool, bool]]

    else:
        # Noise packet
        queue = queues[TM_NOISE_PACKET_QUEUE]
        content = (noise_assembly_packet, log_messages, log_as_ph)

    while True:
        with ignored(EOFError, KeyboardInterrupt):
            while queue.qsize() < NOISE_PACKET_BUFFER:
                queue.put(content)
            time.sleep(0.1)

            if unit_test:
                break
