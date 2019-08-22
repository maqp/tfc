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

import random
import threading
import time
import typing

from typing import Any, Dict, Optional, Tuple, Union

from src.common.misc    import ignored
from src.common.statics import *

if typing.TYPE_CHECKING:
    from multiprocessing        import Queue
    from src.common.db_contacts import ContactList
    from src.common.db_settings import Settings
    QueueDict = Dict[bytes, Queue[Any]]


class HideRunTime(object):
    """Runtime hiding time context manager.

    By joining a thread that sleeps for a longer time than it takes for
    the function to run, this context manager hides the actual running
    time of the function.

    Note that random.SystemRandom() uses the Kernel CSPRNG (/dev/urandom),
    not Python's weak PRNG based on Mersenne Twister:
        https://docs.python.org/2/library/random.html#random.SystemRandom
    """

    def __init__(self,
                 settings:   'Settings',
                 delay_type: str   = STATIC,
                 duration:   float = 0.0
                 ) -> None:

        if delay_type == TRAFFIC_MASKING:
            self.length  = settings.tm_static_delay
            self.length += random.SystemRandom().uniform(0, settings.tm_random_delay)

        elif delay_type == STATIC:
            self.length = duration

    def __enter__(self) -> None:
        self.timer = threading.Thread(target=time.sleep, args=(self.length,))
        self.timer.start()

    def __exit__(self, exc_type: Any, exc_value: Any, traceback: Any) -> None:
        self.timer.join()


def noise_loop(queues:       'QueueDict',
               contact_list: Optional['ContactList'] = None,
               unit_test:    bool                    = False
               ) -> None:
    """Generate noise packets for traffic masking.

    This process ensures noise packet / noise command queue always has
    noise assembly packets available.
    """
    log_messages = True  # This setting is ignored: settings.log_file_masking controls logging of noise packets.
    log_as_ph    = True

    header                = C_N_HEADER if contact_list is None else P_N_HEADER
    noise_assembly_packet = header + bytes(PADDING_LENGTH)

    if contact_list is None:
        # Noise command
        queue   = queues[TM_NOISE_COMMAND_QUEUE]
        content = noise_assembly_packet  # type: Union[bytes, Tuple[bytes, bool, bool]]

    else:
        # Noise packet
        queue   = queues[TM_NOISE_PACKET_QUEUE]
        content = (noise_assembly_packet, log_messages, log_as_ph)

    while True:
        with ignored(EOFError, KeyboardInterrupt):
            while queue.qsize() < NOISE_PACKET_BUFFER:
                queue.put(content)
            time.sleep(0.1)

            if unit_test:
                break
