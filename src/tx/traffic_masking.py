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

import random
import threading
import time
import typing

from typing import Tuple, Union

from src.common.misc    import ignored
from src.common.statics import *

if typing.TYPE_CHECKING:
    from multiprocessing        import Queue
    from src.common.db_contacts import ContactList
    from src.common.db_settings import Settings


class ConstantTime(object):
    """Constant time context manager.

    By joining a thread that sleeps for longer time than it takes for
    the function to run, this context manager hides the actual running
    time of the function.

    Note that random.SystemRandom() uses Kernel CSPRNG (/dev/urandom),
    not Python's weak RNG based on Mersenne Twister:
        https://docs.python.org/2/library/random.html#random.SystemRandom
    """

    def __init__(self,
                 settings: 'Settings',
                 d_type:   str   = STATIC,
                 length:   float = 0.0) -> None:

        if d_type == TRAFFIC_MASKING:
            self.length  = settings.traffic_masking_static_delay
            self.length += random.SystemRandom().uniform(0, settings.traffic_masking_random_delay)
            if settings.multi_packet_random_delay:
                self.length += random.SystemRandom().uniform(0, settings.max_duration_of_random_delay)

        elif d_type == STATIC:
            self.length = length

    def __enter__(self) -> None:
        self.timer = threading.Thread(target=time.sleep, args=(self.length,))
        self.timer.start()

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        self.timer.join()


def noise_loop(header:       bytes,
               queue:        'Queue',
               contact_list: 'ContactList' = None,
               unittest:     bool          = False) -> None:
    """Generate noise packets and keep noise queues filled."""
    packet = header + bytes(PADDING_LEN)

    if contact_list is None:
        content = (packet, None) # type: Union[Tuple[bytes, None], Tuple[bytes, None, bool]]
    else:
        content = (packet, None, True)

    while True:
        with ignored(EOFError, KeyboardInterrupt):
            while queue.qsize() < 100:
                queue.put(content)
            time.sleep(0.1)

            if unittest:
                break
