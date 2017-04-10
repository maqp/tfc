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
import time
import threading
import typing

from typing import Dict, Tuple, Union

from src.common.crypto import byte_padding

if typing.TYPE_CHECKING:
    from multiprocessing        import Queue
    from src.common.db_settings import Settings
    from src.common.db_contacts import ContactList


class ConstantTime:
    """Constant time context manager.

    By joining a thread that sleeps for longer time than it takes
    for the function to run, this context manager hides the actual
    running time of the function.
    """
    def __init__(self,
                 settings: 'Settings',
                 d_type:   str = 'static',
                 length:   float = 0.0) -> None:

        if d_type == 'trickle':
            self.length  = settings.trickle_stat_delay
            self.length += random.SystemRandom().uniform(0, settings.trickle_rand_delay)
            if settings.long_packet_rand_d:
                self.length += random.SystemRandom().uniform(0, settings.max_val_for_rand_d)

        elif d_type == 'static':
            self.length = length

    def __enter__(self) -> None:
        self.timer = threading.Thread(target=time.sleep, args=(self.length,))
        self.timer.start()

    def __exit__(self, exc_type, exc_value, traceback):
        self.timer.join()


def noise_process(header:       bytes,
                  queue:        'Queue',
                  contact_list: 'ContactList' = None) -> None:
    """Ensure noise queues have noise packets (with padded length of 256) always available."""
    packet  = header + byte_padding(header)

    if contact_list is None:
        content = packet  # type: Union[bytes, Tuple[bytes, Dict[str, bool]]]
    else:
        log_dict = dict()
        for c in contact_list:
            log_dict[c.rx_account] = False
        content = (packet, log_dict)

    while True:
        try:
            if queue.qsize() < 1000:
                queue.put(content)
            else:
                time.sleep(0.1)
        except (EOFError, KeyboardInterrupt):
            pass
