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

import time

from typing import TYPE_CHECKING

from src.common.exceptions import ignored
from src.common.types_custom import BoolUnitTesting

if TYPE_CHECKING:
    from src.common.queues import RelayQueue


def process_traffic_masking_void(queues       : 'RelayQueue',
                                 unit_testing : BoolUnitTesting = BoolUnitTesting(False)
                                 ) -> None:
    """Consume and discard server-side traffic masking datagrams."""
    queue = queues.from_cli_to_npv_datagram_messages

    while True:
        with ignored(EOFError, KeyboardInterrupt):
            while queue.qsize() == 0:
                time.sleep(0.1)

                if unit_testing and queues.unit_test.qsize() != 0:
                    return

            while queue.qsize() != 0:
                queue.get()

            if unit_testing and queues.unit_test.qsize() != 0:
                break
