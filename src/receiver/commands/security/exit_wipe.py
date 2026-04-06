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

from src.common.statics import MonitorQueueSignal
from src.ui.common.output.vt100_utils import reset_terminal

if TYPE_CHECKING:
    from src.common.queues import RxQueue


def exit_tfc(queues: 'RxQueue') -> None:
    """Exit TFC."""
    queues.to_process_monitor.put(MonitorQueueSignal.EXIT)


def wipe_system(queues: 'RxQueue') -> None:
    """\
    Reset terminals, wipe all TFC user data on Destination Computer and
    power off the system.

    No effective RAM overwriting tool currently exists, so as long as
    Source and Destination Computers use FDE and DDR3 memory, recovery
    of user data becomes impossible very fast:
        https://www1.cs.fau.de/filepool/projects/coldboot/fares_coldboot.pdf
    """
    reset_terminal()
    queues.to_process_monitor.put(MonitorQueueSignal.WIPE)
