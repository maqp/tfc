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

from src.common.replay import clear_cached_receive_data, clear_cached_send_data
from src.common.statics import Delay, MonitorQueueSignal
from src.ui.common.output.print_message import print_message
from src.ui.common.output.vt100_utils import clear_screen, reset_terminal

if TYPE_CHECKING:
    from src.common.gateway import Gateway
    from src.common.queues import RelayQueue


def race_condition_delay(gateway: 'Gateway') -> None:
    """Prevent race condition with Receiver command."""
    if gateway.settings.local_testing_mode:
        time.sleep(Delay.LOCAL_TESTING_PACKET_DELAY.value)
        time.sleep(gateway.settings.data_diode_sockets * 1.0)


def exit_tfc(gateway: 'Gateway', queues: 'RelayQueue') -> None:
    """Exit TFC.

    The queue is read by
        relay.onion.onion_service()
    """
    race_condition_delay(gateway)
    queues.close_onion_service_signal.put(MonitorQueueSignal.EXIT)


def wipe(gateway: 'Gateway', queues: 'RelayQueue') -> None:
    """Reset terminal, wipe all user data and power off the system.

    No effective RAM overwriting tool currently exists, so as long as Source and
    Destination Computers use FDE and DDR3 memory, recovery of user data becomes
    impossible very fast:
        https://www1.cs.fau.de/filepool/projects/coldboot/fares_coldboot.pdf

    The queue is read by
        relay.onion.onion_service()
    """
    reset_terminal()
    race_condition_delay(gateway)
    queues.close_onion_service_signal.put(MonitorQueueSignal.WIPE)


def clear_windows(gateway: 'Gateway') -> None:
    """Clear Relay Program screen."""
    race_condition_delay(gateway)
    clear_screen()


def clear_ciphertext_cache(gateway: 'Gateway', queues: 'RelayQueue') -> None:
    """Clear Relay-side replay caches used for resend recovery."""
    cleared_entries = clear_cached_send_data(gateway.settings.program_id)
    cleared_entries += clear_cached_receive_data(gateway.settings.program_id, clear_files=True)
    queues.replay_cache_clear.put(True)
    print_message(f'Cleared {cleared_entries} cached replay entr{"y" if cleared_entries == 1 else "ies"} on Relay.',
                  padding_top    = 1,
                  padding_bottom = 1)


def reset_windows(gateway: 'Gateway') -> None:
    """Reset Relay Program screen."""
    race_condition_delay(gateway)
    reset_terminal()
