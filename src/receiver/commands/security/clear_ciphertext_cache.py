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

from datetime import datetime
from typing import TYPE_CHECKING

from src.common.replay import clear_cached_receive_data

if TYPE_CHECKING:
    from src.common.queues import RxQueue
    from src.database.db_settings import Settings
    from src.ui.receiver.window_rx import WindowList


def clear_ciphertext_cache(ts          : datetime,
                           window_list : 'WindowList',
                           settings    : 'Settings',
                           queues      : 'RxQueue',
                           ) -> None:
    """Clear Receiver-side replay caches used for resend recovery."""
    cleared_entries = clear_cached_receive_data(settings.program_id, clear_files=False)
    queues.replay_cache_clear.put(True)
    window_list.sys_msg_win.add_new_system_message(ts,
                                                   f"Cleared {cleared_entries} cached replay "
                                                   f"entr{'y' if cleared_entries == 1 else 'ies'}.",
                                                   output=True)
