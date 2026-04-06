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
from typing import Optional as O

from src.common.statics import VT100
from src.common.utils.date_time import get_log_ts


def print_log_message(message : str,
                      ts      : O[datetime] = None,
                      bold    : bool        = False
                      ) -> None:
    """Print an event in Relay Program."""
    ts_str = get_log_ts() if ts is None else ts.strftime('%b %d - %H:%M:%S.%f')[:-4]

    if bold:
        print(f'{VT100.BOLD_ON}{ts_str} - {message}{VT100.NORMAL_TEXT}')
    else:
        print(f'{ts_str} - {message}')
