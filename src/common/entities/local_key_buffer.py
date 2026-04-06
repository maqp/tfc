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
from typing import ItemsView, TYPE_CHECKING

if TYPE_CHECKING:
    from src.common.crypto.pt_ct import LocalKeySetCT


class LocalKeyBuffer:
    """LocalKeyBuffer is a type-safe wrapper for LocalKey Packets."""

    def __init__(self) -> None:
        """Create new GroupName Object"""
        self.__buffer : 'dict[datetime, LocalKeySetCT]' = {}

    def __delitem__(self, key: datetime) -> None:
        """Delete the local key set for the given timestamp."""
        del self.__buffer[key]

    def items(self) -> 'ItemsView[datetime, LocalKeySetCT]':
        """Return timestamp/local key set pairs."""
        return self.__buffer.items()

    def insert(self, ts: datetime, enc_local_keyset: 'LocalKeySetCT') -> None:
        """Insert new EncryptedLocalKeySet into the buffer."""
        self.__buffer[ts] = enc_local_keyset

    def has_key(self, ts: datetime) -> bool:
        """Check if the given timestamp exists in the buffer."""
        return ts in self.__buffer

    def get_packets_after(self, ts: datetime) -> 'list[tuple[datetime, LocalKeySetCT]]':
        """Return all local key sets whose timestamp is after the given timestamp."""
        return [(packet_ts, packet) for packet_ts, packet in self.__buffer.items() if packet_ts > ts]
