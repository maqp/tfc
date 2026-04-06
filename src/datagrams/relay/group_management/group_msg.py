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
from typing import TYPE_CHECKING, Optional as O, Iterator

from src.common.exceptions import CriticalError
from src.common.crypto.keys.onion_service_keys import OnionPublicKeyContact
from src.datagrams.datagram import DatagramShared

if TYPE_CHECKING:
    from src.common.entities.group_id import GroupID


class DatagramGroupMessage(DatagramShared):

    _group_id  : 'GroupID'
    _members   : list[OnionPublicKeyContact]
    _recipient : O[OnionPublicKeyContact]

    def __init__(self,
                 group_id  : 'GroupID',
                 members   : list[OnionPublicKeyContact],
                 recipient : O[OnionPublicKeyContact] = None,
                 *,
                 timestamp : O[datetime]              = None,
                 ) -> None:
        """Store the shared state for all group-management datagrams."""
        self._group_id  = group_id
        self._members   = members
        self._recipient = recipient
        self._timestamp = timestamp

    def __iter__(self) -> Iterator[OnionPublicKeyContact]:
        """Iterate through all members of the group."""
        yield from self._members

    @property
    def group_id_bytes(self) -> bytes:
        """Return the group ID's raw bytes."""
        return self._group_id.raw_bytes

    @property
    def pub_key_contact(self) -> OnionPublicKeyContact:
        """Return the recipient of the datagram."""
        if self._recipient is None:
            raise CriticalError('Datagram recipient is missing.')
        return self._recipient

    @property
    def serialized_members_all(self) -> bytes:
        """Return the serialized members of the group datagram."""
        return b''.join(k.serialize() for k in self._members)

    @property
    def serialized_members_other(self) -> bytes:
        """Return the serialized members of the group datagram."""
        return b''.join(k.serialize() for k in self._members if k != self._recipient)
