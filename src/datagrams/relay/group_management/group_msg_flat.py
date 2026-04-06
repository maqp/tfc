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

import base64

from datetime import datetime
from typing import Optional as O, Self

from src.common.crypto.keys.onion_service_keys import OnionPublicKeyContact
from src.common.entities.group_id import GroupID
from src.common.statics import DatagramHeader, FieldLength, DatagramTypeHR
from src.common.utils.strings import separate_header, split_byte_string
from src.datagrams.relay.group_management.group_msg import DatagramGroupMessage


class DatagramGroupMessageFlat(DatagramGroupMessage):
    """Flat group management messages.

    These have single list of group members as context, and are shared by
        * Group creation messages,
        * Group join messages, and
        * Group exit messages
    """

    GROUP_DATAGRAM_HEADER : DatagramHeader

    def __init__(self,
                 group_id  : GroupID,
                 members   : list[OnionPublicKeyContact],
                 recipient : O[OnionPublicKeyContact] = None,
                 timestamp : O[datetime]              = None,
                 ) -> None:
        """Create new DatagramGroupMessageFlat object."""
        super().__init__(group_id, members, recipient, timestamp=timestamp)

    def to_txp_rep_bytes(self) -> bytes:
        """Return the multicasting datagram serialized to bytes."""
        return self.GROUP_DATAGRAM_HEADER.value + self.group_id_bytes + self.serialized_members_all

    @classmethod
    def from_txp_rep_bytes(cls, ts: datetime, datagram_bytes: bytes) -> list[Self]:
        """Parse the group message datagram from Transmitter Program's multi-casted bytes."""
        group_id_bytes, member_onion_addr_bytes = separate_header(datagram_bytes, FieldLength.GROUP_ID.value)

        group_id        = GroupID(group_id_bytes)
        member_addr_enc = split_byte_string(member_onion_addr_bytes, FieldLength.ONION_ADDRESS.value)
        members         = [OnionPublicKeyContact.from_onion_address_bytes(addr_bytes) for addr_bytes in member_addr_enc]

        datagrams = []
        for recipient in members:
            other_group_members = [m for m in members if m != recipient]
            datagrams.append(cls(group_id, other_group_members, recipient, ts))

        return datagrams

    def to_server_b85(self) -> bytes:
        """Return the per-recipient datagram serialized to bytes."""
        return self.GROUP_DATAGRAM_HEADER.value + base64.b85encode(self.group_id_bytes + self.serialized_members_other)

    @classmethod
    def from_server_b85(cls, ts: datetime, b85_bytes: bytes) -> Self:
        """Parse the group message datagram from contact's server bytes."""
        datagram_bytes                          = base64.b85decode(b85_bytes)
        group_id_bytes, member_onion_addr_bytes = separate_header(datagram_bytes, FieldLength.GROUP_ID.value)

        group_id        = GroupID(group_id_bytes)
        member_addr_enc = split_byte_string(member_onion_addr_bytes, FieldLength.ONION_ADDRESS.value)
        members         = [OnionPublicKeyContact.from_onion_address_bytes(addr_bytes) for addr_bytes in member_addr_enc]

        return cls(group_id, members, timestamp=ts)


# ┌─────────────┐
# │ Subclassing │
# └─────────────┘

class DatagramGroupInvite(DatagramGroupMessageFlat):
    GROUP_DATAGRAM_HEADER = DatagramHeader.GROUP_INVITE
    DATAGRAM_TYPE_HR      = DatagramTypeHR.GROUP_INVITE


class DatagramGroupJoin(DatagramGroupMessageFlat):
    GROUP_DATAGRAM_HEADER = DatagramHeader.GROUP_JOIN
    DATAGRAM_TYPE_HR      = DatagramTypeHR.GROUP_JOIN


class DatagramGroupExit(DatagramGroupMessageFlat):
    GROUP_DATAGRAM_HEADER = DatagramHeader.GROUP_EXIT_GROUP
    DATAGRAM_TYPE_HR      = DatagramTypeHR.GROUP_EXIT
