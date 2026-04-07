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
from src.common.utils.encoding import int_to_bytes, bytes_to_int
from src.common.utils.strings import separate_header, split_byte_string, separate_headers
from src.common.utils.validators import validate_int, validate_bytes
from src.datagrams.relay.group_management.group_msg import DatagramGroupMessage


class DatagramGroupMessageDelta(DatagramGroupMessage):
    """Add/remove members group management messages.

    These have ordered list of members and counter that tells how many
    of the trailing members in the list are being added or removed.

    Note: These do not control group members, they just announce to
          contacts who the user has added to group. Sending them is
          optional.
    """
    GROUP_DATAGRAM_HEADER: DatagramHeader

    def __init__(self,
                 group_id  : GroupID,
                 members   : list[OnionPublicKeyContact],
                 delta     : O[list[OnionPublicKeyContact]] = None,
                 recipient : O[OnionPublicKeyContact]       = None,
                 timestamp : O[datetime]                    = None,
                 ) -> None:
        """Create new DatagramGroupMessageDelta object."""
        if delta is None:   # Server to client
            ordered_members = members
            self.__no_delta = 0
        else:               # Transmitter to Relay
            ordered_members = [member for member in members if member not in delta] + delta
            self.__no_delta = len(delta)

        super().__init__(group_id, ordered_members, recipient, timestamp=timestamp)

    # ┌───────────────────────────────┐
    # │ Serialization/Deserialization │
    # └───────────────────────────────┘

    @property
    def __delta(self) -> list[OnionPublicKeyContact]:
        """Get the list members in the group that are being added or removed."""
        return self._members[-self.__no_delta:]

    @property
    def __serialized_members_delta(self) -> bytes:
        """Return the serialized members of the group datagram."""
        return b''.join([k.serialize() for k in self.__delta])

    def to_txp_rep_bytes(self) -> bytes:
        """Return the multicasting datagram serialized to bytes."""
        return (self.GROUP_DATAGRAM_HEADER.value
                + self.group_id_bytes
                + int_to_bytes(self.__no_delta)
                + self.serialized_members_all)

    def to_server_b85(self) -> bytes:
        """Return the per-recipient datagram serialized to bytes."""
        header  = self.GROUP_DATAGRAM_HEADER.value
        payload = base64.b85encode(self.group_id_bytes
                                   + self.__serialized_members_delta)
        return header + payload

    @staticmethod
    def bytes_to_members_and_delta(datagram_bytes: bytes) -> tuple[GroupID,
                                                                   list[OnionPublicKeyContact],
                                                                   list[OnionPublicKeyContact]]:
        """Parse datagram bytes to members and delta."""
        header_lengths = [FieldLength.GROUP_ID.value,
                  FieldLength.ENCODED_INTEGER.value]

        group_id_bytes, no_delta_bytes, member_onion_addr_bytes = separate_headers(datagram_bytes, header_lengths)

        # Group ID
        group_id = GroupID(group_id_bytes)

        # Onion Addresses
        validate_bytes(member_onion_addr_bytes, len_is_mul_of=FieldLength.ONION_ADDRESS.value)
        member_addresses_enc = split_byte_string(member_onion_addr_bytes, FieldLength.ONION_ADDRESS.value)

        # Delta
        validate_bytes(no_delta_bytes, is_length=FieldLength.ENCODED_INTEGER.value)
        no_delta = bytes_to_int(no_delta_bytes)
        validate_int(no_delta, min_value=0, max_value=len(member_addresses_enc))

        # Member segments
        members = [OnionPublicKeyContact.from_onion_address_bytes(addr_bytes) for addr_bytes in member_addresses_enc]
        members, delta = members[:no_delta], members[no_delta:]

        return group_id, members, delta

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

class DatagramGroupAddMember(DatagramGroupMessageDelta):

    GROUP_DATAGRAM_HEADER = DatagramHeader.GROUP_ADD_MEMBER
    DATAGRAM_TYPE_HR      = DatagramTypeHR.GROUP_ADD_MEMBER

    @classmethod
    def from_txp_rep_bytes(cls, ts: datetime, datagram_bytes: bytes) -> list[Self]:
        """Parse the group message datagram from Transmitter Program's multi-casted bytes."""
        group_id, members_before, new_members = cls.bytes_to_members_and_delta(datagram_bytes)

        datagrams = []

        for recipient in members_before:
            datagrams.append(cls(group_id, new_members, recipient=recipient, timestamp=ts))

        all_members = members_before + new_members
        for recipient in new_members:
            other_group_members = [m for m in all_members if m != recipient]
            datagrams.append(cls(group_id, other_group_members, recipient=recipient, timestamp=ts))

        return datagrams


class DatagramGroupRemMember(DatagramGroupMessageDelta):

    GROUP_DATAGRAM_HEADER = DatagramHeader.GROUP_REM_MEMBER
    DATAGRAM_TYPE_HR      = DatagramTypeHR.GROUP_REM_MEMBER

    @classmethod
    def from_txp_rep_bytes(cls, ts: datetime, datagram_bytes: bytes) -> list[Self]:
        """Parse the group message datagram from Transmitter Program's multi-casted bytes.

        We only send to remaining members the notification about
        user having removed the members. The removed members never
        learn about having been removed from the group by the user.
        """
        group_id, members_before, removed_members = cls.bytes_to_members_and_delta(datagram_bytes)

        datagrams = []

        remaining_members = [m for m in members_before if m != removed_members]

        for recipient in remaining_members:
            datagrams.append(cls(group_id, removed_members, recipient=recipient, timestamp=ts))

        return datagrams
