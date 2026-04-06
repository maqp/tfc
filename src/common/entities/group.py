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

from typing import TYPE_CHECKING, Callable, Iterator

from src.common.crypto.keys.onion_service_keys import OnionPublicKeyContact
from src.common.statics import DummyID
from src.common.utils.encoding import str_to_padded_bytes, bool_to_bytes

if TYPE_CHECKING:
    from src.common.entities.contact import Contact
    from src.common.entities.group_id import GroupID
    from src.common.entities.group_name import GroupName
    from src.common.types_custom import BoolLogMessages, BoolShowNotifications
    from src.database.db_settings import Settings


class Group:
    """\
    Group object contains a list of Contact objects (group members) and
    settings related to the group:

    name:          In TFC, groups are identified by random group IDs
                   that are hard to remember. Groups are therefore
                   managed mostly with names assigned by the user. The
                   name of the group must be unique among group names
                   and nicknames of contacts. This way a single command
                   `/msg <selection>` can select the specified contact
                   or group. Some group names are reserved, e.g., for
                   database padding. Group names also have a length
                   limit of 254 chars.

    group_id:      Group ID is a random 4-byte value used to identify a
                   group among user's peers. To prevent data leakage
                   from Destination Computer via group IDs, the
                   received group management messages are displayed by
                   the Relay Program on Networked Computer. Since group
                   ID must be considered public information, they are
                   random. For more details on Destination Computer
                   exfiltration attacks, refer to TFC's documentation
                   on Security Design. Identification of groups via a
                   separate group ID allows the user to choose the name
                   for the group which is useful because users do not
                   need to take into account what names their contacts
                   have chosen for their groups.

    log_messages:  This setting defines whether the Receiver Program
                   writes the assembly packets of a successfully
                   received group message into a log file. When logging
                   is enabled, Transmitter Program will also log
                   assembly packets of sent group messages to its log
                   file.

    notifications: This setting defines whether in situations where some
                   other window is active the Receiver Program displays
                   a notification about a group member sending a new
                   message to the group's window. The setting has no
                   effect on user's Transmitter Program.

    members:       Manually managed list of Contact objects that the
                   user accepts as members of their side of the group.
                   The Transmitter Program of user multicasts messages
                   to these contacts when the group is active. The
                   Receiver Program of user accepts messages from these
                   contacts to Group's window when the contact sends the
                   user a message, that contains the group ID in its
                   header.
    """

    def __init__(self,
                 group_name    : 'GroupName',
                 group_id      : 'GroupID',
                 log_messages  : 'BoolLogMessages',
                 notifications : 'BoolShowNotifications',
                 members       : list['Contact'],
                 settings      : 'Settings',
                 store_groups  : Callable[..., None]
                 ) -> None:
        """Create a new Group object.

        The `self.store_groups` is a reference to the method of the
        parent object GroupList that stores the list of groups into an
        encrypted database.
        """
        self.group_name    = group_name
        self.group_id      = group_id
        self.log_messages  = log_messages
        self.notifications = notifications
        self.members       = members
        self.settings      = settings
        self.store_groups  = store_groups

    def __iter__(self) -> Iterator['Contact']:
        """Iterate over members (Contact objects) in the Group object."""
        yield from self.members

    def __len__(self) -> int:
        """Return the number of members in the Group object."""
        return len(self.members)

    def serialize_g(self) -> bytes:
        """Return group data as a constant length bytestring.

        This function serializes the group's data into a bytestring
        that always has a constant length. The exact length depends on
        the attribute `max_number_of_group_members` of TFC's Settings
        object. With the default setting of 300 members per group, the
        length of the serialized data is
            1024             (Group name as padded UTF-32 bytestring)
            + 4              (32-bit Group ID)
            + 2*1            (The two booleans settings)
            + 300*56         (The 300 v3 onion addresses, 56 bytes each when UTF-8 encoded)
            = 17,830 bytes

        The purpose of the constant length serialization is to hide
        any metadata the ciphertext length of the group database
        could reveal.
        """
        members           = self.get_list_of_member_pub_keys()
        number_of_dummies = self.settings.max_number_of_group_members - len(self.members)
        members          += number_of_dummies * [OnionPublicKeyContact.from_onion_address(DummyID.DUMMY_MEMBER, DO_NOT_VALIDATE=True)]
        member_bytes      = b''.join([m.serialize() for m in members])

        return (str_to_padded_bytes(self.group_name.value)
                + self.group_id.raw_bytes
                + bool_to_bytes(self.log_messages)
                + bool_to_bytes(self.notifications)
                + member_bytes)

    def add_members(self, contacts: list['Contact']) -> None:
        """Add a list of Contact objects to the group."""
        pre_existing = self.get_list_of_member_pub_keys()
        self.members.extend((c for c in contacts if c.onion_pub_key not in pre_existing))
        self.store_groups()

    def remove_members(self, pub_keys: list['OnionPublicKeyContact']) -> bool:
        """Remove a list of Contact objects from the group.

        Return True if the member(s) were removed, else False.
        """
        to_remove = {pub_key for pub_key in pub_keys}
        to_remove &= set(self.get_list_of_member_pub_keys())
        if to_remove:
            self.members = [m for m in self.members if m.onion_pub_key not in to_remove]
            self.store_groups()
        return any(to_remove)

    def get_list_of_member_pub_keys(self) -> list[OnionPublicKeyContact]:
        """Return list of members' public keys."""
        return [OnionPublicKeyContact(m.onion_pub_key.ed_25519_pub_key) for m in self.members]

    def get_list_of_raw_pub_keys(self) -> list[bytes]:
        """Return list of members' raw public keys."""
        return [m.onion_pub_key.public_bytes_raw for m in self.members]

    def has_member(self, onion_pub_key: 'OnionPublicKeyContact | bytes') -> bool:
        """Return True if a member with Onion public key is in the group, else False."""
        return any(m.onion_pub_key == onion_pub_key for m in self.members)

    def empty(self) -> bool:
        """Return True if the group is empty, else False."""
        return not any(self.members)
