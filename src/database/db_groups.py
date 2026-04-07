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

import os

from typing import Iterable, Iterator, Sized, TYPE_CHECKING

from src.common.entities.group import Group
from src.common.entities.group_id import GroupID
from src.common.entities.group_name import GroupName
from src.common.entities.window_uid import WindowUID
from src.common.crypto.keys.onion_service_keys import OnionPublicKeyContact
from src.common.types_custom import (BoolLogMessages, BoolShowNotifications, IntMaxNumberOfGroupMembers,
                                     IntMaxNumberOfGroups, BoolReplaceDB)
from src.common.utils.validators import validate_bytes
from src.database.database import TFCEncryptedDatabase
from src.common.utils.encoding import int_to_bytes, bytes_to_bool, bytes_to_int, padded_bytes_to_str
from src.common.utils.conversion import round_up
from src.common.utils.strings import split_byte_string, separate_header, separate_headers
from src.common.statics import DummyID, FieldLength, CompoundFieldLength, DBName

if TYPE_CHECKING:
    from src.common.entities.contact import Contact
    from src.database.db_contacts import ContactList
    from src.database.db_masterkey import MasterKey
    from src.database.db_settings import Settings


class GroupList(Iterable[Group], Sized):
    """\
    GroupList object manages TFC's Group objects and the storage of the
    objects in an encrypted database.

    The main purpose of this object is to manage the `self.groups`-list
    that contains TFC's groups. The database is stored on disk in
    encrypted form. Prior to encryption, the database is padded with
    dummy groups. Because each group might have a different number of
    members, each group is also padded with dummy members. The dummy
    groups and members hide the actual number of groups and members that
    could otherwise be revealed by the size of the encrypted database.

    As long as the user sticks to default settings that limits TFC's
    group database to 50 groups and 50 members per group, the database
    will effectively hide the actual number of groups and number of
    members in them. The maximum number of groups and number of members
    per group can be changed by editing the `max_number_of_groups` and
    `max_number_of_group_members` settings respectively. Deviating from
    the default settings can, however, in theory, reveal to a physical
    attacker the user has more than 50 groups or more than 50 members
    in a group.

    The GroupList object also provides handy methods with human-readable
    names for making queries to the database.
    """

    def __init__(self,
                 master_key   : 'MasterKey',
                 settings     : 'Settings',
                 contact_list : 'ContactList'
                 ) -> None:
        """Create a new GroupList object."""
        self.__settings     = settings
        self.__contact_list = contact_list

        self.__database : TFCEncryptedDatabase = TFCEncryptedDatabase(DBName.GROUPS, master_key, settings.program_id)
        self.__groups   : dict[GroupID, Group] = {}

        if os.path.isfile(self.__database.path_to_db):
            self.__load_groups()
        else:
            self.store_groups()

    def __iter__(self) -> Iterator[Group]:
        """Iterate over Group objects in `self.groups`."""
        yield from self.__groups.values()

    def __len__(self) -> int:
        """Return the number of Group objects in `self.groups`."""
        return len(self.__groups)

    # ┌───────────────────────────────────────────────────────────────────────────┐
    # │                                  Setters                                  │
    # └───────────────────────────────────────────────────────────────────────────┘

    def add_group(self,
                  group_name    : GroupName,
                  group_id      : GroupID,
                  log_messages  : BoolLogMessages,
                  notifications : BoolShowNotifications,
                  members       : list['Contact']
                  ) -> None:
        """Add a new group to `self.groups` and write changes to the database."""
        if self.has_group(group_name):
            self.remove_group_by_name(group_name)

        self.__groups[group_id] = (Group(group_name,
                                         group_id,
                                         log_messages,
                                         notifications,
                                         members,
                                         self.__settings,
                                         self.store_groups))
        self.store_groups()


    # ┌───────────────────────────────────────────────────────────────────────────┐
    # │                                  Deleters                                 │
    # └───────────────────────────────────────────────────────────────────────────┘

    def remove_group_by_name(self, group_name: GroupName) -> None:
        """Remove the specified group from the group list.

        If a group with the matching name was found and removed, write
        changes to the database.
        """
        for i, g in enumerate(self.__groups.values()):
            if g.group_name == group_name:
                del self.__groups[g.group_id]
                self.store_groups()
                break

    def remove_group_by_id(self, group_id: GroupID) -> None:
        """Remove the specified group from the group list.

        If a group with the matching group ID was found and removed,
        write changes to the database.
        """
        if group_id in self.__groups:
            del self.__groups[group_id]


    # ┌───────────────────────────────────────────────────────────────────────────┐
    # │                                  Getters                                  │
    # └───────────────────────────────────────────────────────────────────────────┘

    def get_group(self, group_name: GroupName) -> Group:
        """Return Group object based on its name."""
        return next(g for g in self.__groups.values() if g.group_name == group_name)

    def get_group_by_id(self, group_id: GroupID) -> Group:
        """Return Group object based on its group ID."""
        return self.__groups[group_id]

    def get_list_of_group_ids(self) -> list[GroupID]:
        """Return list of group IDs."""
        return list(self.__groups.keys())

    def get_list_of_group_names(self) -> list[GroupName]:
        """Return list of group names."""
        return [g.group_name for g in self.__groups.values()]

    def get_list_of_hr_group_ids(self) -> list[str]:
        """Return list of human-readable (B58 encoded) group IDs."""
        return [g.group_id.hr_value for g in self.__groups.values()]

    def get_list_of_win_uids(self) -> list[WindowUID]:
        """Return list of window UIDs."""
        return [WindowUID.for_group(group) for group in self.__groups.values()]


    # ┌───────────────────────────────────────────────────────────────────────────┐
    # │                              Database Status                              │
    # └───────────────────────────────────────────────────────────────────────────┘

    def has_group(self, group_name: GroupName) -> bool:
        """Return True if group list has a group with the specified name, else False."""
        return any(g.group_name == group_name for g in self.__groups.values())

    def has_group_id(self, group_id: GroupID) -> bool:
        """Return True if group list has a group with the specified group ID, else False."""
        return any(g.group_id == group_id for g in self.__groups.values())

    def size_of_largest_group(self) -> int:
        """Return size of the group that has the most members."""
        return max([0] + [len(g) for g in self.__groups.values()])


    # ┌───────────────────────────────────────────────────────────────────────────┐
    # │                              Database Padding                             │
    # └───────────────────────────────────────────────────────────────────────────┘

    def __generate_dummy_group(self) -> Group:
        """Generate a dummy Group object.

        The dummy group simplifies the code around the constant length
        serialization when the data is stored to, or read from the
        database.
        """
        dummy_member = self.__contact_list.generate_dummy_contact()

        return Group(group_name    = GroupName(DummyID.DUMMY_GROUP),
                     group_id      = GroupID(bytes(FieldLength.GROUP_ID)),
                     log_messages  = BoolLogMessages       (False),
                     notifications = BoolShowNotifications (False),
                     members       =self.__settings.max_number_of_group_members * [dummy_member],
                     settings      = self.__settings,
                     store_groups  = lambda: None)

    def __dummy_groups(self) -> list[Group]:
        """Generate a proper size list of dummy groups for database padding."""
        number_of_dummies = self.__settings.max_number_of_groups - len(self.__groups)
        dummy_group       = self.__generate_dummy_group()
        return [dummy_group] * number_of_dummies


    # ┌───────────────────────────────────────────────────────────────────────────┐
    # │                              Database Storage                             │
    # └───────────────────────────────────────────────────────────────────────────┘

    def __serialize(self) -> bytes:
        """Serialize groups and padding to constant-length plaintext."""
        pt_bytes  = self.__generate_group_db_header()
        pt_bytes += b''.join([g.serialize_g() for g in self.__groups.values()])
        pt_bytes += b''.join([g.serialize_g() for g in self.__dummy_groups()])
        return pt_bytes

    def store_groups(self, replace: BoolReplaceDB = BoolReplaceDB(True)) -> None:
        """Write the list of groups to an encrypted database.

        This function will first generate a header that stores
        information about the group database content and padding at the
        moment of calling. Next, the function will serialize every Group
        object (including dummy groups) to form the constant length
        plaintext that will be encrypted and stored in the database.

        By default, TFC has a maximum number of 300 groups with 300
        members each. In addition, the group database stores the header
        that contains four 8-byte values. The database plaintext length
        with 300 groups, each with 300 members is
            4*8 + 300*(1024 + 4 + 2*1 + 300*56)
          =  32 + 300*17830
          = 5,349,032 bytes.

        The ciphertext includes a 24-byte nonce and a 16-byte tag, so
        the size of the final database is 5,349,072 bytes.
        """
        self.__database.store_database(self.__serialize(), replace)

    def new_group_id(self) -> GroupID:
        """Return the a new unused group ID."""
        group_id_bytes = os.urandom(FieldLength.GROUP_ID.value)
        while group_id_bytes in [group_id.raw_bytes for group_id in self.get_list_of_group_ids()]:
            group_id_bytes = os.urandom(FieldLength.GROUP_ID.value)
        return GroupID(group_id_bytes)

    def __load_groups(self) -> None:
        """Load groups from the encrypted database.

        The function first reads, authenticates and decrypts the group
        database data. Next, it slices and decodes the header values
        that help the function to properly de-serialize the database
        content. The function then removes dummy groups based on header
        data. Next, the function updates the group database settings if
        necessary. It then splits group data based on header data into
        blocks, which are further sliced, and processed if necessary,
        to obtain data required to create Group objects. Finally, if
        needed, the function will update the group database content.
        """
        pt_bytes = self.__database.load_database()

        # Slice and decode headers
        group_db_headers, pt_bytes = separate_header(pt_bytes, header_length=FieldLength.GROUP_DB_HEADER.value)
        db_header_fields           = split_byte_string(group_db_headers, item_len=FieldLength.ENCODED_INTEGER.value)
        number_of_all_groups, members_per_group, number_of_real_groups, members_in_largest_group = map(bytes_to_int, db_header_fields)

        # Slice dummy groups
        bytes_per_group = (CompoundFieldLength.GROUP_STATIC.value + members_per_group * FieldLength.ONION_ADDRESS.value)
        dummy_data_len  = (number_of_all_groups - number_of_real_groups) * bytes_per_group
        group_data      = pt_bytes[:-dummy_data_len]

        # Update group database settings
        update_db = self.__update_db_size_setting(number_of_actual_groups  = number_of_real_groups,
                                                  members_in_largest_group = members_in_largest_group)
        blocks    = split_byte_string(group_data, item_len=bytes_per_group)

        existing_pub_keys = self.__contact_list.get_list_of_pub_keys()
        enc_dummy_addr    = OnionPublicKeyContact.from_onion_address(DummyID.DUMMY_MEMBER, DO_NOT_VALIDATE=True).serialize()

        group_header_lengths = [FieldLength.PADDED_UTF32_STR.value,
                                FieldLength.GROUP_ID.value,
                                FieldLength.ENCODED_BOOLEAN.value,
                                FieldLength.ENCODED_BOOLEAN.value]

        # Parse Group objects
        for block in blocks:
            validate_bytes(block, is_length=bytes_per_group)

            name_bytes, group_id_bytes, log_messages_byte, notification_byte, ser_addresses = separate_headers(block, group_header_lengths)

            all_addresses          = split_byte_string(ser_addresses, item_len=FieldLength.ONION_ADDRESS.value)
            dummy_free_addresses   = [a.decode()                                    for a in all_addresses if a != enc_dummy_addr]
            member_pub_keys_stored = [OnionPublicKeyContact.from_onion_address(a)   for a in dummy_free_addresses]
            member_pub_keys_avail  = [self.__contact_list.get_contact_by_pub_key(k) for k in member_pub_keys_stored if k in existing_pub_keys]

            group_id = GroupID(group_id_bytes)

            self.__groups[group_id] = (Group(group_name    = GroupName(padded_bytes_to_str(name_bytes)),
                                             group_id      = group_id,
                                             log_messages  = BoolLogMessages       ( bytes_to_bool(log_messages_byte) ),
                                             notifications = BoolShowNotifications ( bytes_to_bool(notification_byte) ),
                                             members       = member_pub_keys_avail,
                                             settings      = self.__settings,
                                             store_groups  = self.store_groups))

            available_member_pub_keys = {contact.onion_pub_key for contact in member_pub_keys_avail}
            update_db |= set(member_pub_keys_stored) > available_member_pub_keys

        if update_db:
            self.store_groups()

    def __update_db_size_setting(self,
                                 *,
                                 number_of_actual_groups  : int,
                                 members_in_largest_group : int
                                 ) -> bool:
        """\
        Adjust TFC's settings automatically if the loaded group database
        was stored using larger database setting values.

        If settings had to be adjusted, return True so the method
        `self._load_groups` knows to write changes to a new database.
        """
        update_db = False

        if number_of_actual_groups > self.__settings.max_number_of_groups:
            self.__settings.max_number_of_groups = IntMaxNumberOfGroups(round_up(number_of_actual_groups))
            update_db = True

        if members_in_largest_group > self.__settings.max_number_of_group_members:
            self.__settings.max_number_of_group_members = IntMaxNumberOfGroupMembers(round_up(members_in_largest_group))
            update_db = True

        if update_db:
            self.__settings.store_settings()

        return update_db

    def __generate_group_db_header(self) -> bytes:
        """Generate group database metadata header.

        This function produces a 32-byte bytestring that contains four
        values that allow the Transmitter or Receiver program to
        properly de-serialize the database content:

               `max_number_of_groups` helps slice off dummy groups when
                                      loading the database.

        `max_number_of_group_members` helps split dummy free group data
                                      into proper length blocks that can
                                      be further sliced and decoded to
                                      data used to build Group objects.

                   `len(self.groups)` helps slice off dummy groups when
                                      loading the database. It also
                                      allows TFC to automatically adjust
                                      the max_number_of_groups setting.
                                      The value is needed, e.g., in
                                      cases where the group database is
                                      swapped to a backup that has a
                                      different number of groups than
                                      TFC's settings expect.

               `self.largest_group()` helps TFC to automatically adjust
                                      the max_number_of_group_members
                                      setting (e.g., in cases like the
                                      one described above).
        """
        return b''.join(list(map(int_to_bytes, [self.__settings.max_number_of_groups,
                                                self.__settings.max_number_of_group_members,
                                                len(self.__groups),
                                                self.size_of_largest_group()])))


    # ┌───────────────────────────────────────────────────────────────────────────┐
    # │                             Database Rekeying                             │
    # └───────────────────────────────────────────────────────────────────────────┘

    def rekey_to_temp_db(self, new_master_key: 'MasterKey') -> None:
        """Rekey the database to temporary file."""
        self.__database.rekey_to_temp_db(new_master_key, data_to_write=self.__serialize())

    def migrate_to_rekeyed_db(self) -> None:
        """Migrate to the rekeyed database."""
        self.__database.migrate_to_rekeyed_db()
