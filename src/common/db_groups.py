#!/usr/bin/env python3.7
# -*- coding: utf-8 -*-

"""
TFC - Onion-routed, endpoint secure messaging system
Copyright (C) 2013-2019  Markus Ottela

This file is part of TFC.

TFC is free software: you can redistribute it and/or modify it under the terms
of the GNU General Public License as published by the Free Software Foundation,
either version 3 of the License, or (at your option) any later version.

TFC is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with TFC. If not, see <https://www.gnu.org/licenses/>.
"""

import os
import textwrap
import typing

from typing import Callable, Iterable, Iterator, List, Sized

from src.common.database    import TFCDatabase
from src.common.db_contacts import Contact
from src.common.encoding    import bool_to_bytes, int_to_bytes, str_to_bytes, onion_address_to_pub_key, b58encode
from src.common.encoding    import bytes_to_bool, bytes_to_int, bytes_to_str
from src.common.exceptions  import CriticalError
from src.common.misc        import ensure_dir, get_terminal_width, round_up, separate_header, separate_headers
from src.common.misc        import split_byte_string
from src.common.statics     import (CONTACT_LIST_INDENT, DIR_USER_DATA, DUMMY_GROUP, DUMMY_MEMBER,
                                    ENCODED_BOOLEAN_LENGTH, ENCODED_INTEGER_LENGTH, GROUP_DB_HEADER_LENGTH,
                                    GROUP_ID_LENGTH, GROUP_STATIC_LENGTH, ONION_SERVICE_PUBLIC_KEY_LENGTH,
                                    PADDED_UTF32_STR_LENGTH)

if typing.TYPE_CHECKING:
    from src.common.db_contacts  import ContactList
    from src.common.db_masterkey import MasterKey
    from src.common.db_settings  import Settings


class Group(Iterable[Contact], Sized):
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
                 name:          str,
                 group_id:      bytes,
                 log_messages:  bool,
                 notifications: bool,
                 members:       List['Contact'],
                 settings:      'Settings',
                 store_groups:  Callable[..., None]
                 ) -> None:
        """Create a new Group object.

        The `self.store_groups` is a reference to the method of the
        parent object GroupList that stores the list of groups into an
        encrypted database.
        """
        self.name          = name
        self.group_id      = group_id
        self.log_messages  = log_messages
        self.notifications = notifications
        self.members       = members
        self.settings      = settings
        self.store_groups  = store_groups

    def __iter__(self) -> Iterator[Contact]:
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
        object. With the default setting of 50 members per group, the
        length of the serialized data is
            1024 + 4 + 2*1 + 50*32 = 2630 bytes
        The purpose of the constant length serialization is to hide any
        metadata the ciphertext length of the group database could
        reveal.
        """
        members           = self.get_list_of_member_pub_keys()
        number_of_dummies = self.settings.max_number_of_group_members - len(self.members)
        members          += number_of_dummies * [onion_address_to_pub_key(DUMMY_MEMBER)]
        member_bytes      = b''.join(members)

        return (str_to_bytes(self.name)
                + self.group_id
                + bool_to_bytes(self.log_messages)
                + bool_to_bytes(self.notifications)
                + member_bytes)

    def add_members(self, contacts: List['Contact']) -> None:
        """Add a list of Contact objects to the group."""
        pre_existing = self.get_list_of_member_pub_keys()
        self.members.extend((c for c in contacts if c.onion_pub_key not in pre_existing))
        self.store_groups()

    def remove_members(self, pub_keys: List[bytes]) -> bool:
        """Remove a list of Contact objects from the group.

        Return True if the member(s) were removed, else False.
        """
        to_remove = set(pub_keys) & set(self.get_list_of_member_pub_keys())
        if to_remove:
            self.members = [m for m in self.members if m.onion_pub_key not in to_remove]
            self.store_groups()
        return any(to_remove)

    def get_list_of_member_pub_keys(self) -> List[bytes]:
        """Return list of members' public keys."""
        return [m.onion_pub_key for m in self.members]

    def has_member(self, onion_pub_key: bytes) -> bool:
        """Return True if a member with Onion public key is in the group, else False."""
        return any(m.onion_pub_key == onion_pub_key for m in self.members)

    def empty(self) -> bool:
        """Return True if the group is empty, else False."""
        return not any(self.members)


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
                 master_key:   'MasterKey',
                 settings:     'Settings',
                 contact_list: 'ContactList'
                 ) -> None:
        """Create a new GroupList object."""
        self.settings     = settings
        self.contact_list = contact_list
        self.groups       = []  # type: List[Group]
        self.file_name    = f'{DIR_USER_DATA}{settings.software_operation}_groups'
        self.database     = TFCDatabase(self.file_name, master_key)

        ensure_dir(DIR_USER_DATA)
        if os.path.isfile(self.file_name):
            self._load_groups()
        else:
            self.store_groups()

    def __iter__(self) -> Iterator[Group]:
        """Iterate over Group objects in `self.groups`."""
        yield from self.groups

    def __len__(self) -> int:
        """Return the number of Group objects in `self.groups`."""
        return len(self.groups)

    def store_groups(self, replace: bool = True) -> None:
        """Write the list of groups to an encrypted database.

        This function will first generate a header that stores
        information about the group database content and padding at the
        moment of calling. Next, the function will serialize every Group
        object (including dummy groups) to form the constant length
        plaintext that will be encrypted and stored in the database.

        By default, TFC has a maximum number of 50 groups with 50
        members. In addition, the group database stores the header that
        contains four 8-byte values. The database plaintext length with
        50 groups, each with 50 members is
            4*8 + 50*(1024 + 4 + 2*1 + 50*32)
          =  32 + 50*2630
          = 131532 bytes.

        The ciphertext includes a 24-byte nonce and a 16-byte tag, so
        the size of the final database is 131572 bytes.
        """
        pt_bytes  = self._generate_group_db_header()
        pt_bytes += b''.join([g.serialize_g() for g in (self.groups + self._dummy_groups())])
        self.database.store_database(pt_bytes, replace)

    def _load_groups(self) -> None:
        """Load groups from the encrypted database.

        The function first reads, authenticates and decrypts the group
        database data. Next, it slices and decodes the header values
        that help the function to properly de-serialize the database
        content. The function then removes dummy groups based on header
        data. Next, the function updates the group database settings if
        necessary. It then splits group data based on header data into
        blocks, which are further sliced, and processed if necessary, to
        obtain data required to create Group objects. Finally, if
        needed, the function will update the group database content.
        """
        pt_bytes = self.database.load_database()

        # Slice and decode headers
        group_db_headers, pt_bytes = separate_header(pt_bytes, GROUP_DB_HEADER_LENGTH)

        padding_for_group_db, padding_for_members, number_of_groups, members_in_largest_group \
            = list(map(bytes_to_int, split_byte_string(group_db_headers, ENCODED_INTEGER_LENGTH)))

        # Slice dummy groups
        bytes_per_group = GROUP_STATIC_LENGTH + padding_for_members * ONION_SERVICE_PUBLIC_KEY_LENGTH
        dummy_data_len  = (padding_for_group_db - number_of_groups) * bytes_per_group
        group_data      = pt_bytes[:-dummy_data_len]

        update_db = self._check_db_settings(number_of_groups, members_in_largest_group)
        blocks    = split_byte_string(group_data, item_len=bytes_per_group)

        all_pub_keys  = self.contact_list.get_list_of_pub_keys()
        dummy_pub_key = onion_address_to_pub_key(DUMMY_MEMBER)

        # Deserialize group objects
        for block in blocks:
            if len(block) != bytes_per_group:
                raise CriticalError("Invalid data in group database.")

            name_bytes, group_id, log_messages_byte, notification_byte, ser_pub_keys \
                = separate_headers(block, [PADDED_UTF32_STR_LENGTH, GROUP_ID_LENGTH] + 2*[ENCODED_BOOLEAN_LENGTH])

            pub_key_list   = split_byte_string(ser_pub_keys, item_len=ONION_SERVICE_PUBLIC_KEY_LENGTH)
            group_pub_keys = [k for k in pub_key_list if k != dummy_pub_key]
            group_members  = [self.contact_list.get_contact_by_pub_key(k) for k in group_pub_keys if k in all_pub_keys]

            self.groups.append(Group(name         =bytes_to_str(name_bytes),
                                     group_id     =group_id,
                                     log_messages =bytes_to_bool(log_messages_byte),
                                     notifications=bytes_to_bool(notification_byte),
                                     members      =group_members,
                                     settings     =self.settings,
                                     store_groups =self.store_groups))

            update_db |= set(all_pub_keys) > set(group_pub_keys)

        if update_db:
            self.store_groups()

    def _check_db_settings(self,
                           number_of_actual_groups:  int,
                           members_in_largest_group: int
                           ) -> bool:
        """\
        Adjust TFC's settings automatically if loaded group database was
        stored using larger database setting values.

        If settings had to be adjusted, return True so the method
        `self._load_groups` knows to write changes to a new database.
        """
        update_db = False

        if number_of_actual_groups > self.settings.max_number_of_groups:
            self.settings.max_number_of_groups = round_up(number_of_actual_groups)
            update_db = True

        if members_in_largest_group > self.settings.max_number_of_group_members:
            self.settings.max_number_of_group_members = round_up(members_in_largest_group)
            update_db = True

        if update_db:
            self.settings.store_settings()

        return update_db

    def _generate_group_db_header(self) -> bytes:
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
        return b''.join(list(map(int_to_bytes, [self.settings.max_number_of_groups,
                                                self.settings.max_number_of_group_members,
                                                len(self.groups),
                                                self.largest_group()])))

    def _generate_dummy_group(self) -> 'Group':
        """Generate a dummy Group object.

        The dummy group simplifies the code around the constant length
        serialization when the data is stored to, or read from the
        database.
        """
        dummy_member = self.contact_list.generate_dummy_contact()

        return Group(name         =DUMMY_GROUP,
                     group_id     =bytes(GROUP_ID_LENGTH),
                     log_messages =False,
                     notifications=False,
                     members      =self.settings.max_number_of_group_members * [dummy_member],
                     settings     =self.settings,
                     store_groups =lambda: None)

    def _dummy_groups(self) -> List[Group]:
        """Generate a proper size list of dummy groups for database padding."""
        number_of_dummies = self.settings.max_number_of_groups - len(self.groups)
        dummy_group       = self._generate_dummy_group()
        return [dummy_group] * number_of_dummies

    def add_group(self,
                  name:          str,
                  group_id:      bytes,
                  log_messages:  bool,
                  notifications: bool,
                  members:       List['Contact']) -> None:
        """Add a new group to `self.groups` and write changes to the database."""
        if self.has_group(name):
            self.remove_group_by_name(name)

        self.groups.append(Group(name,
                                 group_id,
                                 log_messages,
                                 notifications,
                                 members,
                                 self.settings,
                                 self.store_groups))
        self.store_groups()

    def remove_group_by_name(self, name: str) -> None:
        """Remove the specified group from the group list.

        If a group with the matching name was found and removed, write
        changes to the database.
        """
        for i, g in enumerate(self.groups):
            if g.name == name:
                del self.groups[i]
                self.store_groups()
                break

    def remove_group_by_id(self, group_id: bytes) -> None:
        """Remove the specified group from the group list.

        If a group with the matching group ID was found and removed,
        write changes to the database.
        """
        for i, g in enumerate(self.groups):
            if g.group_id == group_id:
                del self.groups[i]
                self.store_groups()
                break

    def get_group(self, name: str) -> Group:
        """Return Group object based on its name."""
        return next(g for g in self.groups if g.name == name)

    def get_group_by_id(self, group_id: bytes) -> Group:
        """Return Group object based on its group ID."""
        return next(g for g in self.groups if g.group_id == group_id)

    def get_list_of_group_names(self) -> List[str]:
        """Return list of group names."""
        return [g.name for g in self.groups]

    def get_list_of_group_ids(self) -> List[bytes]:
        """Return list of group IDs."""
        return [g.group_id for g in self.groups]

    def get_list_of_hr_group_ids(self) -> List[str]:
        """Return list of human readable (B58 encoded) group IDs."""
        return [b58encode(g.group_id) for g in self.groups]

    def get_group_members(self, group_id: bytes) -> List['Contact']:
        """Return list of group members (Contact objects)."""
        return self.get_group_by_id(group_id).members

    def has_group(self, name: str) -> bool:
        """Return True if group list has a group with the specified name, else False."""
        return any(g.name == name for g in self.groups)

    def has_group_id(self, group_id: bytes) -> bool:
        """Return True if group list has a group with the specified group ID, else False."""
        return any(g.group_id == group_id for g in self.groups)

    def largest_group(self) -> int:
        """Return size of the group that has the most members."""
        return max([0] + [len(g) for g in self.groups])

    def print_groups(self) -> None:
        """Print list of groups.

        Neatly printed group list allows easy group management and it
        also allows the user to check active logging and notification
        setting, as well as what group ID Relay Program shows
        corresponds to what group, and which contacts are in the group.
        """
        # Initialize columns
        c1 = ['Group'   ]
        c2 = ['Group ID']
        c3 = ['Logging ']
        c4 = ['Notify'  ]
        c5 = ['Members' ]

        # Populate columns with group data that has only a single line
        for g in self.groups:
            c1.append(g.name)
            c2.append(b58encode(g.group_id))
            c3.append('Yes' if g.log_messages  else 'No')
            c4.append('Yes' if g.notifications else 'No')

        # Calculate the width of single-line columns
        c1w, c2w, c3w, c4w = [max(len(v) for v in column) + CONTACT_LIST_INDENT for column in [c1, c2, c3, c4]]

        # Create a wrapper for Members-column
        wrapped_members_line_indent = c1w + c2w + c3w + c4w
        members_column_width        = max(1, get_terminal_width() - wrapped_members_line_indent)
        wrapper                     = textwrap.TextWrapper(width=members_column_width)

        # Populate the Members-column
        for g in self.groups:
            if g.empty():
                c5.append("<Empty group>\n")
            else:
                comma_separated_nicks = ', '.join(sorted([m.nick for m in g.members]))
                members_column_lines  = wrapper.fill(comma_separated_nicks).split('\n')

                final_str = members_column_lines[0] + '\n'
                for line in members_column_lines[1:]:
                    final_str += wrapped_members_line_indent * ' ' + line + '\n'

                c5.append(final_str)

        # Align columns by adding whitespace between fields of each line
        lines = [f'{f1:{c1w}}{f2:{c2w}}{f3:{c3w}}{f4:{c4w}}{f5}' for f1, f2, f3, f4, f5 in zip(c1, c2, c3, c4, c5)]

        # Add a terminal-wide line between the column names and the data
        lines.insert(1, get_terminal_width() * '─')

        # Print the group list
        print('\n'.join(lines) + '\n')
