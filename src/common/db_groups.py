#!/usr/bin/env python3.6
# -*- coding: utf-8 -*-

"""
Copyright (C) 2013-2017  Markus Ottela

This file is part of TFC.

TFC is free software: you can redistribute it and/or modify it under the terms
of the GNU General Public License as published by the Free Software Foundation,
either version 3 of the License, or (at your option) any later version.

TFC is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with TFC. If not, see <http://www.gnu.org/licenses/>.
"""

import os
import textwrap
import typing

from typing import Callable, Generator, Iterable, List, Sized

from src.common.crypto   import auth_and_decrypt, encrypt_and_sign
from src.common.encoding import bool_to_bytes, int_to_bytes, str_to_bytes
from src.common.encoding import bytes_to_bool, bytes_to_int, bytes_to_str
from src.common.misc     import ensure_dir, get_terminal_width, round_up, split_byte_string
from src.common.statics  import *

if typing.TYPE_CHECKING:
    from src.common.db_contacts  import Contact, ContactList
    from src.common.db_masterkey import MasterKey
    from src.common.db_settings  import Settings


class Group(Iterable, Sized):
    """\
    Group object contains a list of contact objects
    (group members) and settings related to the group.
    """

    def __init__(self,
                 name:          str,
                 log_messages:  bool,
                 notifications: bool,
                 members:       List['Contact'],
                 settings:      'Settings',
                 store_groups:  Callable) -> None:
        """Create a new Group object."""
        self.name          = name
        self.log_messages  = log_messages
        self.notifications = notifications
        self.members       = members
        self.settings      = settings
        self.store_groups  = store_groups

    def __iter__(self) -> Generator:
        """Iterate over members in group."""
        yield from self.members

    def __len__(self) -> int:
        """Return number of members in group."""
        return len(self.members)

    def serialize_g(self) -> bytes:
        """Return group data as constant length byte string."""
        name           = str_to_bytes(self.name)
        log_messages   = bool_to_bytes(self.log_messages)
        notifications  = bool_to_bytes(self.notifications)
        members        = self.get_list_of_member_accounts()
        num_of_dummies = self.settings.max_number_of_group_members - len(self.members)
        members       += num_of_dummies * [DUMMY_MEMBER]
        member_bytes   = b''.join([str_to_bytes(m) for m in members])

        return name + log_messages + notifications + member_bytes

    def add_members(self, contacts: List['Contact']) -> None:
        """Add list of contact objects to group."""
        for c in contacts:
            if c.rx_account not in self.get_list_of_member_accounts():
                self.members.append(c)
        self.store_groups()

    def remove_members(self, accounts: List[str]) -> bool:
        """Remove contact objects from group."""
        to_remove = set(accounts) & set(self.get_list_of_member_accounts())
        if to_remove:
            self.members = [m for m in self.members if m.rx_account not in to_remove]
            self.store_groups()
        return any(to_remove)

    def get_list_of_member_accounts(self) -> List[str]:
        """Return list of members' rx_accounts."""
        return [m.rx_account for m in self.members]

    def get_list_of_member_nicks(self) -> List[str]:
        """Return list of members' nicks."""
        return [m.nick for m in self.members]

    def has_member(self, account: str) -> bool:
        """Return True if specified account is in group, else False."""
        return any(m.rx_account == account for m in self.members)

    def has_members(self) -> bool:
        """Return True if group has contact objects, else False."""
        return any(self.members)


class GroupList(Iterable, Sized):
    """\
    GroupList object manages list of group
    objects and encrypted group database.
    """

    def __init__(self,
                 master_key:   'MasterKey',
                 settings:     'Settings',
                 contact_list: 'ContactList') -> None:
        """Create a new GroupList object."""
        self.master_key   = master_key
        self.settings     = settings
        self.contact_list = contact_list
        self.groups       = []  # type: List[Group]
        self.file_name    = f'{DIR_USER_DATA}{settings.software_operation}_groups'

        ensure_dir(DIR_USER_DATA)
        if os.path.isfile(self.file_name):
            self.load_groups()
        else:
            self.store_groups()

    def __iter__(self) -> Generator:
        """Iterate over list of groups."""
        yield from self.groups

    def __len__(self) -> int:
        """Return number of groups."""
        return len(self.groups)

    def store_groups(self) -> None:
        """Write groups to encrypted database."""
        groups    = self.groups + [self.generate_dummy_group()] * (self.settings.max_number_of_groups - len(self.groups))
        pt_bytes  = self.generate_group_db_header()
        pt_bytes += b''.join([g.serialize_g() for g in groups])
        ct_bytes  = encrypt_and_sign(pt_bytes, self.master_key.master_key)

        ensure_dir(DIR_USER_DATA)
        with open(self.file_name, 'wb+') as f:
            f.write(ct_bytes)

    def load_groups(self) -> None:
        """Load groups from encrypted database."""
        with open(self.file_name, 'rb') as f:
            ct_bytes = f.read()

        pt_bytes  = auth_and_decrypt(ct_bytes, self.master_key.master_key)
        update_db = False

        # Slice and decode headers
        padding_for_group_db    = bytes_to_int(pt_bytes[0:8])
        padding_for_members     = bytes_to_int(pt_bytes[8:16])
        number_of_actual_groups = bytes_to_int(pt_bytes[16:24])
        largest_group           = bytes_to_int(pt_bytes[24:32])

        if number_of_actual_groups > self.settings.max_number_of_groups:
            self.settings.max_number_of_groups = round_up(number_of_actual_groups)
            self.settings.store_settings()
            update_db = True
            print("Group database had {} groups. Increased max number of groups to {}."
                  .format(number_of_actual_groups, self.settings.max_number_of_groups))

        if largest_group > self.settings.max_number_of_group_members:
            self.settings.max_number_of_group_members = round_up(largest_group)
            self.settings.store_settings()
            update_db = True
            print("A group in group database had {} members. Increased max size of groups to {}."
                  .format(largest_group, self.settings.max_number_of_group_members))

        group_name_field       = 1
        string_fields_in_group = padding_for_members + group_name_field
        bytes_per_group        = string_fields_in_group * PADDED_UTF32_STR_LEN + 2 * BOOLEAN_SETTING_LEN

        # Remove group header and dummy groups
        dummy_group_data = (padding_for_group_db - number_of_actual_groups) * bytes_per_group
        group_data       = pt_bytes[GROUP_DB_HEADER_LEN:-dummy_group_data]

        groups = split_byte_string(group_data, item_len=bytes_per_group)

        for g in groups:
            assert len(g) == bytes_per_group

            name              = bytes_to_str(     g[   0:1024])
            log_messages      = bytes_to_bool(    g[1024:1025])
            notifications     = bytes_to_bool(    g[1025:1026])
            members_bytes     = split_byte_string(g[1026:], item_len=PADDED_UTF32_STR_LEN)
            members_w_dummies = [bytes_to_str(m) for m in members_bytes]
            members           = [m for m in members_w_dummies if m != DUMMY_MEMBER]

            # Load contacts based on stored rx_account
            group_members = [self.contact_list.get_contact(m) for m in members if self.contact_list.has_contact(m)]

            # Update group database if any member has been removed from contact database
            if not all(m in self.contact_list.get_list_of_accounts() for m in members):
                update_db = True

            self.groups.append(Group(name, log_messages, notifications, group_members, self.settings, self.store_groups))

        if update_db:
            self.store_groups()

    def generate_group_db_header(self) -> bytes:
        """Generate group database metadata header.

        padding_for_group_db     helps define how many groups are actually in the database.

        padding_for_members      defines to how many members each group is padded to.

        number_of_actual_groups  helps define how many groups are actually in the database.
                                 Also allows TFC to automatically adjust the minimum
                                 settings for number of groups. This is needed e.g. in cases
                                 where the group database is swapped to a backup that has
                                 different number of groups than TFC's settings expect.

       largest_group             helps TFC to automatically adjust minimum setting for max
                                 number of members in each group (e.g. in cases like the one
                                 described above).
        """
        return b''.join(list(map(int_to_bytes, [self.settings.max_number_of_groups,
                                                self.settings.max_number_of_group_members,
                                                len(self.groups),
                                                self.largest_group()])))

    def generate_dummy_group(self) -> 'Group':
        """Generate a dummy group."""
        return Group(name         =DUMMY_GROUP,
                     log_messages =False,
                     notifications=False,
                     members      =self.settings.max_number_of_group_members * [self.contact_list.generate_dummy_contact()],
                     settings     =self.settings,
                     store_groups =lambda: None)

    def add_group(self,
                  name:          str,
                  log_messages:  bool,
                  notifications: bool,
                  members:       List['Contact']) -> None:
        """Add a new group to group list."""
        if self.has_group(name):
            self.remove_group(name)

        self.groups.append(Group(name, log_messages, notifications, members, self.settings, self.store_groups))
        self.store_groups()

    def remove_group(self, name: str) -> None:
        """Remove group from group list."""
        for i, g in enumerate(self.groups):
            if g.name == name:
                del self.groups[i]
                self.store_groups()
                break

    def get_list_of_group_names(self) -> List[str]:
        """Return list of group names."""
        return [g.name for g in self.groups]

    def get_group(self, name: str) -> Group:
        """Return group object based on it's name."""
        return next(g for g in self.groups if g.name == name)

    def get_group_members(self, name: str) -> List['Contact']:
        """Return list of group members."""
        return self.get_group(name).members

    def has_group(self, name: str) -> bool:
        """Return True if group list has group with specified name, else False."""
        return any([g.name == name for g in self.groups])

    def has_groups(self) -> bool:
        """Return True if group list has groups, else False."""
        return any(self.groups)

    def largest_group(self) -> int:
        """Return size of group with most members."""
        return max([0] + [len(g) for g in self.groups])

    def print_groups(self) -> None:
        """Print list of groups."""
        # Columns
        c1 = ['Group  ']
        c2 = ['Logging']
        c3 = ['Notify' ]
        c4 = ['Members']

        for g in self.groups:
            c1.append(g.name)
            c2.append('Yes' if g.log_messages  else 'No')
            c3.append('Yes' if g.notifications else 'No')

            if g.has_members():
                m_indent  = max(len(g.name) for g in self.groups) + 28
                m_string  = ', '.join(sorted([m.nick for m in g.members]))
                wrapper   = textwrap.TextWrapper(width=max(1, (get_terminal_width() - m_indent)))
                mem_lines = wrapper.fill(m_string).split('\n')
                f_string  = mem_lines[0] + '\n'

                for l in mem_lines[1:]:
                    f_string += m_indent * ' ' + l + '\n'
                c4.append(f_string)
            else:
                c4.append("<Empty group>\n")

        lst = []
        for name, log_setting, notify_setting, members in zip(c1, c2, c3, c4):
            lst.append('{0:{1}} {2:{3}} {4:{5}} {6}'.format(
                name,           max(len(v) for v in c1) + CONTACT_LIST_INDENT,
                log_setting,    max(len(v) for v in c2) + CONTACT_LIST_INDENT,
                notify_setting, max(len(v) for v in c3) + CONTACT_LIST_INDENT,
                members))

        lst.insert(1, get_terminal_width() * '─')
        print('\n'.join(lst) + '\n')
