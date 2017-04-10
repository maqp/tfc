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

from typing import Callable, List

from src.common.crypto   import auth_and_decrypt, encrypt_and_sign
from src.common.encoding import bool_to_bytes, int_to_bytes, str_to_bytes
from src.common.encoding import bytes_to_bool, bytes_to_int, bytes_to_str
from src.common.misc     import ensure_dir, get_tty_w, round_up, split_byte_string
from src.common.statics  import *

if typing.TYPE_CHECKING:
    from src.common.db_contacts  import Contact, ContactList
    from src.common.db_masterkey import MasterKey
    from src.common.db_settings  import Settings


class Group(object):
    """Group object contains a list of contact objects (members of group) and settings related to group."""

    def __init__(self,
                 name:          str,
                 log_messages:  bool,
                 notifications: bool,
                 members:       List['Contact'],
                 settings:      'Settings',
                 store_groups:  Callable  # Reference to group list's method that stores groups
                 ) -> None:
        """Create a new group object."""
        self.name          = name
        self.log_messages  = log_messages
        self.notifications = notifications
        self.members       = members
        self.settings      = settings
        self.store_groups  = store_groups

    def __iter__(self) -> 'Contact':
        """Iterate over members in group."""
        for m in self.members:
            yield m

    def __len__(self) -> int:
        """Return number of members in group."""
        return len(self.members)

    def dump_g(self) -> bytes:
        """Return group data as constant length byte string."""
        name           = str_to_bytes(self.name)
        log_messages   = bool_to_bytes(self.log_messages)
        notifications  = bool_to_bytes(self.notifications)
        members        = self.get_list_of_member_accounts()

        num_of_dummies = self.settings.m_members_in_group - len(self.members)
        members       += num_of_dummies * ['dummy_member']
        member_bytes   = b''.join([str_to_bytes(m) for m in members])

        return name + log_messages + notifications + member_bytes

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

    def add_members(self, contacts: List['Contact']) -> None:
        """Add list of contact objects to group."""
        for c in contacts:
            if c.rx_account not in self.get_list_of_member_accounts():
                self.members.append(c)
        self.store_groups()

    def remove_members(self, accounts: List[str]) -> bool:
        """Remove contact objects from group."""
        removed_one = False
        for account in accounts:
            for i, m in enumerate(self.members):
                if account == m.rx_account:
                    del self.members[i]
                    removed_one = True
        if removed_one:
            self.store_groups()
        return removed_one


class GroupList(object):
    """GroupList object manages list of group objects and encrypted group database."""

    def __init__(self,
                 master_key:   'MasterKey',
                 settings:     'Settings',
                 contact_list: 'ContactList') -> None:
        """Create a new group list object."""
        self.master_key   = master_key
        self.contact_list = contact_list
        self.settings     = settings
        self.groups       = []  # type: List[Group]
        self.file_name    = f'{DIR_USER_DATA}/{settings.software_operation}_groups'

        if os.path.isfile(self.file_name):
            self.load_groups()
        else:
            self.store_groups()

    def __iter__(self) -> 'Group':
        """Iterate over list of groups."""
        for g in self.groups:
            yield g

    def __len__(self) -> int:
        """Return number of groups."""
        return len(self.groups)

    def load_groups(self) -> None:
        """Load groups from encrypted database."""
        ensure_dir(f'{DIR_USER_DATA}/')
        with open(self.file_name, 'rb') as f:
            ct_bytes = f.read()

        pt_bytes  = auth_and_decrypt(ct_bytes, self.master_key.master_key)
        update_db = False

        # Slice and decode headers
        padding_for_g = bytes_to_int(pt_bytes[0:8])
        padding_for_m = bytes_to_int(pt_bytes[8:16])
        n_of_actual_g = bytes_to_int(pt_bytes[16:24])
        largest_group = bytes_to_int(pt_bytes[24:32])

        if n_of_actual_g > self.settings.m_number_of_groups:
            self.settings.m_number_of_groups = round_up(n_of_actual_g)
            self.settings.store_settings()
            update_db = True
            print("Group database had {} groups. Increased max number of groups to {}."
                  .format(n_of_actual_g, self.settings.m_number_of_groups))

        if largest_group > self.settings.m_members_in_group:
            self.settings.m_members_in_group = round_up(largest_group)
            self.settings.store_settings()
            update_db = True
            print("A group in group database had {} members. Increased max size of groups to {}."
                  .format(largest_group, self.settings.m_members_in_group))

        # Strip header bytes
        pt_bytes = pt_bytes[32:]

        #                 (      no_fields     * (padding + BOM) * bytes/char) + booleans
        bytes_per_group = ((1 + padding_for_m) * (  255   +  1 ) *     4     ) +    2

        # Remove dummy groups
        no_dummy_groups = padding_for_g - n_of_actual_g
        pt_bytes        = pt_bytes[:-(no_dummy_groups * bytes_per_group)]

        groups = split_byte_string(pt_bytes, item_len=bytes_per_group)

        for g in groups:

            # Remove padding
            name          = bytes_to_str(     g[   0:1024])
            log_messages  = bytes_to_bool(    g[1024:1025])
            notifications = bytes_to_bool(    g[1025:1026])
            members_b     = split_byte_string(g[1026:], item_len=1024)
            members       = [bytes_to_str(m) for m in members_b]

            # Remove dummy members
            members_df = [m for m in members if not m == 'dummy_member']

            # Load contacts based on stored rx_account
            group_members = [self.contact_list.get_contact(m) for m in members_df if self.contact_list.has_contact(m)]

            self.groups.append(Group(name, log_messages, notifications, group_members, self.settings, self.store_groups))

        if update_db:
            self.store_groups()

    def store_groups(self) -> None:
        """Write groups to encrypted database."""
        dummy_group_bytes = self.generate_dummy_group()
        number_of_dummies = self.settings.m_number_of_groups - len(self.groups)

        pt_bytes  = self.generate_header()
        pt_bytes += b''.join([g.dump_g() for g in self.groups])
        pt_bytes += number_of_dummies * dummy_group_bytes
        ct_bytes  = encrypt_and_sign(pt_bytes, self.master_key.master_key)

        ensure_dir(f'{DIR_USER_DATA}/')
        with open(self.file_name, 'wb+') as f:
            f.write(ct_bytes)

    def generate_header(self) -> bytes:
        """Generate group database metadata header."""
        padding_for_g = int_to_bytes(self.settings.m_number_of_groups)
        padding_for_m = int_to_bytes(self.settings.m_members_in_group)
        n_of_actual_g = int_to_bytes(len(self.groups))
        largest_group = int_to_bytes(self.largest_group())

        return b''.join([padding_for_g, padding_for_m, n_of_actual_g, largest_group])


    def generate_dummy_group(self) -> bytes:
        """Generate a byte string that represents a dummy group."""
        name          = str_to_bytes('dummy_group')
        log_messages  = bool_to_bytes(False)
        notifications = bool_to_bytes(False)
        members       = self.settings.m_members_in_group * ['dummy_member']
        member_bytes  = b''.join([str_to_bytes(m) for m in members])

        return name + log_messages + notifications + member_bytes

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

    def largest_group(self) -> int:
        """Return size of largest group."""
        largest = 0
        for g in self.groups:
            largest = max(len(g), largest)
        return largest

    def get_list_of_group_names(self) -> List[str]:
        """Return list of group names."""
        return [g.name for g in self.groups]

    def get_group(self, name: str) -> Group:
        """Return group object based on it's name."""
        return next(g for g in self.groups if g.name == name)

    def has_group(self, name: str) -> bool:
        """Return True if group list has group with specified name, else False."""
        return any([g.name == name for g in self.groups])

    def has_groups(self) -> bool:
        """Return True if group list has groups, else False."""
        return any(self.groups)

    def get_group_members(self, name: str) -> List['Contact']:
        """Return list of group members."""
        return self.get_group(name).members

    def remove_group(self, name: str) -> None:
        """Remove group from group list."""
        for i, g in enumerate(self.groups):
            if g.name == name:
                del self.groups[i]
                self.store_groups()
                break

    def print_groups(self) -> None:
        """Print list of groups."""
        # Columns
        c1 = ['Group  ']
        c2 = ['Logging']
        c3 = ['Notify']
        c4 = ['Members']

        for g in self.groups:
            c1.append(g.name)
            c2.append('Yes' if g.log_messages  else 'No')
            c3.append('Yes' if g.notifications else 'No')

            m_indent  = 40
            m_string  = ', '.join(sorted([m.nick for m in g.members]))
            wrapper   = textwrap.TextWrapper(width=max(1, (get_tty_w() - m_indent)))
            mem_lines = wrapper.fill(m_string).split('\n')
            f_string  = mem_lines[0] + '\n'

            for l in mem_lines[1:]:
                f_string += m_indent * ' ' + l + '\n'
            c4.append(f_string)

        lst = []
        for name, log_setting, notify_setting, members in zip(c1, c2, c3, c4):
            lst.append('{0:{4}} {1:{5}} {2:{6}} {3}'.format(
                name, log_setting, notify_setting, members,
                len(max(c1, key=len)) + 4,
                len(max(c2, key=len)) + 4,
                len(max(c3, key=len)) + 4))

        print(lst[0] + '\n' + get_tty_w() * '─')
        print('\n'.join(str(l) for l in lst[1:]) + '\n')
