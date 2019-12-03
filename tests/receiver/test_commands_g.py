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

import datetime
import unittest

from src.common.statics import US_BYTE

from src.receiver.commands_g import (
    group_add,
    group_create,
    group_delete,
    group_remove,
    group_rename,
)

from tests.mock_classes import (
    Contact,
    ContactList,
    GroupList,
    RxWindow,
    Settings,
    WindowList,
)
from tests.utils import (
    group_name_to_group_id,
    nick_to_pub_key,
    TFCTestCase,
    UNDECODABLE_UNICODE,
)


class TestGroupCreate(TFCTestCase):
    def setUp(self) -> None:
        """Pre-test actions."""
        self.ts = datetime.datetime.now()
        self.settings = Settings()
        self.window_list = WindowList()
        self.group_id = group_name_to_group_id("test_group")

    def test_too_many_purp_accounts_raises_fr(self) -> None:
        # Setup
        create_list = [nick_to_pub_key(str(n)) for n in range(51)]
        cmd_data = self.group_id + b"test_group" + US_BYTE + b"".join(create_list)
        group_list = GroupList(groups=["test_group"])
        contact_list = ContactList(nicks=[str(n) for n in range(51)])
        group = group_list.get_group("test_group")
        group.members = contact_list.contacts

        # Test
        self.assert_se(
            "Error: TFC settings only allow 50 members per group.",
            group_create,
            cmd_data,
            self.ts,
            self.window_list,
            contact_list,
            group_list,
            self.settings,
        )

    def test_full_group_list_raises_fr(self) -> None:
        # Setup
        cmd_data = self.group_id + b"test_group" + US_BYTE + nick_to_pub_key("51")
        group_list = GroupList(groups=[f"test_group_{n}" for n in range(50)])
        contact_list = ContactList(nicks=["Alice"])

        # Test
        self.assert_se(
            "Error: TFC settings only allow 50 groups.",
            group_create,
            cmd_data,
            self.ts,
            self.window_list,
            contact_list,
            group_list,
            self.settings,
        )

    def test_successful_group_creation(self) -> None:
        # Setup
        group_list = GroupList(groups=["test_group"])
        cmd_data = (
            group_name_to_group_id("test_group")
            + b"test_group2"
            + US_BYTE
            + nick_to_pub_key("Bob")
        )
        contact_list = ContactList(nicks=["Alice", "Bob"])
        window_list = WindowList(
            nicks=["Alice", "Bob"],
            contact_list=contact_list,
            group_lis=group_list,
            packet_list=None,
            settings=Settings,
        )
        # Test
        self.assertIsNone(
            group_create(
                cmd_data, self.ts, window_list, contact_list, group_list, self.settings
            )
        )
        self.assertEqual(len(group_list.get_group("test_group")), 2)


class TestGroupAdd(TFCTestCase):
    def setUp(self) -> None:
        """Pre-test actions."""
        self.ts = datetime.datetime.now()
        self.settings = Settings()
        self.window_list = WindowList()

    def test_too_large_final_member_list_raises_fr(self) -> None:
        # Setup
        group_list = GroupList(groups=["test_group"])
        contact_list = ContactList(nicks=[str(n) for n in range(51)])
        group = group_list.get_group("test_group")
        group.members = contact_list.contacts[:50]
        cmd_data = group_name_to_group_id("test_group") + nick_to_pub_key("50")

        # Test
        self.assert_se(
            "Error: TFC settings only allow 50 members per group.",
            group_add,
            cmd_data,
            self.ts,
            self.window_list,
            contact_list,
            group_list,
            self.settings,
        )

    def test_unknown_group_id_raises_fr(self) -> None:
        # Setup
        group_list = GroupList(groups=["test_group"])
        contact_list = ContactList(nicks=[str(n) for n in range(21)])
        cmd_data = group_name_to_group_id("test_group2") + nick_to_pub_key("50")

        # Test
        self.assert_se(
            "Error: No group with ID '2e7mHQznTMsP6' found.",
            group_add,
            cmd_data,
            self.ts,
            self.window_list,
            contact_list,
            group_list,
            self.settings,
        )

    def test_successful_group_add(self) -> None:
        # Setup
        contact_list = ContactList(nicks=[str(n) for n in range(21)])
        group_lst = GroupList(groups=["test_group"])
        group = group_lst.get_group("test_group")
        group.members = contact_list.contacts[:19]
        cmd_data = group_name_to_group_id("test_group") + nick_to_pub_key("20")

        # Test
        self.assertIsNone(
            group_add(
                cmd_data,
                self.ts,
                self.window_list,
                contact_list,
                group_lst,
                self.settings,
            )
        )

        group2 = group_lst.get_group("test_group")
        self.assertEqual(len(group2), 20)

        for c in group2:
            self.assertIsInstance(c, Contact)


class TestGroupRemove(TFCTestCase):
    def setUp(self) -> None:
        """Pre-test actions."""
        self.ts = datetime.datetime.now()
        self.window_list = WindowList()
        self.contact_list = ContactList(nicks=[f"contact_{n}" for n in range(21)])
        self.group_list = GroupList(groups=["test_group"])
        self.group = self.group_list.get_group("test_group")
        self.group.members = self.contact_list.contacts[:19]
        self.settings = Settings()

    def test_unknown_group_id_raises_fr(self) -> None:
        # Setup
        group_list = GroupList(groups=["test_group"])
        contact_list = ContactList(nicks=[str(n) for n in range(21)])
        cmd_data = group_name_to_group_id("test_group2") + nick_to_pub_key("20")

        # Test
        self.assert_se(
            "Error: No group with ID '2e7mHQznTMsP6' found.",
            group_remove,
            cmd_data,
            self.ts,
            self.window_list,
            contact_list,
            group_list,
        )

    def test_successful_member_removal(self) -> None:
        self.cmd_data = group_name_to_group_id("test_group") + b"".join(
            [nick_to_pub_key("contact_18"), nick_to_pub_key("contact_20")]
        )
        self.assertIsNone(
            group_remove(
                self.cmd_data,
                self.ts,
                self.window_list,
                self.contact_list,
                self.group_list,
            )
        )


class TestGroupDelete(TFCTestCase):
    def setUp(self) -> None:
        """Pre-test actions."""
        self.ts = datetime.datetime.now()
        self.window_list = WindowList()
        self.group_list = GroupList(groups=["test_group"])

    def test_missing_group_raises_fr(self) -> None:
        cmd_data = group_name_to_group_id("test_group2")
        self.assert_se(
            "Error: No group with ID '2e7mHQznTMsP6' found.",
            group_delete,
            cmd_data,
            self.ts,
            self.window_list,
            self.group_list,
        )

    def test_unknown_group_id_raises_fr(self) -> None:
        # Setup
        group_list = GroupList(groups=["test_group"])
        cmd_data = group_name_to_group_id("test_group2")

        # Test
        self.assert_se(
            "Error: No group with ID '2e7mHQznTMsP6' found.",
            group_delete,
            cmd_data,
            self.ts,
            self.window_list,
            group_list,
        )

    def test_successful_remove(self) -> None:
        cmd_data = group_name_to_group_id("test_group")
        self.assertIsNone(
            group_delete(cmd_data, self.ts, self.window_list, self.group_list)
        )
        self.assertEqual(len(self.group_list.groups), 0)


class TestGroupRename(TFCTestCase):
    def setUp(self) -> None:
        """Pre-test actions."""
        self.ts = datetime.datetime.now()
        self.group_list = GroupList(groups=["test_group"])
        self.window_list = WindowList()
        self.window = RxWindow()
        self.window_list.windows = [self.window]
        self.contact_list = ContactList(nicks=["alice"])
        self.args = self.ts, self.window_list, self.contact_list, self.group_list

    def test_missing_group_id_raises_fr(self) -> None:
        # Setup
        cmd_data = group_name_to_group_id("test_group2") + b"new_name"

        # Test
        self.assert_se(
            "Error: No group with ID '2e7mHQznTMsP6' found.",
            group_rename,
            cmd_data,
            *self.args,
        )

    def test_invalid_group_name_encoding_raises_fr(self) -> None:
        # Setup
        cmd_data = (
            group_name_to_group_id("test_group") + b"new_name" + UNDECODABLE_UNICODE
        )

        # Test
        self.assert_se(
            "Error: New name for group 'test_group' was invalid.",
            group_rename,
            cmd_data,
            *self.args,
        )

    def test_invalid_group_name_raises_fr(self) -> None:
        # Setup
        cmd_data = group_name_to_group_id("test_group") + b"new_name\x1f"

        # Test
        self.assert_se(
            "Error: Group name must be printable.", group_rename, cmd_data, *self.args
        )

    def test_valid_group_name_change(self) -> None:
        # Setup
        cmd_data = group_name_to_group_id("test_group") + b"new_name"

        # Test
        self.assertIsNone(group_rename(cmd_data, *self.args))


if __name__ == "__main__":
    unittest.main(exit=False)
