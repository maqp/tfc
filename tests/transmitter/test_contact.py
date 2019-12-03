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
import unittest

from unittest import mock

from src.common.crypto import blake2b
from src.common.statics import (
    COMMAND_PACKET_QUEUE,
    CONFIRM_CODE_LENGTH,
    FINGERPRINT_LENGTH,
    KDB_REMOVE_ENTRY_HEADER,
    KEY_MANAGEMENT_QUEUE,
    LOG_SETTING_QUEUE,
    RELAY_PACKET_QUEUE,
    TM_COMMAND_PACKET_QUEUE,
    WIN_TYPE_CONTACT,
    WIN_TYPE_GROUP,
)

from src.transmitter.contact import (
    add_new_contact,
    change_nick,
    contact_setting,
    remove_contact,
)

from tests.mock_classes import (
    ContactList,
    create_contact,
    create_group,
    Group,
    GroupList,
    MasterKey,
    OnionService,
)
from tests.mock_classes import Settings, TxWindow, UserInput
from tests.utils import (
    cd_unit_test,
    cleanup,
    gen_queue_dict,
    group_name_to_group_id,
    ignored,
)
from tests.utils import (
    nick_to_onion_address,
    nick_to_pub_key,
    tear_queues,
    TFCTestCase,
    VALID_ECDHE_PUB_KEY,
)


class TestAddNewContact(TFCTestCase):
    def setUp(self) -> None:
        """Pre-test actions."""
        self.contact_list = ContactList()
        self.group_list = GroupList()
        self.settings = Settings(disable_gui_dialog=True)
        self.queues = gen_queue_dict()
        self.onion_service = OnionService()
        self.args = (
            self.contact_list,
            self.group_list,
            self.settings,
            self.queues,
            self.onion_service,
        )

    def tearDown(self) -> None:
        """Post-test actions."""
        with ignored(OSError):
            os.remove(f"v4dkh.psk - Give to hpcra")
        tear_queues(self.queues)

    def test_adding_new_contact_during_traffic_masking_raises_fr(self) -> None:
        # Setup
        self.settings.traffic_masking = True

        # Test
        self.assert_se(
            "Error: Command is disabled during traffic masking.",
            add_new_contact,
            *self.args,
        )

    def test_contact_list_full_raises_fr(self) -> None:
        # Setup
        contact_list = ContactList(nicks=[str(n) for n in range(50)])
        self.contact_list.contacts = contact_list.contacts

        # Test
        self.assert_se(
            "Error: TFC settings only allow 50 accounts.", add_new_contact, *self.args
        )

    @mock.patch(
        "builtins.input",
        side_effect=[
            nick_to_onion_address("Bob"),
            "Bob",
            "",
            VALID_ECDHE_PUB_KEY,
            "Yes",
            blake2b(nick_to_pub_key("Bob"), digest_size=CONFIRM_CODE_LENGTH).hex(),
        ],
    )
    @mock.patch("shutil.get_terminal_size", return_value=[200, 200])
    @mock.patch("time.sleep", return_value=None)
    def test_default_nick_ecdhe(self, *_) -> None:
        self.assertIsNone(add_new_contact(*self.args))
        contact = self.contact_list.get_contact_by_address_or_nick("Bob")
        self.assertEqual(contact.nick, "Bob")
        self.assertNotEqual(contact.tx_fingerprint, bytes(FINGERPRINT_LENGTH))

    @mock.patch("src.transmitter.key_exchanges.ARGON2_PSK_MEMORY_COST", 200)
    @mock.patch("src.common.statics.MIN_KEY_DERIVATION_TIME", 0.1)
    @mock.patch("src.common.statics.MAX_KEY_DERIVATION_TIME", 1.0)
    @mock.patch(
        "builtins.input",
        side_effect=[
            nick_to_onion_address("Alice"),
            "Alice_",
            "psk",
            ".",
            "",
            "ff",
            "fc",
        ],
    )
    @mock.patch("getpass.getpass", return_value="test_password")
    @mock.patch("time.sleep", return_value=None)
    def test_standard_nick_psk_kex(self, *_) -> None:
        self.onion_service.account = nick_to_onion_address("Bob").encode()
        self.assertIsNone(add_new_contact(*self.args))
        contact = self.contact_list.get_contact_by_pub_key(nick_to_pub_key("Alice"))
        self.assertEqual(contact.nick, "Alice_")
        self.assertEqual(contact.tx_fingerprint, bytes(FINGERPRINT_LENGTH))

    @mock.patch("time.sleep", return_value=None)
    @mock.patch("builtins.input", side_effect=KeyboardInterrupt)
    def test_keyboard_interrupt_raises_fr(self, *_) -> None:
        self.assert_se("Contact creation aborted.", add_new_contact, *self.args)


class TestRemoveContact(TFCTestCase):
    def setUp(self) -> None:
        """Pre-test actions."""
        self.unit_test_dir = cd_unit_test()
        self.contact_list = ContactList(nicks=["Alice"])
        self.group_list = GroupList(groups=["test_group"])
        self.settings = Settings()
        self.queues = gen_queue_dict()
        self.master_key = MasterKey()
        self.pub_key = nick_to_pub_key("Alice")
        self.args = (
            self.contact_list,
            self.group_list,
            self.settings,
            self.queues,
            self.master_key,
        )

    def tearDown(self) -> None:
        """Post-test actions."""
        cleanup(self.unit_test_dir)
        tear_queues(self.queues)

    def test_contact_removal_during_traffic_masking_raises_fr(self) -> None:
        # Setup
        self.settings.traffic_masking = True

        # Test
        self.assert_se(
            "Error: Command is disabled during traffic masking.",
            remove_contact,
            UserInput(),
            None,
            *self.args,
        )

    def test_missing_account_raises_fr(self) -> None:
        self.assert_se(
            "Error: No account specified.",
            remove_contact,
            UserInput("rm "),
            None,
            *self.args,
        )

    @mock.patch("time.sleep", return_value=None)
    @mock.patch("shutil.get_terminal_size", return_value=[150, 150])
    @mock.patch("builtins.input", return_value="Yes")
    def test_invalid_account_raises_fr(self, *_) -> None:
        # Setup
        user_input = UserInput(f'rm {nick_to_onion_address("Alice")[:-1]}')
        window = TxWindow(
            window_contacts=[self.contact_list.get_contact_by_address_or_nick("Alice")],
            type=WIN_TYPE_CONTACT,
            uid=self.pub_key,
        )

        # Test
        self.assert_se(
            "Error: Invalid selection.", remove_contact, user_input, window, *self.args
        )

    @mock.patch("time.sleep", return_value=None)
    @mock.patch("shutil.get_terminal_size", return_value=[150, 150])
    @mock.patch("builtins.input", return_value="No")
    def test_user_abort_raises_fr(self, *_) -> None:
        # Setup
        user_input = UserInput(f'rm {nick_to_onion_address("Alice")}')

        # Test
        self.assert_se(
            "Removal of contact aborted.", remove_contact, user_input, None, *self.args
        )

    @mock.patch("builtins.input", return_value="Yes")
    def test_successful_removal_of_contact(self, _) -> None:
        # Setup
        window = TxWindow(
            window_contacts=[self.contact_list.get_contact_by_address_or_nick("Alice")],
            type=WIN_TYPE_CONTACT,
            uid=self.pub_key,
        )

        # Test
        for g in self.group_list:
            self.assertIsInstance(g, Group)
            self.assertTrue(g.has_member(self.pub_key))

        self.assertIsNone(remove_contact(UserInput("rm Alice"), window, *self.args))
        self.assertEqual(self.queues[COMMAND_PACKET_QUEUE].qsize(), 1)

        km_data = self.queues[KEY_MANAGEMENT_QUEUE].get()
        self.assertEqual(km_data, (KDB_REMOVE_ENTRY_HEADER, self.pub_key))
        self.assertFalse(self.contact_list.has_pub_key(self.pub_key))

        for g in self.group_list:
            self.assertIsInstance(g, Group)
            self.assertFalse(g.has_member(self.pub_key))

    @mock.patch("builtins.input", return_value="Yes")
    def test_successful_removal_of_last_member_of_active_group(self, _) -> None:
        # Setup
        user_input = UserInput("rm Alice")
        window = TxWindow(
            window_contacts=[self.contact_list.get_contact_by_address_or_nick("Alice")],
            type=WIN_TYPE_GROUP,
            name="test_group",
        )
        group = self.group_list.get_group("test_group")
        group.members = [self.contact_list.get_contact_by_address_or_nick("Alice")]
        pub_key = nick_to_pub_key("Alice")

        # Test
        for g in self.group_list:
            self.assertIsInstance(g, Group)
            self.assertTrue(g.has_member(pub_key))
        self.assertEqual(len(group), 1)

        self.assertIsNone(remove_contact(user_input, window, *self.args))

        for g in self.group_list:
            self.assertIsInstance(g, Group)
            self.assertFalse(g.has_member(pub_key))

        self.assertFalse(self.contact_list.has_pub_key(pub_key))
        self.assertEqual(self.queues[COMMAND_PACKET_QUEUE].qsize(), 1)

        km_data = self.queues[KEY_MANAGEMENT_QUEUE].get()
        self.assertEqual(km_data, (KDB_REMOVE_ENTRY_HEADER, pub_key))

    @mock.patch("shutil.get_terminal_size", return_value=[150, 150])
    @mock.patch("builtins.input", return_value="Yes")
    def test_no_contact_found_on_transmitter(self, *_) -> None:
        # Setup
        user_input = UserInput(f'rm {nick_to_onion_address("Charlie")}')
        contact_list = ContactList(nicks=["Bob"])
        window = TxWindow(
            window_contact=[contact_list.get_contact_by_address_or_nick("Bob")],
            type=WIN_TYPE_GROUP,
        )

        # Test
        self.assertIsNone(remove_contact(user_input, window, *self.args))
        self.assertEqual(self.queues[COMMAND_PACKET_QUEUE].qsize(), 1)
        self.assertEqual(self.queues[RELAY_PACKET_QUEUE].qsize(), 1)
        command_packet = self.queues[COMMAND_PACKET_QUEUE].get()
        self.assertIsInstance(command_packet, bytes)


class TestChangeNick(TFCTestCase):
    def setUp(self) -> None:
        """Pre-test actions."""
        self.contact_list = ContactList(nicks=["Alice"])
        self.group_list = GroupList()
        self.settings = Settings()
        self.queues = gen_queue_dict()
        self.args = self.contact_list, self.group_list, self.settings, self.queues

    def tearDown(self) -> None:
        """Post-test actions."""
        tear_queues(self.queues)

    def test_missing_nick_raises_fr(self) -> None:
        self.assert_se(
            "Error: No nick specified.",
            change_nick,
            UserInput("nick "),
            TxWindow(type=WIN_TYPE_CONTACT),
            *self.args,
        )

    def test_invalid_nick_raises_fr(self) -> None:
        # Setup
        window = TxWindow(type=WIN_TYPE_CONTACT, contact=create_contact("Bob"))

        # Test
        self.assert_se(
            "Error: Nick must be printable.",
            change_nick,
            UserInput("nick Alice\x01"),
            window,
            *self.args,
        )

    def test_no_contact_raises_fr(self) -> None:
        # Setup
        window = TxWindow(type=WIN_TYPE_CONTACT, contact=create_contact("Bob"))
        window.contact = None

        # Test
        self.assert_se(
            "Error: Window does not have contact.",
            change_nick,
            UserInput("nick Alice\x01"),
            window,
            *self.args,
        )

    def test_successful_nick_change(self) -> None:
        # Setup
        window = TxWindow(
            name="Alice",
            type=WIN_TYPE_CONTACT,
            contact=self.contact_list.get_contact_by_address_or_nick("Alice"),
        )

        # Test
        self.assertIsNone(change_nick(UserInput("nick Alice_"), window, *self.args))
        self.assertEqual(
            self.contact_list.get_contact_by_pub_key(nick_to_pub_key("Alice")).nick,
            "Alice_",
        )

    @mock.patch("time.sleep", return_value=None)
    def test_successful_group_nick_change(self, _) -> None:
        # Setup
        group = create_group("test_group")
        user_input = UserInput("nick group2")
        window = TxWindow(
            name="test_group", type=WIN_TYPE_GROUP, group=group, uid=group.group_id
        )

        # Test
        self.assert_se(
            "Renamed group 'test_group' to 'group2'.",
            change_nick,
            user_input,
            window,
            *self.args,
        )
        self.assertEqual(window.group.name, "group2")


class TestContactSetting(TFCTestCase):
    def setUp(self) -> None:
        """Pre-test actions."""
        self.contact_list = ContactList(nicks=["Alice", "Bob"])
        self.group_list = GroupList(groups=["test_group"])
        self.settings = Settings()
        self.queues = gen_queue_dict()
        self.pub_key = nick_to_pub_key("Alice")
        self.args = self.contact_list, self.group_list, self.settings, self.queues

    def tearDown(self) -> None:
        """Post-test actions."""
        tear_queues(self.queues)

    def test_invalid_command_raises_fr(self) -> None:
        self.assert_se(
            "Error: Invalid command.",
            contact_setting,
            UserInput("loging on"),
            None,
            *self.args,
        )

    def test_missing_parameter_raises_fr(self) -> None:
        self.assert_se(
            "Error: Invalid command.", contact_setting, UserInput(""), None, *self.args
        )

    def test_invalid_extra_parameter_raises_fr(self) -> None:
        self.assert_se(
            "Error: Invalid command.",
            contact_setting,
            UserInput("logging on al"),
            None,
            *self.args,
        )

    def test_enable_logging_for_user(self) -> None:
        # Setup
        contact = self.contact_list.get_contact_by_address_or_nick("Alice")
        contact.log_messages = False
        window = TxWindow(uid=self.pub_key, type=WIN_TYPE_CONTACT, contact=contact)

        # Test
        self.assertFalse(contact.log_messages)
        self.assertIsNone(contact_setting(UserInput("logging on"), window, *self.args))
        self.assertEqual(self.queues[COMMAND_PACKET_QUEUE].qsize(), 1)
        self.assertEqual(self.queues[LOG_SETTING_QUEUE].qsize(), 0)
        self.assertTrue(contact.log_messages)

    def test_enable_logging_for_user_during_traffic_masking(self) -> None:
        # Setup
        contact = self.contact_list.get_contact_by_address_or_nick("Alice")
        contact.log_messages = False
        window = TxWindow(
            uid=self.pub_key, type=WIN_TYPE_CONTACT, contact=contact, log_messages=False
        )
        self.settings.traffic_masking = True

        # Test
        self.assertFalse(contact.log_messages)
        self.assertFalse(window.log_messages)

        self.assertIsNone(contact_setting(UserInput("logging on"), window, *self.args))

        self.assertEqual(self.queues[TM_COMMAND_PACKET_QUEUE].qsize(), 1)
        self.assertTrue(self.queues[LOG_SETTING_QUEUE].get())
        self.assertTrue(window.log_messages)
        self.assertTrue(contact.log_messages)

    def test_enable_logging_for_group(self) -> None:
        # Setup
        group = self.group_list.get_group("test_group")
        group.log_messages = False
        window = TxWindow(
            uid=group_name_to_group_id("test_group"),
            type=WIN_TYPE_GROUP,
            group=group,
            window_contacts=group.members,
        )

        # Test
        self.assertFalse(group.log_messages)
        self.assertIsNone(contact_setting(UserInput("logging on"), window, *self.args))
        self.assertTrue(group.log_messages)

    def test_enable_logging_for_all_users(self) -> None:
        # Setup
        contact = self.contact_list.get_contact_by_address_or_nick("Alice")
        window = TxWindow(
            uid=self.pub_key,
            type=WIN_TYPE_CONTACT,
            contact=contact,
            window_contacts=[contact],
        )

        for c in self.contact_list:
            c.log_messages = False
        for g in self.group_list:
            g.log_messages = False

        # Test
        for c in self.contact_list:
            self.assertFalse(c.log_messages)
        for g in self.group_list:
            self.assertFalse(g.log_messages)

        self.assertIsNone(
            contact_setting(UserInput("logging on all"), window, *self.args)
        )

        for c in self.contact_list:
            self.assertTrue(c.log_messages)
        for g in self.group_list:
            self.assertTrue(g.log_messages)

    def test_disable_logging_for_user(self) -> None:
        # Setup
        contact = self.contact_list.get_contact_by_address_or_nick("Alice")
        contact.log_messages = True
        window = TxWindow(
            uid=self.pub_key,
            type=WIN_TYPE_CONTACT,
            contact=contact,
            window_contacts=[contact],
        )

        # Test
        self.assertTrue(contact.log_messages)
        self.assertIsNone(contact_setting(UserInput("logging off"), window, *self.args))
        self.assertFalse(contact.log_messages)

    def test_disable_logging_for_group(self) -> None:
        # Setup
        group = self.group_list.get_group("test_group")
        group.log_messages = True
        window = TxWindow(
            uid=group_name_to_group_id("test_group"),
            type=WIN_TYPE_GROUP,
            group=group,
            window_contacts=group.members,
        )

        # Test
        self.assertTrue(group.log_messages)
        self.assertIsNone(contact_setting(UserInput("logging off"), window, *self.args))
        self.assertFalse(group.log_messages)

    def test_disable_logging_for_all_users(self) -> None:
        # Setup
        contact = self.contact_list.get_contact_by_address_or_nick("Alice")
        window = TxWindow(
            uid=self.pub_key,
            type=WIN_TYPE_CONTACT,
            contact=contact,
            window_contacts=[contact],
        )

        for c in self.contact_list:
            c.log_messages = True
        for g in self.group_list:
            g.log_messages = True

        # Test
        for c in self.contact_list:
            self.assertTrue(c.log_messages)
        for g in self.group_list:
            self.assertTrue(g.log_messages)

        self.assertIsNone(
            contact_setting(UserInput("logging off all"), window, *self.args)
        )

        for c in self.contact_list:
            self.assertFalse(c.log_messages)
        for g in self.group_list:
            self.assertFalse(g.log_messages)

    def test_enable_file_reception_for_user(self) -> None:
        # Setup
        contact = self.contact_list.get_contact_by_address_or_nick("Alice")
        contact.file_reception = False
        window = TxWindow(
            uid=self.pub_key,
            type=WIN_TYPE_CONTACT,
            contact=contact,
            window_contacts=[contact],
        )

        # Test
        self.assertFalse(contact.file_reception)
        self.assertIsNone(contact_setting(UserInput("store on"), window, *self.args))
        self.assertTrue(contact.file_reception)

    def test_enable_file_reception_for_group(self) -> None:
        # Setup
        group = self.group_list.get_group("test_group")
        window = TxWindow(
            uid=group_name_to_group_id("test_group"),
            type=WIN_TYPE_GROUP,
            group=group,
            window_contacts=group.members,
        )

        for m in group:
            m.file_reception = False

        # Test
        for m in group:
            self.assertFalse(m.file_reception)
        self.assertIsNone(contact_setting(UserInput("store on"), window, *self.args))
        for m in group:
            self.assertTrue(m.file_reception)

    def test_enable_file_reception_for_all_users(self) -> None:
        # Setup
        contact = self.contact_list.get_contact_by_address_or_nick("Alice")
        window = TxWindow(
            uid=self.pub_key,
            type=WIN_TYPE_CONTACT,
            contact=contact,
            window_contacts=[contact],
        )

        for c in self.contact_list:
            c.file_reception = False

        # Test
        for c in self.contact_list:
            self.assertFalse(c.file_reception)

        self.assertIsNone(
            contact_setting(UserInput("store on all"), window, *self.args)
        )
        for c in self.contact_list:
            self.assertTrue(c.file_reception)

    def test_disable_file_reception_for_user(self) -> None:
        # Setup
        contact = self.contact_list.get_contact_by_address_or_nick("Alice")
        contact.file_reception = True
        window = TxWindow(
            uid=self.pub_key,
            type=WIN_TYPE_CONTACT,
            contact=contact,
            window_contacts=[contact],
        )

        # Test
        self.assertTrue(contact.file_reception)
        self.assertIsNone(contact_setting(UserInput("store off"), window, *self.args))
        self.assertFalse(contact.file_reception)

    def test_disable_file_reception_for_group(self) -> None:
        # Setup
        group = self.group_list.get_group("test_group")
        window = TxWindow(
            uid=group_name_to_group_id("test_group"),
            type=WIN_TYPE_GROUP,
            group=group,
            window_contacts=group.members,
        )

        for m in group:
            m.file_reception = True

        # Test
        for m in group:
            self.assertTrue(m.file_reception)

        self.assertIsNone(contact_setting(UserInput("store off"), window, *self.args))
        for m in group:
            self.assertFalse(m.file_reception)

    def test_disable_file_reception_for_all_users(self) -> None:
        # Setup
        contact = self.contact_list.get_contact_by_address_or_nick("Alice")
        window = TxWindow(
            uid=self.pub_key,
            type=WIN_TYPE_CONTACT,
            contact=contact,
            window_contacts=[contact],
        )

        for c in self.contact_list:
            c.file_reception = True

        # Test
        for c in self.contact_list:
            self.assertTrue(c.file_reception)
        self.assertIsNone(
            contact_setting(UserInput("store off all"), window, *self.args)
        )
        for c in self.contact_list:
            self.assertFalse(c.file_reception)

    def test_enable_notifications_for_user(self) -> None:
        # Setup
        contact = self.contact_list.get_contact_by_address_or_nick("Alice")
        contact.notifications = False
        window = TxWindow(uid=self.pub_key, type=WIN_TYPE_CONTACT, contact=contact)

        # Test
        self.assertFalse(contact.notifications)
        self.assertIsNone(contact_setting(UserInput("notify on"), window, *self.args))
        self.assertTrue(contact.notifications)

    def test_enable_notifications_for_group(self) -> None:
        # Setup
        user_input = UserInput("notify on")
        group = self.group_list.get_group("test_group")
        group.notifications = False
        window = TxWindow(
            uid=group_name_to_group_id("test_group"),
            type=WIN_TYPE_GROUP,
            group=group,
            window_contacts=group.members,
        )

        # Test
        self.assertFalse(group.notifications)
        self.assertIsNone(contact_setting(user_input, window, *self.args))
        self.assertTrue(group.notifications)

    def test_enable_notifications_for_all_users(self) -> None:
        # Setup
        contact = self.contact_list.get_contact_by_address_or_nick("Alice")
        window = TxWindow(
            uid=self.pub_key,
            type=WIN_TYPE_CONTACT,
            contact=contact,
            window_contacts=[contact],
        )

        for c in self.contact_list:
            c.notifications = False
        for g in self.group_list:
            g.notifications = False

        # Test
        for c in self.contact_list:
            self.assertFalse(c.notifications)
        for g in self.group_list:
            self.assertFalse(g.notifications)

        self.assertIsNone(
            contact_setting(UserInput("notify on all"), window, *self.args)
        )

        for c in self.contact_list:
            self.assertTrue(c.notifications)
        for g in self.group_list:
            self.assertTrue(g.notifications)

    def test_disable_notifications_for_user(self) -> None:
        # Setup
        contact = self.contact_list.get_contact_by_address_or_nick("Alice")
        contact.notifications = True
        window = TxWindow(
            uid=self.pub_key,
            type=WIN_TYPE_CONTACT,
            contact=contact,
            window_contacts=[contact],
        )

        # Test
        self.assertTrue(contact.notifications)
        self.assertIsNone(contact_setting(UserInput("notify off"), window, *self.args))
        self.assertFalse(contact.notifications)

    def test_disable_notifications_for_group(self) -> None:
        # Setup
        group = self.group_list.get_group("test_group")
        group.notifications = True
        window = TxWindow(
            uid=group_name_to_group_id("test_group"),
            type=WIN_TYPE_GROUP,
            group=group,
            window_contacts=group.members,
        )

        # Test
        self.assertTrue(group.notifications)
        self.assertIsNone(contact_setting(UserInput("notify off"), window, *self.args))
        self.assertFalse(group.notifications)

    def test_disable_notifications_for_all_users(self) -> None:
        # Setup
        contact = self.contact_list.get_contact_by_address_or_nick("Alice")
        window = TxWindow(
            uid=self.pub_key,
            type=WIN_TYPE_CONTACT,
            contact=contact,
            window_contacts=[contact],
        )

        for c in self.contact_list:
            c.notifications = True
        for g in self.group_list:
            g.notifications = True

        # Test
        for c in self.contact_list:
            self.assertTrue(c.notifications)
        for g in self.group_list:
            self.assertTrue(g.notifications)

        self.assertIsNone(
            contact_setting(UserInput("notify off all"), window, *self.args)
        )

        for c in self.contact_list:
            self.assertFalse(c.notifications)
        for g in self.group_list:
            self.assertFalse(g.notifications)


if __name__ == "__main__":
    unittest.main(exit=False)
