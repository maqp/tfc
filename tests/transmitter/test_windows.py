#!/usr/bin/env python3.7
# -*- coding: utf-8 -*-

"""
TFC - Onion-routed, endpoint secure messaging system
Copyright (C) 2013-2020  Markus Ottela

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

import unittest

from unittest import mock
from typing   import Any

from src.common.crypto      import blake2b
from src.common.db_contacts import Contact
from src.common.statics     import (COMMAND_PACKET_QUEUE, CONFIRM_CODE_LENGTH, KEX_STATUS_PENDING, KEX_STATUS_VERIFIED,
                                    LOCAL_ID, WINDOW_SELECT_QUEUE, WIN_TYPE_CONTACT, WIN_TYPE_GROUP)

from src.transmitter.windows import select_window, TxWindow


from tests.mock_classes import ContactList, create_contact, Gateway, GroupList, OnionService, Settings, UserInput
from tests.utils        import (gen_queue_dict, group_name_to_group_id, nick_to_onion_address, nick_to_pub_key,
                                tear_queues, TFCTestCase, VALID_ECDHE_PUB_KEY)


class TestTxWindow(TFCTestCase):

    def setUp(self) -> None:
        """Pre-test actions."""
        self.contact_list  = ContactList(['Alice', 'Bob', LOCAL_ID])
        self.group_list    = GroupList(groups=['test_group', 'test_group_2'])
        self.window        = TxWindow(self.contact_list, self.group_list)
        self.window.group  = self.group_list.get_group('test_group')
        self.window.type   = WIN_TYPE_GROUP
        self.settings      = Settings()
        self.queues        = gen_queue_dict()
        self.onion_service = OnionService()
        self.gateway       = Gateway()
        self.args          = self.settings, self.queues, self.onion_service, self.gateway

    def tearDown(self) -> None:
        """Post-test actions."""
        tear_queues(self.queues)

    def test_window_iterates_over_contacts(self) -> None:
        # Setup
        self.window.window_contacts = self.contact_list.contacts

        # Test
        for c in self.window:
            self.assertIsInstance(c, Contact)

    def test_len_returns_number_of_contacts_in_window(self) -> None:
        # Setup
        self.window.window_contacts = [self.contact_list.get_contact_by_pub_key(nick_to_pub_key('Alice')),
                                       self.contact_list.get_contact_by_pub_key(nick_to_pub_key('Bob'))]

        # Test
        self.assertEqual(len(self.window), 2)

    def test_group_window_change_during_traffic_masking_raises_soft_error(self) -> None:
        # Setup
        self.settings.traffic_masking = True
        self.window.uid               = 'test_group'

        # Test
        self.assert_se("Error: Can't change window during traffic masking.",
                       self.window.select_tx_window, *self.args, selection='test_group_2', cmd=True)

    def test_contact_window_change_during_traffic_masking_raises_soft_error(self) -> None:
        # Setup
        self.settings.traffic_masking = True
        self.window.uid               = nick_to_pub_key("Alice")

        # Test
        self.assert_se("Error: Can't change window during traffic masking.",
                       self.window.select_tx_window, *self.args, selection=nick_to_onion_address("Bob"), cmd=True)

    def test_contact_window_reload_during_traffic_masking(self) -> None:
        # Setup
        self.settings.traffic_masking = True
        self.window.uid               = nick_to_pub_key("Alice")

        # Test
        self.assertIsNone(self.window.select_tx_window(*self.args, selection=nick_to_onion_address("Alice"), cmd=True))
        self.assertEqual(self.window.uid, nick_to_pub_key("Alice"))

    def test_group_window_reload_during_traffic_masking(self) -> None:
        # Setup
        self.settings.traffic_masking = True
        self.window.name              = 'test_group'
        self.window.uid               = group_name_to_group_id('test_group')

        # Test
        self.assertIsNone(self.window.select_tx_window(*self.args, selection='test_group', cmd=True))
        self.assertEqual(self.window.uid, group_name_to_group_id('test_group'))

    def test_invalid_selection_raises_soft_error(self) -> None:
        # Setup
        self.window.uid = nick_to_pub_key("Alice")

        # Test
        self.assert_se("Error: No contact/group was found.",
                       self.window.select_tx_window, *self.args, selection=nick_to_onion_address("Charlie"), cmd=True)

    @mock.patch('builtins.input', return_value=nick_to_onion_address("Bob"))
    def test_window_selection_during_traffic_masking(self, *_: Any) -> None:
        # Setup
        self.settings.traffic_masking = True
        self.window.uid               = None

        # Test
        self.assertIsNone(self.window.select_tx_window(*self.args))
        self.assertEqual(self.queues[WINDOW_SELECT_QUEUE].qsize(), 1)

    @mock.patch('builtins.input', return_value=nick_to_onion_address("Bob"))
    def test_contact_window_selection_from_input(self, *_: Any) -> None:
        # Setup
        self.window.uid = None

        # Test
        self.assertIsNone(self.window.select_tx_window(*self.args))
        self.assertEqual(self.window.uid, nick_to_pub_key("Bob"))

    def test_group_window_selection_from_command(self) -> None:
        # Setup
        self.window.uid = None

        self.assertIsNone(self.window.select_tx_window(*self.args, selection='test_group', cmd=True))
        self.assertEqual(self.window.uid, group_name_to_group_id('test_group'))

    def test_deselect_window(self) -> None:
        # Setup
        self.window.window_contacts = self.contact_list.contacts
        self.window.contact         = self.contact_list.get_contact_by_address_or_nick("Bob")
        self.window.name            = 'Bob'
        self.window.type            = WIN_TYPE_CONTACT
        self.window.uid             = nick_to_pub_key("Bob")

        # Test
        self.assertIsNone(self.window.deselect())
        self.assertIsNone(self.window.contact)
        self.assertEqual(self.window.name,  '')
        self.assertEqual(self.window.type,  '')
        self.assertEqual(self.window.uid,  b'')

    def test_is_selected(self) -> None:
        self.window.name = ''
        self.assertFalse(self.window.is_selected())

        self.window.name = nick_to_pub_key("Bob")
        self.assertTrue(self.window.is_selected())

    def test_update_log_messages_for_contact(self) -> None:
        # Setup
        self.window.type                 = WIN_TYPE_CONTACT
        self.window.log_messages         = None
        self.window.contact              = self.contact_list.get_contact_by_address_or_nick('Alice')
        self.window.contact.log_messages = False

        # Test
        self.assertIsNone(self.window.update_log_messages())
        self.assertFalse(self.window.log_messages)

    def test_update_log_messages_for_group(self) -> None:
        # Setup
        self.window.type               = WIN_TYPE_GROUP
        self.window.log_messages       = None
        self.window.group              = self.group_list.get_group('test_group')
        self.window.group.log_messages = False

        # Test
        self.assertIsNone(self.window.update_log_messages())
        self.assertFalse(self.window.log_messages)

    def test_update_group_win_members_if_group_is_available(self) -> None:
        # Setup
        self.window.window_contacts = []
        self.window.group           = None
        self.window.group_id        = group_name_to_group_id('test_group')
        self.window.name            = 'test_group'
        self.window.type            = WIN_TYPE_GROUP

        # Test
        self.assertIsNone(self.window.update_window(self.group_list))
        self.assertEqual(self.window.group, self.group_list.get_group('test_group'))
        self.assertEqual(self.window.window_contacts, self.window.group.members)

    def test_window_contact_is_reloaded_when_contact_is_active(self) -> None:
        # Setup
        self.window.type            = WIN_TYPE_CONTACT
        self.window.contact         = create_contact('Alice')
        self.window.window_contacts = [self.window.contact]
        self.assertIsNot(self.window.contact,
                         self.window.contact_list.get_contact_by_pub_key(nick_to_pub_key('Alice')))
        self.assertIsNot(self.window.window_contacts[0],
                         self.window.contact_list.get_contact_by_pub_key(nick_to_pub_key('Alice')))

        # Test
        self.assertIsNone(self.window.update_window(self.group_list))
        self.assertIs(self.window.contact,
                      self.window.contact_list.get_contact_by_pub_key(nick_to_pub_key('Alice')))
        self.assertIs(self.window.window_contacts[0],
                      self.window.contact_list.get_contact_by_pub_key(nick_to_pub_key('Alice')))

    def test_deactivate_window_if_group_is_not_available(self) -> None:
        # Setup
        self.window.window_contacts = []
        self.window.group           = None
        self.window.name            = 'test_group_3'
        self.window.type            = WIN_TYPE_GROUP

        # Test
        self.assertIsNone(self.window.update_window(self.group_list))
        self.assertIsNone(self.window.contact)
        self.assertEqual(self.window.name,  '')
        self.assertEqual(self.window.type,  '')
        self.assertEqual(self.window.uid,  b'')

    @mock.patch('time.sleep',     return_value=None)
    @mock.patch('builtins.input', side_effect=['Alice',
                                               VALID_ECDHE_PUB_KEY,
                                               'yes',
                                               blake2b(nick_to_pub_key('Alice'),
                                                       digest_size=CONFIRM_CODE_LENGTH).hex()])
    @mock.patch('shutil.get_terminal_size', return_value=[200, 200])
    def test_selecting_pending_contact_starts_key_exchange(self, *_: Any) -> None:
        # Setup
        alice            = self.contact_list.get_contact_by_address_or_nick('Alice')
        bob              = self.contact_list.get_contact_by_address_or_nick('Bob')
        alice.kex_status = KEX_STATUS_PENDING
        bob.kex_status   = KEX_STATUS_PENDING

        # Test
        self.assertIsNone(self.window.select_tx_window(*self.args))
        self.assertEqual(self.queues[COMMAND_PACKET_QUEUE].qsize(), 2)
        self.assertEqual(self.queues[WINDOW_SELECT_QUEUE].qsize(),  0)
        self.assertEqual(alice.kex_status, KEX_STATUS_VERIFIED)

    @mock.patch('time.sleep',     return_value=None)
    @mock.patch('builtins.input', side_effect=['/add',
                                               nick_to_onion_address('Alice'),
                                               'Alice',
                                               '',
                                               VALID_ECDHE_PUB_KEY,
                                               'yes',
                                               blake2b(nick_to_pub_key('Alice'),
                                                       digest_size=CONFIRM_CODE_LENGTH).hex()])
    @mock.patch('shutil.get_terminal_size', return_value=[200, 200])
    def test_adding_new_contact_from_contact_selection(self, *_: Any) -> None:
        # Setup
        alice            = self.contact_list.get_contact_by_address_or_nick('Alice')
        alice.kex_status = KEX_STATUS_PENDING

        # Test
        self.assert_se('New contact added.',
                       self.window.select_tx_window, *self.args)
        self.assertEqual(self.queues[COMMAND_PACKET_QUEUE].qsize(), 1)
        self.assertEqual(self.queues[WINDOW_SELECT_QUEUE].qsize(),  0)
        self.assertEqual(alice.kex_status, KEX_STATUS_VERIFIED)

    @mock.patch('time.sleep',     return_value=None)
    @mock.patch('builtins.input', side_effect=['/rm '])
    def test_missing_account_when_removing_raises_soft_error(self, *_: Any) -> None:
        self.assert_se("Error: No account specified.", self.window.select_tx_window, *self.args)

    @mock.patch('time.sleep',     return_value=None)
    @mock.patch('builtins.input', side_effect=['/rm Charlie', 'yes'])
    def test_unknown_account_when_removing_raises_soft_error(self, *_: Any) -> None:
        self.assert_se("Error: Unknown contact 'Charlie'.", self.window.select_tx_window, *self.args)

    @mock.patch('time.sleep',     return_value=None)
    @mock.patch('builtins.input', side_effect=['/rm Alice', 'no'])
    def test_abort_removal_of_contact_form_contact_selection(self, *_: Any) -> None:
        self.assert_se("Removal of contact aborted.", self.window.select_tx_window, *self.args)

    @mock.patch('time.sleep',     return_value=None)
    @mock.patch('builtins.input', side_effect=['/rm Alice', 'yes'])
    def test_removing_pending_contact_from_contact_selection(self, *_: Any) -> None:
        self.assert_se("Removed contact 'Alice'.", self.window.select_tx_window, *self.args)

    @mock.patch('time.sleep',     return_value=None)
    @mock.patch('builtins.input', side_effect=['/connect', b'a'.hex()])
    def test_sending_onion_service_data_from_contact_selection(self, *_: Any) -> None:
        self.assertIsNone(self.window.select_tx_window(*self.args))
        self.assertEqual(len(self.gateway.packets), 1)

    @mock.patch('time.sleep',     return_value=None)
    @mock.patch('builtins.input', side_effect=['/help'])
    def test_invalid_command_raises_soft_error(self, *_: Any) -> None:
        self.assert_se("Error: Invalid command.", self.window.select_tx_window, *self.args)


class TestSelectWindow(TFCTestCase):

    def setUp(self) -> None:
        """Pre-test actions."""
        self.contact_list  = ContactList(nicks=['Alice'])
        self.group_list    = GroupList()
        self.user_input    = UserInput()
        self.window        = TxWindow(self.contact_list, self.group_list)
        self.settings      = Settings()
        self.queues        = gen_queue_dict()
        self.onion_service = OnionService()
        self.gateway       = Gateway()
        self.args          = self.user_input, self.window, self.settings, self.queues, self.onion_service, self.gateway

    def tearDown(self) -> None:
        """Post-test actions."""
        tear_queues(self.queues)

    def test_invalid_selection_raises_soft_error(self) -> None:
        # Setup
        self.user_input.plaintext = 'msg'
        self.assert_se("Error: Invalid recipient.", select_window, *self.args)

        # Test
        self.assertEqual(self.queues[COMMAND_PACKET_QUEUE].qsize(), 0)
        self.assertEqual(self.queues[WINDOW_SELECT_QUEUE].qsize(),  0)

    def test_window_selection(self) -> None:
        # Setup
        self.user_input.plaintext = f"msg {nick_to_onion_address('Alice')}"

        # Test
        self.assertIsNone(select_window(*self.args))
        self.assertEqual(self.queues[COMMAND_PACKET_QUEUE].qsize(), 1)
        self.assertEqual(self.queues[WINDOW_SELECT_QUEUE].qsize(),  0)


if __name__ == '__main__':
    unittest.main(exit=False)
