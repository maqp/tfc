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

import builtins
import getpass
import os
import unittest
import time

from multiprocessing import Queue

from src.common.statics import *

from src.tx.contact import add_new_contact, change_nick, contact_setting, show_fingerprints, remove_contact

from tests.mock_classes import create_contact, ContactList, Group, GroupList, MasterKey, Settings, TxWindow, UserInput
from tests.utils        import ignored, TFCTestCase


class TestAddNewContact(TFCTestCase):

    def setUp(self):
        self.o_getpass    = getpass.getpass
        self.contact_list = ContactList()
        self.group_list   = GroupList()
        self.settings     = Settings(disable_gui_dialog=True)
        self.queues       = {COMMAND_PACKET_QUEUE: Queue(),
                             NH_PACKET_QUEUE:      Queue(),
                             KEY_MANAGEMENT_QUEUE: Queue()}

    def tearDown(self):
        getpass.getpass = self.o_getpass
        
        with ignored(OSError):
            os.remove('bob@jabber.org.psk - Give to alice@jabber.org')

        for key in self.queues:
            while not self.queues[key].empty():
                self.queues[key].get()
            time.sleep(0.1)
            self.queues[key].close()

    def test_adding_new_contact_during_traffic_masking_raises_fr(self):
        # Setup
        self.settings.session_traffic_masking = True

        # Test
        self.assertFR("Error: Command is disabled during traffic masking.",
                      add_new_contact, self.contact_list, self.group_list, self.settings, self.queues)

    def test_contact_list_full_raises_fr(self):
        # Setup
        self.contact_list = ContactList(nicks=['contact_{}'.format(n) for n in range(20)])

        # Test
        self.assertFR("Error: TFC settings only allow 20 accounts.",
                      add_new_contact, self.contact_list, self.group_list, self.settings, self.queues)

    def test_default_nick_x25519_kex(self):
        # Setup
        input_list     = ['alice@jabber.org', 'bob@jabber.org', '', '',
                          '5JJwZE46Eic9B8sKJ8Qocyxa8ytUJSfcqRo7Hr5ES7YgFGeJjCJ', 'Yes']
        gen            = iter(input_list)
        builtins.input = lambda _: str(next(gen))

        # Test
        self.assertIsNone(add_new_contact(self.contact_list, self.group_list, self.settings, self.queues))

        contact = self.contact_list.get_contact('alice@jabber.org')
        self.assertEqual(contact.nick, 'Alice')
        self.assertNotEqual(contact.tx_fingerprint, bytes(FINGERPRINT_LEN))  # Indicates that PSK function was not called

    def test_standard_nick_psk_kex(self):
        # Setup
        getpass.getpass = lambda _: 'test_password'
        input_list      = ['alice@jabber.org', 'bob@jabber.org', 'Alice_', 'psk', '.']
        gen             = iter(input_list)
        builtins.input  = lambda _: str(next(gen))

        # Test
        self.assertIsNone(add_new_contact(self.contact_list, self.group_list, self.settings, self.queues))
        contact = self.contact_list.get_contact('alice@jabber.org')
        self.assertEqual(contact.nick, 'Alice_')
        self.assertEqual(contact.tx_fingerprint, bytes(FINGERPRINT_LEN))  # Indicates that PSK function was called


class TestRemoveContact(TFCTestCase):

    def setUp(self):
        self.o_input      = builtins.input
        self.settings     = Settings()
        self.master_key   = MasterKey()
        self.queues       = {KEY_MANAGEMENT_QUEUE: Queue(),
                             COMMAND_PACKET_QUEUE: Queue()}
        self.contact_list = ContactList(nicks=['Alice'])
        self.group_list   = GroupList(groups=['testgroup'])

    def tearDown(self):
        builtins.input = self.o_input

        for key in self.queues:
            while not self.queues[key].empty():
                self.queues[key].get()
            time.sleep(0.1)
            self.queues[key].close()

    def test_contact_removal_during_traffic_masking_raises_fr(self):
        # Setup
        self.settings.session_traffic_masking = True

        # Test
        self.assertFR("Error: Command is disabled during traffic masking.",
                      remove_contact, None, None, None, None, self.settings, None, self.master_key)

    def test_missing_account_raises_fr(self):
        # Setup
        user_input = UserInput('rm ')

        # Test
        self.assertFR("Error: No account specified.",
                      remove_contact, user_input, None, None, None, self.settings, None, self.master_key)

    def test_user_abort_raises_fr(self):
        # Setup
        builtins.input = lambda _: 'No'
        user_input     = UserInput('rm alice@jabber.org')

        # Test
        self.assertFR("Removal of contact aborted.",
                      remove_contact, user_input, None, None, None, self.settings, None, self.master_key)

    def test_successful_removal_of_contact(self):
        # Setup
        builtins.input = lambda _: 'Yes'
        user_input     = UserInput('rm Alice')
        window         = TxWindow(window_contacts=[self.contact_list.get_contact('Alice')],
                                  type=WIN_TYPE_CONTACT,
                                  uid='alice@jabber.org')

        # Test
        for g in self.group_list:
            self.assertIsInstance(g, Group)
            self.assertTrue(g.has_member('alice@jabber.org'))

        self.assertIsNone(remove_contact(user_input, window, self.contact_list, self.group_list, self.settings, self.queues, self.master_key))
        time.sleep(0.1)
        self.assertEqual(self.queues[COMMAND_PACKET_QUEUE].qsize(), 2)

        km_data = self.queues[KEY_MANAGEMENT_QUEUE].get()
        self.assertEqual(km_data, (KDB_REMOVE_ENTRY_HEADER, 'alice@jabber.org'))
        self.assertFalse(self.contact_list.has_contact('alice@jabber.org'))

        for g in self.group_list:
            self.assertIsInstance(g, Group)
            self.assertFalse(g.has_member('alice@jabber.org'))

    def test_successful_removal_of_last_member_of_active_group(self):
        # Setup
        builtins.input = lambda _: 'Yes'
        user_input     = UserInput('rm Alice')
        window         = TxWindow(window_contacts=[self.contact_list.get_contact('Alice')],
                                  type=WIN_TYPE_GROUP,
                                  name='testgroup')
        group          = self.group_list.get_group('testgroup')
        group.members  = [self.contact_list.get_contact('alice@jabber.org')]

        # Test
        for g in self.group_list:
            self.assertIsInstance(g, Group)
            self.assertTrue(g.has_member('alice@jabber.org'))
        self.assertEqual(len(group), 1)

        self.assertIsNone(remove_contact(user_input, window, self.contact_list, self.group_list, self.settings, self.queues, self.master_key))
        time.sleep(0.1)

        for g in self.group_list:
            self.assertIsInstance(g, Group)
            self.assertFalse(g.has_member('alice@jabber.org'))

        self.assertFalse(self.contact_list.has_contact('alice@jabber.org'))
        self.assertEqual(self.queues[COMMAND_PACKET_QUEUE].qsize(), 2)

        km_data = self.queues[KEY_MANAGEMENT_QUEUE].get()
        self.assertEqual(km_data, (KDB_REMOVE_ENTRY_HEADER, 'alice@jabber.org'))

    def test_no_contact_found_on_txm(self):
        # Setup
        builtins.input = lambda _: 'Yes'
        user_input     = UserInput('rm charlie@jabber.org')
        contact_list   = ContactList(nicks=['Bob'])
        window         = TxWindow(window_contact=[contact_list.get_contact('Bob')],
                                  type=WIN_TYPE_GROUP)

        # Test
        self.assertIsNone(remove_contact(user_input, window, self.contact_list, self.group_list, self.settings, self.queues, self.master_key))
        time.sleep(0.1)

        self.assertEqual(self.queues[COMMAND_PACKET_QUEUE].qsize(), 2)
        command_packet, settings_ = self.queues[COMMAND_PACKET_QUEUE].get()
        self.assertIsInstance(command_packet, bytes)
        self.assertIsInstance(settings_, Settings)


class TestChangeNick(TFCTestCase):

    def setUp(self):
        self.c_queue      = Queue()
        self.group_list   = GroupList()
        self.settings     = Settings()
        self.contact_list = ContactList(nicks=['Alice'])

    def tearDown(self):
        while not self.c_queue.empty():
            self.c_queue.get()
        time.sleep(0.1)
        self.c_queue.close()

    def test_active_group_raises_fr(self):
        # Setup
        window = TxWindow(type=WIN_TYPE_GROUP)

        # Test
        self.assertFR("Error: Group is selected.", change_nick, None, window, None, None, None, None)

    def test_missing_nick_raises_fr(self):
        # Setup
        user_input = UserInput("nick ")
        window     = TxWindow(type=WIN_TYPE_CONTACT)

        # Test
        self.assertFR("Error: No nick specified.", change_nick, user_input, window, None, None, None, None)

    def test_invalid_nick_raises_fr(self):
        # Setup
        user_input = UserInput("nick Alice\x01")
        window     = TxWindow(type=WIN_TYPE_CONTACT,
                              contact=create_contact('Bob'))

        # Test
        self.assertFR("Nick must be printable.",
                      change_nick, user_input, window, self.contact_list, self.group_list, None, None)

    def test_successful_nick_change(self):
        # Setup
        user_input = UserInput("nick Alice_")
        window     = TxWindow(name='Alice',
                              type=WIN_TYPE_CONTACT,
                              contact=self.contact_list.get_contact('Alice'))

        # Test
        self.assertIsNone(change_nick(user_input, window, self.contact_list, self.group_list, self.settings, self.c_queue))
        self.assertEqual(self.contact_list.get_contact('alice@jabber.org').nick, 'Alice_')


class TestContactSetting(TFCTestCase):

    def setUp(self):
        self.c_queue      = Queue()
        self.contact_list = ContactList(nicks=['Alice', 'Bob'])
        self.settings     = Settings()
        self.group_list   = GroupList(groups=['testgroup'])

    def tearDown(self):
        while not self.c_queue.empty():
            self.c_queue.get()
        time.sleep(0.1)
        self.c_queue.close()

    def test_invalid_command_raises_fr(self):
        # Setup
        user_input = UserInput('loging on')

        # Test
        self.assertFR("Error: Invalid command.", contact_setting, user_input, None, None, None, None, None)

    def test_missing_parameter_raises_fr(self):
        # Setup
        user_input = UserInput('')

        # Test
        self.assertFR("Error: Invalid command.", contact_setting, user_input, None, None, None, None, None)

    def test_invalid_extra_parameter_raises_fr(self):
        # Setup
        user_input = UserInput('logging on al')

        # Test
        self.assertFR("Error: Invalid command.", contact_setting, user_input, None, None, None, None, None)

    def test_enable_logging_for_user(self):
        # Setup
        user_input           = UserInput('logging on')
        contact              = self.contact_list.get_contact('Alice')
        contact.log_messages = False
        window               = TxWindow(uid='alice@jabber.org',
                                        type=WIN_TYPE_CONTACT,
                                        contact=contact)

        # Test
        self.assertFalse(contact.log_messages)

        self.assertIsNone(contact_setting(user_input, window, self.contact_list, self.group_list, self.settings, self.c_queue))
        time.sleep(0.1)

        self.assertTrue(contact.log_messages)

    def test_enable_logging_for_user_during_traffic_masking(self):
        # Setup
        user_input           = UserInput('logging on')
        contact              = self.contact_list.get_contact('Alice')
        contact.log_messages = False
        window               = TxWindow(uid='alice@jabber.org',
                                        type=WIN_TYPE_CONTACT,
                                        contact=contact,
                                        log_messages=False)
        self.settings.session_traffic_masking = True

        # Test
        self.assertFalse(contact.log_messages)
        self.assertFalse(window.log_messages)

        self.assertIsNone(contact_setting(user_input, window, self.contact_list, self.group_list, self.settings, self.c_queue))
        time.sleep(0.1)

        self.assertEqual(self.c_queue.qsize(), 1)
        self.assertTrue(window.log_messages)
        self.assertTrue(contact.log_messages)

    def test_enable_logging_for_group(self):
        # Setup
        user_input         = UserInput('logging on')
        group              = self.group_list.get_group('testgroup')
        group.log_messages = False
        window             = TxWindow(uid='testgroup',
                                      type=WIN_TYPE_GROUP,
                                      group=group,
                                      window_contacts=group.members)

        # Test
        self.assertFalse(group.log_messages)

        self.assertIsNone(contact_setting(user_input, window, self.contact_list, self.group_list, self.settings, self.c_queue))
        time.sleep(0.1)

        self.assertTrue(group.log_messages)

    def test_enable_logging_for_all_users(self):
        # Setup
        user_input = UserInput('logging on all')
        contact    = self.contact_list.get_contact('alice@jabber.org')
        window     = TxWindow(uid='alice@jabber.org',
                              type=WIN_TYPE_CONTACT,
                              contact=contact,
                              window_contacts=[contact])

        for c in self.contact_list:
            c.log_messages = False
        for g in self.group_list:
            g.log_messages = False

        # Test
        for c in self.contact_list:
            self.assertFalse(c.log_messages)
        for g in self.group_list:
            self.assertFalse(g.log_messages)

        self.assertIsNone(contact_setting(user_input, window, self.contact_list, self.group_list, self.settings, self.c_queue))
        time.sleep(0.1)

        for c in self.contact_list:
            self.assertTrue(c.log_messages)
        for g in self.group_list:
            self.assertTrue(g.log_messages)

    def test_disable_logging_for_user(self):
        # Setup
        user_input           = UserInput('logging off')
        contact              = self.contact_list.get_contact('Alice')
        contact.log_messages = True
        window               = TxWindow(uid='alice@jabber.org',
                                        type=WIN_TYPE_CONTACT,
                                        contact=contact,
                                        window_contacts=[contact])

        # Test
        self.assertTrue(contact.log_messages)

        self.assertIsNone(contact_setting(user_input, window, self.contact_list, self.group_list, self.settings, self.c_queue))
        time.sleep(0.1)

        self.assertFalse(contact.log_messages)

    def test_disable_logging_for_group(self):
        # Setup
        user_input         = UserInput('logging off')
        group              = self.group_list.get_group('testgroup')
        group.log_messages = True
        window             = TxWindow(uid='testgroup',
                                      type=WIN_TYPE_GROUP,
                                      group=group,
                                      window_contacts=group.members)

        # Test
        self.assertTrue(group.log_messages)

        self.assertIsNone(contact_setting(user_input, window, self.contact_list, self.group_list, self.settings, self.c_queue))
        time.sleep(0.1)

        self.assertFalse(group.log_messages)

    def test_disable_logging_for_all_users(self):
        # Setup
        user_input = UserInput('logging off all')
        contact    = self.contact_list.get_contact('alice@jabber.org')
        window     = TxWindow(uid='alice@jabber.org',
                              type=WIN_TYPE_CONTACT,
                              contact=contact,
                              window_contacts=[contact])

        for c in self.contact_list:
            c.log_messages = True
        for g in self.group_list:
            g.log_messages = True

        # Test
        for c in self.contact_list:
            self.assertTrue(c.log_messages)
        for g in self.group_list:
            self.assertTrue(g.log_messages)

        self.assertIsNone(contact_setting(user_input, window, self.contact_list, self.group_list, self.settings, self.c_queue))
        time.sleep(0.1)

        for c in self.contact_list:
            self.assertFalse(c.log_messages)
        for g in self.group_list:
            self.assertFalse(g.log_messages)

    def test_enable_file_reception_for_user(self):
        # Setup
        user_input             = UserInput('store on')
        contact                = self.contact_list.get_contact('Alice')
        contact.file_reception = False
        window                 = TxWindow(uid='alice@jabber.org',
                                          type=WIN_TYPE_CONTACT,
                                          contact=contact,
                                          window_contacts=[contact])

        # Test
        self.assertFalse(contact.file_reception)

        self.assertIsNone(contact_setting(user_input, window, self.contact_list, self.group_list, self.settings, self.c_queue))
        time.sleep(0.1)

        self.assertTrue(contact.file_reception)

    def test_enable_file_reception_for_group(self):
        # Setup
        user_input = UserInput('store on')
        group      = self.group_list.get_group('testgroup')
        window     = TxWindow(uid='testgroup',
                              type=WIN_TYPE_GROUP,
                              group=group,
                              window_contacts=group.members)

        for m in group:
            m.file_reception = False

        # Test
        for m in group:
            self.assertFalse(m.file_reception)

        self.assertIsNone(contact_setting(user_input, window, self.contact_list, self.group_list, self.settings, self.c_queue))
        time.sleep(0.1)

        for m in group:
            self.assertTrue(m.file_reception)

    def test_enable_file_reception_for_all_users(self):
        # Setup
        user_input = UserInput('store on all')
        contact    = self.contact_list.get_contact('alice@jabber.org')
        window     = TxWindow(uid='alice@jabber.org',
                              type=WIN_TYPE_CONTACT,
                              contact=contact,
                              window_contacts=[contact])

        for c in self.contact_list:
            c.file_reception = False

        # Test
        for c in self.contact_list:
            self.assertFalse(c.file_reception)

        self.assertIsNone(contact_setting(user_input, window, self.contact_list, self.group_list, self.settings, self.c_queue))
        time.sleep(0.1)

        for c in self.contact_list:
            self.assertTrue(c.file_reception)

    def test_disable_file_reception_for_user(self):
        # Setup
        user_input             = UserInput('store off')
        contact                = self.contact_list.get_contact('Alice')
        contact.file_reception = True
        window                 = TxWindow(uid='alice@jabber.org',
                                          type=WIN_TYPE_CONTACT,
                                          contact=contact,
                                          window_contacts=[contact])

        # Test
        self.assertTrue(contact.file_reception)

        self.assertIsNone(contact_setting(user_input, window, self.contact_list, self.group_list, self.settings, self.c_queue))
        time.sleep(0.1)

        self.assertFalse(contact.file_reception)

    def test_disable_file_reception_for_group(self):
        # Setup
        user_input   = UserInput('store off')
        group        = self.group_list.get_group('testgroup')
        window       = TxWindow(uid='testgroup',
                                type=WIN_TYPE_GROUP,
                                group=group,
                                window_contacts=group.members)

        for m in group:
            m.file_reception = True

        # Test
        for m in group:
            self.assertTrue(m.file_reception)

        self.assertIsNone(contact_setting(user_input, window, self.contact_list, self.group_list, self.settings, self.c_queue))
        time.sleep(0.1)

        for m in group:
            self.assertFalse(m.file_reception)

    def test_disable_file_reception_for_all_users(self):
        # Setup
        user_input = UserInput('store off all')
        contact    = self.contact_list.get_contact('alice@jabber.org')
        window     = TxWindow(uid='alice@jabber.org',
                              type=WIN_TYPE_CONTACT,
                              contact=contact,
                              window_contacts=[contact])

        for c in self.contact_list:
            c.file_reception = True

        # Test
        for c in self.contact_list:
            self.assertTrue(c.file_reception)

        self.assertIsNone(contact_setting(user_input, window, self.contact_list, self.group_list, self.settings, self.c_queue))
        time.sleep(0.1)

        for c in self.contact_list:
            self.assertFalse(c.file_reception)

    def test_enable_notifications_for_user(self):
        # Setup
        user_input            = UserInput('notify on')
        contact               = self.contact_list.get_contact('Alice')
        contact.notifications = False
        window                = TxWindow(uid='alice@jabber.org',
                                         type=WIN_TYPE_CONTACT,
                                         contact=contact)

        # Test
        self.assertFalse(contact.notifications)

        self.assertIsNone(contact_setting(user_input, window, self.contact_list, self.group_list, self.settings, self.c_queue))
        time.sleep(0.1)

        self.assertTrue(contact.notifications)

    def test_enable_notifications_for_group(self):
        # Setup
        user_input          = UserInput('notify on')
        group               = self.group_list.get_group('testgroup')
        group.notifications = False
        window              = TxWindow(uid='testgroup',
                                       type=WIN_TYPE_GROUP,
                                       group=group,
                                       window_contacts=group.members)

        # Test
        self.assertFalse(group.notifications)

        self.assertIsNone(contact_setting(user_input, window, self.contact_list, self.group_list, self.settings, self.c_queue))
        time.sleep(0.1)

        self.assertTrue(group.notifications)

    def test_enable_notifications_for_all_users(self):
        # Setup
        user_input = UserInput('notify on all')
        contact    = self.contact_list.get_contact('alice@jabber.org')
        window     = TxWindow(uid='alice@jabber.org',
                              type=WIN_TYPE_CONTACT,
                              contact=contact,
                              window_contacts=[contact])

        for c in self.contact_list:
            c.notifications = False
        for g in self.group_list:
            g.notifications = False

        # Test
        for c in self.contact_list:
            self.assertFalse(c.notifications)
        for g in self.group_list:
            self.assertFalse(g.notifications)

        self.assertIsNone(contact_setting(user_input, window, self.contact_list, self.group_list, self.settings, self.c_queue))
        time.sleep(0.1)

        for c in self.contact_list:
            self.assertTrue(c.notifications)
        for g in self.group_list:
            self.assertTrue(g.notifications)

    def test_disable_notifications_for_user(self):
        # Setup
        user_input            = UserInput('notify off')
        contact               = self.contact_list.get_contact('Alice')
        contact.notifications = True
        window                = TxWindow(uid='alice@jabber.org',
                                         type=WIN_TYPE_CONTACT,
                                         contact=contact,
                                         window_contacts=[contact])

        # Test
        self.assertTrue(contact.notifications)

        self.assertIsNone(contact_setting(user_input, window, self.contact_list, self.group_list, self.settings, self.c_queue))
        time.sleep(0.1)

        self.assertFalse(contact.notifications)

    def test_disable_notifications_for_group(self):
        # Setup
        user_input          = UserInput('notify off')
        group               = self.group_list.get_group('testgroup')
        group.notifications = True
        window              = TxWindow(uid='testgroup',
                                       type=WIN_TYPE_GROUP,
                                       group=group,
                                       window_contacts=group.members)

        # Test
        self.assertTrue(group.notifications)

        self.assertIsNone(contact_setting(user_input, window, self.contact_list, self.group_list, self.settings, self.c_queue))
        time.sleep(0.1)

        self.assertFalse(group.notifications)

    def test_disable_notifications_for_all_users(self):
        # Setup
        user_input = UserInput('notify off all')
        contact    = self.contact_list.get_contact('alice@jabber.org')
        window     = TxWindow(uid='alice@jabber.org',
                              type=WIN_TYPE_CONTACT,
                              contact=contact,
                              window_contacts=[contact])

        for c in self.contact_list:
            c.notifications = True
        for g in self.group_list:
            g.notifications = True

        # Test
        for c in self.contact_list:
            self.assertTrue(c.notifications)
        for g in self.group_list:
            self.assertTrue(g.notifications)

        self.assertIsNone(contact_setting(user_input, window, self.contact_list, self.group_list, self.settings, self.c_queue))
        time.sleep(0.1)

        for c in self.contact_list:
            self.assertFalse(c.notifications)
        for g in self.group_list:
            self.assertFalse(g.notifications)


class TestFingerprints(TFCTestCase):

    def test_active_group_raises_fr(self):
        # Setup
        window = TxWindow(type=WIN_TYPE_GROUP)

        # Test
        self.assertFR("Group is selected.", show_fingerprints, window)

    def test_psk_raises_fr(self):
        # Setup
        contact                = create_contact()
        contact.tx_fingerprint = bytes(FINGERPRINT_LEN)
        window                 = TxWindow(name='Alice',
                                          type=WIN_TYPE_CONTACT,
                                          contact=contact)
        # Test
        self.assertFR("Pre-shared keys have no fingerprints.", show_fingerprints, window)

    def test_fingerprint_print_command(self):
        # Setup
        window = TxWindow(name='Alice',
                          type=WIN_TYPE_CONTACT,
                          contact=create_contact())
        # Test
        self.assertIsNone(show_fingerprints(window))


if __name__ == '__main__':
    unittest.main(exit=False)
