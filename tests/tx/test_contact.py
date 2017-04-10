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
from src.tx.contact     import add_new_contact, change_nick, contact_setting, fingerprints, remove_contact

from tests.mock_classes import create_contact, ContactList, Gateway, Group, GroupList, Settings, UserInput, Window
from tests.utils        import TFCTestCase


class TestAddNewContact(TFCTestCase):

    def test_during_tricle_raises_fr(self):
        # Setup
        settings = Settings(session_trickle=True)

        # Test
        self.assertFR("Command disabled during trickle connection.", add_new_contact, None, None, settings, None, None)

    def test_contact_list_full_raises_fr(self):
        # Setup
        settings     = Settings()
        contact_list = ContactList(nicks=['contact_{}'.format(n) for n in range(20)])

        # Test
        self.assertFR("Error: TFC settings only allow 20 accounts.", add_new_contact, contact_list, None, settings, None, None)

    def test_autonick_ecdhe_kex(self):
        # Setup
        input_list = ['alice@jabber.org', 'bob@jabber.org', '', '', '2QJL5gVSPEjMTaxWPfYkzG9UJxzZDNSx6PPeVWdzS5CFN7knZy', 'Yes']
        gen        = iter(input_list)

        def mock_input(_):
            return str(next(gen))
        builtins.input = mock_input

        contact_list = ContactList()
        group_list   = GroupList()
        gateway      = Gateway()
        settings     = Settings()
        queues       = {COMMAND_PACKET_QUEUE: Queue(),
                        KEY_MANAGEMENT_QUEUE: Queue()}

        # Test
        self.assertIsNone(add_new_contact(contact_list, group_list, settings, queues, gateway))

        contact = contact_list.get_contact('alice@jabber.org')
        self.assertEqual(contact.nick, 'Alice')
        self.assertNotEqual(contact.tx_fingerprint, bytes(32))  # Indicates that PSK function was not called

    def test_standard_nick_psk_kex(self):
        # Setup
        o_getpass       = getpass.getpass
        getpass.getpass = lambda x: 'test_password'
        input_list      = ['alice@jabber.org', 'bob@jabber.org', 'Alice_', 'psk', '.']
        gen             = iter(input_list)

        def mock_input(_):
            return str(next(gen))
        builtins.input = mock_input

        contact_list = ContactList()
        group_list   = GroupList()
        gateway      = Gateway()
        settings     = Settings(disable_gui_dialog=True)
        queues       = {COMMAND_PACKET_QUEUE: Queue(),
                        KEY_MANAGEMENT_QUEUE: Queue()}

        # Test
        self.assertIsNone(add_new_contact(contact_list, group_list, settings, queues, gateway))
        contact = contact_list.get_contact('alice@jabber.org')
        self.assertEqual(contact.nick, 'Alice_')
        self.assertEqual(contact.tx_fingerprint, bytes(32))  # Indicates that PSK function was called

        # Teardown
        getpass.getpass = o_getpass
        os.remove('bob@jabber.org.psk - Give to alice@jabber.org')


class TestRemoveContact(TFCTestCase):

    def test_during_tricle_raises_fr(self):
        # Setup
        settings = Settings(session_trickle=True)

        # Test
        self.assertFR("Command disabled during trickle connection.", remove_contact, None, None, None, None, settings, None)

    def test_missing_account_raises_fr(self):
        # Setup
        user_input = UserInput('rm ')
        settings   = Settings()

        # Test
        self.assertFR("Error: No account specified.", remove_contact, user_input, None, None, None, settings, None)

    def test_user_abort_raises_fr(self):
        # Setup
        o_input        = builtins.input
        builtins.input = lambda x: 'No'
        user_input     = UserInput('rm alice@jabber.org')
        settings       = Settings()

        # Test
        self.assertFR("Removal of contact aborted.", remove_contact, user_input, None, None, None, settings, None)

        # Teardown
        builtins.input = o_input

    def test_successful_removal_of_contact(self):
        # Setup
        o_input        = builtins.input
        builtins.input = lambda x: 'Yes'
        user_input     = UserInput('rm Alice')
        contact_list   = ContactList(nicks=['Alice'])
        window         = Window(window_contacts=[contact_list.get_contact('Alice')],
                                type='contact')
        group_list     = GroupList(groups=['testgroup'])
        settings       = Settings()
        queues         = {KEY_MANAGEMENT_QUEUE: Queue(),
                          COMMAND_PACKET_QUEUE: Queue()}

        # Test
        for g in group_list:
            self.assertIsInstance(g, Group)
            self.assertTrue(g.has_member('alice@jabber.org'))

        self.assertIsNone(remove_contact(user_input, window, contact_list, group_list, settings, queues))
        self.assertEqual(queues[COMMAND_PACKET_QUEUE].qsize(), 1)

        km_data = queues[KEY_MANAGEMENT_QUEUE].get()
        self.assertEqual(km_data, ('REM', 'alice@jabber.org'))
        self.assertFalse(contact_list.has_contact('alice@jabber.org'))

        for g in group_list:
            self.assertIsInstance(g, Group)
            self.assertFalse(g.has_member('alice@jabber.org'))

        # Teardown
        builtins.input = o_input

    def test_successful_removal_of_last_member_of_active_group(self):
        # Setup
        o_input        = builtins.input
        builtins.input = lambda x: 'Yes'
        user_input     = UserInput('rm Alice')
        contact_list   = ContactList(nicks=['Alice'])
        window         = Window(window_contacts=[contact_list.get_contact('Alice')],
                                type='group',
                                name='testgroup')
        group_list     = GroupList(groups=['testgroup'])
        group          = group_list.get_group('testgroup')
        group.members  = [contact_list.get_contact('alice@jabber.org')]
        settings       = Settings()
        queues         = {KEY_MANAGEMENT_QUEUE: Queue(),
                          COMMAND_PACKET_QUEUE: Queue()}

        # Test
        for g in group_list:
            self.assertIsInstance(g, Group)
            self.assertTrue(g.has_member('alice@jabber.org'))

        self.assertIsNone(remove_contact(user_input, window, contact_list, group_list, settings, queues))
        self.assertEqual(queues[COMMAND_PACKET_QUEUE].qsize(), 1)

        km_data = queues[KEY_MANAGEMENT_QUEUE].get()
        self.assertEqual(km_data, ('REM', 'alice@jabber.org'))
        self.assertFalse(contact_list.has_contact('alice@jabber.org'))

        for g in group_list:
            self.assertIsInstance(g, Group)
            self.assertFalse(g.has_member('alice@jabber.org'))

        # Teardown
        builtins.input = o_input

        queues[KEY_MANAGEMENT_QUEUE].close()
        queues[COMMAND_PACKET_QUEUE].close()


    def test_contact_not_present_on_txm(self):
        # Setup
        o_input        = builtins.input
        builtins.input = lambda x: 'Yes'
        user_input     = UserInput('rm alice@jabber.org')
        contact_list   = ContactList(nicks=['Bob'])
        window         = Window(window_contact=[contact_list.get_contact('Bob')],
                                type='group')
        group_list     = GroupList(groups=[])
        settings       = Settings()
        queues         = {KEY_MANAGEMENT_QUEUE: Queue(),
                          COMMAND_PACKET_QUEUE: Queue()}

        # Test
        self.assertIsNone(remove_contact(user_input, window, contact_list, group_list, settings, queues))
        self.assertEqual(queues[COMMAND_PACKET_QUEUE].qsize(), 1)

        command_packet, settings_ = queues[COMMAND_PACKET_QUEUE].get()
        self.assertIsInstance(command_packet, bytes)
        self.assertIsInstance(settings_, Settings)

        # Teardown
        builtins.input = o_input

        queues[KEY_MANAGEMENT_QUEUE].close()
        queues[COMMAND_PACKET_QUEUE].close()


class TestChangeNick(TFCTestCase):

    def test_active_group_raises_fr(self):
        # Setup
        window = Window(type='group')

        # Test
        self.assertFR("Error: Group is selected.", change_nick, None, window, None, None, None, None)

    def test_missing_nick_raises_fr(self):
        # Setup
        user_input = UserInput("nick ")
        window     = Window(type='contact')

        # Test
        self.assertFR("Error: No nick specified.", change_nick, user_input, window, None, None, None, None)

    def test_invalid_nick_raises_fr(self):
        # Setup
        user_input   = UserInput("nick Alice\x01")
        window       = Window(type='contact',
                              contact=create_contact('Alice'))
        contact_list = ContactList(nicks=['Alice'])
        group_list   = GroupList()

        # Test
        self.assertFR("Nick must be printable.", change_nick, user_input, window, contact_list, group_list, None, None)

    def test_successful_nick_change(self):
        # Setup
        user_input   = UserInput("nick Alice_")
        contact_list = ContactList(nicks=['Alice'])
        window       = Window(name='Alice',
                              type='contact',
                              contact=contact_list.get_contact('Alice'))
        group_list   = GroupList()
        settings     = Settings()
        c_queue      = Queue()

        # Test
        self.assertIsNone(change_nick(user_input, window, contact_list, group_list, settings, c_queue))
        contact = contact_list.get_contact('alice@jabber.org')
        self.assertEqual(contact.nick, 'Alice_')


class TestContactSetting(TFCTestCase):

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
        contact_list         = ContactList(nicks=['Alice'])
        group_list           = GroupList()
        settings             = Settings()
        c_queue              = Queue()
        contact              = contact_list.get_contact('Alice')
        contact.log_messages = False
        window               = Window(uid='alice@jabber.org',
                                      type='contact',
                                      contact=contact)
        # Test
        self.assertFalse(contact.log_messages)
        self.assertIsNone(contact_setting(user_input, window, contact_list, group_list, settings, c_queue))
        time.sleep(0.2)
        self.assertTrue(contact.log_messages)

    def test_enable_logging_for_group(self):
        # Setup
        user_input         = UserInput('logging on')
        contact_list       = ContactList(nicks=['Alice'])
        group_list         = GroupList(groups=['testgroup'])
        settings           = Settings()
        c_queue            = Queue()
        group              = group_list.get_group('testgroup')
        group.log_messages = False
        window             = Window(uid='testgroup',
                                    type='group',
                                    group=group,
                                    window_contacts=group.members)
        # Test
        self.assertFalse(group.log_messages)
        self.assertIsNone(contact_setting(user_input, window, contact_list, group_list, settings, c_queue))
        time.sleep(0.2)
        self.assertTrue(group.log_messages)

    def test_enable_logging_for_all_users(self):
        # Setup
        user_input   = UserInput('logging on all')
        contact_list = ContactList(nicks=['Alice', 'Bob'])
        group_list   = GroupList(groups=['testgroup'])
        contact      = contact_list.get_contact('alice@jabber.org')
        settings     = Settings()
        c_queue      = Queue()
        window       = Window(uid='alice@jabber.org',
                              type='contact',
                              contact=contact,
                              window_contacts=[contact])
        for c in contact_list:
            c.log_messages = False
        for g in group_list:
            g.log_messages = False

        # Test
        for c in contact_list:
            self.assertFalse(c.log_messages)
        for g in group_list:
            self.assertFalse(g.log_messages)
        self.assertIsNone(contact_setting(user_input, window, contact_list, group_list, settings, c_queue))
        time.sleep(0.2)
        for c in contact_list:
            self.assertTrue(c.log_messages)
        for g in group_list:
            self.assertTrue(g.log_messages)

    def test_disable_logging_for_user(self):
        # Setup
        user_input           = UserInput('logging off')
        contact_list         = ContactList(nicks=['Alice'])
        group_list           = GroupList()
        settings             = Settings()
        c_queue              = Queue()
        contact              = contact_list.get_contact('Alice')
        contact.log_messages = True
        window               = Window(uid='alice@jabber.org',
                                      type='contact',
                                      contact=contact,
                                      window_contacts=[contact])
        # Test
        self.assertTrue(contact.log_messages)
        self.assertIsNone(contact_setting(user_input, window, contact_list, group_list, settings, c_queue))
        time.sleep(0.2)
        self.assertFalse(contact.log_messages)

    def test_disable_logging_for_group(self):
        # Setup
        user_input         = UserInput('logging off')
        contact_list       = ContactList(nicks=['Alice'])
        group_list         = GroupList(groups=['testgroup'])
        settings           = Settings()
        c_queue            = Queue()
        group              = group_list.get_group('testgroup')
        group.log_messages = True
        window             = Window(uid='testgroup',
                                    type='group',
                                    group=group,
                                    window_contacts=group.members)
        # Test
        self.assertTrue(group.log_messages)
        self.assertIsNone(contact_setting(user_input, window, contact_list, group_list, settings, c_queue))
        time.sleep(0.2)
        self.assertFalse(group.log_messages)

    def test_disable_logging_for_all_users(self):
        # Setup
        user_input   = UserInput('logging off all')
        contact_list = ContactList(nicks=['Alice', 'Bob'])
        group_list   = GroupList()
        contact      = contact_list.get_contact('alice@jabber.org')
        settings     = Settings()
        c_queue      = Queue()
        window       = Window(uid='alice@jabber.org',
                              type='contact',
                              contact=contact,
                              window_contacts=[contact])
        for c in contact_list:
            c.log_messages = True
        for g in group_list:
            g.log_messages = True

        # Test
        for c in contact_list:
            self.assertTrue(c.log_messages)
        for g in group_list:
            self.assertTrue(g.log_messages)
        self.assertIsNone(contact_setting(user_input, window, contact_list, group_list, settings, c_queue))
        time.sleep(0.2)
        for c in contact_list:
            self.assertFalse(c.log_messages)
        for g in group_list:
            self.assertFalse(g.log_messages)

    def test_enable_file_reception_for_user(self):
        # Setup
        user_input             = UserInput('store on')
        contact_list           = ContactList(nicks=['Alice'])
        group_list             = GroupList()
        settings               = Settings()
        c_queue                = Queue()
        contact                = contact_list.get_contact('Alice')
        contact.file_reception = False
        window                 = Window(uid='alice@jabber.org',
                                        type='contact',
                                        contact=contact,
                                        window_contacts=[contact])
        # Test
        self.assertFalse(contact.file_reception)
        self.assertIsNone(contact_setting(user_input, window, contact_list, group_list, settings, c_queue))
        time.sleep(0.2)
        self.assertTrue(contact.file_reception)

    def test_enable_file_reception_for_group(self):
        # Setup
        user_input   = UserInput('store on')
        contact_list = ContactList(nicks=['Alice'])
        group_list   = GroupList(groups=['testgroup'])
        settings     = Settings()
        c_queue      = Queue()
        group        = group_list.get_group('testgroup')
        window       = Window(uid='testgroup',
                              type='group',
                              group=group,
                              window_contacts=group.members)
        for m in group:
            m.file_reception = False

        # Test
        for m in group:
            self.assertFalse(m.file_reception)
        self.assertIsNone(contact_setting(user_input, window, contact_list, group_list, settings, c_queue))
        time.sleep(0.2)
        for m in group:
            self.assertTrue(m.file_reception)

    def test_enable_file_reception_for_all_users(self):
        # Setup
        user_input   = UserInput('store on all')
        contact_list = ContactList(nicks=['Alice', 'Bob'])
        group_list   = GroupList()
        contact      = contact_list.get_contact('alice@jabber.org')
        settings     = Settings()
        c_queue      = Queue()
        window       = Window(uid='alice@jabber.org',
                              type='contact',
                              contact=contact,
                              window_contacts=[contact])
        for c in contact_list:
            c.file_reception = False
        for g in group_list:
            g.file_reception = False

        # Test
        for c in contact_list:
            self.assertFalse(c.file_reception)
        for g in group_list:
            self.assertFalse(g.log_messages)
        self.assertIsNone(contact_setting(user_input, window, contact_list, group_list, settings, c_queue))
        time.sleep(0.2)
        for c in contact_list:
            self.assertTrue(c.file_reception)
        for g in group_list:
            self.assertTrue(g.log_messages)

    def test_disable_file_reception_for_user(self):
        # Setup
        user_input             = UserInput('store off')
        contact_list           = ContactList(nicks=['Alice'])
        group_list             = GroupList()
        settings               = Settings()
        c_queue                = Queue()
        contact                = contact_list.get_contact('Alice')
        contact.file_reception = True
        window                 = Window(uid='alice@jabber.org',
                                        type='contact',
                                        contact=contact,
                                        window_contacts=[contact])
        # Test
        self.assertTrue(contact.file_reception)
        self.assertIsNone(contact_setting(user_input, window, contact_list, group_list, settings, c_queue))
        time.sleep(0.2)
        self.assertFalse(contact.file_reception)

    def test_disable_file_reception_for_group(self):
        # Setup
        user_input   = UserInput('store off')
        contact_list = ContactList(nicks=['Alice'])
        group_list   = GroupList(groups=['testgroup'])
        settings     = Settings()
        c_queue      = Queue()
        group        = group_list.get_group('testgroup')
        window       = Window(uid='testgroup',
                              type='group',
                              group=group,
                              window_contacts=group.members)
        for m in group:
            m.file_reception = True

        # Test
        for m in group:
            self.assertTrue(m.file_reception)
        self.assertIsNone(contact_setting(user_input, window, contact_list, group_list, settings, c_queue))
        time.sleep(0.2)
        for m in group:
            self.assertFalse(m.file_reception)

    def test_disable_file_reception_for_all_users(self):
        # Setup
        user_input   = UserInput('store off all')
        contact_list = ContactList(nicks=['Alice', 'Bob'])
        group_list   = GroupList()
        contact      = contact_list.get_contact('alice@jabber.org')
        settings     = Settings()
        c_queue      = Queue()
        window       = Window(uid='alice@jabber.org',
                              type='contact',
                              contact=contact,
                              window_contacts=[contact])
        for c in contact_list:
            c.file_reception = True
        for g in group_list:
            g.file_reception = True

        # Test
        for c in contact_list:
            self.assertTrue(c.file_reception)
        for g in group_list:
            self.assertTrue(g.log_messages)
        self.assertIsNone(contact_setting(user_input, window, contact_list, group_list, settings, c_queue))
        time.sleep(0.2)
        for c in contact_list:
            self.assertFalse(c.file_reception)
        for g in group_list:
            self.assertFalse(g.log_messages)

    def test_enable_notifications_for_user(self):
        # Setup
        user_input            = UserInput('notify on')
        contact_list          = ContactList(nicks=['Alice'])
        group_list            = GroupList()
        settings              = Settings()
        c_queue               = Queue()
        contact               = contact_list.get_contact('Alice')
        contact.notifications = False
        window                = Window(uid='alice@jabber.org',
                                       type='contact',
                                       contact=contact)
        # Test
        self.assertFalse(contact.notifications)
        self.assertIsNone(contact_setting(user_input, window, contact_list, group_list, settings, c_queue))
        time.sleep(0.2)
        self.assertTrue(contact.notifications)

    def test_enable_notifications_for_group(self):
        # Setup
        user_input          = UserInput('notify on')
        contact_list        = ContactList(nicks=['Alice'])
        group_list          = GroupList(groups=['testgroup'])
        settings            = Settings()
        c_queue             = Queue()
        group               = group_list.get_group('testgroup')
        group.notifications = False
        window              = Window(uid='testgroup',
                                     type='group',
                                     group=group,
                                     window_contacts=group.members)
        # Test
        self.assertFalse(group.notifications)
        self.assertIsNone(contact_setting(user_input, window, contact_list, group_list, settings, c_queue))
        time.sleep(0.2)
        self.assertTrue(group.notifications)

    def test_enable_notifications_for_all_users(self):
        # Setup
        user_input   = UserInput('notify on all')
        contact_list = ContactList(nicks=['Alice', 'Bob'])
        group_list   = GroupList()
        contact      = contact_list.get_contact('alice@jabber.org')
        settings     = Settings()
        c_queue      = Queue()
        window       = Window(uid='alice@jabber.org',
                              type='contact',
                              contact=contact,
                              window_contacts=[contact])
        for c in contact_list:
            c.notifications = False
        for g in group_list:
            g.notifications = False

        # Test
        for c in contact_list:
            self.assertFalse(c.notifications)
        for g in group_list:
            self.assertFalse(g.notifications)
        self.assertIsNone(contact_setting(user_input, window, contact_list, group_list, settings, c_queue))
        time.sleep(0.2)
        for c in contact_list:
            self.assertTrue(c.notifications)
        for g in group_list:
            self.assertTrue(g.notifications)

    def test_disable_notifications_for_user(self):
        # Setup
        user_input            = UserInput('notify off')
        contact_list          = ContactList(nicks=['Alice'])
        group_list            = GroupList()
        settings              = Settings()
        c_queue               = Queue()
        contact               = contact_list.get_contact('Alice')
        contact.notifications = True
        window                = Window(uid='alice@jabber.org',
                                       type='contact',
                                       contact=contact,
                                       window_contacts=[contact])
        # Test
        self.assertTrue(contact.notifications)
        self.assertIsNone(contact_setting(user_input, window, contact_list, group_list, settings, c_queue))
        time.sleep(0.2)
        self.assertFalse(contact.notifications)

    def test_disable_notifications_for_group(self):
        # Setup
        user_input          = UserInput('notify off')
        contact_list        = ContactList(nicks=['Alice'])
        group_list          = GroupList(groups=['testgroup'])
        settings            = Settings()
        c_queue             = Queue()
        group               = group_list.get_group('testgroup')
        group.notifications = True
        window              = Window(uid='testgroup',
                                     type='group',
                                     group=group,
                                     window_contacts=group.members)
        # Test
        self.assertTrue(group.notifications)
        self.assertIsNone(contact_setting(user_input, window, contact_list, group_list, settings, c_queue))
        time.sleep(0.2)
        self.assertFalse(group.notifications)

    def test_disable_notifications_for_all_users(self):
        # Setup
        user_input   = UserInput('notify off all')
        contact_list = ContactList(nicks=['Alice', 'Bob'])
        group_list   = GroupList(groups=['testgroup'])
        contact      = contact_list.get_contact('alice@jabber.org')
        settings     = Settings()
        c_queue      = Queue()
        window       = Window(uid='alice@jabber.org',
                              type='contact',
                              contact=contact,
                              window_contacts=[contact])
        for c in contact_list:
            c.notifications = True
        for g in group_list:
            g.notifications = True

        # Test
        for c in contact_list:
            self.assertTrue(c.notifications)
        for g in group_list:
            self.assertTrue(g.notifications)
        self.assertIsNone(contact_setting(user_input, window, contact_list, group_list, settings, c_queue))
        time.sleep(0.2)
        for c in contact_list:
            self.assertFalse(c.notifications)
        for g in group_list:
            self.assertFalse(g.notifications)


class TestFingerprints(TFCTestCase):

    def test_active_group_raises_fr(self):
        # Setup
        window = Window(type='group')

        # Test
        self.assertFR('Group is selected.', fingerprints, window)

    def test_psk_raises_fr(self):
        # Setup
        contact                = create_contact('Alice')
        contact.tx_fingerprint = bytes(32)
        window                 = Window(name='Alice',
                                        type='contact',
                                        contact=contact)
        # Test
        self.assertFR("Key have been pre-shared with Alice and thus have no fingerprints.", fingerprints, window)

    def test_fingerprint_print_command(self):
        # Setup
        window = Window(name='Alice',
                        type='contact',
                        contact=create_contact('Alice'))
        # Test
        self.assertIsNone(fingerprints(window))


if __name__ == '__main__':
    unittest.main(exit=False)
