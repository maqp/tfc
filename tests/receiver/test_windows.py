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

import unittest

from datetime import datetime
from unittest import mock

from src.common.statics import *

from src.receiver.windows import RxWindow, WindowList

from tests.mock_classes import create_contact, ContactList, GroupList, Packet, PacketList, Settings
from tests.utils        import group_name_to_group_id, nick_to_pub_key, nick_to_short_address, TFCTestCase


class TestRxWindow(TFCTestCase):

    def setUp(self):
        self.contact_list = ContactList(nicks=['Alice', 'Bob', 'Charlie', LOCAL_ID])
        self.group_list   = GroupList(groups=['test_group', 'test_group2'])
        self.settings     = Settings()
        self.packet_list  = PacketList()
        self.ts           = datetime.fromtimestamp(1502750000)
        self.time         = self.ts.strftime('%H:%M:%S.%f')[:-4]

        group         = self.group_list.get_group('test_group')
        group.members = list(map(self.contact_list.get_contact_by_address_or_nick, ['Alice', 'Bob', 'Charlie']))

    def create_window(self, uid: bytes):
        """Create new RxWindow object."""
        return RxWindow(uid, self.contact_list, self.group_list, self.settings, self.packet_list)

    def test_command_window_creation(self):
        window = self.create_window(WIN_UID_LOCAL)
        self.assertEqual(window.type, WIN_TYPE_COMMAND)
        self.assertEqual(window.name, WIN_TYPE_COMMAND)

    def test_file_window_creation(self):
        window = self.create_window(WIN_UID_FILE)
        self.assertEqual(window.type, WIN_TYPE_FILE)

    def test_contact_window_creation(self):
        window = self.create_window(nick_to_pub_key("Alice"))
        self.assertEqual(window.type, WIN_TYPE_CONTACT)
        self.assertEqual(window.window_contacts[0].onion_pub_key, nick_to_pub_key("Alice"))
        self.assertEqual(window.name, 'Alice')

    def test_group_window_creation(self):
        window = self.create_window(group_name_to_group_id('test_group'))
        self.assertEqual(window.type, WIN_TYPE_GROUP)
        self.assertEqual(window.window_contacts[0].onion_pub_key, nick_to_pub_key("Alice"))
        self.assertEqual(window.name, 'test_group')

    def test_invalid_uid_raises_fr(self):
        self.assert_fr("Invalid window 'bad_uid'.", self.create_window, 'bad_uid')

    def test_window_iterates_over_message_tuples(self):
        # Setup
        window             = self.create_window(nick_to_pub_key("Alice"))
        window.message_log = 5*[(datetime.now(), 'Lorem ipsum', nick_to_pub_key("Alice"),
                                 ORIGIN_CONTACT_HEADER, False, False)]

        # Test
        for mt in window:
            self.assertEqual(mt[1:],
                             ("Lorem ipsum", nick_to_pub_key("Alice"), ORIGIN_CONTACT_HEADER, False, False))

    def test_len_returns_number_of_messages_in_window(self):
        # Setup
        window             = self.create_window(nick_to_pub_key("Alice"))
        window.message_log = 5*[(datetime.now(), "Lorem ipsum", nick_to_pub_key("Alice"),
                                 ORIGIN_CONTACT_HEADER, False, False)]

        # Test
        self.assertEqual(len(window), 5)

    def test_remove_contacts(self):
        # Setup
        window = self.create_window(group_name_to_group_id('test_group'))

        # Test
        self.assertEqual(len(window.window_contacts), 3)
        self.assertIsNone(window.remove_contacts([nick_to_pub_key("Alice"),
                                                  nick_to_pub_key("Bob"),
                                                  nick_to_pub_key("DoesNotExist")]))
        self.assertEqual(len(window.window_contacts), 1)

    def test_add_contacts(self):
        # Setup
        window                 = self.create_window(group_name_to_group_id('test_group'))
        window.window_contacts = [self.contact_list.get_contact_by_address_or_nick('Alice')]

        # Test
        self.assertIsNone(window.add_contacts([nick_to_pub_key("Alice"),
                                               nick_to_pub_key("Bob"),
                                               nick_to_pub_key("DoesNotExist")]))
        self.assertEqual(len(window.window_contacts), 2)

    def test_reset_window(self):
        # Setup
        window             = self.create_window(group_name_to_group_id('test_group'))
        window.message_log = \
            [(datetime.now(), "Hi everybody", nick_to_pub_key("Alice"), ORIGIN_USER_HEADER,    False, False),
             (datetime.now(), "Hi David",     nick_to_pub_key("Alice"), ORIGIN_CONTACT_HEADER, False, False),
             (datetime.now(), "Hi David",     nick_to_pub_key("Bob"),   ORIGIN_CONTACT_HEADER, False, False)]

        # Test
        self.assertIsNone(window.reset_window())
        self.assertEqual(len(window), 0)

    def test_has_contact(self):
        window = self.create_window(group_name_to_group_id('test_group'))
        self.assertTrue(window.has_contact(nick_to_pub_key("Alice")))
        self.assertFalse(window.has_contact(nick_to_pub_key("DoesNotExist")))

    def test_create_handle_dict(self):
        # Setup
        window      = self.create_window(group_name_to_group_id('test_group'))
        message_log = [(datetime.now(), "Lorem ipsum", nick_to_pub_key("Alice"),   ORIGIN_CONTACT_HEADER, False, False),
                       (datetime.now(), "Lorem ipsum", nick_to_pub_key("Bob"),     ORIGIN_USER_HEADER,    False, False),
                       (datetime.now(), "Lorem ipsum", nick_to_pub_key("Charlie"), ORIGIN_CONTACT_HEADER, False, False),
                       (datetime.now(), "Lorem ipsum", nick_to_pub_key("Charlie"), ORIGIN_CONTACT_HEADER, True,  False),
                       (datetime.now(), "Lorem ipsum", nick_to_pub_key("Charlie"), ORIGIN_CONTACT_HEADER, False, False),
                       (datetime.now(), "Lorem ipsum", nick_to_pub_key("David"),   ORIGIN_CONTACT_HEADER, False, False),
                       (datetime.now(), "Lorem ipsum", nick_to_pub_key("Eric"),    ORIGIN_CONTACT_HEADER, False, False)]

        # Test
        self.assertIsNone(window.create_handle_dict(message_log))
        self.assertEqual(window.handle_dict, {nick_to_pub_key("Alice"):   'Alice',
                                              nick_to_pub_key("Bob"):     'Bob',
                                              nick_to_pub_key("Charlie"): 'Charlie',
                                              nick_to_pub_key("David"):   nick_to_short_address("David"),
                                              nick_to_pub_key("Eric"):    nick_to_short_address("Eric")})

    def test_get_command_handle(self):
        # Setup
        window           = self.create_window(WIN_UID_LOCAL)
        window.is_active = True

        # Test
        self.assertEqual(window.get_handle(self.ts, WIN_UID_LOCAL, ORIGIN_USER_HEADER), f"{self.time} -!- ")

    def test_get_contact_handle(self):
        # Setup
        window             = self.create_window(nick_to_pub_key("Alice"))
        window.is_active   = True
        window.handle_dict = {nick_to_pub_key("Alice"): 'Alice'}

        # Test
        self.assertEqual(window.get_handle(self.ts, nick_to_pub_key("Alice"), ORIGIN_USER_HEADER),
                         f"{self.time}    Me: ")
        self.assertEqual(window.get_handle(self.ts, nick_to_pub_key("Alice"), ORIGIN_CONTACT_HEADER),
                         f"{self.time} Alice: ")

        window.is_active = False
        self.assertEqual(window.get_handle(self.ts, nick_to_pub_key("Alice"), ORIGIN_USER_HEADER),
                         f"{self.time} Me (private message): ")
        self.assertEqual(window.get_handle(self.ts, nick_to_pub_key("Alice"), ORIGIN_CONTACT_HEADER),
                         f"{self.time} Alice (private message): ")

    def test_get_group_contact_handle(self):
        # Setup
        window             = self.create_window(group_name_to_group_id('test_group'))
        window.is_active   = True
        window.handle_dict = {nick_to_pub_key("Alice"):   'Alice',
                              nick_to_pub_key("Charlie"): 'Charlie',
                              nick_to_pub_key("David"):   nick_to_short_address("David"),
                              nick_to_pub_key("Eric"):    nick_to_short_address("Eric")}

        # Test
        self.assertEqual(window.get_handle(self.ts, nick_to_pub_key("Alice"), ORIGIN_USER_HEADER),
                         f"{self.time}      Me: ")
        self.assertEqual(window.get_handle(self.ts, nick_to_pub_key("Charlie"), ORIGIN_CONTACT_HEADER),
                         f"{self.time} Charlie: ")

        window.is_active = False
        self.assertEqual(window.get_handle(self.ts, nick_to_pub_key("Alice"), ORIGIN_USER_HEADER),
                         f"{self.time} Me (group test_group): ")
        self.assertEqual(window.get_handle(self.ts, nick_to_pub_key("Charlie"), ORIGIN_CONTACT_HEADER),
                         f"{self.time} Charlie (group test_group): ")

    @mock.patch('time.sleep', return_value=None)
    def test_print_to_inactive_window_preview_on_short_message(self, _):
        # Setup
        window             = self.create_window(nick_to_pub_key("Alice"))
        window.handle_dict = {nick_to_pub_key("Alice"): 'Alice'}
        window.is_active   = False
        window.settings    = Settings(new_message_notify_preview=True)
        msg_tuple          = (self.ts, "Hi Bob", nick_to_pub_key("Bob"), ORIGIN_USER_HEADER, False, False)

        # Test
        self.assert_prints(f"{BOLD_ON}{self.time} Me (private message): {NORMAL_TEXT}"
                           f"Hi Bob\n{CURSOR_UP_ONE_LINE}{CLEAR_ENTIRE_LINE}",
                           window.print, msg_tuple)

    @mock.patch('time.sleep', return_value=None)
    def test_print_to_inactive_window_preview_on_long_message(self, _):
        # Setup
        window             = self.create_window(nick_to_pub_key("Alice"))
        window.is_active   = False
        window.handle_dict = {nick_to_pub_key("Alice"): 'Alice'}
        window.settings    = Settings(new_message_notify_preview=True)
        long_message       = ("Lorem ipsum dolor sit amet, consectetur adipiscing elit. Quisque consequat libero et lao"
                              "reet egestas. Aliquam a arcu malesuada, elementum metus eget, elementum mi. Vestibulum i"
                              "d arcu sem. Ut sodales odio sed viverra mollis. Praesent gravida ante tellus, pellentesq"
                              "ue venenatis massa placerat quis. Nullam in magna porta, hendrerit sem vel, dictum ipsum"
                              ". Ut sagittis, ipsum ut bibendum ornare, ex lorem congue metus, vel posuere metus nulla "
                              "at augue.")
        msg_tuple          = (self.ts, long_message, nick_to_pub_key("Bob"), ORIGIN_USER_HEADER, False, False)

        # Test
        self.assert_prints(f"{BOLD_ON}{self.time} Me (private message): {NORMAL_TEXT}Lorem ipsum dolor sit "
                           f"amet, consectetu…\n{CURSOR_UP_ONE_LINE}{CLEAR_ENTIRE_LINE}",
                           window.print, msg_tuple)

    @mock.patch('time.sleep', return_value=None)
    def test_print_to_inactive_window_preview_off(self, _):
        # Setup
        window             = self.create_window(nick_to_pub_key("Alice"))
        window.is_active   = False
        window.handle_dict = {nick_to_pub_key("Alice"): 'Alice'}
        window.settings    = Settings(new_message_notify_preview=False)
        msg_tuple          = (self.ts, "Hi Bob", nick_to_pub_key("Bob"), ORIGIN_USER_HEADER, False, False)

        # Test
        self.assert_prints(
            f"{BOLD_ON}{self.time} Me (private message): {NORMAL_TEXT}{BOLD_ON}1 unread message{NORMAL_TEXT}\n"
            f"{CURSOR_UP_ONE_LINE}{CLEAR_ENTIRE_LINE}", window.print, msg_tuple)

    def test_print_to_active_window_no_date_change(self):
        # Setup
        window                 = self.create_window(nick_to_pub_key("Alice"))
        window.previous_msg_ts = datetime.fromtimestamp(1502750000)
        window.is_active       = True
        window.handle_dict     = {nick_to_pub_key("Bob"): 'Bob'}
        window.settings        = Settings(new_message_notify_preview=False)
        msg_tuple              = (self.ts, "Hi Alice", nick_to_pub_key("Bob"), ORIGIN_CONTACT_HEADER, False, False)

        # Test
        self.assert_prints(f"{BOLD_ON}{self.time} Bob: {NORMAL_TEXT}Hi Alice\n",
                           window.print, msg_tuple)

    def test_print_to_active_window_with_date_change_and_whisper(self):
        # Setup
        window                 = self.create_window(nick_to_pub_key("Alice"))
        window.previous_msg_ts = datetime.fromtimestamp(1501750000)
        window.is_active       = True
        window.handle_dict     = {nick_to_pub_key("Bob"): 'Bob'}
        window.settings        = Settings(new_message_notify_preview=False)
        msg_tuple              = (self.ts, "Hi Alice", nick_to_pub_key("Bob"), ORIGIN_CONTACT_HEADER, True, False)
        self.time              = self.ts.strftime('%H:%M:%S.%f')[:-4]

        # Test
        self.assert_prints(f"""\
{BOLD_ON}00:00 -!- Day changed to 2017-08-15{NORMAL_TEXT}
{BOLD_ON}{self.time} Bob (whisper): {NORMAL_TEXT}Hi Alice
""", window.print, msg_tuple)

    def test_print_to_active_window_with_date_change_and_whisper_empty_message(self):
        # Setup
        window                 = self.create_window(nick_to_pub_key("Alice"))
        window.previous_msg_ts = datetime.fromtimestamp(1501750000)
        window.is_active       = True
        window.handle_dict     = {nick_to_pub_key("Bob"): 'Bob'}
        window.settings        = Settings(new_message_notify_preview=False)
        msg_tuple              = (self.ts, " ", nick_to_pub_key("Bob"), ORIGIN_CONTACT_HEADER, True, False)

        # Test
        self.assert_prints(f"""\
{BOLD_ON}00:00 -!- Day changed to 2017-08-15{NORMAL_TEXT}
{BOLD_ON}{self.time} Bob (whisper): {NORMAL_TEXT}
""", window.print, msg_tuple)

    @mock.patch('time.sleep', return_value=None)
    def test_print_new(self, _):
        # Setup
        window = self.create_window(nick_to_pub_key("Alice"))

        # Test
        self.assertIsNone(window.add_new(self.ts, "Hi Alice", nick_to_pub_key("Bob"),
                                         ORIGIN_CONTACT_HEADER, output=True))
        self.assertEqual(len(window.message_log), 1)
        self.assertEqual(window.handle_dict[nick_to_pub_key("Bob")], 'Bob')

    def test_redraw_message_window(self):
        # Setup
        window                 = self.create_window(nick_to_pub_key("Alice"))
        window.is_active       = True
        window.message_log     = [(self.ts, "Hi Alice", nick_to_pub_key("Bob"), ORIGIN_CONTACT_HEADER, False, False)]
        window.unread_messages = 1

        # Test
        self.assert_prints(f"""\
{CLEAR_ENTIRE_SCREEN}{CURSOR_LEFT_UP_CORNER}
------------------------------- Unread Messages --------------------------------

{BOLD_ON}{self.time}   Bob: {NORMAL_TEXT}Hi Alice
""", window.redraw)
        self.assertEqual(window.unread_messages, 0)

    def test_redraw_empty_window(self):
        # Setup
        window             = self.create_window(nick_to_pub_key("Alice"))
        window.is_active   = True
        window.message_log = []

        # Test
        self.assert_prints(f"""\
{CLEAR_ENTIRE_SCREEN}{CURSOR_LEFT_UP_CORNER}
{BOLD_ON}                   This window for Alice is currently empty.                    {NORMAL_TEXT}\n
""", window.redraw)

    @mock.patch('time.sleep', return_value=None)
    def test_redraw_file_win(self, _):
        # Setup
        self.packet_list.packets = [Packet(type=FILE,
                                           name='testfile.txt',
                                           assembly_pt_list=5*[b'a'],
                                           packets=10,
                                           size="100.0KB",
                                           contact=create_contact('Bob')),
                                    Packet(type=FILE,
                                           name='testfile2.txt',
                                           assembly_pt_list=7 * [b'a'],
                                           packets=100,
                                           size="15.0KB",
                                           contact=create_contact('Charlie'))]

        # Test
        window = self.create_window(WIN_UID_FILE)
        self.assert_prints(f"""\

File name        Size       Sender     Complete    
────────────────────────────────────────────────────────────────────────────────
testfile.txt     100.0KB    Bob        50.00%      
testfile2.txt    15.0KB     Charlie    7.00%       

{6*(CURSOR_UP_ONE_LINE+CLEAR_ENTIRE_LINE)}""", window.redraw_file_win)

    @mock.patch('time.sleep', return_value=None)
    def test_redraw_empty_file_win(self, _):
        # Setup
        self.packet_list.packet_l = []

        # Test
        window = self.create_window(WIN_UID_FILE)
        self.assert_prints(f"""\

{BOLD_ON}                  No file transmissions currently in progress.                  {NORMAL_TEXT}

{3*(CURSOR_UP_ONE_LINE+CLEAR_ENTIRE_LINE)}""", window.redraw_file_win)


class TestWindowList(TFCTestCase):

    def setUp(self):
        self.settings     = Settings()
        self.contact_list = ContactList(nicks=['Alice', 'Bob', 'Charlie', LOCAL_ID])
        self.group_list   = GroupList(groups=['test_group', 'test_group2'])
        self.packet_list  = PacketList()

        group         = self.group_list.get_group('test_group')
        group.members = list(map(self.contact_list.get_contact_by_address_or_nick, ['Alice', 'Bob', 'Charlie']))

        self.window_list = WindowList(self.settings, self.contact_list, self.group_list, self.packet_list)

    def create_window(self, uid):
        """Create new RxWindow object."""
        return RxWindow(uid, self.contact_list, self.group_list, self.settings, self.packet_list)

    def test_active_win_is_none_if_local_key_is_not_present(self):
        # Setup
        self.contact_list.contacts = []

        # Test
        window_list = WindowList(self.settings, self.contact_list, self.group_list, self.packet_list)
        self.assertEqual(window_list.active_win, None)

    def test_active_win_is_command_win_if_local_key_is_present(self):
        # Setup
        self.contact_list.contacts = [create_contact(LOCAL_ID)]

        # Test
        self.assertEqual(self.window_list.active_win.uid, WIN_UID_LOCAL)

    def test_window_list_iterates_over_windows(self):
        for w in self.window_list:
            self.assertIsInstance(w, RxWindow)

    def test_len_returns_number_of_windows(self):
        self.assertEqual(len(self.window_list), 7)

    def test_group_windows(self):
        # Setup
        self.window_list.windows = [self.create_window(group_name_to_group_id(g)) for g in ['test_group',
                                                                                            'test_group2']]

        # Test
        for g in self.window_list.get_group_windows():
            self.assertEqual(g.type, WIN_TYPE_GROUP)

    def test_has_window(self):
        # Setup
        self.window_list.windows = [self.create_window(group_name_to_group_id(g)) for g in ['test_group',
                                                                                            'test_group2']]

        # Test
        self.assertTrue(self.window_list.has_window(group_name_to_group_id('test_group')))
        self.assertTrue(self.window_list.has_window(group_name_to_group_id('test_group2')))
        self.assertFalse(self.window_list.has_window(group_name_to_group_id('test_group3')))

    def test_remove_window(self):
        # Setup
        self.window_list.windows = [self.create_window(group_name_to_group_id(g)) for g in ['test_group',
                                                                                            'test_group2']]

        # Test
        self.assertEqual(len(self.window_list), 2)
        self.assertIsNone(self.window_list.remove_window(group_name_to_group_id('test_group3')))
        self.assertEqual(len(self.window_list), 2)
        self.assertIsNone(self.window_list.remove_window(group_name_to_group_id('test_group2')))
        self.assertEqual(len(self.window_list), 1)

    def test_select_rx_window(self):
        # Setup
        self.window_list.windows    = [self.create_window(group_name_to_group_id(g)) for g in ['test_group',
                                                                                               'test_group2']]
        tg_win                      = self.window_list.windows[0]
        tg2_win                     = self.window_list.windows[1]
        tg_win.is_active            = True
        self.window_list.active_win = tg_win

        # Test
        self.assert_prints(f"""{CLEAR_ENTIRE_SCREEN}{CURSOR_LEFT_UP_CORNER}
{BOLD_ON}                This window for test_group2 is currently empty.                 {NORMAL_TEXT}

""", self.window_list.set_active_rx_window, group_name_to_group_id('test_group2'))
        self.assertFalse(tg_win.is_active)
        self.assertTrue(tg2_win.is_active)

    @mock.patch('time.sleep', return_value=None)
    def test_select_rx_file_window(self, _):
        # Setup
        self.window_list.windows    = [self.create_window(WIN_UID_FILE)]
        self.window_list.windows   += [self.create_window(group_name_to_group_id(g)) for g in ['test_group',
                                                                                               'test_group2']]
        tg_win                      = self.window_list.get_window(group_name_to_group_id('test_group'))
        tg_win.is_active            = True
        self.window_list.active_win = tg_win
        self.packet_list.packets    = [Packet(type=FILE,
                                              name='testfile.txt',
                                              assembly_pt_list=5 * [b'a'],
                                              packets=10,
                                              size="100.0KB",
                                              contact=create_contact('Bob'))]

        # Test
        self.assert_prints(f"""\

File name       Size       Sender    Complete    
────────────────────────────────────────────────────────────────────────────────
testfile.txt    100.0KB    Bob       50.00%      

{5*(CURSOR_UP_ONE_LINE+CLEAR_ENTIRE_LINE)}""", self.window_list.set_active_rx_window, WIN_UID_FILE)

        self.assertFalse(tg_win.is_active)
        self.assertTrue(self.window_list.get_window(WIN_UID_FILE).is_active)

    def test_get_local_window(self):
        # Setup
        self.window_list.windows = [self.create_window(uid) for uid in [group_name_to_group_id('test_group'),
                                                                        group_name_to_group_id('test_group2'),
                                                                        WIN_UID_FILE,
                                                                        WIN_UID_LOCAL]]

        # Test
        self.assertEqual(self.window_list.get_local_window().uid, WIN_UID_LOCAL)

    def test_get_non_existing_window(self):
        # Setup
        self.window_list.windows = [self.create_window(uid) for uid in [group_name_to_group_id('test_group'),
                                                                        WIN_UID_FILE,
                                                                        WIN_UID_LOCAL]]

        # Test existing window
        self.assertTrue(self.window_list.has_window(group_name_to_group_id('test_group')))
        window = self.window_list.get_window(       group_name_to_group_id('test_group'))
        self.assertEqual(window.uid,                group_name_to_group_id('test_group'))

        # Test non-existing window
        self.assertFalse(self.window_list.has_window(group_name_to_group_id('test_group2')))
        window2 = self.window_list.get_window(       group_name_to_group_id('test_group2'))
        self.assertEqual(window2.uid,                group_name_to_group_id('test_group2'))
        self.assertTrue(self.window_list.has_window( group_name_to_group_id('test_group2')))


if __name__ == '__main__':
    unittest.main(exit=False)
