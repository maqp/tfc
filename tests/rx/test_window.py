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

import unittest
import datetime

from src.rx.windows     import FileWindow, Window, WindowList

from tests.mock_classes import create_contact, ContactList, GroupList, Packet, PacketList, Settings


class TestFileWindow(unittest.TestCase):

    def test_class(self):
        # Setup
        packet_list = PacketList()
        file_window = FileWindow('alice@jabber.org', packet_list)

        # Test
        self.assertIsNone(file_window.redraw())

        packet_list.packet_l = [Packet(assembly_pt_list=[5*b'a'],
                                       type='file',
                                       f_size=b'30kb',
                                       contact=create_contact(nick='Alice'),
                                       f_packets=20)]

        file_window = FileWindow('alice@jabber.org', packet_list)
        self.assertIsNone(file_window.redraw())


class TestWindow(unittest.TestCase):

    def test_class(self):
        # Setup
        contact_list          = ContactList(nicks=['Alice', 'Bob', 'local'])
        contact               = contact_list.get_contact('Alice')
        contact.notifications = True
        group_list            = GroupList(groups=['testgroup'], contact_list=contact_list)
        settings              = Settings()

        window1 = Window('alice@jabber.org', contact_list, group_list, settings)
        window2 = Window('local',            contact_list, group_list, settings)
        window3 = Window('testgroup',        contact_list, group_list, settings)

        # Test
        with self.assertRaises(ValueError):
            Window('charlie', contact_list, group_list, settings)

        self.assertEqual(len(window1), 0)

        window1.message_log = ['a', 'b']
        for m in window1:
            self.assertIsInstance(m, str)

        window3.remove_contacts(['alice@jabber.org'])
        self.assertEqual(len(window3.window_contacts), 1)
        self.assertFalse(window3.has_contact('alice@jabber.org'))
        window3.add_contacts(['alice@jabber.org'])
        self.assertEqual(len(window3.window_contacts), 2)
        self.assertTrue(window3.has_contact('alice@jabber.org'))

        self.assertIsNone(window1.clear_window())
        self.assertEqual(len(window1), 2)
        self.assertIsNone(window1.reset_window())
        self.assertEqual(len(window1), 0)

        ts = datetime.datetime.now()
        window3.previous_msg_ts = datetime.datetime.strptime('01/01/2017', '%d/%m/%Y')
        self.assertIsNone(window3.print_new(ts, 20 * 'test message', 'alice@jabber.org', print_=True))
        self.assertIsNone(window3.print_new(ts, 'test message', 'alice@jabber.org', print_=True))

        window2.is_active = True
        self.assertIsNone(window2.print_new(ts, 'test message', print_=True))
        window3.message_log = []
        self.assertIsNone(window2.redraw())
        self.assertIsNone(window3.redraw())


class TestWindowList(unittest.TestCase):

    def test_class(self):
        # Setup
        contact_list           = ContactList(nicks=['Alice', 'Bob', 'local'])
        group_list             = GroupList(groups=['testgroup'])
        packet_list            = PacketList()
        settings               = Settings()
        window_list            = WindowList(contact_list, group_list, packet_list, settings)
        window_list.active_win = window_list.get_window('bob@jabber.org')

        # Test
        self.assertEqual(len(window_list), 3)

        for w in window_list:
            self.assertIsInstance(w, Window)

        self.assertIsNone(window_list.select_rx_window('alice@jabber.org'))

        self.assertTrue(window_list.active_win.is_active)
        self.assertEqual(window_list.active_win, window_list.get_window('alice@jabber.org'))

        self.assertTrue(window_list.has_window('alice@jabber.org'))
        self.assertFalse(window_list.has_window('charlie@jabber.org'))

        local_win = window_list.get_local_window()
        self.assertIsInstance(local_win, Window)
        self.assertEqual(local_win.name, 'system messages')

        file_win = window_list.get_window('file_window')
        self.assertIsInstance(file_win, FileWindow)


if __name__ == '__main__':
    unittest.main(exit=False)
