#!/usr/bin/env python3.6
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

from src.common.output  import clear_screen, group_management_print, m_print, phase, print_fingerprint, print_key
from src.common.output  import print_title, print_on_previous_line, print_spacing, rp_print
from src.common.statics import *

from tests.mock_classes import ContactList, nick_to_pub_key, Settings
from tests.utils        import TFCTestCase


class TestClearScreen(TFCTestCase):

    def test_clear_screen(self):
        self.assert_prints(CLEAR_ENTIRE_SCREEN + CURSOR_LEFT_UP_CORNER, clear_screen)


class TestGroupManagementPrint(TFCTestCase):

    def setUp(self):
        self.contact_list = ContactList(nicks=['Alice'])
        self.lines        = [nick_to_pub_key('Alice'), nick_to_pub_key('Bob')]
        self.group_name   = 'test_group'

    def test_group_management_print(self):
        group_management_print(NEW_GROUP, self.lines, self.contact_list, self.group_name)
        self.assert_prints("""\
        ┌──────────────────────────────────────────────────────────────┐        
        │    Created new group 'test_group' with following members:    │        
        │   * Alice                                                    │        
        │   * zwp3dykiztmeils2u5eqjtdtx5x3kti5ktjthpkznku3ws5u5fq2bnad │        
        └──────────────────────────────────────────────────────────────┘        
""", group_management_print, NEW_GROUP, self.lines, self.contact_list, self.group_name)

        self.assert_prints("""\
        ┌──────────────────────────────────────────────────────────────┐        
        │       Added following accounts to group 'test_group':        │        
        │   * Alice                                                    │        
        │   * zwp3dykiztmeils2u5eqjtdtx5x3kti5ktjthpkznku3ws5u5fq2bnad │        
        └──────────────────────────────────────────────────────────────┘        
""", group_management_print, ADDED_MEMBERS, self.lines, self.contact_list, self.group_name)

        self.assert_prints("""\
        ┌──────────────────────────────────────────────────────────────┐        
        │    Following accounts were already in group 'test_group':    │        
        │   * Alice                                                    │        
        │   * zwp3dykiztmeils2u5eqjtdtx5x3kti5ktjthpkznku3ws5u5fq2bnad │        
        └──────────────────────────────────────────────────────────────┘        
""", group_management_print, ALREADY_MEMBER, self.lines, self.contact_list, self.group_name)

        self.assert_prints("""\
        ┌──────────────────────────────────────────────────────────────┐        
        │      Removed following members from group 'test_group':      │        
        │   * Alice                                                    │        
        │   * zwp3dykiztmeils2u5eqjtdtx5x3kti5ktjthpkznku3ws5u5fq2bnad │        
        └──────────────────────────────────────────────────────────────┘        
""", group_management_print, REMOVED_MEMBERS, self.lines, self.contact_list, self.group_name)

        self.assert_prints("""\
        ┌──────────────────────────────────────────────────────────────┐        
        │      Following accounts were not in group 'test_group':      │        
        │   * Alice                                                    │        
        │   * zwp3dykiztmeils2u5eqjtdtx5x3kti5ktjthpkznku3ws5u5fq2bnad │        
        └──────────────────────────────────────────────────────────────┘        
""", group_management_print, NOT_IN_GROUP, self.lines, self.contact_list, self.group_name)

        self.assert_prints("""\
        ┌──────────────────────────────────────────────────────────────┐        
        │           Following unknown accounts were ignored:           │        
        │   * Alice                                                    │        
        │   * zwp3dykiztmeils2u5eqjtdtx5x3kti5ktjthpkznku3ws5u5fq2bnad │        
        └──────────────────────────────────────────────────────────────┘        
""", group_management_print, UNKNOWN_ACCOUNTS, self.lines, self.contact_list, self.group_name)


class TestMPrint(TFCTestCase):

    long_msg = ("Lorem ipsum dolor sit amet, consectetur adipiscing elit. Aenean condimentum consectetur purus quis"
                " dapibus. Fusce venenatis lacus ut rhoncus faucibus. Cras sollicitudin commodo sapien, sed bibendu"
                "m velit maximus in. Aliquam ac metus risus. Sed cursus ornare luctus. Integer aliquet lectus id ma"
                "ssa blandit imperdiet. Ut sed massa eget quam facilisis rutrum. Mauris eget luctus nisl. Sed ut el"
                "it iaculis, faucibus lacus eget, sodales magna. Nunc sed commodo arcu. In hac habitasse platea dic"
                "tumst. Integer luctus aliquam justo, at vestibulum dolor iaculis ac. Etiam laoreet est eget odio r"
                "utrum, vel malesuada lorem rhoncus. Cras finibus in neque eu euismod. Nulla facilisi. Nunc nec ali"
                "quam quam, quis ullamcorper leo. Nunc egestas lectus eget est porttitor, in iaculis felis sceleris"
                "que. In sem elit, fringilla id viverra commodo, sagittis varius purus. Pellentesque rutrum loborti"
                "s neque a facilisis. Mauris id tortor placerat, aliquam dolor ac, venenatis arcu.")

    @mock.patch('builtins.input', return_value='')
    def test_m_print(self, _):
        self.assert_prints("Test message\n", m_print, ["Test message"], center=False)
        self.assert_prints("Test message\n", m_print, "Test message", center=False)

    def test_long_message(self):
        self.assert_prints("""\
Lorem ipsum dolor sit amet, consectetur adipiscing elit. Aenean condimentum
consectetur purus quis dapibus. Fusce venenatis lacus ut rhoncus faucibus.
Cras sollicitudin commodo sapien, sed bibendum velit maximus in. Aliquam ac
metus risus. Sed cursus ornare luctus. Integer aliquet lectus id massa blandit
imperdiet. Ut sed massa eget quam facilisis rutrum. Mauris eget luctus nisl.
Sed ut elit iaculis, faucibus lacus eget, sodales magna. Nunc sed commodo
arcu. In hac habitasse platea dictumst. Integer luctus aliquam justo, at
vestibulum dolor iaculis ac. Etiam laoreet est eget odio rutrum, vel malesuada
lorem rhoncus. Cras finibus in neque eu euismod. Nulla facilisi. Nunc nec
aliquam quam, quis ullamcorper leo. Nunc egestas lectus eget est porttitor, in
iaculis felis scelerisque. In sem elit, fringilla id viverra commodo, sagittis
varius purus. Pellentesque rutrum lobortis neque a facilisis. Mauris id tortor
placerat, aliquam dolor ac, venenatis arcu.
""", m_print, TestMPrint.long_msg, center=False)

        self.assert_prints("""\
┌──────────────────────────────────────────────────────────────────────────────┐
│ Lorem ipsum dolor sit amet, consectetur adipiscing elit. Aenean condimentum  │
│  consectetur purus quis dapibus. Fusce venenatis lacus ut rhoncus faucibus.  │
│ Cras sollicitudin commodo sapien, sed bibendum velit maximus in. Aliquam ac  │
│    metus risus. Sed cursus ornare luctus. Integer aliquet lectus id massa    │
│   blandit imperdiet. Ut sed massa eget quam facilisis rutrum. Mauris eget    │
│  luctus nisl. Sed ut elit iaculis, faucibus lacus eget, sodales magna. Nunc  │
│  sed commodo arcu. In hac habitasse platea dictumst. Integer luctus aliquam  │
│  justo, at vestibulum dolor iaculis ac. Etiam laoreet est eget odio rutrum,  │
│     vel malesuada lorem rhoncus. Cras finibus in neque eu euismod. Nulla     │
│  facilisi. Nunc nec aliquam quam, quis ullamcorper leo. Nunc egestas lectus  │
│ eget est porttitor, in iaculis felis scelerisque. In sem elit, fringilla id  │
│ viverra commodo, sagittis varius purus. Pellentesque rutrum lobortis neque a │
│   facilisis. Mauris id tortor placerat, aliquam dolor ac, venenatis arcu.    │
└──────────────────────────────────────────────────────────────────────────────┘
""", m_print, TestMPrint.long_msg, center=False, box=True)

        self.assert_prints(f"""\
{BOLD_ON}┌──────────────────────────────────────────────────────────────────────────────┐{NORMAL_TEXT}
{BOLD_ON}│ Lorem ipsum dolor sit amet, consectetur adipiscing elit. Aenean condimentum  │{NORMAL_TEXT}
{BOLD_ON}│  consectetur purus quis dapibus. Fusce venenatis lacus ut rhoncus faucibus.  │{NORMAL_TEXT}
{BOLD_ON}│ Cras sollicitudin commodo sapien, sed bibendum velit maximus in. Aliquam ac  │{NORMAL_TEXT}
{BOLD_ON}│    metus risus. Sed cursus ornare luctus. Integer aliquet lectus id massa    │{NORMAL_TEXT}
{BOLD_ON}│   blandit imperdiet. Ut sed massa eget quam facilisis rutrum. Mauris eget    │{NORMAL_TEXT}
{BOLD_ON}│  luctus nisl. Sed ut elit iaculis, faucibus lacus eget, sodales magna. Nunc  │{NORMAL_TEXT}
{BOLD_ON}│  sed commodo arcu. In hac habitasse platea dictumst. Integer luctus aliquam  │{NORMAL_TEXT}
{BOLD_ON}│  justo, at vestibulum dolor iaculis ac. Etiam laoreet est eget odio rutrum,  │{NORMAL_TEXT}
{BOLD_ON}│     vel malesuada lorem rhoncus. Cras finibus in neque eu euismod. Nulla     │{NORMAL_TEXT}
{BOLD_ON}│  facilisi. Nunc nec aliquam quam, quis ullamcorper leo. Nunc egestas lectus  │{NORMAL_TEXT}
{BOLD_ON}│ eget est porttitor, in iaculis felis scelerisque. In sem elit, fringilla id  │{NORMAL_TEXT}
{BOLD_ON}│ viverra commodo, sagittis varius purus. Pellentesque rutrum lobortis neque a │{NORMAL_TEXT}
{BOLD_ON}│   facilisis. Mauris id tortor placerat, aliquam dolor ac, venenatis arcu.    │{NORMAL_TEXT}
{BOLD_ON}└──────────────────────────────────────────────────────────────────────────────┘{NORMAL_TEXT}
""", m_print, TestMPrint.long_msg, center=False, box=True, bold=True)

    def test_multi_line(self):
        self.assert_prints("""\
                                  ┌─────────┐                                   
                                  │  Test   │                                   
                                  │         │                                   
                                  │ message │                                   
                                  └─────────┘                                   
""", m_print, ["Test", '', "message"], box=True)

    def test_head_and_tail(self):
        self.assert_prints("""\
[2J[H

                                    ┌──────┐                                    
                                    │ Test │                                    
                                    └──────┘                                    

[2J[H""", m_print, ["Test"], box=True, head_clear=True, tail_clear=True, head=2, tail=1)

    def test_wrapping(self):
        self.assert_prints("""\
┌──────────────────────────────────────────────────────────────────────────────┐
│                                short message                                 │
│ Lorem ipsum dolor sit amet, consectetur adipiscing elit. Aenean condimentum  │
│  consectetur purus quis dapibus. Fusce venenatis lacus ut rhoncus faucibus.  │
│ Cras sollicitudin commodo sapien, sed bibendum velit maximus in. Aliquam ac  │
│    metus risus. Sed cursus ornare luctus. Integer aliquet lectus id massa    │
│   blandit imperdiet. Ut sed massa eget quam facilisis rutrum. Mauris eget    │
│  luctus nisl. Sed ut elit iaculis, faucibus lacus eget, sodales magna. Nunc  │
│  sed commodo arcu. In hac habitasse platea dictumst. Integer luctus aliquam  │
│  justo, at vestibulum dolor iaculis ac. Etiam laoreet est eget odio rutrum,  │
│     vel malesuada lorem rhoncus. Cras finibus in neque eu euismod. Nulla     │
│  facilisi. Nunc nec aliquam quam, quis ullamcorper leo. Nunc egestas lectus  │
│ eget est porttitor, in iaculis felis scelerisque. In sem elit, fringilla id  │
│ viverra commodo, sagittis varius purus. Pellentesque rutrum lobortis neque a │
│   facilisis. Mauris id tortor placerat, aliquam dolor ac, venenatis arcu.    │
└──────────────────────────────────────────────────────────────────────────────┘
""", m_print, ["short message", TestMPrint.long_msg], box=True)

    @mock.patch("builtins.input", return_value='')
    def test_manual_proceed(self, _):
        self.assertIsNone(m_print("test", manual_proceed=True))


class TestPhase(unittest.TestCase):

    @mock.patch('time.sleep', return_value=None)
    def test_phase(self, _):
        self.assertIsNone(phase('Entering phase'))
        self.assertIsNone(phase(DONE))
        self.assertIsNone(phase('Starting phase', head=1, offset=len("Finished")))
        self.assertIsNone(phase('Finished', done=True))


class TestPrintFingerprint(TFCTestCase):

    def test_print_fingerprints(self):
        self.assert_prints("""\
                       ┌───────────────────────────────┐                        
                       │     Fingerprint for Alice     │                        
                       │                               │                        
                       │ 45408 66244 60063 51146 49842 │                        
                       │ 54936 03101 11892 94057 51231 │                        
                       │ 59374 09637 58434 47573 71137 │                        
                       └───────────────────────────────┘                        \n""",
                           print_fingerprint, FINGERPRINT_LENGTH * b'\x01', 'Fingerprint for Alice')


class TestPrintKey(TFCTestCase):

    def setUp(self):
        self.settings = Settings()

    def test_print_kdk(self):
        self.assert_prints("""\
    ┌─────────────────────────────────────────────────────────────────────┐     
    │               Local key decryption key (to Receiver)                │     
    │  A   B   C   D   E   F   G   H   I   J   K   L   M   N   O   P   Q  │     
    │ 5Hp Hag T65 TZz G1P H3C Su6 3k8 Dbp vD8 s5i p4n EB3 kEs reA bua tmU │     
    └─────────────────────────────────────────────────────────────────────┘     \n""",
                           print_key, "Local key decryption key (to Receiver)",
                           bytes(SYMMETRIC_KEY_LENGTH), self.settings)

    def test_print_kdk_local_testing(self):
        self.settings.local_testing_mode = True
        self.assert_prints("""\
            ┌─────────────────────────────────────────────────────┐             
            │       Local key decryption key (to Receiver)        │             
            │ 5HpHagT65TZzG1PH3CSu63k8DbpvD8s5ip4nEB3kEsreAbuatmU │             
            └─────────────────────────────────────────────────────┘             \n""",
                           print_key, "Local key decryption key (to Receiver)",
                           bytes(SYMMETRIC_KEY_LENGTH), self.settings)


class TestPrintTitle(TFCTestCase):

    def test_print_tx_title(self):
        self.assert_prints(f"""\
{CLEAR_ENTIRE_SCREEN+CURSOR_LEFT_UP_CORNER}
{BOLD_ON}                           TFC - Transmitter {VERSION}                            {NORMAL_TEXT}\n
""", print_title, TX)

    def test_print_rx_title(self):
        self.assert_prints(f"""\
{CLEAR_ENTIRE_SCREEN+CURSOR_LEFT_UP_CORNER}
{BOLD_ON}                             TFC - Receiver {VERSION}                             {NORMAL_TEXT}\n
""", print_title, RX)


class TestPrintOnPreviousLine(TFCTestCase):

    def test_print_on_previous_line(self):
        self.assert_prints(CURSOR_UP_ONE_LINE + CLEAR_ENTIRE_LINE, print_on_previous_line)
        self.assert_prints(2 * (CURSOR_UP_ONE_LINE + CLEAR_ENTIRE_LINE), print_on_previous_line, reps=2)
        self.assert_prints(2 * (CURSOR_UP_ONE_LINE + CLEAR_ENTIRE_LINE), print_on_previous_line, reps=2, flush=True)


class TestPrintSpacing(TFCTestCase):

    def test_print_spacing(self):
        for i in range(20):
            self.assert_prints(i * '\n', print_spacing, i)


class TestRPPrint(TFCTestCase):

    def setUp(self):
        self.ts        = datetime.now()
        self.timestamp = self.ts.strftime("%b %d - %H:%M:%S.%f")[:-4]

    def test_bold_print(self):
        self.assert_prints(f"{BOLD_ON}{self.timestamp} - testMessage{NORMAL_TEXT}\n",
                           rp_print, "testMessage", self.ts, bold=True)

    def test_normal_print(self):
        self.assert_prints(f"{self.timestamp} - testMessage\n", rp_print, "testMessage", self.ts, bold=False)

    def test_works_without_timestamp(self):
        self.assertIsNone(rp_print("testMessage"))


if __name__ == '__main__':
    unittest.main(exit=False)
