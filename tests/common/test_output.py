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
import unittest

from src.common.output  import box_print, c_print, clear_screen, group_management_print, message_printer
from src.common.output  import phase, print_fingerprint, print_key, print_on_previous_line
from src.common.statics import *

from tests.mock_classes import ContactList, Settings
from tests.utils        import TFCTestCase


class TestBoxPrint(TFCTestCase):

    def setUp(self):
        self.o_input = builtins.input
        builtins.input = lambda _: ''

    def tearDown(self):
        builtins.input = self.o_input

    def test_box_print(self):
        self.assertIsNone(box_print("Test message", manual_proceed=True))
        self.assertPrints("""
                                ┌──────────────┐                                
                                │ Test message │                                
                                └──────────────┘                                \n
""", box_print, "Test message", head=1, tail=1)

        self.assertPrints("""
                              ┌─────────────────┐                               
                              │  Test message   │                               
                              │                 │                               
                              │ Another message │                               
                              └─────────────────┘                               \n
""", box_print, ["Test message", '', "Another message"], head=1, tail=1)


class TestCPrint(TFCTestCase):

    def test_c_print(self):
        self.assertPrints("""
                                  Test message                                  \n
""", c_print, 'Test message', head=1, tail=1)


class TestClearScreen(TFCTestCase):

    def test_clear_screen(self):
        self.assertPrints(CLEAR_ENTIRE_SCREEN + CURSOR_LEFT_UP_CORNER, clear_screen)


class TestGroupManagementPrint(TFCTestCase):

    def setUp(self):
        self.contact_list = ContactList(nicks=['Alice'])

    def test_group_management_print(self):
        self.assertPrints("""
           ┌───────────────────────────────────────────────────────┐            
           │ Created new group 'testgroup' with following members: │            
           │                    * Alice                            │            
           │                    * bob@jabber.org                   │            
           └───────────────────────────────────────────────────────┘            \n
""", group_management_print, NEW_GROUP, ['alice@jabber.org', 'bob@jabber.org'], self.contact_list, group_name='testgroup')

        self.assertPrints("""
               ┌────────────────────────────────────────────────┐               
               │ Added following accounts to group 'testgroup': │               
               │                 * Alice                        │               
               │                 * bob@jabber.org               │               
               └────────────────────────────────────────────────┘               \n
""", group_management_print, ADDED_MEMBERS, ['alice@jabber.org', 'bob@jabber.org'], self.contact_list, group_name='testgroup')

        self.assertPrints("""
           ┌───────────────────────────────────────────────────────┐            
           │ Following accounts were already in group 'testgroup': │            
           │                    * Alice                            │            
           │                    * bob@jabber.org                   │            
           └───────────────────────────────────────────────────────┘            \n
""", group_management_print, ALREADY_MEMBER, ['alice@jabber.org', 'bob@jabber.org'], self.contact_list, group_name='testgroup')

        self.assertPrints("""
             ┌───────────────────────────────────────────────────┐              
             │ Removed following members from group 'testgroup': │              
             │                  * Alice                          │              
             │                  * bob@jabber.org                 │              
             └───────────────────────────────────────────────────┘              \n
""", group_management_print, REMOVED_MEMBERS, ['alice@jabber.org', 'bob@jabber.org'], self.contact_list, group_name='testgroup')

        self.assertPrints("""
             ┌───────────────────────────────────────────────────┐              
             │ Following accounts were not in group 'testgroup': │              
             │                  * Alice                          │              
             │                  * bob@jabber.org                 │              
             └───────────────────────────────────────────────────┘              \n
""", group_management_print, NOT_IN_GROUP, ['alice@jabber.org', 'bob@jabber.org'], self.contact_list, group_name='testgroup')

        self.assertPrints("""
                  ┌──────────────────────────────────────────┐                  
                  │ Following unknown accounts were ignored: │                  
                  │              * Alice                     │                  
                  │              * bob@jabber.org            │                  
                  └──────────────────────────────────────────┘                  \n
""", group_management_print, UNKNOWN_ACCOUNTS, ['alice@jabber.org', 'bob@jabber.org'], self.contact_list, group_name='testgroup')


class TestMessagePrinter(TFCTestCase):

    def test_message_printer(self):
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

        self.assertPrints("""\

                    Lorem ipsum dolor sit amet, consectetur                     
                adipiscing elit. Aenean condimentum consectetur                 
                  purus quis dapibus. Fusce venenatis lacus ut                  
                  rhoncus faucibus. Cras sollicitudin commodo                   
               sapien, sed bibendum velit maximus in. Aliquam ac                
                 metus risus. Sed cursus ornare luctus. Integer                 
               aliquet lectus id massa blandit imperdiet. Ut sed                
                 massa eget quam facilisis rutrum. Mauris eget                  
                luctus nisl. Sed ut elit iaculis, faucibus lacus                
                 eget, sodales magna. Nunc sed commodo arcu. In                 
                 hac habitasse platea dictumst. Integer luctus                  
                 aliquam justo, at vestibulum dolor iaculis ac.                 
               Etiam laoreet est eget odio rutrum, vel malesuada                
                lorem rhoncus. Cras finibus in neque eu euismod.                
                  Nulla facilisi. Nunc nec aliquam quam, quis                   
                 ullamcorper leo. Nunc egestas lectus eget est                  
                porttitor, in iaculis felis scelerisque. In sem                 
                  elit, fringilla id viverra commodo, sagittis                  
                varius purus. Pellentesque rutrum lobortis neque                
                a facilisis. Mauris id tortor placerat, aliquam                 
                           dolor ac, venenatis arcu.                            \n
""", message_printer, long_msg, head=1, tail=1)


class TestPhase(unittest.TestCase):

    def test_phase(self):
        self.assertIsNone(phase('Entering phase'))
        self.assertIsNone(phase(DONE))
        self.assertIsNone(phase('Starting phase', head=1, offset=len("Finished")))
        self.assertIsNone(phase('Finished', done=True))


class TestPrintFingerprint(TFCTestCase):

    def test_print_fingerprints(self):
        self.assertPrints("""\
                       ┌───────────────────────────────┐                        
                       │     Fingerprint for Alice     │                        
                       │                               │                        
                       │ 45408 66244 60063 51146 49842 │                        
                       │ 54936 03101 11892 94057 51231 │                        
                       │ 59374 09637 58434 47573 71137 │                        
                       └───────────────────────────────┘                        \n""",
                          print_fingerprint, FINGERPRINT_LEN * b'\x01', 'Fingerprint for Alice')


class TestPrintKey(TFCTestCase):

    def setUp(self):
        self.settings = Settings()

    def test_print_kdk(self):
        self.assertPrints("""\
    ┌─────────────────────────────────────────────────────────────────────┐     
    │                  Local key decryption key (to RxM)                  │     
    │  A   B   C   D   E   F   G   H   I   J   K   L   M   N   O   P   Q  │     
    │ 5Hp Hag T65 TZz G1P H3C Su6 3k8 Dbp vD8 s5i p4n EB3 kEs reA bua tmU │     
    └─────────────────────────────────────────────────────────────────────┘     
""", print_key, "Local key decryption key (to RxM)", bytes(32), self.settings)

        self.settings.local_testing_mode = True
        self.assertPrints("""\
            ┌─────────────────────────────────────────────────────┐             
            │          Local key decryption key (to RxM)          │             
            │ 5HpHagT65TZzG1PH3CSu63k8DbpvD8s5ip4nEB3kEsreAbuatmU │             
            └─────────────────────────────────────────────────────┘             
""", print_key, "Local key decryption key (to RxM)", bytes(32), self.settings)


class TestPrintOnPreviousLine(TFCTestCase):

    def test_print_on_previous_line(self):
        self.assertPrints(CURSOR_UP_ONE_LINE + CLEAR_ENTIRE_LINE, print_on_previous_line)
        self.assertPrints(2*(CURSOR_UP_ONE_LINE + CLEAR_ENTIRE_LINE), print_on_previous_line, reps=2)
        self.assertPrints(2*(CURSOR_UP_ONE_LINE + CLEAR_ENTIRE_LINE), print_on_previous_line, reps=2, flush=True)


if __name__ == '__main__':
    unittest.main(exit=False)
