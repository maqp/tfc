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

import argparse
import os
import threading
import time
import types
import unittest
import zlib

from multiprocessing import Process
from unittest        import mock

from src.common.misc    import calculate_race_condition_delay, decompress, ensure_dir, get_tab_complete_list
from src.common.misc    import get_tab_completer, get_terminal_height, get_terminal_width, ignored, monitor_processes
from src.common.misc    import process_arguments, readable_size, round_up, separate_header, separate_headers
from src.common.misc    import separate_trailer, split_string, split_byte_string, terminal_width_check
from src.common.misc    import validate_group_name, validate_key_exchange, validate_onion_addr, validate_nick
from src.common.statics import *

from tests.mock_classes import ContactList, Gateway, GroupList, Settings
from tests.utils        import cd_unit_test, cleanup, gen_queue_dict, ignored, nick_to_onion_address
from tests.utils        import nick_to_pub_key, tear_queues, TFCTestCase


class TestCalculateRaceConditionDelay(unittest.TestCase):

    def setUp(self):
        self.settings = Settings()

    def test_race_condition_delay_calculation(self):
        self.assertIsInstance(calculate_race_condition_delay(5, 9600), float)


class TestDecompress(TFCTestCase):

    def setUp(self):
        self.settings                     = Settings()
        self.settings.max_decompress_size = 1000

    def test_successful_decompression(self):
        # Setup
        data       = os.urandom(self.settings.max_decompress_size)
        compressed = zlib.compress(data)

        # Test
        self.assertEqual(decompress(compressed, self.settings.max_decompress_size), data)

    def test_oversize_decompression_raises_fr(self):
        # Setup
        data       = os.urandom(self.settings.max_decompress_size + 1)
        compressed = zlib.compress(data)

        # Test
        self.assert_fr("Error: Decompression aborted due to possible zip bomb.",
                       decompress, compressed, self.settings.max_decompress_size)


class TestEnsureDir(unittest.TestCase):

    def tearDown(self):
        with ignored(OSError):
            os.rmdir('test_dir/')

    def test_ensure_dir(self):
        self.assertIsNone(ensure_dir('test_dir/'))
        self.assertIsNone(ensure_dir('test_dir/'))
        self.assertTrue(os.path.isdir('test_dir/'))


class TestTabCompleteList(unittest.TestCase):

    def setUp(self):
        self.contact_list = ContactList(nicks=['Alice', 'Bob'])
        self.group_list   = GroupList(groups=['test_group'])
        self.settings     = Settings(key_list=['key1', 'key2'])
        self.gateway      = Gateway()

    def test_get_tab_complete_list(self):
        tab_complete_list  = [a + ' ' for a in self.contact_list.get_list_of_addresses()]
        tab_complete_list += [i + ' ' for i in self.group_list.get_list_of_hr_group_ids()]
        tab_complete_list += [s + ' ' for s in self.settings.key_list]
        tab_complete_list += [s + ' ' for s in self.gateway.settings.key_list]

        tc_list = get_tab_complete_list(self.contact_list, self.group_list, self.settings, self.gateway)
        self.assertTrue(set(tab_complete_list) < set(tc_list))
        self.assertIsInstance(get_tab_completer(self.contact_list, self.group_list, self.settings, self.gateway),
                              types.FunctionType)

        completer = get_tab_completer(self.contact_list, self.group_list, self.settings, self.gateway)
        options   = completer('a', state=0)

        self.assertEqual(options, 'all')
        self.assertIsNone(completer('a', state=5))


class TestGetTerminalHeight(unittest.TestCase):

    def test_get_terminal_height(self):
        self.assertIsInstance(get_terminal_height(), int)


class TestGetTerminalWidth(unittest.TestCase):

    def test_get_terminal_width(self):
        self.assertIsInstance(get_terminal_width(), int)


class TestIgnored(unittest.TestCase):

    @staticmethod
    def func():
        """Mock function that raises exception."""
        raise KeyboardInterrupt

    def test_ignored_contextmanager(self):
        raised = False
        try:
            with ignored(KeyboardInterrupt):
                TestIgnored.func()
        except KeyboardInterrupt:
            raised = True
        self.assertFalse(raised)


class TestMonitorProcesses(TFCTestCase):

    def setUp(self):
        self.unit_test_dir = cd_unit_test()
        self.settings      = Settings()

    def tearDown(self):
        cleanup(self.unit_test_dir)

    @staticmethod
    def mock_process():
        """Mock process that does not return."""
        while True:
            time.sleep(0.01)

    @mock.patch('time.sleep', return_value=None)
    def test_exit(self, *_):
        queues       = gen_queue_dict()
        process_list = [Process(target=self.mock_process)]

        for p in process_list:
            p.start()

        def queue_delayer():
            """Place EXIT packet into queue after delay."""
            time.sleep(0.01)
            queues[EXIT_QUEUE].put(EXIT)
        threading.Thread(target=queue_delayer).start()

        with self.assertRaises(SystemExit):
            monitor_processes(process_list, RX, queues)

        tear_queues(queues)

    @mock.patch('time.sleep', return_value=None)
    def test_dying_process(self, *_):

        def mock_process():
            """Function that returns after a moment."""
            time.sleep(0.01)

        queues       = gen_queue_dict()
        process_list = [Process(target=mock_process)]

        for p in process_list:
            p.start()

        with self.assertRaises(SystemExit):
            monitor_processes(process_list, RX, queues)

        tear_queues(queues)

    @mock.patch('time.sleep', return_value=None)
    @mock.patch('os.system', return_value=None)
    def test_wipe(self, mock_os_system, *_):
        queues       = gen_queue_dict()
        process_list = [Process(target=self.mock_process)]

        os.mkdir(DIR_USER_DATA)
        os.mkdir(DIR_RECV_FILES)
        self.assertTrue(os.path.isdir(DIR_USER_DATA))
        self.assertTrue(os.path.isdir(DIR_RECV_FILES))

        for p in process_list:
            p.start()

        def queue_delayer():
            """Place WIPE packet to queue after delay."""
            time.sleep(0.01)
            queues[EXIT_QUEUE].put(WIPE)
        threading.Thread(target=queue_delayer).start()

        with self.assertRaises(SystemExit):
            monitor_processes(process_list, RX, queues)
        self.assertFalse(os.path.isdir(DIR_USER_DATA))
        self.assertFalse(os.path.isdir(DIR_RECV_FILES))
        mock_os_system.assert_called_with('poweroff')

        tear_queues(queues)

    @mock.patch('time.sleep', return_value=None)
    @mock.patch('os.system', return_value=None)
    @mock.patch('subprocess.check_output', lambda *popenargs, timeout=None, **kwargs: TAILS)
    def test_wipe_tails(self, mock_os_system, *_):
        queues       = gen_queue_dict()
        process_list = [Process(target=self.mock_process)]

        os.mkdir(DIR_USER_DATA)
        self.assertTrue(os.path.isdir(DIR_USER_DATA))

        for p in process_list:
            p.start()

        def queue_delayer():
            """Place WIPE packet to queue after delay."""
            time.sleep(0.01)
            queues[EXIT_QUEUE].put(WIPE)
        threading.Thread(target=queue_delayer).start()

        with self.assertRaises(SystemExit):
            monitor_processes(process_list, RX, queues)

        mock_os_system.assert_called_with('poweroff')

        # Test that user data wasn't removed
        self.assertTrue(os.path.isdir(DIR_USER_DATA))
        tear_queues(queues)


class TestProcessArguments(unittest.TestCase):

    def setUp(self):
        class MockParser(object):
            """MockParse object."""
            def __init__(self, *_, **__):
                pass

            def parse_args(self):
                """Return Args mock object."""

                class Args(object):
                    """Mock object for command line arguments."""
                    def __init__(self):
                        """Create new Args mock object."""
                        self.operation          = True
                        self.local_test         = True
                        self.data_diode_sockets = True
                args = Args()
                return args

            def add_argument(self, *_, **__):
                """Mock function for adding argument."""
                pass

        self.o_argparse         = argparse.ArgumentParser
        argparse.ArgumentParser = MockParser

    def tearDown(self):
        argparse.ArgumentParser = self.o_argparse

    def test_process_arguments(self):
        self.assertEqual(process_arguments(), (RX, True, True))


class TestReadableSize(unittest.TestCase):

    def test_readable_size(self):
        sizes = ['', 'K', 'M', 'G', 'T', 'P', 'E', 'Z', 'Y']
        for i in range(0, 9):
            size = readable_size(1024 ** i)
            self.assertEqual(size, f'1.0{sizes[i]}B')


class TestRoundUp(unittest.TestCase):

    def test_round_up(self):
        self.assertEqual(round_up(1),  10)
        self.assertEqual(round_up(5),  10)
        self.assertEqual(round_up(8),  10)
        self.assertEqual(round_up(10), 10)
        self.assertEqual(round_up(11), 20)
        self.assertEqual(round_up(15), 20)
        self.assertEqual(round_up(18), 20)
        self.assertEqual(round_up(20), 20)
        self.assertEqual(round_up(21), 30)


class TestSplitString(unittest.TestCase):

    def test_split_string(self):
        self.assertEqual(split_string('cypherpunk', 1),  ['c',
                                                          'y',
                                                          'p',
                                                          'h',
                                                          'e',
                                                          'r',
                                                          'p',
                                                          'u',
                                                          'n',
                                                          'k'])

        self.assertEqual(split_string('cypherpunk', 2),  ['cy',
                                                          'ph',
                                                          'er',
                                                          'pu',
                                                          'nk'])

        self.assertEqual(split_string('cypherpunk', 3),  ['cyp',
                                                          'her',
                                                          'pun',
                                                          'k'])

        self.assertEqual(split_string('cypherpunk', 5),  ['cyphe',
                                                          'rpunk'])

        self.assertEqual(split_string('cypherpunk', 10), ['cypherpunk'])
        self.assertEqual(split_string('cypherpunk', 15), ['cypherpunk'])


class TestSplitByteString(unittest.TestCase):

    def test_split_byte_string(self):
        self.assertEqual(split_byte_string(b'cypherpunk', 1),  [b'c',
                                                                b'y',
                                                                b'p',
                                                                b'h',
                                                                b'e',
                                                                b'r',
                                                                b'p',
                                                                b'u',
                                                                b'n',
                                                                b'k'])

        self.assertEqual(split_byte_string(b'cypherpunk', 2),  [b'cy',
                                                                b'ph',
                                                                b'er',
                                                                b'pu',
                                                                b'nk'])

        self.assertEqual(split_byte_string(b'cypherpunk', 3),  [b'cyp',
                                                                b'her',
                                                                b'pun',
                                                                b'k'])

        self.assertEqual(split_byte_string(b'cypherpunk', 5),  [b'cyphe',
                                                                b'rpunk'])

        self.assertEqual(split_byte_string(b'cypherpunk', 10), [b'cypherpunk'])
        self.assertEqual(split_byte_string(b'cypherpunk', 15), [b'cypherpunk'])


class TestSeparateHeader(unittest.TestCase):

    def test_separate_header(self):
        self.assertEqual(separate_header(b"cypherpunk", header_length=len(b"cypher")),
                         (b"cypher", b"punk"))


class TestSeparateHeaders(unittest.TestCase):

    def test_separate_headers(self):
        self.assertEqual(separate_headers(b"cypherpunk", header_length_list=[1, 2, 3]),
                         [b"c", b"yp", b"her", b"punk"])

    def test_too_small_string(self):
        self.assertEqual(separate_headers(b"cypherpunk", header_length_list=[1, 2, 10]),
                         [b"c", b"yp", b"herpunk", b""])


class TestSeparateTrailer(unittest.TestCase):

    def test_separate_header(self):
        self.assertEqual(separate_trailer(b"cypherpunk", trailer_length=len(b"punk")),
                         (b"cypher", b"punk"))


class TestTerminalWidthCheck(unittest.TestCase):

    @mock.patch('time.sleep',               return_value=None)
    @mock.patch('shutil.get_terminal_size', side_effect=[[50, 50], [50, 50], [100, 100]])
    def test_width_check(self, *_):
        self.assertIsNone(terminal_width_check(80))


class TestValidateOnionAddr(unittest.TestCase):

    def test_validate_account(self):
        user_account = nick_to_onion_address("Bob")
        self.assertEqual(validate_onion_addr(nick_to_onion_address("Alice"),            user_account),
                         '')
        self.assertEqual(validate_onion_addr(nick_to_onion_address("Bob"),              user_account),
                         'Error: Can not add own account.')
        self.assertEqual(validate_onion_addr(nick_to_onion_address("Alice")[:-1] + 'a', user_account),
                         'Checksum error - Check that the entered account is correct.')
        self.assertEqual(validate_onion_addr(nick_to_onion_address("Alice")[:-1] + '%', user_account),
                         'Error: Invalid account format.')
        self.assertEqual(validate_onion_addr(nick_to_onion_address("Alice")      + 'a', user_account),
                         'Error: Invalid account format.')
        self.assertEqual(validate_onion_addr(nick_to_onion_address("Alice")[:-1] + '€', user_account),
                         'Error: Invalid account format.')
        self.assertEqual(validate_onion_addr(LOCAL_ID,                                  user_account),
                         'Error: Can not add reserved account.')


class TestValidateGroupName(unittest.TestCase):

    def setUp(self):
        self.contact_list = ContactList(nicks=['Alice'])
        self.group_list   = GroupList(groups=['test_group'])

    def test_validate_group_name(self):
        self.assertEqual(validate_group_name('test_group\x1f',               self.contact_list, self.group_list),
                         "Error: Group name must be printable.")
        self.assertEqual(validate_group_name(PADDING_LENGTH * 'a',           self.contact_list, self.group_list),
                         "Error: Group name must be less than 255 chars long.")
        self.assertEqual(validate_group_name(DUMMY_GROUP,                    self.contact_list, self.group_list),
                         "Error: Group name cannot use the name reserved for database padding.")
        self.assertEqual(validate_group_name(nick_to_onion_address("Alice"), self.contact_list, self.group_list),
                         "Error: Group name cannot have the format of an account.")
        self.assertEqual(validate_group_name('Alice',                        self.contact_list, self.group_list),
                         "Error: Group name cannot be a nick of contact.")
        self.assertEqual(validate_group_name('test_group',                   self.contact_list, self.group_list),
                         "Error: Group with name 'test_group' already exists.")
        self.assertEqual(validate_group_name('test_group2',                  self.contact_list, self.group_list),
                         '')


class TestValidateKeyExchange(unittest.TestCase):

    def test_validate_key_exchange(self):
        self.assertEqual(validate_key_exchange(''),            'Invalid key exchange selection.')
        self.assertEqual(validate_key_exchange('x2'),          'Invalid key exchange selection.')
        self.assertEqual(validate_key_exchange('x'),           '')
        self.assertEqual(validate_key_exchange('X'),           '')
        self.assertEqual(validate_key_exchange(ECDHE),         '')
        self.assertEqual(validate_key_exchange(ECDHE.lower()), '')
        self.assertEqual(validate_key_exchange('p'),           '')
        self.assertEqual(validate_key_exchange('P'),           '')
        self.assertEqual(validate_key_exchange('psk'),         '')
        self.assertEqual(validate_key_exchange('PSK'),         '')


class TestValidateNick(unittest.TestCase):

    def setUp(self):
        self.contact_list = ContactList(nicks=['Alice', 'Bob'])
        self.group_list   = GroupList(groups=['test_group'])

    def test_validate_nick(self):
        self.assertEqual(validate_nick("Alice_",                   (self.contact_list, self.group_list, nick_to_pub_key(
            "Alice"))), '')
        self.assertEqual(validate_nick(254 * "a",                  (self.contact_list, self.group_list, nick_to_pub_key(
            "Alice"))), '')
        self.assertEqual(validate_nick(255 * "a",                  (self.contact_list, self.group_list, nick_to_pub_key(
            "Alice"))), 'Error: Nick must be shorter than 255 chars.')
        self.assertEqual(validate_nick("\x01Alice",                (self.contact_list, self.group_list, nick_to_pub_key(
            "Alice"))), 'Error: Nick must be printable.')
        self.assertEqual(validate_nick('',                         (self.contact_list, self.group_list, nick_to_pub_key(
            "Alice"))), "Error: Nick cannot be empty.")
        self.assertEqual(validate_nick('Me',                       (self.contact_list, self.group_list, nick_to_pub_key(
            "Alice"))), "Error: 'Me' is a reserved nick.")
        self.assertEqual(validate_nick('-!-',                      (self.contact_list, self.group_list, nick_to_pub_key(
            "Alice"))), "Error: '-!-' is a reserved nick.")
        self.assertEqual(validate_nick(LOCAL_ID,                   (self.contact_list, self.group_list, nick_to_pub_key(
            "Alice"))), "Error: Nick cannot have the format of an account.")
        self.assertEqual(validate_nick(nick_to_onion_address('A'), (self.contact_list, self.group_list, nick_to_pub_key(
            "Alice"))), "Error: Nick cannot have the format of an account.")
        self.assertEqual(validate_nick('Bob',                      (self.contact_list, self.group_list, nick_to_pub_key(
            "Alice"))), 'Error: Nick already in use.')
        self.assertEqual(validate_nick("Alice",                    (self.contact_list, self.group_list, nick_to_pub_key(
            "Alice"))), '')
        self.assertEqual(validate_nick("test_group",               (self.contact_list, self.group_list, nick_to_pub_key(
            "Alice"))), "Error: Nick cannot be a group name.")


if __name__ == '__main__':
    unittest.main(exit=False)
