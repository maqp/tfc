#!/usr/bin/env python
# -*- coding: utf-8 -*-

# TFC 0.16.10 || test_rx.py

"""
Copyright (C) 2013-2016  Markus Ottela

This file is part of TFC.

TFC is free software: you can redistribute it and/or modify it under the terms
of the GNU General Public License as published by the Free Software Foundation,
either version 3 of the License, or (at your option) any later version.

TFC is distributed in the hope that it will be useful, but WITHOUT ANY
WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with
TFC. If not, see <http://www.gnu.org/licenses/>.
"""

import Rx
from Rx import *
import binascii
import os.path
import os
import shutil
import sys
import unittest


###############################################################################
#                               UNITTEST HELPERS                              #
###############################################################################

Rx.m_members_in_group = 20
Rx.m_number_of_groups = 20
Rx.m_number_of_accnts = 20

Rx.master_key = 64 * 'a'
Rx.active_window = "alice@jabber.org"
Rx.rpi_os = False
not_bool = [1.0, "string", 1]
not_str = [1, 1.0, True]
not_int = ["string", 1.0]
not_tuple = [1.0, "string", 1, True]
reed_solomon = RSCodec(2 * e_correction_ratio)


class ExtendedTestCase(unittest.TestCase):

    def assertFR(self, msg, func, *args, **kwargs):
        e_raised = False
        try:
            func(*args, **kwargs)
        except FunctionReturn as inst:
            e_raised = True
            self.assertEqual(inst.message, msg)
        self.assertTrue(e_raised)


def create_contact(nick_list,
                   u_key=64*'a', u_hek=64*'a',
                   c_key=64*'a', c_hek=64*'a', store=False):
    """
    Add entry to contact database.

    :param nick_list: List of nicks based on which accounts are created
    :param u_key:     Forward secret encryption key for sent messages
    :param u_hek:     Static header encryption key for sent messages
    :param c_key:     Forward secret encryption key for received messages
    :param c_hek:     Static header encryption key for received messages
    :param store:     When True, writes database to file    
    :return:          None
    """

    for nick in nick_list:

        if nick == "local":
            c_dictionary["local"] = dict(nick="local",
                                         u_harac=1, c_harac=1,
                                         u_key=u_key, u_hek=u_hek,
                                         c_key=c_key, c_hek=c_hek,
                                         windowp=Rx.n_m_notify_privacy,
                                         storing=Rx.store_file_default,
                                         logging=Rx.rxm_side_m_logging)

        else:
            c_dictionary["%s@jabber.org" % nick] = \
                dict(nick=nick,
                     u_harac=1, c_harac=1,
                     u_key=u_key, u_hek=u_hek,
                     c_key=c_key, c_hek=c_hek,
                     windowp=Rx.n_m_notify_privacy,
                     storing=Rx.store_file_default,
                     logging=Rx.rxm_side_m_logging)

    if store:
        contact_db(write_db=c_dictionary)


def create_group(group_data, store=False):
    """
    Add entry to group database.

    :param group_data: List of tuples containing group name and list of members
    :param store:      When True, writes database to file
    :return:           None
    """

    for group_name, nick_list in group_data:
        members = ["%s@jabber.org" % nick for nick in nick_list]
        g_dictionary[group_name] = dict(logging=Rx.rxm_side_m_logging,
                                        members=members)

    # Add dummy groups
    for i in xrange(m_number_of_groups - len(g_dictionary)):
        g_dictionary["dummy_group_%s" % i] = dict(logging="False",
                                                  members=[])

    # Add dummy members
    for g in g_dictionary:
        dummy_count = m_members_in_group - len(g_dictionary[g]["members"])
        g_dictionary[g]["members"] += dummy_count * ["dummy_member"]

    if store:
        group_db(write_db=g_dictionary)


def ut_validate_key(key):
    """
    Test that encryption key is valid.

    :param key: Key to test
    :return:    True if key was valid, else False.
    """

    if not set(key.lower()).issubset("abcdef0123456789"):
        return False
    if len(key) != 64:
        return False
    return True


def ut_ensure_dir(directory):
    """
    Ensure directory exists.

    :param directory: Directory the existence of which to ensure
    :return:          None
    """

    name = os.path.dirname(directory)
    if not os.path.exists(name):
        os.makedirs(name)


def ut_cleanup():
    """
    Remove files and directories created by tests.

    :return: None
    """

    for directory in ["unittest_directory", "received_files"]:
        try:
            shutil.rmtree(directory)
        except OSError:
            pass

    for f in [Rx.login_file, Rx.datab_file, Rx.group_file, Rx.rxlog_file,
              "tfc_unittest_doc.txt"]:
        try:
            os.remove(f)
        except OSError:
            pass

    for key in g_dictionary.keys():
        del g_dictionary[key]

    for key in c_dictionary.keys():
        del c_dictionary[key]

    for key in window_log_d.keys():
        del window_log_d[key]


def ut_encrypt(plaintext):
    """
    Encrypt plaintext for testing.

    :param plaintext: Plaintext to encrypt
    :return:          Base64 encoded nonce, ciphertext and tag
    """

    hex_key = 64 * 'a'
    s_box = nacl.secret.SecretBox(binascii.unhexlify(hex_key))
    nonce = 24 * 'a'
    return b64e(s_box.encrypt(plaintext, nonce))


def ut_yes(prompt, wsl=0):
    """
    Prompt user a question that is answered with yes / no.

    :param prompt: Question to be asked
    :param wsl:    Trailing whitespace length
    :return:       True if user types 'y' or 'yes'
                   False if user types 'n' or 'no'
    """

    input_validation((prompt, str), (wsl, int))

    while prompt.startswith('\n'):
        print('')
        prompt = prompt[1:]

    wsl = 0 if wsl < 0 else wsl
    tws = wsl * ' ' if wsl > 0 else (54 - len(prompt)) * ' '
    string = "%s (y/n):%s" % (prompt, tws)

    while True:
        answer = raw_input(string)
        print_on_previous_line()

        if answer.lower() in "yes":
            print("%sYes" % string)
            return True

        elif answer.lower() in "no":
            print("%sNo" % string)
            return False

        else:
            continue


###############################################################################
#                                CRYPTOGRAPHY                                 #
###############################################################################

class TestSHA3256(ExtendedTestCase):

    def test_1_input_parameter(self):
        for a in not_str:
            with self.assertRaises(SystemExit):
                sha3_256(a)

    def test_2_SHA3_256_KAT(self):
        """
        Test SHA3-256 with official KAT:

        csrc.nist.gov/groups/ST/toolkit/documents/Examples/SHA3-256_Msg0.pdf
        """

        self.assertEqual(sha3_256(''), "a7ffc6f8bf1ed76651c14756a061d662"
                                       "f580ff4de43b49fa82d80a4b80f8434a")


class TestPBKDF2HMACSHA256(ExtendedTestCase):

    def test_1_input_parameters(self):
        for a in not_str:
            for b in not_int:
                for c in not_str:
                    with self.assertRaises(SystemExit):
                        pbkdf2_hmac_sha256(a, b, c)

    def test_2_invalid_rounds(self):
        for i in [-1, 0]:
            with self.assertRaises(AssertionError):
                pbkdf2_hmac_sha256("password", i, "salt")

    def test_3_pbkdf2_hmac_sha256_kat(self):
        """
        Testing with only KAT that could be found:

        https://stackoverflow.com/questions/5130513/
        pbkdf2-hmac-sha2-test-vectors/5136918#5136918
        """

        self.assertEqual(pbkdf2_hmac_sha256("password", salt="salt"),
                         "120fb6cffcf8b32c43e7225256c4f837"
                         "a86548c92ccc35480805987cb70be17b")

        self.assertEqual(pbkdf2_hmac_sha256("password", 4096, "salt"),
                         "c5e478d59288c841aa530db6845c4c8d"
                         "962893a001ce4e11a4963873aa98134a")


class TestAuthAndDecrypt(ExtendedTestCase):

    def test_1_input_parameters(self):
        for a in not_str:
            for b in not_str:
                for c in not_int:
                    for d in not_int:
                        with self.assertRaises(SystemExit):
                            auth_and_decrypt(a, b, c, d)

    def test_2_auth_and_decrypt(self):

        # Setup
        create_contact(["bob"])

        # Test valid decryption
        ct_tag = ut_encrypt("plaintext")
        pt = auth_and_decrypt("bob@jabber.org", 'c', b64d(ct_tag), 1)
        self.assertEqual(pt, "plaintext")

        # Test MAC error
        ct_tag = ut_encrypt("plaintext")
        ct_tag += 'a'
        with self.assertRaises(nacl.exceptions.CryptoError):
            auth_and_decrypt("bob@jabber.org", 'c', b64d(ct_tag), 1)

        # Teardown
        ut_cleanup()

    def test_3_official_test_vectors(self):

        # Setup
        nonce = ("69696ee955b62b73"
                 "cd62bda875fc73d6"
                 "8219e0036b7a0b37")

        nonce = binascii.unhexlify(nonce)

        # Test
        key_tv_hex = ("1b27556473e985d4"
                      "62cd51197a9a46c7"
                      "6009549eac6474f2"
                      "06c4ee0844f68389")

        create_contact(["bob"])
        c_dictionary["bob@jabber.org"]["c_key"] = key_tv_hex

        pt_tv_hex = ("be075fc53c81f2d5"
                     "cf141316ebeb0c7b"
                     "5228c52a4c62cbd4"
                     "4b66849b64244ffc"
                     "e5ecbaaf33bd751a"
                     "1ac728d45e6c6129"
                     "6cdc3c01233561f4"
                     "1db66cce314adb31"
                     "0e3be8250c46f06d"
                     "ceea3a7fa1348057"
                     "e2f6556ad6b1318a"
                     "024a838f21af1fde"
                     "048977eb48f59ffd"
                     "4924ca1c60902e52"
                     "f0a089bc76897040"
                     "e082f93776384864"
                     "5e0705")

        ct_tv_hex = ("f3ffc7703f9400e5"
                     "2a7dfb4b3d3305d9"
                     "8e993b9f48681273"
                     "c29650ba32fc76ce"
                     "48332ea7164d96a4"
                     "476fb8c531a1186a"
                     "c0dfc17c98dce87b"
                     "4da7f011ec48c972"
                     "71d2c20f9b928fe2"
                     "270d6fb863d51738"
                     "b48eeee314a7cc8a"
                     "b932164548e526ae"
                     "90224368517acfea"
                     "bd6bb3732bc0e9da"
                     "99832b61ca01b6de"
                     "56244a9e88d5f9b3"
                     "7973f622a43d14a6"
                     "599b1f654cb45a74"
                     "e355a5")

        ct_tv_bin = binascii.unhexlify(ct_tv_hex)

        pt = auth_and_decrypt("bob@jabber.org", 'c', nonce + ct_tv_bin, 1)

        self.assertEqual(binascii.hexlify(pt), pt_tv_hex)

        # Teardown
        ut_cleanup()


class TestPadding(ExtendedTestCase):

    def test_1_input_parameter(self):
        for a in not_str:
            with self.assertRaises(SystemExit):
                padding(a)

    def test_2_oversize_pt(self):
        for s in range(255, 260):
            with self.assertRaises(AssertionError):
                padding(s * 'm')

    def test_3_padding_with_length_check(self):
        for s in range(0, 255):
            string = s * 'm'
            padded = padding(string)
            self.assertEqual(len(padded), 255)

            # Verify removal of padding doesn't alter the string.
            self.assertEqual(string, padded[:-ord(padded[-1:])])


class TestRmPadding(unittest.TestCase):

    def test_1_input_parameter(self):
        for a in not_str:
            with self.assertRaises(SystemExit):
                rm_padding(a)

    def test_2_function(self):
        for i in range(0, 1000):
            string = i * 'm'
            length_of_padding = 255 - (len(string) % 255)
            padded_string = string + length_of_padding * chr(length_of_padding)
            self.assertEqual(rm_padding(padded_string), string)


class TestEncryptData(ExtendedTestCase):

    def test_1_input_parameter(self):
        for a in not_str:
            with self.assertRaises(SystemExit):
                encrypt_data(a)

    def test_2_official_test_vectors(self):
        """
        Test vectors:

        https://cr.yp.to/highspeed/naclcrypto-20090310.pdf // page 35
        """

        # Setup
        nonce = ("69696ee955b62b73"
                 "cd62bda875fc73d6"
                 "8219e0036b7a0b37")

        o_nacl_utils_random = Rx.nacl.utils.random
        Rx.nacl.utils.random = lambda x: binascii.unhexlify(nonce)

        key_tv_hex = ("1b27556473e985d4"
                      "62cd51197a9a46c7"
                      "6009549eac6474f2"
                      "06c4ee0844f68389")

        o_master_key = Rx.master_key
        Rx.master_key = key_tv_hex

        # Test
        pt_tv_hex = ("be075fc53c81f2d5"
                     "cf141316ebeb0c7b"
                     "5228c52a4c62cbd4"
                     "4b66849b64244ffc"
                     "e5ecbaaf33bd751a"
                     "1ac728d45e6c6129"
                     "6cdc3c01233561f4"
                     "1db66cce314adb31"
                     "0e3be8250c46f06d"
                     "ceea3a7fa1348057"
                     "e2f6556ad6b1318a"
                     "024a838f21af1fde"
                     "048977eb48f59ffd"
                     "4924ca1c60902e52"
                     "f0a089bc76897040"
                     "e082f93776384864"
                     "5e0705")

        ct_tv_hex = ("f3ffc7703f9400e5"
                     "2a7dfb4b3d3305d9"
                     "8e993b9f48681273"
                     "c29650ba32fc76ce"
                     "48332ea7164d96a4"
                     "476fb8c531a1186a"
                     "c0dfc17c98dce87b"
                     "4da7f011ec48c972"
                     "71d2c20f9b928fe2"
                     "270d6fb863d51738"
                     "b48eeee314a7cc8a"
                     "b932164548e526ae"
                     "90224368517acfea"
                     "bd6bb3732bc0e9da"
                     "99832b61ca01b6de"
                     "56244a9e88d5f9b3"
                     "7973f622a43d14a6"
                     "599b1f654cb45a74"
                     "e355a5")

        pt_tv_bin = binascii.unhexlify(pt_tv_hex)
        ct_purp_bin = b64d(encrypt_data(pt_tv_bin))
        ct_purp_hex = binascii.hexlify(ct_purp_bin)

        self.assertEqual(ct_purp_hex, (nonce + ct_tv_hex))

        # Teardown
        Rx.nacl.utils.random = o_nacl_utils_random
        Rx.master_key = o_master_key


class TestDecryptData(ExtendedTestCase):
    """
    Test vectors:

    https://cr.yp.to/highspeed/naclcrypto-20090310.pdf // page 35
    """

    def test_1_input_parameters(self):
        for a in not_str:
            for b in not_str:
                with self.assertRaises(SystemExit):
                    decrypt_data(a, b)

    def test_2_official_test_vector(self):

        # Setup
        o_master_key = Rx.master_key

        Rx.master_key = ("1b27556473e985d4"
                         "62cd51197a9a46c7"
                         "6009549eac6474f2"
                         "06c4ee0844f68389")

        # Test
        nonce = ("69696ee955b62b73"
                 "cd62bda875fc73d6"
                 "8219e0036b7a0b37")
        nonce = binascii.unhexlify(nonce)

        pt_tv_hex = ("be075fc53c81f2d5"
                     "cf141316ebeb0c7b"
                     "5228c52a4c62cbd4"
                     "4b66849b64244ffc"
                     "e5ecbaaf33bd751a"
                     "1ac728d45e6c6129"
                     "6cdc3c01233561f4"
                     "1db66cce314adb31"
                     "0e3be8250c46f06d"
                     "ceea3a7fa1348057"
                     "e2f6556ad6b1318a"
                     "024a838f21af1fde"
                     "048977eb48f59ffd"
                     "4924ca1c60902e52"
                     "f0a089bc76897040"
                     "e082f93776384864"
                     "5e0705")

        ct_tv_hex = ("f3ffc7703f9400e5"
                     "2a7dfb4b3d3305d9"
                     "8e993b9f48681273"
                     "c29650ba32fc76ce"
                     "48332ea7164d96a4"
                     "476fb8c531a1186a"
                     "c0dfc17c98dce87b"
                     "4da7f011ec48c972"
                     "71d2c20f9b928fe2"
                     "270d6fb863d51738"
                     "b48eeee314a7cc8a"
                     "b932164548e526ae"
                     "90224368517acfea"
                     "bd6bb3732bc0e9da"
                     "99832b61ca01b6de"
                     "56244a9e88d5f9b3"
                     "7973f622a43d14a6"
                     "599b1f654cb45a74"
                     "e355a5")

        ct_tv_bin = binascii.unhexlify(ct_tv_hex)

        pt = decrypt_data(nonce + ct_tv_bin)

        self.assertEqual(binascii.hexlify(pt), pt_tv_hex)

        # Teardown
        Rx.master_key = o_master_key


###############################################################################
#                               PASSWORD LOGIN                                #
###############################################################################

class TestLoginScreen(ExtendedTestCase):
    """
    This function doesn't have any tests yet.
    """


class TestNewMasterPWD(ExtendedTestCase):

    def test_1_new_master_password(self):

        # Setup
        o_new_password = Rx.new_password
        Rx.new_password = lambda x: "test"

        # Test
        new_master_pwd()
        data = open(Rx.login_file).readline()
        rounds, salt, keyh = data.split('|')

        self.assertTrue(str(rounds).isdigit())
        self.assertTrue(ut_validate_key(salt))
        self.assertTrue(ut_validate_key(keyh))

        # Teardown
        Rx.new_password = o_new_password
        ut_cleanup()


class TestCheckMasterPWD(ExtendedTestCase):

    def test_1_correct_pwd(self):

        # Setup
        class QueueMock(object):

            def __init__(self):
                self.value = ''

            @staticmethod
            def empty():
                return False

            @staticmethod
            def get():
                return "test"

            def put(self, value):
                self.value = value

            def test(self):
                return self.value

        Rx.pwd_queue = QueueMock()
        Rx.key_queue = QueueMock()

        data = ("262144|"
                "79e098346bd45faf91bc599f2579c06f"
                "0a2b22a4b83cc3f25a5123380a3cc7b2|"
                "4ea8a5662ac638819789dc84104aa320"
                "d53a6bb633603771054b1332d29e9384")

        open(Rx.login_file, "w+").write(data)

        # Test
        check_master_pwd()
        tv = "346e12134edf2c4105be018745cd80f5a50041d21b771e1c6fd3f9151cfc1a08"
        key = Rx.key_queue.test()
        self.assertEqual(key, tv)

        # Teardown
        ut_cleanup()

    def test_2_incorrect_pwd(self):

        # Setup
        class QueueMock(object):

            def __init__(self):
                self.value = ''

            @staticmethod
            def empty():
                return False

            @staticmethod
            def get():
                return "incorrect"

            def put(self, value):
                self.value = value

            def test(self):
                return self.value

        Rx.pwd_queue = QueueMock()
        Rx.key_queue = QueueMock()

        data = ("262144|"
                "79e098346bd45faf91bc599f2579c06f"
                "0a2b22a4b83cc3f25a5123380a3cc7b2|"
                "4ea8a5662ac638819789dc84104aa320"
                "d53a6bb633603771054b1332d29e9384")

        open(Rx.login_file, "w+").write(data)

        # Test
        check_master_pwd()
        key = Rx.key_queue.test()
        self.assertEqual(key, '')

        # Teardown
        ut_cleanup()

    def test_3_missing_login_data(self):

        with self.assertRaises(SystemExit):
            check_master_pwd()

    def test_4_incoherent_login_data(self):

        # Setup
        data = ("262144|"
                "79e098346bd45faf91bc599f2579c06f"
                "0a2b22a4b83cc3f25a5123380a3cc7b2")

        open(Rx.login_file, "w+").write(data)

        # Test
        with self.assertRaises(ValueError):
            check_master_pwd()

        # Teardown
        ut_cleanup()

    def test_5_invalid_salt(self):

        # Setup
        data = ("262144|"
                "79e098346bd45faf91bc599f2579c06f"
                "0a2b22a4b83cc3f25a5123380a3cc7bG|"
                "4ea8a5662ac638819789dc84104aa320"
                "d53a6bb633603771054b1332d29e9385")

        open(Rx.login_file, "w+").write(data)

        # Test
        with self.assertRaises(SystemExit):
            check_master_pwd()

        # Teardown
        ut_cleanup()

    def test_6_invalid_master_key_hash(self):

        # Setup
        data = ("262144|"
                "G9e098346bd45faf91bc599f2579c06f"
                "0a2b22a4b83cc3f25a5123380a3cc7b2|"
                "4ea8a5662ac638819789dc84104aa320"
                "d53a6bb633603771054b1332d29e9385")

        open(Rx.login_file, "w+").write(data)

        # Test
        with self.assertRaises(SystemExit):
            check_master_pwd()

        # Teardown
        ut_cleanup()

    def test_7_non_digit_rounds(self):

        # Setup
        data = ("A62144|"
                "79e098346bd45faf91bc599f2579c06f"
                "0a2b22a4b83cc3f25a5123380a3cc7b2|"
                "4ea8a5662ac638819789dc84104aa320"
                "d53a6bb633603771054b1332d29e9385")

        open(Rx.login_file, "w+").write(data)

        # Test
        with self.assertRaises(AssertionError):
            check_master_pwd()

        # Teardown
        ut_cleanup()


###############################################################################
#                                 KEY EXCHANGE                                #
###############################################################################

class TestKDKInputProcess(ExtendedTestCase):
    """
    This function doesn't have any tests yet.
    """


class TestProcessLocalKey(ExtendedTestCase):

    def test_1_input_parameter(self):
        for a in not_str:
            with self.assertRaises(SystemExit):
                process_local_key(a)

    def test_3_mac_fail(self):

        # Setup
        class QueueMock(object):

            def __init__(self):
                self.value = ''

            @staticmethod
            def empty():
                return False

            @staticmethod
            def get():
                return 64 * 'a'

            def put(self, value):
                self.value = value

            def test(self):
                return self.value

        Rx.kdk_queue = QueueMock()

        packet = b64d("aqH5qbH3sVCXY59ABlP8jl8KcHtdHnmGzPL1TNCg0hKmoGXupI9xqtd"
                      "iFMp0WpP+s1GIkmFnsadyIU0FvU3Ta9ZJKPXgU0QLkdYgD48BBilD+U"
                      "n5Wt1zCt/vu9xbISh5gTZcnvb7te8XGHDUiWpqZ0F0yZJ+fhyiQPJPy"
                      "qxQMRGxTz67MfiXsGVmngEfvMZkv2twaSE+rf59teZSFIOFu9itMDtl"
                      "QbobyUc=")
        # Test
        self.assertFR("Error: Local key packet MAC fail.",
                      process_local_key, packet)

    def test_4_valid_packet_and_key(self):

        # Setup
        class QueueMock(object):
            def __init__(self):
                self.value = ''

            @staticmethod
            def empty():
                return False

            @staticmethod
            def get():
                return 64 * 'a'

            def put(self, value):
                self.value = value

            def test(self):
                return self.value

        Rx.kdk_queue = QueueMock()

        Rx.local_testing_mode = False

        # Test
        packet = b64d("OqH5qbH3sVCXY59ABlP8jl8KcHtdHnmGzPL1TNCg0hKmoGXupI9xqtd"
                      "iFMp0WpP+s1GIkmFnsadyIU0FvU3Ta9ZJKPXgU0QLkdYgD48BBilD+U"
                      "n5Wt1zCt/vu9xbISh5gTZcnvb7te8XGHDUiWpqZ0F0yZJ+fhyiQPJPy"
                      "qxQMRGxTz67MfiXsGVmngEfvMZkv2twaSE+rf59teZSFIOFu9itMDtl"
                      "QbobyUc=")

        self.assertIsNone(process_local_key(packet))

        self.assertEqual(c_dictionary["local"],
                         dict(nick="local",
                              u_harac=1, c_harac=1,
                              c_key="dummy_key", c_hek="dummy_key",
                              u_key=64 * 'a', u_hek=64 * 'a',
                              windowp=False,
                              storing=False,
                              logging=False))

        # Teardown
        ut_cleanup()


# ECDHE
class TestDisplayPubKey(ExtendedTestCase):

    def test_1_input_parameter(self):
        for a in not_str:
            with self.assertRaises(SystemExit):
                display_pub_key(a)

    def test_2_invalid_key(self):
        self.assertFR("Error: Received an invalid public "
                      "key from alice@jabber.org.",
                      display_pub_key, "G743b4ddf00d6e8eb8fbbe0603d90948"
                                       "c04663731795fae5eab5f1cba8ed1b36"
                                       "calice@jabber.org")

    def test_3_valid_packet_from_contact(self):
        self.assertIsNone(display_pub_key("7743b4ddf00d6e8eb8fbbe0603d90948"
                                          "c04663731795fae5eab5f1cba8ed1b36"
                                          "calice@jabber.org"))

    def test_4_valid_packet_from_user(self):
        self.assertIsNone(display_pub_key("7743b4ddf00d6e8eb8fbbe0603d90948"
                                          "c04663731795fae5eab5f1cba8ed1b36"
                                          "ualice@jabber.org"))


class TestECDHECommand(ExtendedTestCase):

    def test_1_input_parameter(self):
        for a in not_str:
            with self.assertRaises(SystemExit):
                ecdhe_command(a)

    def test_2_invalid_packet(self):
        self.assertFR("Error: Received invalid packet from TxM.",
                      ecdhe_command, us.join(["KE", "bob@jabber.org", "Bob"]))

    def test_3_invalid_keys(self):
        params = us.join(["KE", "bob@jabber.org", "bob",
                         (64 * 'a'), (64 * 'a'),
                         (64 * 'a'), (64 * 'g')])

        self.assertFR("Error: Received invalid key(s) from TxM.",
                      ecdhe_command, params)

    def test_4_valid_packet(self):

        # Setup
        o_rxm_side_m_logging = Rx.rxm_side_m_logging
        o_store_file_default = Rx.store_file_default
        Rx.rxm_side_m_logging = False
        Rx.store_file_default = False
        public_key_d["bob@jabber.org"] = ("2JAT9y2EcnV6DPUGikLJYjWwk"
                                          "5UmUEFXRiQVmTbfSLbL4A4CMp")

        # Test key writing and dictionaries
        params = us.join(["KE", "bob@jabber.org", "Bob",
                          (64 * 'a'), (64 * 'a'),
                          (64 * 'a'), (64 * 'a')])

        self.assertIsNone(ecdhe_command(params))

        self.assertEqual(public_key_d["bob@jabber.org"], '')
        self.assertEqual(c_dictionary["bob@jabber.org"]["nick"], "Bob")
        self.assertEqual(c_dictionary["bob@jabber.org"]["u_key"], 64 * 'a')
        self.assertEqual(c_dictionary["bob@jabber.org"]["c_key"], 64 * 'a')
        self.assertEqual(c_dictionary["bob@jabber.org"]["u_hek"], 64 * 'a')
        self.assertEqual(c_dictionary["bob@jabber.org"]["c_hek"], 64 * 'a')
        self.assertEqual(c_dictionary["bob@jabber.org"]["windowp"],
                         Rx.n_m_notify_privacy)
        self.assertEqual(c_dictionary["bob@jabber.org"]["storing"],
                         Rx.store_file_default)
        self.assertEqual(c_dictionary["bob@jabber.org"]["logging"],
                         Rx.rxm_side_m_logging)

        self.assertFalse(Rx.l_m_incoming["ubob@jabber.org"])
        self.assertFalse(Rx.l_m_incoming["cbob@jabber.org"])
        self.assertFalse(Rx.l_m_received["ubob@jabber.org"])
        self.assertFalse(Rx.l_m_received["cbob@jabber.org"])
        self.assertEqual(Rx.l_m_p_buffer["ubob@jabber.org"], '')
        self.assertEqual(Rx.l_m_p_buffer["cbob@jabber.org"], '')

        self.assertFalse(Rx.l_f_incoming["ubob@jabber.org"])
        self.assertFalse(Rx.l_f_incoming["cbob@jabber.org"])
        self.assertFalse(Rx.l_f_received["ubob@jabber.org"])
        self.assertFalse(Rx.l_f_received["cbob@jabber.org"])
        self.assertEqual(Rx.l_f_p_buffer["ubob@jabber.org"], '')
        self.assertEqual(Rx.l_f_p_buffer["cbob@jabber.org"], '')

        # Teardown
        ut_cleanup()
        Rx.rxm_side_m_logging = o_rxm_side_m_logging
        Rx.store_file_default = o_store_file_default


# PSK
class TestAddPSK(ExtendedTestCase):

    def test_1_input_parameter(self):
        for a in not_str:
            with self.assertRaises(SystemExit):
                add_psk(a)

    def test_2_invalid_account(self):
        self.assertFR("Error: Received invalid PSK command.",
                      add_psk, "KT")

    def test_3_unknown_account(self):
        self.assertFR("Error: Unknown account bob@jabber.org.",
                      add_psk, us.join(["KT", "bob@jabber.org"]))

    def test_4_invalid_psk_data_length(self):

        # Setup
        create_contact(["bob"])
        c_dictionary["bob@jabber.org"]["c_key"] = "dummy_key"
        c_dictionary["bob@jabber.org"]["c_hek"] = "dummy_key"

        f_path = "unittest_directory/"
        f_name = "bob@jabber.org.psk"
        ut_ensure_dir(f_path)

        open(f_path + f_name, "w+").write("test")

        o_ask_file_path_gui = Rx.ask_file_path_gui
        Rx.ask_file_path_gui = lambda x: (f_path + f_name)

        # Test
        self.assertFR("Error: Invalid PSK data length. Aborting.",
                      add_psk, us.join(["KT", "bob@jabber.org"]))

        # Teardown
        ut_cleanup()
        Rx.ask_file_path_gui = o_ask_file_path_gui

    def test_5_invalid_salt_in_psk(self):

        # Setup
        create_contact(["bob"])
        c_dictionary["bob@jabber.org"]["c_key"] = "dummy_key"
        c_dictionary["bob@jabber.org"]["c_hek"] = "dummy_key"

        f_path = "unittest_directory/"
        f_name = "bob@jabber.org.psk"
        ut_ensure_dir(f_path)

        packet = ("H3869ee1d432e4c3eb82828e073a0c309d0f4b7d789b9c7d0c556460e1b"
                  "981ce7RfR8H15Q9XPna86HdQngQ6MzbTBFFGQcdkxviKDTfKhNEjiEuKvkw"
                  "VG8BypOwcfgK9OBlWpZHvEJM51w6El/e3SQEg9mQaN0JMXv9PIoruyoQCSy"
                  "ngNRasKTUGmkKkktGEcZLVXWnJh5bPwZ6p0cJeqfsvdaVGollLgP+rnD1Jc"
                  "Ekjn9Nk40jNw0vR9K57I3Ef/rdk/zG1oH5JJeryJuLkpJ89iUdtm")

        open(f_path + f_name, "w+").write(packet)

        o_ask_file_path_gui = Rx.ask_file_path_gui
        Rx.ask_file_path_gui = lambda x: (f_path + f_name)

        # Test
        self.assertFR("Error: Invalid salt in PSK. Aborting.",
                      add_psk, us.join(["KT", "bob@jabber.org"]))

        # Teardown
        ut_cleanup()
        Rx.ask_file_path_gui = o_ask_file_path_gui

    def test_6_valid_psk(self):

        # Setup
        create_contact(["bob"])
        c_dictionary["bob@jabber.org"]["c_key"] = "dummy_key"
        c_dictionary["bob@jabber.org"]["c_hek"] = "dummy_key"

        o_getpass_getpass = getpass.getpass
        getpass.getpass = lambda x: "test"

        f_path = "unittest_directory/"
        f_name = "bob@jabber.org.psk"
        ut_ensure_dir(f_path)

        packet = ("23869ee1d432e4c3eb82828e073a0c309d0f4b7d789b9c7d0c556460e1b"
                  "981ce7RfR8H15Q9XPna86HdQngQ6MzbTBFFGQcdkxviKDTfKhNEjiEuKvkw"
                  "VG8BypOwcfgK9OBlWpZHvEJM51w6El/e3SQEg9mQaN0JMXv9PIoruyoQCSy"
                  "ngNRasKTUGmkKkktGEcZLVXWnJh5bPwZ6p0cJeqfsvdaVGollLgP+rnD1Jc"
                  "Ekjn9Nk40jNw0vR9K57I3Ef/rdk/zG1oH5JJeryJuLkpJ89iUdtm")

        open(f_path + f_name, "w+").write(packet)

        o_ask_file_path_gui = Rx.ask_file_path_gui
        Rx.ask_file_path_gui = lambda x: (f_path + f_name)

        # Test
        self.assertIsNone(add_psk(us.join(["KT", "bob@jabber.org"])))

        self.assertTrue(ut_validate_key(
            c_dictionary["bob@jabber.org"]["c_key"]))
        self.assertTrue(ut_validate_key(
            c_dictionary["bob@jabber.org"]["c_hek"]))

        # Teardown
        ut_cleanup()
        Rx.ask_file_path_gui = o_ask_file_path_gui
        getpass.getpass = o_getpass_getpass


class TestPSKCommand(ExtendedTestCase):

    def test_1_input_parameter(self):
        for a in not_str:
            with self.assertRaises(SystemExit):
                psk_command(a)

    def test_2_invalid_packet(self):
        self.assertFR("Error: Received invalid packet from TxM.",
                      psk_command, us.join(["KR", "bob@jabber.org", "bob"]))

    def test_3_invalid_key(self):
        self.assertFR("Error: Received invalid key(s) from TxM.",
                      psk_command, us.join(["KR", "bob@jabber.org", "Bob",
                                            (64 * 'a'), (64 * 'g')]))

    def test_4_invalid_account(self):
        self.assertFR("invalid account",
                      psk_command, us.join(["KR", "bobjabber.org", "Bob",
                                            (64 * 'a'), (64 * 'a')]))

    def test_5_valid_packet(self):

        # Test
        self.assertIsNone(psk_command(us.join(["KR", "bob@jabber.org", "Bob",
                                               (64 * 'a'), (64 * 'a')])))

        self.assertEqual(c_dictionary["bob@jabber.org"]["nick"], "Bob")
        self.assertEqual(c_dictionary["bob@jabber.org"]["u_key"], (64*'a'))
        self.assertEqual(c_dictionary["bob@jabber.org"]["u_hek"], (64*'a'))
        self.assertEqual(c_dictionary["bob@jabber.org"]["c_key"], "dummy_key")
        self.assertEqual(c_dictionary["bob@jabber.org"]["c_hek"], "dummy_key")

        # Teardown
        ut_cleanup()


###############################################################################
#                               SECURITY RELATED                              #
###############################################################################

class TestValidateKey(ExtendedTestCase):

    def test_1_input_parameters(self):
        for a in not_str:
            for b in not_str:
                for c in not_bool:
                    with self.assertRaises(SystemExit):
                        validate_key(a, b, c)

    def test_2_illegal_key_length(self):
        for b in range(0, 64):
            self.assertFalse(validate_key(b * 'a'))
            with self.assertRaises(SystemExit):
                validate_key((b * 'a'), "alice@jabber.org")

        for b in range(65, 250):
            self.assertFalse(validate_key(b * 'a'))
            with self.assertRaises(SystemExit):
                validate_key((b * 'a'), "alice@jabber.org")

    def test_3_illegal_key_content(self):
        self.assertFalse(validate_key("%sg" % (63 * 'a')))
        with self.assertRaises(SystemExit):
            validate_key("%sg" % (63 * 'a'), "alice@jabber.org")

    def test_4_hex_char_keys_are_valid(self):
        for c in ['0', '1', '2', '3', '4',
                  '5', '6', '7', '8', '9',
                  'A', 'B', 'C', 'D', 'E', 'F',
                  'a', 'b', 'c', 'd', 'e', 'f']:
            self.assertTrue(validate_key(64 * c))
            self.assertTrue(validate_key(64 * c), "alice@jabber.org")


class TestInputValidation(ExtendedTestCase):

    def test_1_input_parameter(self):
        for a in not_tuple:
            with self.assertRaises(TypeError):
                input_validation(a)

    def test_2_function(self):
        with self.assertRaises(SystemExit):
            input_validation(("string", int))


class TestGracefulExit(ExtendedTestCase):

    def test_1_input_parameterd(self):
        for a in not_str:
            for b in not_bool:
                with self.assertRaises(SystemExit):
                    graceful_exit(a, b)

    def test_2_function(self):

        # Setup
        Rx.unittesting = False

        # Test
        with self.assertRaises(SystemExit):
            graceful_exit()

        # Teardown
        Rx.unittesting = True


class TestWriteLogEntry(ExtendedTestCase):

    def test_1_input_parameters(self):
        for a in not_str:
            for b in not_str:
                for c in not_str:
                    with self.assertRaises(SystemExit):
                        write_log_entry(a, b, c)

    def test_2_log_entry(self):

        # Setup
        create_contact(["alice"])
        c_dictionary["alice@jabber.org"]["logging"] = True
        c_dictionary["alice@jabber.org"]["logging"] = True

        # Test
        self.assertIsNone(write_log_entry("alice@jabber.org", "aMessage", 'c'))
        logged = str(open(Rx.rxlog_file).read().splitlines())

        self.assertEqual(len(logged), 1080)

        # Teardown
        ut_cleanup()


class TestAccessHistory(ExtendedTestCase):

    def test_1_input_parameter(self):
        for a in not_str:
            with self.assertRaises(SystemExit):
                access_history(a)

    def test_2_invalid_command(self):
        self.assertFR("Error: Invalid command.", access_history,
                      us.join(["LF", "alice@jabber.org"]))

    def test_3_no_log_file(self):
        self.assertFR("Error: Could not find '.rx_logs'.", access_history,
                      us.join(["LF", "alice@jabber.org", 'd']))

    def test_4_no_messages_in_log_file(self):

        # Setup
        open(Rx.rxlog_file, "w+").close()

        # Test
        self.assertFR("No messages in logfile.", access_history,
                      us.join(["LF", "alice@jabber.org", 'd']))

        # Teardown
        ut_cleanup()

    def test_5_short_message(self):

        # Setup
        create_contact(["local", "alice"])
        c_dictionary["alice@jabber.org"]["logging"] = True
        write_log_entry(us.join(["ap", "ShortMessage"]),
                        "alice@jabber.org", 'c')

        # Test
        access_history(us.join(["LF", "alice@jabber.org", 'd']))

        # Teardown
        ut_cleanup()

    def test_6_long_message(self):

        # Setup
        create_contact(["local", "alice"])
        c_dictionary["alice@jabber.org"]["logging"] = True

        msg = 'p' + us + 100 * "VeryLongMessage "
        compressed = zlib.compress(msg, 9)
        ct = ut_encrypt(compressed)
        ct += 64 * 'a'

        packet_l = split_string(ct, 253)

        packet_list = (['b' + packet_l[0]] +
                       ['c' + p for p in packet_l[1:-1]] +
                       ['d' + packet_l[-1]])

        for p in packet_list:
            write_log_entry(p, "alice@jabber.org", 'c')

        access_history(us.join(["LF", "alice@jabber.org", 'd']))

        # Teardown
        ut_cleanup()

    def test_7_long_message_sent(self):

        # Setup
        create_contact(["local", "alice"])
        c_dictionary["alice@jabber.org"]["logging"] = True

        msg = 'p' + us + 100 * "VeryLongMessage "
        compressed = zlib.compress(msg, 9)
        ct = ut_encrypt(compressed)
        ct += 64 * 'a'

        packet_l = split_string(ct, 253)

        packet_list = (['b' + packet_l[0]] +
                       ['c' + p for p in packet_l[1:-1]] +
                       ['d' + packet_l[-1]])

        for p in packet_list:
            write_log_entry(p, "alice@jabber.org", 'u')

        access_history(us.join(["LF", "alice@jabber.org", 'd']))

        # Teardown
        ut_cleanup()

    def test_8_long_message_from_group_member(self):

        # Setup
        create_contact(["local", "alice"])
        c_dictionary["alice@jabber.org"]["logging"] = True
        create_group([("testgroup", ["alice"])])

        msg = "g%stestgroup%s" % (us, us) + 2000 * "VeryLongMessage "
        compressed = zlib.compress(msg, 9)
        ct = ut_encrypt(compressed)
        ct += 64 * 'a'

        packet_l = split_string(ct, 253)

        packet_list = (['b' + packet_l[0]] +
                       ['c' + p for p in packet_l[1:-1]] +
                       ['d' + packet_l[-1]])

        for p in packet_list:
            write_log_entry(p, "alice@jabber.org", 'c')

        access_history(us.join(["LF", "testgroup", 'd']))

        # Teardown
        ut_cleanup()


###############################################################################
#                             CONTACT MANAGEMENT                              #
###############################################################################

class TestRMContact(ExtendedTestCase):

    def test_1_input_parameter(self):
        for a in not_str:
            with self.assertRaises(SystemExit):
                rm_contact(a)

    def test_2_missing_account(self):
        self.assertFR("Error: No account specified.",
                      rm_contact, "CR")

    def test_3_unknown_contact(self):

        # Setup
        create_contact(["alice", "local"])

        # Test
        self.assertIsNone(rm_contact(us.join(["CR", "bob@jabber.org"])))

        # Teardown
        ut_cleanup()

    def test_4_remove_from_databases(self):

        # Setup
        create_contact(["alice", "local"])
        create_group([("testgroup", ["alice"])])

        # Setup
        create_contact(["alice", "local"])

        # Test
        self.assertIsNone(rm_contact(us.join(["CR", "alice@jabber.org"])))

        # Teardown
        ut_cleanup()


class TestValidateAccount(ExtendedTestCase):

    def test_1_input_parameters(self):
        for a in not_str:
            for b in not_int:
                with self.assertRaises(SystemExit):
                    validate_account(a, b)

    def test_2_valid_account(self):
        self.assertTrue(validate_account("alice@jabber.org", 1))

    def test_3_invalid_account(self):
        for a in ["alice@jabber.", "alice@jabber", "@jabber.org",
                  "alicejabber.org", "alice@.org", "alice@org",
                  "%s@jabber.org" % (245 * 'a')]:
            self.assertFalse(validate_account(a))


class TestGetListOf(ExtendedTestCase):

    def test_1_input_parameters(self):
        for a in not_str:
            for b in not_str:
                with self.assertRaises(SystemExit):
                    get_list_of(a, b)

    def test_2_invalid_key(self):
        with self.assertRaises(KeyError):
            get_list_of("invalid_key")

    def test_3_list_of_accounts(self):

        # Setup
        create_contact(["local", "alice", "bob", "charlie"])

        # Test
        self.assertEqual(get_list_of("accounts"),
                         ["alice@jabber.org", "bob@jabber.org",
                          "charlie@jabber.org"])
        # Teardown
        ut_cleanup()

    def test_4_list_of_nicks(self):

        # Setup
        create_contact(["local", "alice", "bob", "charlie"])

        # Test
        self.assertEqual(get_list_of("nicks"),
                         ["alice", "bob", "charlie"])

        # Teardown
        ut_cleanup()

    def test_5_list_of_groups(self):

        # Setup
        create_group([("testgroup1", ["alice", "bob"]),
                      ("testgroup2", ["alice"]),
                      ("testgroup3", ["bob"])])

        # Test
        self.assertEqual(get_list_of("groups"),
                         ["testgroup1", "testgroup2", "testgroup3"])

        # Teardown
        ut_cleanup()

    def test_6_list_of_members(self):

        # Setup
        create_group([("testgroup1", ["alice", "bob"]),
                      ("testgroup2", ["alice"]),
                      ("testgroup3", ["bob"])])

        # Test
        self.assertEqual(get_list_of("members", "testgroup1"),
                         ["alice@jabber.org", "bob@jabber.org"])

        self.assertEqual(get_list_of("members", "testgroup2"),
                         ["alice@jabber.org"])

        self.assertEqual(get_list_of("members", "testgroup3"),
                         ["bob@jabber.org"])

        # Teardown
        ut_cleanup()


###############################################################################
#                             CONTACT SELECTION                              #
###############################################################################

class TestSelectWindow(ExtendedTestCase):

    def test_1_input_parameter(self):
        for a in not_str:
            with self.assertRaises(SystemExit):
                select_window(a)

    def test_2_no_window(self):
        self.assertFR("Error: No window specified.", select_window, "WS")

    def test_3_unknown_window(self):
        self.assertFR("Error: Unknown window.", select_window,
                      us.join(["WS", "alice@jabber.org"]))

    def test_4_new_session_for_account(self):

        # Setup
        create_contact(["alice"])

        # Test
        self.assertIsNone(select_window(us.join(["WS", "alice@jabber.org"])))

        # Teardown
        ut_cleanup()

    def test_5_new_session_for_group(self):

        # Setup
        create_contact(["alice"])
        create_group([("testgroup", ["alice"])])

        # Test
        self.assertIsNone(select_window(us.join(["WS", "testgroup"])))

        # Teardown
        ut_cleanup()

    def test_6_fresh_command_window(self):

        # Setup
        create_contact(["alice"])
        create_group([("testgroup", ["alice"])])

        # Test
        self.assertIsNone(select_window(us.join(["WS", "local"])))

        # Teardown
        ut_cleanup()

    def test_7_day_change(self):

        # Setup
        create_contact(["alice"])
        dto1 = datetime.datetime.strptime("Jun 1 2016  1:33PM",
                                          "%b %d %Y %I:%M%p")
        dto2 = datetime.datetime.strptime("Jun 2 2016  8:51PM",
                                          "%b %d %Y %I:%M%p")

        window_log_d["alice@jabber.org"] = [(dto1, "alice@jabber.org",
                                            ["older message"], ''),
                                            (dto2, "alice@jabber.org",
                                             ["old message"], '')]

        # Test
        self.assertIsNone(select_window(us.join(["WS", "alice@jabber.org"])))

        # Teardown
        ut_cleanup()

    def test_8_pub_keys(self):

        # Setup
        create_contact(["alice"])
        dto1 = datetime.datetime.strptime("Jun 1 2016  1:33PM",
                                          "%b %d %Y %I:%M%p")

        public_key_d["alice@jabber.org"] = ("5JhvsapkHeHjy2FiUQYwXh1d74"
                                            "evuMd3rGcKGnifCdFR5G8e6nH")

        window_log_d["alice@jabber.org"] = [(dto1, "alice@jabber.org",
                                            ["old message"], '')]

        # Test
        self.assertIsNone(select_window(us.join(["WS", "alice@jabber.org"])))

        # Teardown
        ut_cleanup()


class TestWPrint(ExtendedTestCase):

    def test_1_input_parameters(self):
        for a in not_tuple:
            for b in not_str:
                for c in not_str:
                    for d in not_str:
                        with self.assertRaises(SystemExit):
                            w_print(a, b, c, d)

    def test_2_notification_to_inactive_window(self):

        # Setup
        create_contact(["alice", "bob"])
        Rx.active_window = "alice@jabber.org"

        # Test
        self.assertIsNone(w_print(["test message"], "bob@jabber.org",
                                  "bob@jabber.org"))

        # Teardown
        ut_cleanup()

    def test_3_message_to_active_window(self):

        # Setup
        create_contact(["alice", "bob"])
        Rx.active_window = "bob@jabber.org"

        # Test
        self.assertIsNone(w_print(["test message"], "bob@jabber.org",
                                  "bob@jabber.org"))

        # Teardown
        ut_cleanup()

    def test_4_command_to_inactive_window(self):

        # Setup
        create_contact(["alice", "bob"])
        Rx.active_window = "alice@jabber.org"

        # Test
        self.assertIsNone(w_print(["test message"]))

        # Teardown
        ut_cleanup()

    def test_5_command_to_active_window(self):

        # Setup
        create_contact(["alice", "bob"])
        Rx.active_window = "local"

        # Test
        self.assertIsNone(w_print(["test message"]))

        # Teardown
        ut_cleanup()


class TestNotifyWinActivity(ExtendedTestCase):

    def test_1_no_unread_messages(self):

        # Setup
        create_contact(["alice", "bob"])
        create_group([("testgroup", ["alice", "bob"])])
        unread_ctr_d["alice@jabber.org"] = 0
        unread_ctr_d["bob@jabber.org"] = 0
        unread_ctr_d["testgroup"] = 0

        # Test
        self.assertFR("no unread messages", notify_win_activity)

        # Teardown
        ut_cleanup()

    def test_2_unread_messages(self):

        # Setup
        create_contact(["alice", "bob"])
        create_group([("testgroup", ["alice", "bob"])])
        unread_ctr_d["alice@jabber.org"] = 5
        unread_ctr_d["bob@jabber.org"] = 2
        unread_ctr_d["testgroup"] = 8

        # Test
        self.assertIsNone(notify_win_activity())

        # Teardown
        ut_cleanup()


###############################################################################
#                             DATABASE MANAGEMENT                             #
###############################################################################

class TestNewContact(ExtendedTestCase):
    def test_1_input_parameters(self):
        for a in not_str:
            for b in not_str:
                for c in not_str:
                    for d in not_str:
                        for e in not_str:
                            for f in not_str:
                                with self.assertRaises(SystemExit):
                                    new_contact(a, b, c, d, e, f)

    def test_2_no_previous_contact(self):

        # Test
        self.assertIsNone(new_contact("bob@jabber.org", "Bob",
                                      64 * 'a', 64 * 'b', 64 * 'c',
                                      64 * 'd'))

        self.assertEqual(c_dictionary["bob@jabber.org"],
                         dict(nick="Bob",
                              u_harac=1, c_harac=1,
                              u_key=(64 * 'a'), u_hek=(64 * 'b'),
                              c_key=(64 * 'c'), c_hek=(64 * 'd'),
                              windowp=Rx.n_m_notify_privacy,
                              storing=Rx.store_file_default,
                              logging=Rx.rxm_side_m_logging))

        # Teardown
        ut_cleanup()

    def test_3_previous_contact(self):

        # Test
        self.assertIsNone(new_contact("bob@jabber.org", "Bob",
                                      64 * 'a', 64 * 'a',
                                      64 * 'a', 64 * 'a'))

        c_dictionary["bob@jabber.org"][
            "windowp"] = not Rx.n_m_notify_privacy
        c_dictionary["bob@jabber.org"][
            "storing"] = not Rx.store_file_default
        c_dictionary["bob@jabber.org"][
            "logging"] = not Rx.rxm_side_m_logging
        c_dictionary["bob@jabber.org"]["u_harac"] = 5
        c_dictionary["bob@jabber.org"]["c_harac"] = 5

        self.assertIsNone(new_contact("bob@jabber.org", "Bob",
                                      64 * 'a', 64 * 'b', 64 * 'c',
                                      64 * 'd'))

        self.assertEqual(c_dictionary["bob@jabber.org"],
                         dict(nick="Bob",
                              u_harac=1, c_harac=1,
                              u_key=(64 * 'a'), u_hek=(64 * 'b'),
                              c_key=(64 * 'c'), c_hek=(64 * 'd'),
                              windowp=not Rx.n_m_notify_privacy,
                              storing=not Rx.store_file_default,
                              logging=not Rx.rxm_side_m_logging))
        # Teardown
        ut_cleanup()


class TestContactDB(ExtendedTestCase):

    def test_1_database_content(self):

        # Setup
        Rx.txm_side_m_logging = True

        # Test
        a_data = dict(nick="Alice",
                      u_harac=1, c_harac=1,
                      u_key=64 * 'a', u_hek=64 * 'b',
                      c_key=64 * 'c', c_hek=64 * 'd',
                      windowp=True,
                      storing=True,
                      logging=True)

        c_data = dict(nick="Charlie",
                      u_harac=1, c_harac=1,
                      u_key=64 * 'a', u_hek=64 * 'b',
                      c_key=64 * 'c', c_hek=64 * 'd',
                      windowp=True,
                      storing=True,
                      logging=True)

        acco_dict = {"alice@jabber.org": a_data,
                     "charlie@jabber.org": c_data}

        self.assertIsNone(contact_db(write_db=acco_dict))

        data = contact_db()

        self.assertEqual(data["charlie@jabber.org"], c_data)
        self.assertEqual(data["alice@jabber.org"], a_data)

        f_data = open(datab_file).read()
        db_len = len(base64.b64encode(
            ((m_number_of_accnts * 11 * 255) + 16 + 24) * 'a'))
        self.assertEqual(len(f_data), db_len)

        # Teardown
        ut_cleanup()

    def test_2_increased_database(self):

        # Setup
        o_m_number_of_accnts = Rx.m_number_of_accnts
        Rx.m_number_of_accnts = 3

        # Test
        a_data = dict(nick="Alice",
                      u_harac=1, c_harac=1,
                      u_key=64 * 'a', u_hek=64 * 'b',
                      c_key=64 * 'c', c_hek=64 * 'd',
                      windowp=True,
                      storing=True,
                      logging=True)

        c_data = dict(nick="Charlie",
                      u_harac=1, c_harac=1,
                      u_key=64 * 'a', u_hek=64 * 'b',
                      c_key=64 * 'c', c_hek=64 * 'd',
                      windowp=True,
                      storing=True,
                      logging=True)
        l_data = dict(nick="local",
                      u_harac=1, c_harac=1,
                      u_key=64 * 'a', u_hek=64 * 'b',
                      c_key=64 * 'c', c_hek=64 * 'd',
                      windowp=True,
                      storing=True,
                      logging=True)

        acco_dict = {"alice@jabber.org": a_data,
                     "charlie@jabber.org": c_data,
                     "local": l_data}

        self.assertIsNone(contact_db(write_db=acco_dict))

        self.assertEqual(len(open(Rx.datab_file).read()), 11276)

        Rx.m_number_of_accnts = 6
        data = contact_db()
        self.assertEqual(set(data.keys()),
                         {"alice@jabber.org", "charlie@jabber.org", "local"})
        self.assertEqual(len(open(Rx.datab_file).read()), 22496)

        # Teardown
        ut_cleanup()
        Rx.m_number_of_accnts = o_m_number_of_accnts

    def test_3_reduced_database(self):

        # Setup
        o_m_number_of_accnts = Rx.m_number_of_accnts
        Rx.m_number_of_accnts = 3

        # Test
        a_data = dict(nick="Alice",
                      u_harac=1, c_harac=1,
                      u_key=64 * 'a', u_hek=64 * 'b',
                      c_key=64 * 'c', c_hek=64 * 'd',
                      windowp=True,
                      storing=True,
                      logging=True)

        c_data = dict(nick="Charlie",
                      u_harac=1, c_harac=1,
                      u_key=64 * 'a', u_hek=64 * 'b',
                      c_key=64 * 'c', c_hek=64 * 'd',
                      windowp=True,
                      storing=True,
                      logging=True)
        l_data = dict(nick="local",
                      u_harac=1, c_harac=1,
                      u_key=64 * 'a', u_hek=64 * 'b',
                      c_key=64 * 'c', c_hek=64 * 'd',
                      windowp=True,
                      storing=True,
                      logging=True)

        acco_dict = {"alice@jabber.org": a_data,
                     "charlie@jabber.org": c_data,
                     "local": l_data}

        self.assertIsNone(contact_db(write_db=acco_dict))

        self.assertEqual(len(open(Rx.datab_file).read()), 11276)

        Rx.m_number_of_accnts = 1

        with self.assertRaises(SystemExit):
            contact_db()

        # Teardown
        ut_cleanup()
        Rx.m_number_of_accnts = o_m_number_of_accnts


class TestGroupDB(ExtendedTestCase):

    def test_1_database_content(self):

        # Test
        g1_data = dict(logging=True, members=["alice@jabber.org",
                                              "bob@jabber.org"])
        g2_data = dict(logging=False, members=["charlie@jabber.org",
                                               "bob@jabber.org"])
        group_dict = dict()
        group_dict["testgroup1"] = g1_data
        group_dict["testgroup2"] = g2_data

        self.assertIsNone(group_db(write_db=group_dict))

        data = group_db()

        self.assertEqual(data["testgroup1"]["logging"], True)
        self.assertEqual(data["testgroup2"]["logging"], False)

        self.assertEqual(data["testgroup1"]["members"],
                         (["alice@jabber.org", "bob@jabber.org"]
                          + (m_members_in_group - 2) * ["dummy_member"]))

        self.assertEqual(data["testgroup2"]["members"],
                         (["charlie@jabber.org", "bob@jabber.org"]
                          + (m_members_in_group - 2) * ["dummy_member"]))

        # Teardown
        ut_cleanup()

    def test_2_increased_number_of_groups(self):

        # Setup
        o_m_number_of_groups = Rx.m_number_of_groups
        Rx.m_number_of_groups = 2

        # Test
        g1_data = dict(logging=True, members=["alice@jabber.org",
                                              "bob@jabber.org"])
        g2_data = dict(logging=False, members=["charlie@jabber.org",
                                               "bob@jabber.org"])
        group_dict = dict()
        group_dict["testgroup1"] = g1_data
        group_dict["testgroup2"] = g2_data

        self.assertIsNone(group_db(write_db=group_dict))

        self.assertEqual(len(open(Rx.group_file).read()), 20060)

        Rx.m_number_of_groups = 4
        data = group_db()

        self.assertEqual(len(data.keys()), 2)
        self.assertEqual(len(open(Rx.group_file).read()), 40064)

        # Teardown
        ut_cleanup()
        Rx.m_number_of_groups = o_m_number_of_groups

    def test_3_reduced_number_of_groups(self):

        # Setup
        o_m_number_of_groups = Rx.m_number_of_groups
        Rx.m_number_of_groups = 2

        # Test
        g1_data = dict(logging=True, members=["alice@jabber.org",
                                              "bob@jabber.org"])
        g2_data = dict(logging=False, members=["charlie@jabber.org",
                                               "bob@jabber.org"])
        group_dict = dict()
        group_dict["testgroup1"] = g1_data
        group_dict["testgroup2"] = g2_data

        self.assertIsNone(group_db(write_db=group_dict))

        self.assertEqual(len(open(Rx.group_file).read()), 20060)

        Rx.m_number_of_groups = 1

        with self.assertRaises(SystemExit):
            group_db()

        # Teardown
        ut_cleanup()
        Rx.m_number_of_groups = o_m_number_of_groups

    def test_4_increased_number_of_members(self):

        # Setup
        o_m_members_in_group = Rx.m_members_in_group
        o_m_number_of_groups = Rx.m_number_of_groups
        Rx.m_number_of_groups = 2
        Rx.m_members_in_group = 2

        # Test
        g1_data = dict(logging=True, members=["alice@jabber.org",
                                              "bob@jabber.org"])
        g2_data = dict(logging=False, members=["charlie@jabber.org",
                                               "bob@jabber.org"])
        group_dict = dict()
        group_dict["testgroup1"] = g1_data
        group_dict["testgroup2"] = g2_data

        self.assertIsNone(group_db(write_db=group_dict))

        self.assertEqual(len(open(Rx.group_file).read()), 3692)

        Rx.m_members_in_group = 3

        data = group_db()

        self.assertEqual(len(data.keys()), 2)
        self.assertEqual(len(data["testgroup1"]["members"]), 3)
        self.assertEqual(len(open(Rx.group_file).read()), 4600)

        # Teardown
        ut_cleanup()
        Rx.m_members_in_group = o_m_members_in_group
        Rx.m_number_of_groups = o_m_number_of_groups

    def test_5_reduced_number_of_members(self):

        # Setup
        o_m_members_in_group = Rx.m_members_in_group
        o_m_number_of_groups = Rx.m_number_of_groups
        Rx.m_number_of_groups = 2
        Rx.m_members_in_group = 2

        # Test
        g1_data = dict(logging=True, members=["alice@jabber.org",
                                              "bob@jabber.org"])
        g2_data = dict(logging=False, members=["charlie@jabber.org",
                                               "bob@jabber.org"])
        group_dict = dict()
        group_dict["testgroup1"] = g1_data
        group_dict["testgroup2"] = g2_data

        self.assertIsNone(group_db(write_db=group_dict))

        self.assertEqual(len(open(Rx.group_file).read()), 3692)

        Rx.m_members_in_group = 1

        with self.assertRaises(SystemExit):
            group_db()

        # Teardown
        ut_cleanup()
        Rx.m_members_in_group = o_m_members_in_group
        Rx.m_number_of_groups = o_m_number_of_groups


###############################################################################
#                            REED SOLOMON ENCODING                            #
###############################################################################

class TestRSEncode(ExtendedTestCase):

    def test_1_correction(self):
        string = 10 * "Testmessage"
        print("Original: %s" % string)

        encoded = reed_solomon.encode(string)
        print ("After encoding: %s" % encoded)

        error = Rx.e_correction_ratio
        altered = os.urandom(error) + encoded[error:]
        print("After errors: %s" % altered)

        corrected = reed_solomon.decode(altered)
        print("Corrected: %s" % corrected)

        self.assertEqual(corrected, string)


###############################################################################
#                              GROUP MANAGEMENT                               #
###############################################################################

class TestGroupCreate(ExtendedTestCase):

    def test_1_input_parameter(self):
        for a in not_str:
            with self.assertRaises(SystemExit):
                group_create(a)

    def test_2_no_group_name(self):
        self.assertFR("No group name specified.", group_create, "GC")

    def test_3_no_group_members(self):
        self.assertIsNone(group_create(us.join(["GC", "testgroup"])))

    def test_4_non_existing_contact(self):
        self.assertIsNone(group_create(us.join(["GC", "testgroup",
                                                "alice@jabber.org"])))

    def test_5_existing_contacts(self):

        # Setup
        create_contact(["alice", "bob"])

        # Test
        cmd = us.join(["GC", "testgroup",
                       "alice@jabber.org", "bob@jabber.org"])
        self.assertIsNone(group_create(cmd))

        self.assertTrue({"alice@jabber.org", "bob@jabber.org"}.issubset(
            set(g_dictionary["testgroup"]["members"])))

        self.assertEqual(g_dictionary["testgroup"]["logging"],
                         Rx.rxm_side_m_logging)

        self.assertEqual(window_log_d["testgroup"], [])

        # Teardown
        ut_cleanup()

    def test_6_existing_and_non_existing_contacts(self):

        # Setup
        create_contact(["alice", "bob"])

        # Test
        cmd = us.join(["GC", "testgroup", "alice@jabber.org",
                       "bob@jabber.org", "charlie@jabber.org"])
        self.assertIsNone(group_create(cmd))

        self.assertTrue({"alice@jabber.org", "bob@jabber.org"}.issubset(
            set(g_dictionary["testgroup"]["members"])))

        self.assertTrue("charlie@jabber.org"
                        not in g_dictionary["testgroup"]["members"])

        self.assertEqual(window_log_d["testgroup"], [])

        # Teardown
        ut_cleanup()


class TestGroupAddMember(ExtendedTestCase):

    def test_1_input_parameter(self):
        for a in not_str:
            with self.assertRaises(SystemExit):
                group_add_member(a)

    def test_2_no_group_name(self):
        self.assertFR("Error: No group name specified.",
                      group_add_member, "GA")

    def test_3_unknown_group(self):

        # Setup
        create_contact(["local"])
        create_group([("testgroup", ["alice", "bob"])])

        # Test
        self.assertFR("Error: Unknown group.",
                      group_add_member, us.join(["GS", "testroup"]))

        # Teardown
        ut_cleanup()

    def test_4_no_members(self):

        # Setup
        create_contact(["local"])
        create_group([("testgroup", ["alice", "bob"])])

        # Test
        self.assertFR("Error: No members to add specified.",
                      group_add_member, us.join(["GS", "testgroup"]))

        # Teardown
        ut_cleanup()

    def test_5_group_add_existing_contact_no_notify(self):

        # Setup
        create_contact(["local", "alice", "bob", "charlie"])
        create_group([("testgroup", ["alice", "bob"])])

        # Test
        self.assertIsNone(group_add_member(
            us.join(["GA", "testgroup", "charlie@jabber.org"])))

        self.assertEqual(g_dictionary["testgroup"]["members"],
                         ["alice@jabber.org",
                          "bob@jabber.org",
                          "charlie@jabber.org"]
                         + 17 * ["dummy_member"])

        for i in range(m_number_of_groups - 1):
            self.assertEqual(g_dictionary["dummy_group_%s" % i]["members"],
                             20 * ["dummy_member"])

        # Teardown
        ut_cleanup()

    def test_6_group_add_existing_and_unknown_contact(self):

        # Setup
        create_contact(["local", "alice", "bob", "charlie"])
        create_group([("testgroup", ["alice", "bob"])])

        # Test
        self.assertIsNone(group_add_member(us.join(["GA", "testgroup",
                                                    "charlie@jabber.org",
                                                    "david@jabber.org"])))

        self.assertEqual(g_dictionary["testgroup"]["members"],
                         ["alice@jabber.org",
                          "bob@jabber.org",
                          "charlie@jabber.org"]
                         + 17 * ["dummy_member"])

        for i in range(m_number_of_groups - 1):
            self.assertEqual(g_dictionary["dummy_group_%s" % i]["members"],
                             20 * ["dummy_member"])

        # Teardown
        ut_cleanup()

    def test_7_too_many_members(self):

        # Setup
        o_m_members_in_group = Rx.m_members_in_group
        Rx.m_members_in_group = 2

        create_contact(["local", "alice", "bob", "charlie"])
        create_group([("testgroup", ["alice", "bob"])])
        c_dictionary["alice@jabber.org"]["logging"] = False

        # Test
        self.assertFR(
            "Error: TFC settings only allow 2 members per group.",
            group_add_member,
            us.join(["GA", "testgroup", "charlie@jabber.org"]))

        # Teardown
        ut_cleanup()
        Rx.m_members_in_group = o_m_members_in_group


class TestGroupRmMember(ExtendedTestCase):

    def test_1_input_parameter(self):
        for a in not_str:
            with self.assertRaises(SystemExit):
                group_rm_member(a)

    def test_2_missing_group_name(self):

        # Setup
        create_contact(["local"])

        # Test
        self.assertFR("No group name specified.", group_rm_member, "GR")

        # Teardown
        ut_cleanup()

    def test_3_remove_non_existing_group(self):

        # Setup
        create_contact(["local", "alice", "bob"])
        create_group([("differentgroup", ["alice", "bob"])])

        # Test
        self.assertFR("RxM has no group testgroup to remove.",
                      group_rm_member, us.join(["GR", "testgroup"]))

        # Teardown
        ut_cleanup()

    def test_4_remove_group_member(self):

        # Setup
        create_contact(["local", "alice", "bob"])
        create_group([("testgroup", ["alice", "bob"])])

        # Test
        self.assertIsNone(group_rm_member(
            us.join(["GR", "testgroup", "alice@jabber.org"])))

        self.assertFalse("alice@jabber.org" in
                         g_dictionary["testgroup"]["members"])

        self.assertEqual(g_dictionary["testgroup"]["members"],
                         ["bob@jabber.org"]
                         + 19 * ["dummy_member"])

        for i in range(m_number_of_groups - 1):
            self.assertEqual(g_dictionary["dummy_group_%s" % i]["members"],
                             20 * ["dummy_member"])

        # Teardown
        ut_cleanup()

    def test_5_remove_unknown(self):

        # Setup
        create_contact(["local", "alice", "bob"])
        create_group([("testgroup", ["alice", "bob"])])

        # Test
        self.assertIsNone(
            group_rm_member(us.join(["GR", "testgroup",
                                     "charlie@jabber.org"])))

        self.assertEqual(g_dictionary["testgroup"]["members"],
                         ["alice@jabber.org", "bob@jabber.org"]
                         + 18 * ["dummy_member"])

        for i in range(m_number_of_groups - 1):
            self.assertEqual(g_dictionary["dummy_group_%s" % i]["members"],
                             20 * ["dummy_member"])

        # Teardown
        ut_cleanup()

    def test_6_remove_group(self):

        # Setup
        create_contact(["local", "alice", "bob"])
        create_group([("testgroup", ["alice", "bob"])])

        # Test
        self.assertFR("Removed group testgroup.", group_rm_member,
                      us.join(["GR", "testgroup"]))

        self.assertFalse("testgroup" in g_dictionary.keys())

        # Teardown
        ut_cleanup()


class TestGMgmtPrint(ExtendedTestCase):

    def test_1_input_parameters(self):
        for a in not_str:
            for b in not_str:
                for c in not_str:
                    with self.assertRaises(SystemExit):
                        g_mgmt_print(a, b, c)

    def test_2_function(self):
        for key in ["new-s", "add-s", "rem-s", "rem-n", "add-a", "unkwn"]:
            self.assertIsNone(g_mgmt_print(key, ["alice@jabber.org"], "test"))


###############################################################################
#                                    MISC                                     #
###############################################################################

class TestMessagePrinter(ExtendedTestCase):

    def test_1_input_parameter(self):
        for a in not_str:
            with self.assertRaises(SystemExit):
                message_printer(a)

    def test_2_print_message(self):
        self.assertIsNone(message_printer("Test message in the middle"))


class TestNewPassword(ExtendedTestCase):

    def test_1_input_parameter(self):
        for a in not_str:
            with self.assertRaises(SystemExit):
                new_password(a)

    def test_2_function(self):

        # Setup
        o_getpass_getpass = getpass.getpass
        getpass.getpass = lambda x: "test"

        # Test
        self.assertEqual(new_password("test"), "test")

        # Teardown
        getpass.getpass = o_getpass_getpass


class TestRunAsThread(ExtendedTestCase):
    def test_1_input_parameter(self):
        with self.assertRaises(SystemExit):
            run_as_thread("string", "arg")


class TestShell(ExtendedTestCase):

    def test_1_function(self):

        # Test
        shell("touch tfc_unittest_doc.txt")
        self.assertTrue(os.path.isfile("tfc_unittest_doc.txt"))

        # Teardown
        ut_cleanup()


class TestPhase(ExtendedTestCase):

    def test_1_input_parameters(self):
        for a in not_str:
            for b in not_int:
                with self.assertRaises(SystemExit):
                    phase(a, b)

    def test_2_output_type(self):
        self.assertIsNone(phase("test", 10))
        print("Done.")
        self.assertIsNone(phase("\ntest", 10))
        print("Done.")
        self.assertIsNone(phase("\n\n\ntest", 10))
        print("Done.")


class TestGetMS(ExtendedTestCase):

    def test_1_output_type(self):
        self.assertTrue(isinstance(get_ms(), (int, long)))

    def test_2_output_len(self):
        self.assertEqual(len(str(get_ms())), 13)


class TestSplitString(ExtendedTestCase):

    def test_1_input_parameters(self):
        for a in not_str:
            for b in not_int:
                with self.assertRaises(SystemExit):
                    split_string(a, b)

    def test_2_function(self):

        string = "string to split"
        split = split_string(string, 1)

        for s in string:
            self.assertEqual(split[string.index(s)], s)


class TestGetTTyWH(ExtendedTestCase):
    def test_1_function(self):
        self.assertTrue(isinstance(get_tty_w(), int))


class TestProcessArguments(ExtendedTestCase):
    """
    This function doesn't have any tests yet.
    """


class TestClearScreen(ExtendedTestCase):
    def test_1_function(self):
        self.assertIsNone(clear_screen())


class TestResetScreen(ExtendedTestCase):

    def test_1_function_parameter(self):
        for a in not_str:
            with self.assertRaises(SystemExit):
                reset_screen(a)

    def test_2_missing_window(self):

        # Setup
        Rx.window_log_d["alice@jabber.org"] = ["Test"]

        # Test
        self.assertFR("Error: Missing window for reset command.",
                      reset_screen, "SR")
        self.assertEqual(Rx.window_log_d["alice@jabber.org"], ["Test"])

        # Teardown
        ut_cleanup()

    def test_3_unknown_window(self):

        # Setup
        Rx.window_log_d["alice@jabber.org"] = ["Test"]

        # Test
        self.assertFR("Error: Unknown window for reset command.",
                      reset_screen, us.join(["SR", "bob@jabber.org"]))
        self.assertEqual(Rx.window_log_d["alice@jabber.org"], ["Test"])

        # Teardown
        ut_cleanup()

    def test_4_valid_key(self):

        # Setup
        Rx.window_log_d["alice@jabber.org"] = ["Test"]

        # Test
        self.assertIsNone(reset_screen(us.join(["SR", "alice@jabber.org"])))
        self.assertEqual(Rx.window_log_d["alice@jabber.org"], [])

        # Teardown
        ut_cleanup()


class TestPrintOnPreviousLine(ExtendedTestCase):

    def test_1_function(self):
        self.assertIsNone(print_on_previous_line())


class TestSearchSerialInterfaces(ExtendedTestCase):

    def test_1_usb_iface(self):

        # Setup
        Rx.serial_usb_adapter = True

        o_os_listdir = os.listdir
        os.listdir = lambda x: ["ttyUSB0"]

        # Test
        self.assertEqual(search_serial_interfaces(), "/dev/ttyUSB0")

        # Teardown
        os.listdir = o_os_listdir

    def test_2_no_integrated_iface(self):

        # Setup
        Rx.serial_usb_adapter = False

        o_os_listdir = os.listdir
        os.listdir = lambda x: []

        # Test
        with self.assertRaises(SystemExit):
            search_serial_interfaces()

        # Teardown
        os.listdir = o_os_listdir

    def test_3_integrated_RPI_iface(self):

        # Setup
        o_os_listdir = os.listdir
        os.listdir = lambda x: ["serial0"]
        Rx.rpi_os = True

        o_subprocess_check_output = subprocess.check_output
        subprocess.check_output = lambda x: "Raspbian GNU/Linux"

        Rx.serial_usb_adapter = False

        # Test
        self.assertEqual(search_serial_interfaces(), "/dev/serial0")

        # Teardown
        Rx.rpi_os = False
        subprocess.check_output = o_subprocess_check_output
        os.listdir = o_os_listdir

    def test_4_integrated_RPI_iface(self):

        # Setup
        o_os_listdir = os.listdir
        os.listdir = lambda x: ["ttyS0"]

        Rx.serial_usb_adapter = False

        # Test
        self.assertEqual(search_serial_interfaces(), "/dev/ttyS0")

        # Teardown
        os.listdir = o_os_listdir


###############################################################################
#                               FILE SELECTION                                #
###############################################################################

class TestAskPSKPathGUI(ExtendedTestCase):

    def test_1_input_parameter(self):
        for a in not_str:
            with self.assertRaises(SystemExit):
                ask_file_path_gui(a)

    def test_2_guidir(self):

        if not rpi_os:

            # Setup
            Rx.disable_gui_dialog = False

            open("tfc_unittest_doc.txt", "w+").write("test")

            o_tkfilefialog_askopenfilename = tkFileDialog.askopenfilename
            tkFileDialog.askopenfilename = lambda title: "tfc_unittest_doc.txt"

            # Test
            t_dir = ask_file_path_gui("test")
            self.assertEqual(t_dir, "tfc_unittest_doc.txt")

            # Teardown
            ut_cleanup()
            tkFileDialog.askdirectory = o_tkfilefialog_askopenfilename


class TestAskPSKPathCLI(ExtendedTestCase):

    def test_1_input_parameter(self):
        for a in not_str:
            with self.assertRaises(SystemExit):
                ask_psk_path_cli(a)

    def test_2_guidir(self):

        # Setup
        Rx.disable_gui_dialog = True
        import readline
        Rx.default_delims = readline.get_completer_delims()

        open("tfc_unittest_doc.txt", "w+").write("test")

        o_raw_input = __builtins__.raw_input
        __builtins__.raw_input = lambda x: "tfc_unittest_doc.txt"

        # Test
        t_dir = ask_psk_path_cli("test")
        self.assertEqual(t_dir, "tfc_unittest_doc.txt")

        # Teardown
        ut_cleanup()
        __builtins__.raw_input = o_raw_input


class TestCLIinputProcess(ExtendedTestCase):
    """
    This function doesn't have any tests yet.
    """


###############################################################################
#                               ENCRYPTED PACKETS                             #
###############################################################################

class TestPacketDecryption(ExtendedTestCase):

    def test_1_input_parameters(self):
        for a in not_str:
            with self.assertRaises(SystemExit):
                packet_decryption(a)

    def test_2_invalid_account(self):

        eharac = b64d("OPa32FPHZlOjPUW4Fs5kL//pHKcC//Ez"
                      "T/vgwGLmqPfjpWtq/IUZnBQnnm0qb/wd")

        ct_tag = b64d("76SficVDKoxaNzxHtceiA37lFUF5Li9JqXN040hkL69o1rX1304jDG3"
                      "7c/QfoHpL4poUfwPIfcIsp1JQvebg7pKFNuh7e94E8Xz/x5Mn8Iv0Ix"
                      "myJJC5L9EvG+Jyv8b4WMkYklLQPcFlHXPte0BGfHLZLWEJo17WANK/o"
                      "emtj5trjBmnvwj/+TVofFsEuwpIdThaEWBuv+7V1ITOuqyMzf2TLXZJ"
                      "0Nqh6Y5L+D+WEKmvESq0mlApCjzeMZGHO0imgv9SQtNSjCZwKuTzLSG"
                      "ev6hl31GzegvEQX1x0UJzweQyjHFnlCJ3hK9dKYJkMhW9w5+sx/sZad"
                      "V5274VIiyG2+PX0TrLYTn2+0cy/oHSjh/U8BGqhv/KtqMCIQNH0/IrL"
                      "g8mMzuLlA==")

        origin = 'c'
        account = "alice@jabber.org"

        packet = eharac + ct_tag + origin + account

        self.assertFR("Error: Received packet from unknown account.",
                      packet_decryption, packet)

    def test_3_invalid_origin(self):

        # Setup
        create_contact(["alice"])

        # Test
        eharac = b64d("OPa32FPHZlOjPUW4Fs5kL//pHKcC//Ez"
                      "T/vgwGLmqPfjpWtq/IUZnBQnnm0qb/wd")

        ct_tag = b64d("76SficVDKoxaNzxHtceiA37lFUF5Li9JqXN040hkL69o1rX1304jDG3"
                      "7c/QfoHpL4poUfwPIfcIsp1JQvebg7pKFNuh7e94E8Xz/x5Mn8Iv0Ix"
                      "myJJC5L9EvG+Jyv8b4WMkYklLQPcFlHXPte0BGfHLZLWEJo17WANK/o"
                      "emtj5trjBmnvwj/+TVofFsEuwpIdThaEWBuv+7V1ITOuqyMzf2TLXZJ"
                      "0Nqh6Y5L+D+WEKmvESq0mlApCjzeMZGHO0imgv9SQtNSjCZwKuTzLSG"
                      "ev6hl31GzegvEQX1x0UJzweQyjHFnlCJ3hK9dKYJkMhW9w5+sx/sZad"
                      "V5274VIiyG2+PX0TrLYTn2+0cy/oHSjh/U8BGqhv/KtqMCIQNH0/IrL"
                      "g8mMzuLlA==")

        origin = 'g'
        account = "alice@jabber.org"

        packet = eharac + ct_tag + origin + account

        self.assertFR("Error: Received packet to/from alice had "
                      "invalid origin-header.", packet_decryption, packet)

        # Teardown
        ut_cleanup()

    def test_4_bad_hash_ratchet_mac(self):

        # Setup
        create_contact(["alice"])

        # Test
        eharac = b64d("OPa32FPHZlOjPUW4Fs5kL//pHKcC//Ez"
                      "T/vgwGLmqPfjpWtq/IUZnBQnnm0qb/wa")

        ct_tag = b64d("76SficVDKoxaNzxHtceiA37lFUF5Li9JqXN040hkL69o1rX1304jDG3"
                      "7c/QfoHpL4poUfwPIfcIsp1JQvebg7pKFNuh7e94E8Xz/x5Mn8Iv0Ix"
                      "myJJC5L9EvG+Jyv8b4WMkYklLQPcFlHXPte0BGfHLZLWEJo17WANK/o"
                      "emtj5trjBmnvwj/+TVofFsEuwpIdThaEWBuv+7V1ITOuqyMzf2TLXZJ"
                      "0Nqh6Y5L+D+WEKmvESq0mlApCjzeMZGHO0imgv9SQtNSjCZwKuTzLSG"
                      "ev6hl31GzegvEQX1x0UJzweQyjHFnlCJ3hK9dKYJkMhW9w5+sx/sZad"
                      "V5274VIiyG2+PX0TrLYTn2+0cy/oHSjh/U8BGqhv/KtqMCIQNH0/IrL"
                      "g8mMzuLlA==")

        origin = 'c'
        account = "alice@jabber.org"

        packet = eharac + ct_tag + origin + account

        self.assertFR("Warning! Received packet from alice had bad hash "
                      "ratchet MAC.", packet_decryption, packet)

        # Teardown
        ut_cleanup()

    def test_5_old_hash_ratchet_value(self):

        # Setup
        create_contact(["alice"])
        c_dictionary["alice@jabber.org"]["c_harac"] = 3

        # Test
        eharac = b64d("OPa32FPHZlOjPUW4Fs5kL//pHKcC//Ez"
                      "T/vgwGLmqPfjpWtq/IUZnBQnnm0qb/wd")

        ct_tag = b64d("76SficVDKoxaNzxHtceiA37lFUF5Li9JqXN040hkL69o1rX1304jDG3"
                      "7c/QfoHpL4poUfwPIfcIsp1JQvebg7pKFNuh7e94E8Xz/x5Mn8Iv0Ix"
                      "myJJC5L9EvG+Jyv8b4WMkYklLQPcFlHXPte0BGfHLZLWEJo17WANK/o"
                      "emtj5trjBmnvwj/+TVofFsEuwpIdThaEWBuv+7V1ITOuqyMzf2TLXZJ"
                      "0Nqh6Y5L+D+WEKmvESq0mlApCjzeMZGHO0imgv9SQtNSjCZwKuTzLSG"
                      "ev6hl31GzegvEQX1x0UJzweQyjHFnlCJ3hK9dKYJkMhW9w5+sx/sZad"
                      "V5274VIiyG2+PX0TrLYTn2+0cy/oHSjh/U8BGqhv/KtqMCIQNH0/IrL"
                      "g8mMzuLlA==")

        origin = 'c'
        account = "alice@jabber.org"

        packet = eharac + ct_tag + origin + account

        self.assertFR("Warning! Received packet from alice had old hash "
                      "ratchet counter value.", packet_decryption, packet)

        # Teardown
        ut_cleanup()

    def test_6_bad_MAC_in_msg(self):

        # Setup
        create_contact(["alice"])

        # Test
        eharac = b64d("OPa32FPHZlOjPUW4Fs5kL//pHKcC//Ez"
                      "T/vgwGLmqPfjpWtq/IUZnBQnnm0qb/wd")

        ct_tag = b64d("a6SficVDKoxaNzxHtceiA37lFUF5Li9JqXN040hkL69o1rX1304jDG3"
                      "7c/QfoHpL4poUfwPIfcIsp1JQvebg7pKFNuh7e94E8Xz/x5Mn8Iv0Ix"
                      "myJJC5L9EvG+Jyv8b4WMkYklLQPcFlHXPte0BGfHLZLWEJo17WANK/o"
                      "emtj5trjBmnvwj/+TVofFsEuwpIdThaEWBuv+7V1ITOuqyMzf2TLXZJ"
                      "0Nqh6Y5L+D+WEKmvESq0mlApCjzeMZGHO0imgv9SQtNSjCZwKuTzLSG"
                      "ev6hl31GzegvEQX1x0UJzweQyjHFnlCJ3hK9dKYJkMhW9w5+sx/sZad"
                      "V5274VIiyG2+PX0TrLYTn2+0cy/oHSjh/U8BGqhv/KtqMCIQNH0/IrL"
                      "g8mMzuLlA==")

        origin = 'c'
        account = "alice@jabber.org"

        packet = eharac + ct_tag + origin + account

        self.assertFR("Warning! Received packet from alice had bad packet "
                      "MAC.", packet_decryption, packet)

        # Teardown
        ut_cleanup()

    def test_7_bad_header_in_msg(self):

        # Setup
        create_contact(["alice"])

        # Test
        eharac = b64d("OPa32FPHZlOjPUW4Fs5kL//pHKcC//Ez"
                      "T/vgwGLmqPfjpWtq/IUZnBQnnm0qb/wd")

        ct_tag = b64d("76SficVDKoxaNzxHtceiA37lFUF5Li9JqXN040hkL69o1rX1304jDG3"
                      "7c/QfoHpL4poUfwPIfcIsp1JQvebg7pKFNuh7e94E8Xz/x5Mn8Iv0Ix"
                      "myJJC5L9EvG+Jyv8b4WMkYklLQPcFlHXPte0BGfHLZLWEJo17WANK/o"
                      "emtj5trjBmnvwj/+TVofFsEuwpIdThaEWBuv+7V1ITOuqyMzf2TLXZJ"
                      "0Nqh6Y5L+D+WEKmvESq0mlApCjzeMZGHO0imgv9SQtNSjCZwKuTzLSG"
                      "ev6hl31GzegvEQX1x0UJzweQyjHFnlCJ3hK9dKYJkMhW9w5+sx/sZad"
                      "V5274VIiyG2+PX0TrLYTn2+0cy/oHSjh/U8BGqhv/KtqMCIQNH0/IrL"
                      "g8mMzuLlA==")

        origin = 'c'
        account = "alice@jabber.org"

        packet = eharac + ct_tag + origin + account

        self.assertFR("Error: Received packet with incorrect header.",
                      packet_decryption, packet)

        # Please note that the encrypted message is just "plaintext message",
        # so it's only natural it raises exception about invalid header in
        # the next function, assemble_packet(). Catching error there means
        # packet_decryption() functioned the way it was supposed to.

        # Teardown
        ut_cleanup()


class TestAssemblePacket(ExtendedTestCase):

    def test_1_input_parameters(self):
        for a in not_str:
            for b in not_str:
                for c in not_str:
                    with self.assertRaises(SystemExit):
                        assemble_packet(a, b, c)

    def test_2_invalid_header(self):

        for h in "012345":
            self.assertFR("Error: Received packet with incorrect header.",
                          assemble_packet, h, "alice@jabber.org", 'c')

        for h in "abcdeABCDEf":
            self.assertFR("Error: Received command with incorrect header.",
                          assemble_packet, h, "local", 'u')


###############################################################################
#                            PROCESS ASSEMBLY PACKET                          #
###############################################################################

class TestNoisePacket(ExtendedTestCase):

    def test_1_input_parameters(self):
        for a in not_str:
            for b in not_str:
                for c in not_str:
                    with self.assertRaises(SystemExit):
                        noise_packet(a, b, c)

    def test_2_sent_noise_packet(self):

        # Setup
        create_contact(["alice"])
        Rx.l_m_incoming["ualice@jabber.org"] = True
        Rx.l_m_received["ualice@jabber.org"] = False
        Rx.l_m_p_buffer["ualice@jabber.org"] = "test"

        # Test
        self.assertIsNone(noise_packet('f', "alice@jabber.org", 'u'))
        self.assertFalse(Rx.l_m_received["ualice@jabber.org"])
        self.assertFalse(Rx.l_m_incoming["ualice@jabber.org"])
        self.assertEqual(Rx.l_m_p_buffer["ualice@jabber.org"], '')

        # Teardown
        ut_cleanup()

    def test_3_received_noise_packet(self):

        # Setup
        create_contact(["alice"])
        Rx.l_m_incoming["calice@jabber.org"] = True
        Rx.l_m_received["calice@jabber.org"] = False
        Rx.l_m_p_buffer["calice@jabber.org"] = "test"

        # Test
        self.assertIsNone(noise_packet('f', "alice@jabber.org", 'c'))
        self.assertFalse(Rx.l_m_received["calice@jabber.org"])
        self.assertFalse(Rx.l_m_incoming["calice@jabber.org"])
        self.assertEqual(Rx.l_m_p_buffer["calice@jabber.org"], '')

        # Teardown
        ut_cleanup()


class TestNoiseCommand(ExtendedTestCase):

    def test_1_noise_command(self):

        # Setup
        create_contact(["local"])
        Rx.l_c_incoming["local"] = True
        Rx.l_c_received["local"] = False
        Rx.l_c_p_buffer["local"] = "test"

        # Test
        self.assertIsNone(noise_command('5'))
        self.assertFalse(Rx.l_c_received["local"])
        self.assertFalse(Rx.l_c_incoming["local"])
        self.assertEqual(Rx.l_c_p_buffer["local"], '')

        # Teardown
        ut_cleanup()


class TestLongMessageCancel(ExtendedTestCase):

    def test_1_input_parameters(self):
        for a in not_str:
            for b in not_str:
                for c in not_str:
                    with self.assertRaises(SystemExit):
                        long_message_cancel(a, b, c)

    def test_2_sent_cancel_message(self):

        # Setup
        create_contact(["alice"])
        Rx.l_m_incoming["ualice@jabber.org"] = True
        Rx.l_m_received["ualice@jabber.org"] = True
        Rx.l_m_p_buffer["ualice@jabber.org"] = "test"

        # Test
        self.assertIsNone(long_message_cancel('e', "alice@jabber.org", 'u'))
        self.assertFalse(Rx.l_m_incoming["ualice@jabber.org"])
        self.assertFalse(Rx.l_m_received["ualice@jabber.org"])
        self.assertEqual(Rx.l_m_p_buffer["ualice@jabber.org"], '')

        # Teardown
        ut_cleanup()

    def test_3_received_cancel_message(self):

        # Setup
        create_contact(["alice"])
        Rx.l_m_incoming["calice@jabber.org"] = True
        Rx.l_m_received["calice@jabber.org"] = True
        Rx.l_m_p_buffer["calice@jabber.org"] = "test"

        # Test
        self.assertIsNone(long_message_cancel('e', "alice@jabber.org", 'c'))
        self.assertFalse(Rx.l_m_incoming["calice@jabber.org"])
        self.assertFalse(Rx.l_m_received["calice@jabber.org"])
        self.assertEqual(Rx.l_m_p_buffer["calice@jabber.org"], '')

        # Teardown
        ut_cleanup()


class TestCancelFile(ExtendedTestCase):

    def test_1_input_parameters(self):
        for a in not_str:
            for b in not_str:
                for c in not_str:
                    with self.assertRaises(SystemExit):
                        long_file_cancel(a, b, c)

    def test_2_sent_cancel_file(self):

        # Setup
        create_contact(["alice"])
        c_dictionary["alice@jabber.org"]["storing"] = True
        Rx.l_f_incoming["ualice@jabber.org"] = True
        Rx.l_f_received["ualice@jabber.org"] = True
        Rx.l_f_p_buffer["ualice@jabber.org"] = "test"

        # Test
        self.assertIsNone(long_file_cancel('E', "alice@jabber.org", 'u'))
        self.assertFalse(Rx.l_f_incoming["ualice@jabber.org"])
        self.assertFalse(Rx.l_f_received["ualice@jabber.org"])
        self.assertEqual(Rx.l_f_p_buffer["ualice@jabber.org"], '')

        # Teardown
        ut_cleanup()

    def test_3_received_cancel_file(self):

        # Setup
        create_contact(["alice"])
        c_dictionary["alice@jabber.org"]["storing"] = True
        Rx.l_f_incoming["calice@jabber.org"] = True
        Rx.l_f_received["calice@jabber.org"] = True
        Rx.l_f_p_buffer["calice@jabber.org"] = "test"

        # Test
        self.assertIsNone(long_file_cancel('E', "alice@jabber.org", 'c'))
        self.assertFalse(Rx.l_f_incoming["calice@jabber.org"])
        self.assertFalse(Rx.l_f_received["calice@jabber.org"])
        self.assertEqual(Rx.l_f_p_buffer["calice@jabber.org"], '')

        # Teardown
        ut_cleanup()


class TestCancelCommand(ExtendedTestCase):

    def test_1_cancel_command(self):

        # Setup
        create_contact(["local"])
        Rx.l_c_incoming["local"] = True
        Rx.l_c_received["local"] = False
        Rx.l_c_incoming["local"] = True
        Rx.l_c_p_buffer["local"] = "test"

        # Test
        self.assertIsNone(long_command_cancel('4'))
        self.assertTrue(Rx.l_c_received["local"])
        self.assertFalse(Rx.l_c_incoming["local"])
        self.assertEqual(Rx.l_c_p_buffer["local"], '')

        # Teardown
        ut_cleanup()


class TestShortMessage(ExtendedTestCase):

    def test_1_input_parameters(self):
        for a in not_str:
            for b in not_str:
                for c in not_str:
                    with self.assertRaises(SystemExit):
                        short_message(a, b, c)

    def test_2_sent_short_message(self):

        # Setup
        create_contact(["alice"])
        Rx.l_m_incoming["ualice@jabber.org"] = True
        Rx.l_m_received["ualice@jabber.org"] = False
        Rx.l_m_p_buffer["ualice@jabber.org"] = "test"

        # Test
        self.assertIsNone(short_message("atest", "alice@jabber.org", 'u'))
        self.assertTrue(Rx.l_m_received["ualice@jabber.org"])
        self.assertFalse(Rx.l_m_incoming["ualice@jabber.org"])
        self.assertEqual(Rx.l_m_p_buffer["ualice@jabber.org"], "test")

        # Teardown
        ut_cleanup()

    def test_3_received_short_message(self):

        # Setup
        create_contact(["alice"])
        Rx.l_m_incoming["calice@jabber.org"] = True
        Rx.l_m_received["calice@jabber.org"] = False
        Rx.l_m_p_buffer["calice@jabber.org"] = "other_msg"

        # Test
        self.assertIsNone(short_message("atest", "alice@jabber.org", 'c'))
        self.assertTrue(Rx.l_m_received["calice@jabber.org"])
        self.assertFalse(Rx.l_m_incoming["calice@jabber.org"])
        self.assertEqual(Rx.l_m_p_buffer["calice@jabber.org"], "test")

        # Teardown
        ut_cleanup()


class TestShortFile(ExtendedTestCase):

    def test_1_input_parameters(self):
        for a in not_str:
            for b in not_str:
                for c in not_str:
                    with self.assertRaises(SystemExit):
                        short_file(a, b, c)

    def test_2_sent_short_file(self):

        # Setup
        create_contact(["alice"])
        c_dictionary["alice@jabber.org"]["storing"] = True
        Rx.l_f_received["ualice@jabber.org"] = False
        Rx.l_f_incoming["ualice@jabber.org"] = True
        Rx.l_f_p_buffer["ualice@jabber.org"] = "test"

        # Test
        self.assertIsNone(short_file("bfiledata", "alice@jabber.org", 'u'))
        self.assertTrue(Rx.l_f_received["ualice@jabber.org"])
        self.assertFalse(Rx.l_f_incoming["ualice@jabber.org"])
        self.assertEqual(Rx.l_f_p_buffer["ualice@jabber.org"], "filedata")

        # Teardown
        ut_cleanup()

    def test_3_received_short_file(self):

        # Setup
        create_contact(["alice"])
        c_dictionary["alice@jabber.org"]["storing"] = True
        Rx.l_f_received["calice@jabber.org"] = False
        Rx.l_f_incoming["calice@jabber.org"] = True
        Rx.l_f_p_buffer["calice@jabber.org"] = "test"

        # Test
        self.assertIsNone(short_file("bfiledata", "alice@jabber.org", 'c'))
        self.assertTrue(Rx.l_f_received["calice@jabber.org"])
        self.assertFalse(Rx.l_f_incoming["calice@jabber.org"])
        self.assertEqual(Rx.l_f_p_buffer["calice@jabber.org"], "filedata")

        # Teardown
        ut_cleanup()


class TestShortCommand(ExtendedTestCase):

    def test_1_input_parameter(self):
        for a in not_str:
            with self.assertRaises(SystemExit):
                short_command(a)

    def test_2_short_command(self):

        # Setup
        Rx.l_c_received["local"] = True
        Rx.l_c_incoming["local"] = False
        Rx.l_c_p_buffer["local"] = ''

        # Test
        self.assertIsNone(short_command("1command_data"))
        self.assertTrue(Rx.l_c_received["local"])
        self.assertFalse(Rx.l_c_incoming["local"])
        self.assertEqual(Rx.l_c_p_buffer["local"], "command_data")


class TestLongMessageStart(ExtendedTestCase):

    def test_1_input_parameters(self):
        for a in not_str:
            for b in not_str:
                for c in not_str:
                    with self.assertRaises(SystemExit):
                        long_message_start(a, b, c)

    def test_2_sent_long_message_start(self):

        # Setup
        create_contact(["alice"])
        Rx.l_m_incoming["ualice@jabber.org"] = False
        Rx.l_m_received["ualice@jabber.org"] = False
        Rx.l_m_p_buffer["ualice@jabber.org"] = "prev_msg"

        # Test
        self.assertIsNone(long_message_start("bmsg", "alice@jabber.org", 'u'))
        self.assertFalse(Rx.l_m_received["ualice@jabber.org"])
        self.assertTrue(Rx.l_m_incoming["ualice@jabber.org"])
        self.assertEqual(Rx.l_m_p_buffer["ualice@jabber.org"], "msg")

        # Teardown
        ut_cleanup()

    def test_3_received_long_message_start(self):

        # Setup
        create_contact(["alice"])
        Rx.l_m_incoming["calice@jabber.org"] = True
        Rx.l_m_received["calice@jabber.org"] = False
        Rx.l_m_p_buffer["calice@jabber.org"] = "prev_msg"

        # Test
        self.assertIsNone(long_message_start("bmsg", "alice@jabber.org", 'c'))
        self.assertFalse(Rx.l_m_received["calice@jabber.org"])
        self.assertTrue(Rx.l_m_incoming["calice@jabber.org"])
        self.assertEqual(Rx.l_m_p_buffer["calice@jabber.org"], "msg")

        # Teardown
        ut_cleanup()


class TestLongFileStart(ExtendedTestCase):

    def test_1_input_parameters(self):
        for a in not_str:
            for b in not_str:
                for c in not_str:
                    with self.assertRaises(SystemExit):
                        long_file_start(a, b, c)

    def test_2_sent_long_file_start(self):

        # Setup
        create_contact(["alice"])
        c_dictionary["alice@jabber.org"]["storing"] = True
        Rx.l_f_incoming["ualice@jabber.org"] = True
        Rx.l_f_received["ualice@jabber.org"] = True
        Rx.l_f_p_buffer["ualice@jabber.org"] = ''

        # Test
        msg = us.join(['p', "doc.txt", "1.1KB", "00m 01s", "filedata"])
        self.assertIsNone(long_file_start(msg, "alice@jabber.org", 'u'))
        self.assertFalse(Rx.l_f_received["ualice@jabber.org"])
        self.assertTrue(Rx.l_f_incoming["ualice@jabber.org"])
        self.assertEqual(Rx.l_f_p_buffer["ualice@jabber.org"],
                         "\x1fdoc.txt\x1f1.1KB\x1f00m 01s\x1ffiledata")

        # Teardown
        ut_cleanup()

    def test_3_received_long_file_start(self):

        # Setup
        create_contact(["alice"])
        c_dictionary["alice@jabber.org"]["storing"] = True
        Rx.l_f_incoming["calice@jabber.org"] = True
        Rx.l_f_received["calice@jabber.org"] = True
        Rx.l_f_p_buffer["calice@jabber.org"] = ''

        # Test
        msg = us.join(['p', "doc.txt", "1.1KB", "00m 01s", "filedata"])

        self.assertIsNone(long_file_start(msg, "alice@jabber.org", 'c'))
        self.assertFalse(Rx.l_f_received["calice@jabber.org"])
        self.assertTrue(Rx.l_f_incoming["calice@jabber.org"])
        self.assertEqual(Rx.l_f_p_buffer["calice@jabber.org"],
                         "\x1fdoc.txt\x1f1.1KB\x1f00m 01s\x1ffiledata")

        # Teardown
        ut_cleanup()

    def test_4_illegal_header(self):

        # Setup
        create_contact(["alice"])
        c_dictionary["alice@jabber.org"]["storing"] = True
        Rx.l_f_incoming["calice@jabber.org"] = True
        Rx.l_f_received["calice@jabber.org"] = True
        Rx.l_f_p_buffer["calice@jabber.org"] = ''

        # Test
        msg = us.join(['p', "doc.txt", "1.1KB", "filedata"])

        self.assertFR("Received file packet with illegal header.",
                      long_file_start, msg, "alice@jabber.org", 'c')
        self.assertFalse(Rx.l_f_received["calice@jabber.org"])
        self.assertFalse(Rx.l_f_incoming["calice@jabber.org"])
        self.assertEqual(Rx.l_f_p_buffer["calice@jabber.org"], '')

        # Teardown
        ut_cleanup()


class TestLongCommandStart(ExtendedTestCase):

    def test_1_input_parameter(self):
        for a in not_str:
            with self.assertRaises(SystemExit):
                long_command_start(a)

    def test_2_long_command_start(self):

        # Setup
        Rx.l_c_received["local"] = True
        Rx.l_c_incoming["local"] = False
        Rx.l_c_p_buffer["local"] = ''

        # Test
        self.assertIsNone(long_command_start("2long_command"))
        self.assertFalse(Rx.l_c_received["local"])
        self.assertTrue(Rx.l_c_incoming["local"])
        self.assertEqual(Rx.l_c_p_buffer["local"], "long_command")


class TestLongMessageAppend(ExtendedTestCase):

    def test_1_input_parameters(self):
        for a in not_str:
            for b in not_str:
                for c in not_str:
                    with self.assertRaises(SystemExit):
                        long_message_append(a, b, c)

    def test_2_sent_long_message_append(self):

        # Setup
        create_contact(["alice"])
        Rx.l_m_received["ualice@jabber.org"] = True
        Rx.l_m_incoming["ualice@jabber.org"] = False
        Rx.l_m_p_buffer["ualice@jabber.org"] = "1st"

        # Test
        self.assertIsNone(long_message_append("c2nd", "alice@jabber.org", 'u'))
        self.assertFalse(Rx.l_m_received["ualice@jabber.org"])
        self.assertTrue(Rx.l_m_incoming["ualice@jabber.org"])
        self.assertEqual(Rx.l_m_p_buffer["ualice@jabber.org"], "1st2nd")

        # Teardown
        ut_cleanup()

    def test_3_received_long_message_append(self):

        # Setup
        create_contact(["alice"])
        Rx.l_m_received["calice@jabber.org"] = True
        Rx.l_m_incoming["calice@jabber.org"] = False
        Rx.l_m_p_buffer["calice@jabber.org"] = "1st"

        # Test
        self.assertIsNone(long_message_append("c2nd", "alice@jabber.org", 'c'))
        self.assertFalse(Rx.l_m_received["calice@jabber.org"])
        self.assertTrue(Rx.l_m_incoming["calice@jabber.org"])
        self.assertEqual(Rx.l_m_p_buffer["calice@jabber.org"], "1st2nd")

        # Teardown
        ut_cleanup()


class TestLongFileAppend(ExtendedTestCase):

    def test_1_input_parameters(self):
        for a in not_str:
            for b in not_str:
                for c in not_str:
                    with self.assertRaises(SystemExit):
                        long_file_append(a, b, c)

    def test_2_sent_long_file_append(self):

        # Setup
        create_contact(["alice"])
        c_dictionary["alice@jabber.org"]["storing"] = True
        Rx.l_f_received["ualice@jabber.org"] = True
        Rx.l_f_incoming["ualice@jabber.org"] = False
        Rx.l_f_p_buffer["ualice@jabber.org"] = "1st"

        # Test
        self.assertIsNone(long_file_append("C2nd", "alice@jabber.org", 'u'))
        self.assertFalse(Rx.l_f_received["ualice@jabber.org"])
        self.assertTrue(Rx.l_f_incoming["ualice@jabber.org"])
        self.assertEqual(Rx.l_f_p_buffer["ualice@jabber.org"], "1st2nd")

        # Teardown
        ut_cleanup()

    def test_3_received_long_file_append(self):

        # Setup
        create_contact(["alice"])
        c_dictionary["alice@jabber.org"]["storing"] = True
        Rx.l_f_received["calice@jabber.org"] = True
        Rx.l_f_p_buffer["calice@jabber.org"] = "1st"

        # Test
        self.assertIsNone(long_file_append("C2nd", "alice@jabber.org", 'c'))
        self.assertFalse(Rx.l_f_received["calice@jabber.org"])
        self.assertTrue(Rx.l_f_incoming["calice@jabber.org"])
        self.assertEqual(Rx.l_f_p_buffer["calice@jabber.org"], "1st2nd")

        # Teardown
        ut_cleanup()


class TestLongCommandAppend(ExtendedTestCase):

    def test_1_input_parameter(self):
        for a in not_str:
            with self.assertRaises(SystemExit):
                long_command_append(a)

    def test_2_long_command_append(self):

        # Setup
        create_contact(["local"])
        Rx.l_c_received["local"] = True
        Rx.l_c_incoming["local"] = False
        Rx.l_c_p_buffer["local"] = "1st"

        # Test
        self.assertIsNone(long_command_append("22nd"))
        self.assertFalse(l_c_received["local"])
        self.assertTrue(l_c_incoming["local"])
        self.assertEqual(l_c_p_buffer["local"], "1st2nd")


class TestLongMessageEnd(ExtendedTestCase):

    def test_1_input_parameters(self):
        for a in not_str:
            for b in not_str:
                for c in not_str:
                    with self.assertRaises(SystemExit):
                        long_message_end(a, b, c)

    def test_2_invalid_encoding(self):

        # Setup
        create_contact(["alice"])
        c_dictionary["alice@jabber.org"]["storing"] = True
        Rx.l_m_received["ualice@jabber.org"] = False
        Rx.l_m_incoming["ualice@jabber.org"] = True
        Rx.l_m_p_buffer["ualice@jabber.org"] = ("€WFhYWFhYWFhYWFhYWFhYWFhYWFhY"
                                                "WFhxvJOFbUniGIau6MIlsDCWZBqO1"
                                                "QXICBLIkSge77sANjDXdyi7K")

        # Test
        self.assertFR("Error: Message sent to alice had invalid B64 encoding.",
                      long_message_end, "dfzRC2EUhsmUjfY/alEaaaaaaaaaaaaaaa"
                                        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                                        "aaaaaaaaaaaaaaa",
                                        "alice@jabber.org", 'u')
        self.assertFalse(Rx.l_m_received["ualice@jabber.org"])
        self.assertFalse(Rx.l_m_incoming["ualice@jabber.org"])
        self.assertEqual(Rx.l_m_p_buffer["ualice@jabber.org"], '')

        # Teardown
        ut_cleanup()

    def test_3_invalid_MAC(self):

        # Setup
        create_contact(["alice"])
        c_dictionary["alice@jabber.org"]["storing"] = True
        Rx.l_m_received["ualice@jabber.org"] = False
        Rx.l_m_incoming["ualice@jabber.org"] = True
        Rx.l_m_p_buffer["ualice@jabber.org"] = ("aWFhYWFhYWFhYWFhYWFhYWFhYWFhY"
                                                "WFhxvJOFbUniGIau6MIlsDCWZBqO1"
                                                "QXICBLIkSge77sANjDXdyi7K")

        # Test
        self.assertFR("Error: Message sent to alice had an invalid MAC.",
                      long_message_end, "dfzRC2EUhsmUjfY/alEaaaaaaaaaaaaaaa"
                                        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                                        "aaaaaaaaaaaaaaa",
                                        "alice@jabber.org", 'u')
        self.assertFalse(Rx.l_m_received["ualice@jabber.org"])
        self.assertFalse(Rx.l_m_incoming["ualice@jabber.org"])
        self.assertEqual(Rx.l_m_p_buffer["ualice@jabber.org"], '')

        # Teardown
        ut_cleanup()

    def test_4_received_long_message(self):

        # Setup
        create_contact(["alice"])
        c_dictionary["alice@jabber.org"]["storing"] = True
        Rx.l_m_received["ualice@jabber.org"] = False
        Rx.l_m_incoming["ualice@jabber.org"] = True
        Rx.l_m_p_buffer["ualice@jabber.org"] = ("YWFhYWFhYWFhYWFhYWFhYWFhYWFhY"
                                                "WFhxvJOFbUniGIau6MIlsDCWZBqO1"
                                                "QXICBLIkSge77sANjDXdyi7K")

        # Test
        self.assertIsNone(long_message_end("dfzRC2EUhsmUjfY/alEaaaaaaaaaaaaaaa"
                                           "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                                           "aaaaaaaaaaaaaaa",
                                           "alice@jabber.org", 'u'))
        self.assertTrue(Rx.l_m_received["ualice@jabber.org"])
        self.assertFalse(Rx.l_m_incoming["ualice@jabber.org"])
        self.assertEqual(Rx.l_m_p_buffer["ualice@jabber.org"], 2000 * "data")

        # Teardown
        ut_cleanup()


class TestLongFileEnd(ExtendedTestCase):

    def test_1_input_parameters(self):
        for a in not_str:
            for b in not_str:
                for c in not_str:
                    with self.assertRaises(SystemExit):
                        long_file_end(a, b, c)

    def test_2_sent_long_file(self):

        # Setup
        create_contact(["alice"])
        c_dictionary["alice@jabber.org"]["storing"] = True
        Rx.l_f_received["ualice@jabber.org"] = False
        Rx.l_f_incoming["ualice@jabber.org"] = True
        Rx.l_f_p_buffer["ualice@jabber.org"] = "1st2nd"

        # Test
        self.assertIsNone(long_file_end("d3rd", "alice@jabber.org", 'u'))
        self.assertTrue(Rx.l_f_received["ualice@jabber.org"])
        self.assertFalse(Rx.l_f_incoming["ualice@jabber.org"])
        self.assertEqual(Rx.l_f_p_buffer["ualice@jabber.org"], "1st2nd3rd")

        # Teardown
        ut_cleanup()

    def test_3_received_long_file(self):

        # Setup
        create_contact(["alice"])
        c_dictionary["alice@jabber.org"]["storing"] = True
        Rx.l_f_received["calice@jabber.org"] = False
        Rx.l_f_incoming["calice@jabber.org"] = True
        Rx.l_f_p_buffer["calice@jabber.org"] = "1st2nd"

        # Test
        self.assertIsNone(long_file_end("d3rd", "alice@jabber.org", 'c'))
        self.assertTrue(Rx.l_f_received["calice@jabber.org"])
        self.assertFalse(Rx.l_f_incoming["calice@jabber.org"])
        self.assertEqual(Rx.l_f_p_buffer["calice@jabber.org"], "1st2nd3rd")

        # Teardown
        ut_cleanup()


class TestLongCommandEnd(ExtendedTestCase):

    def test_1_input_parameter(self):
        for a in not_str:
            with self.assertRaises(SystemExit):
                long_command_end(a)

    def test_2_long_command_end(self):

        # Setup
        Rx.l_c_p_buffer["local"] = "1st2nd"
        Rx.l_c_received["local"] = False
        Rx.l_c_incoming["local"] = True

        # Test
        h = "ed3a9fb03a8f93944334d49a3dd87122a8fd891512e8515e8cba59da4e9cdcd7"
        self.assertIsNone(long_command_end("33rd" + h))
        self.assertTrue(Rx.l_c_received["local"])
        self.assertFalse(Rx.l_c_incoming["local"])
        self.assertEqual(Rx.l_c_p_buffer["local"], "1st2nd3rd")

        # Teardown
        ut_cleanup()


###############################################################################
#                               PROCESS MESSAGES                              #
###############################################################################

class TestProcessReceivedMessages(ExtendedTestCase):

    def test_1_input_paramteter(self):
        for a in not_str:
            for b in not_str:
                with self.assertRaises(SystemExit):
                    process_received_messages(a, b)

    def test_2_incomplete_message(self):

        l_m_received["calice@jabber.org"] = False

        self.assertFR("message not yet received",
                      process_received_messages, "alice@jabber.org", 'c')

    def test_3_key_error(self):
        l_m_received["calice@jabber.org"] = True
        l_m_p_buffer["calice@jabber.org"] = "aBadPacket"
        self.assertFR("Error: Received message had an invalid header.",
                      process_received_messages, "alice@jabber.org", 'c')


class TestInvitationToNewGroup(ExtendedTestCase):

    def test_1_input_parameters(self):
        for a in not_str:
            for b in not_str:
                for c in not_str:
                    with self.assertRaises(SystemExit):
                        invitation_to_new_group(a, b, c)

    def test_2_ignore_local_packets(self):
        self.assertFR("Ignored notification from TxM.",
                      invitation_to_new_group, us.join(['i', "testgroup"]),
                      "alice@jabber.org", 'u')

    def test_3_invalid_invitation(self):
        self.assertFR("Error: Received invalid group invitation.",
                      invitation_to_new_group, 'i',
                      "alice@jabber.org", 'c')

    def test_4_valid_invitation(self):

        # Setup
        create_contact(["alice", "charlie"])

        # Test
        self.assertIsNone(invitation_to_new_group(
            us.join(['i', "testgroup"]), "alice@jabber.org", 'c'))

        # Teardown
        ut_cleanup()

    def test_5_valid_invitation_with_members(self):

        # Setup
        create_contact(["alice", "charlie", "eric"])

        # Test
        self.assertIsNone(invitation_to_new_group(
            us.join(['i', "testgroup", "bob@jabber.org",
                     "charlie@jabber.org", "david@jabber.org",
                     "eric@jabber.org"]),
            "alice@jabber.org", 'c'))

        # Teardown
        ut_cleanup()


class TestNewMembersInGroup(ExtendedTestCase):

    def test_1_input_parameters(self):
        for a in not_str:
            for b in not_str:
                for c in not_str:
                    with self.assertRaises(SystemExit):
                        new_members_in_group(a, b, c)

    def test_2_ignore_local_packets(self):
        self.assertFR("Ignored notification from TxM.",
                      new_members_in_group, us.join(['n', "testgroup"]),
                      "alice@jabber.org", 'u')

    def test_3_invalid_notification(self):
        self.assertFR("Error: Received an invalid group notification.",
                      new_members_in_group, 'n',
                      "alice@jabber.org", 'c')

    def test_4_invalid_notification(self):
        self.assertFR("Error: Received an invalid group notification.",
                      new_members_in_group, us.join(['n', "testgroup"]),
                      "alice@jabber.org", 'c')

    def test_5_valid_notification(self):

        # Setup
        create_contact(["alice", "eric", "charlie"])

        # Test
        self.assertIsNone(new_members_in_group(
            us.join(['n', "testgroup", "bob@jabber.org",
                     "charlie@jabber.org", "david@jabber.org",
                     "eric@jabber.org"]),
            "alice@jabber.org", 'c'))

        # Teardown
        ut_cleanup()


class TestRemovedMembersFromGroup(ExtendedTestCase):

    def test_1_input_parameters(self):
        for a in not_str:
            for b in not_str:
                for c in not_str:
                    with self.assertRaises(SystemExit):
                        removed_members_from_group(a, b, c)

    def test_2_ignore_local_packets(self):
        self.assertFR("Ignored notification from TxM.",
                      removed_members_from_group, us.join(['r', "testgroup"]),
                      "alice@jabber.org", 'u')

    def test_3_invalid_notification(self):
        self.assertFR("Error: Received an invalid group notification.",
                      removed_members_from_group, 'r',
                      "alice@jabber.org", 'c')

    def test_4_invalid_notification(self):
        self.assertFR("Error: Received an invalid group notification.",
                      removed_members_from_group, us.join(['r', "testgroup"]),
                      "alice@jabber.org", 'c')

    def test_5_valid_notification(self):

        # Setup
        create_contact(["alice", "charlie", "eric"])

        # Test
        self.assertIsNone(removed_members_from_group(
            us.join(['r', "testgroup", "bob@jabber.org",
                     "charlie@jabber.org", "david@jabber.org",
                     "eric@jabber.org"]),
            "alice@jabber.org", 'c'))

        # Teardown
        ut_cleanup()


class TestMemberLeftGroup(ExtendedTestCase):

    def test_1_input_parameters(self):
        for a in not_str:
            for b in not_str:
                for c in not_str:
                    with self.assertRaises(SystemExit):
                        member_left_group(a, b, c)

    def test_2_ignore_local_packets(self):
        self.assertFR("Ignored notification from TxM.",
                      member_left_group, us.join(['l', "testgroup"]),
                      "alice@jabber.org", 'u')

    def test_3_invalid_exit_notification(self):
        self.assertFR("Error: Received an invalid group exit notification.",
                      member_left_group, 'l', "alice@jabber.org", 'c')

    def test_4_unknown_group(self):

        # Setup
        create_contact(["alice"])

        # Test
        self.assertFR("Unknown group in notification.",
                      member_left_group, us.join(['l', "testgroup"]),
                      "alice@jabber.org", 'c')
        # Teardown
        ut_cleanup()

    def test_5_user_not_member(self):

        # Setup
        create_contact(["alice"])
        create_group([("testgroup", ["charlie"])])

        # Test
        self.assertFR("User is not member.",
                      member_left_group, us.join(['l', "testgroup"]),
                      "alice@jabber.org", 'c')
        # Teardown
        ut_cleanup()

    def test_6_valid_notification(self):

        # Setup
        create_contact(["alice"])
        create_contact(["charlie"])
        create_group([("testgroup", ["alice", "charlie"])])

        # Test
        self.assertIsNone(member_left_group(
            us.join(['l', "testgroup"]),
            "alice@jabber.org", 'c'))

        # Teardown
        ut_cleanup()


class TestMessageToGroup(ExtendedTestCase):

    def test_1_input_parameters(self):
        for a in not_str:
            for b in not_str:
                for c in not_str:
                    with self.assertRaises(SystemExit):
                        message_to_group(a, b, c)

    def test_2_invalid_group_message(self):
        self.assertFR("Error: Received invalid group message.",
                      message_to_group, us.join(['g', "testgroup"]),
                      "alice@jabber.org", 'c')

    def test_3_unknown_group(self):
        self.assertFR("Ignored msg to unknown group.",
                      message_to_group, us.join(['g', "testgroup", "msg"]),
                      "alice@jabber.org", 'c')

    def test_4_account_not_member(self):

        # Setup
        create_contact(["alice"])
        create_group([("testgroup", ["charlie"])])

        # Test
        self.assertFR("Ignored msg from non-member.",
                      message_to_group, us.join(['g', "testgroup", "msg"]),
                      "alice@jabber.org", 'c')

        # Teardown
        ut_cleanup()

    def test_5_account_not_member(self):

        # Setup
        create_contact(["alice"])
        create_group([("testgroup", ["alice"])])

        # Test
        self.assertIsNone(message_to_group(
            us.join(['g', "testgroup", "msg"]), "alice@jabber.org", 'c'))

        # Teardown
        ut_cleanup()


class TestMessageToContact(ExtendedTestCase):

    def test_1_input_parameters(self):
        for a in not_str:
            for b in not_str:
                for c in not_str:
                    with self.assertRaises(SystemExit):
                        message_to_contact(a, b, c)

    def test_2_valid_message(self):

        # Setup
        create_contact(["alice"])

        self.assertIsNone(message_to_contact(us.join(['p', "msg"]),
                                             "alice@jabber.org", 'c'))

        # Teardown
        ut_cleanup()


###############################################################################
#                                PROCESS FILES                                #
###############################################################################

class TestProcessReceivedFiles(ExtendedTestCase):

    def test_1_input_parameters(self):
        for a in not_str:
            for b in not_str:
                with self.assertRaises(SystemExit):
                    process_received_files(a, b)

    def test_2_incomplete_file(self):

        # Setup
        create_contact(["alice"])

        l_f_incoming["calice@jabber.org"] = True
        l_f_received["calice@jabber.org"] = False

        # Test
        self.assertFR("file not yet received",
                      process_received_files, "alice@jabber.org", 'c')

    def test_3_disabled_reception(self):

        # Setup
        create_contact(["alice"])

        l_f_p_buffer["calice@jabber.org"] = "data"
        l_f_incoming["calice@jabber.org"] = True
        l_f_received["calice@jabber.org"] = True
        c_dictionary["alice@jabber.org"]["storing"] = False

        # Test
        self.assertFR("file reception disabled",
                      process_received_files, "alice@jabber.org", 'c')

        self.assertEqual(l_f_p_buffer["calice@jabber.org"], '')

    def test_4_discard_local_file(self):

        # Setup
        create_contact(["alice"])

        l_f_p_buffer["ualice@jabber.org"] = "data"
        l_f_incoming["ualice@jabber.org"] = True
        l_f_received["ualice@jabber.org"] = True
        c_dictionary["alice@jabber.org"]["storing"] = True
        Rx.store_copy_of_file = False

        # Test
        self.assertFR("Locally received file was discarded.",
                      process_received_files, "alice@jabber.org", 'u')

        self.assertEqual(l_f_p_buffer["ualice@jabber.org"], '')

    def test_5_invalid_packet_data(self):

        # Setup
        f_data = ("WKtuu4mCmtm8E4zdM03G8G+62M0USGcxcYVbh9dRG7Jz3dK/I/ya56g2m4Y"
                  "jckAn0BH0X1XYzcFSrK8hwrFBy2th4fU=7343add6c9d4bc99c3ea2de5e9"
                  "fcff19957c97c7dcfb73b6818fd3ed58838501")

        packet = us.join(['p', "doc.txt", "00d 00h 00m 00s", f_data])

        l_f_p_buffer["calice@jabber.org"] = packet

        l_f_incoming["calice@jabber.org"] = True
        l_f_received["calice@jabber.org"] = True
        c_dictionary["alice@jabber.org"]["storing"] = True

        # Test
        self.assertFR("Error: Invalid packet data. Discarded file from alice.",
                      process_received_files, "alice@jabber.org", 'c')

    def test_6_invalid_packet_encoding(self):

        # Setup
        f_data = ("€Ktuu4mCmtm8E4zdM03G8G+62M0USGcxcYVbh9dRG7Jz3dK/I/ya56g2m4Y"
                  "jckAn0BH0X1XYzcFSrK8hwrFBy2th4fU=7343add6c9d4bc99c3ea2de5e9"
                  "fcff19957c97c7dcfb73b6818fd3ed58838501")

        packet = us.join(['p', "doc.txt", "1.1KB", "00d 00h 00m 00s", f_data])

        l_f_p_buffer["calice@jabber.org"] = packet

        l_f_incoming["calice@jabber.org"] = True
        l_f_received["calice@jabber.org"] = True
        c_dictionary["alice@jabber.org"]["storing"] = True

        # Test
        self.assertFR("Error: Invalid encoding. Discarded file from alice.",
                      process_received_files, "alice@jabber.org", 'c')

    def test_7_invalid_packet_MAC(self):

        # Setup
        f_data = ("XKtuu4mCmtm8E4zdM03G8G+62M0USGcxcYVbh9dRG7Jz3dK/I/ya56g2m4Y"
                  "jckAn0BH0X1XYzcFSrK8hwrFBy2th4fU=7343add6c9d4bc99c3ea2de5e9"
                  "fcff19957c97c7dcfb73b6818fd3ed58838501")

        packet = us.join(['p', "doc.txt", "1.1KB", "00d 00h 00m 00s", f_data])

        l_f_p_buffer["calice@jabber.org"] = packet

        l_f_incoming["calice@jabber.org"] = True
        l_f_received["calice@jabber.org"] = True
        c_dictionary["alice@jabber.org"]["storing"] = True

        # Test
        self.assertFR("Error: File MAC failed. Discarded file from alice.",
                      process_received_files, "alice@jabber.org", 'c')

    def test_8_valid_packet(self):

        # Setup
        f_data = ("WKtuu4mCmtm8E4zdM03G8G+62M0USGcxcYVbh9dRG7Jz3dK/I/ya56g2m4Y"
                  "jckAn0BH0X1XYzcFSrK8hwrFBy2th4fU=7343add6c9d4bc99c3ea2de5e9"
                  "fcff19957c97c7dcfb73b6818fd3ed58838501")

        packet = us.join(['p', "doc.txt", "1.1KB", "00d 00h 00m 00s", f_data])

        l_f_p_buffer["calice@jabber.org"] = packet

        l_f_incoming["calice@jabber.org"] = True
        l_f_received["calice@jabber.org"] = True
        c_dictionary["alice@jabber.org"]["storing"] = True

        # Test
        self.assertIsNone(process_received_files("alice@jabber.org", 'c'))

        f_data = open("received_files/doc.txt").read().splitlines()[0]

        self.assertEqual(f_data, 100 * "TestData  ")

        # Teardown
        ut_cleanup()


###############################################################################
#                               PROCESS COMMANDS                              #
###############################################################################

class TestProcessReceivedCommand(ExtendedTestCase):

    def test_1_command_not_complete(self):
        l_c_received["local"] = False
        self.assertFR("command not yet received",
                      process_received_command)

    def test_2_invalid_command_exits(self):
        l_c_p_buffer["local"] = "invalid"
        l_c_received["local"] = True

        with self.assertRaises(SystemExit):
            process_received_command()


class TestChangeNick(ExtendedTestCase):

    def test_1_input_parameter(self):
        for a in not_str:
            with self.assertRaises(SystemExit):
                change_nick(a)

    def test_2_invalid_parameters(self):

        # Setup
        create_contact(["alice"])

        # Test
        self.assertFR("Error: Invalid data in command packet.",
                      change_nick, us.join(["CN", "alice@jabber.org"]))

        # Teardown
        ut_cleanup()

    def test_3_unknown_account(self):

        # Setup
        create_contact(["alice"])

        # Test
        cmd = us.join(["CN", "charlie@jabber.org", "CHARLIE"])

        self.assertFR("Error: Unknown account.",
                      change_nick, cmd)

        # Teardown
        ut_cleanup()

    def test_4_valid_parameters(self):

        # Setup
        create_contact(["alice"])

        # Test
        cmd = us.join(["CN", "alice@jabber.org", "ALICE"])
        self.assertIsNone(change_nick(cmd))

        self.assertEqual(c_dictionary["alice@jabber.org"]["nick"], "ALICE")

        # Teardown
        ut_cleanup()


class TestChangeLogging(ExtendedTestCase):

    def test_1_input_parameter(self):
        for a in not_str:
            with self.assertRaises(SystemExit):
                change_logging(a)

    def test_2_invalid_command(self):
        self.assertFR("Error: Invalid command.", change_logging, '')

    def test_3_enable_all(self):

        # Setup
        create_contact(["alice", "bob", "charlie"])
        create_group([("testgroup", ["alice", "bob"])])

        for a in ["alice@jabber.org", "bob@jabber.org", "charlie@jabber.org"]:
            c_dictionary[a]["logging"] = False
        g_dictionary["testgroup"]["logging"] = False

        # Test
        self.assertIsNone(change_logging(us.join(["CL", 'E'])))
        self.assertTrue(c_dictionary["alice@jabber.org"]["logging"])
        self.assertTrue(c_dictionary["bob@jabber.org"]["logging"])
        self.assertTrue(c_dictionary["charlie@jabber.org"]["logging"])
        self.assertTrue(g_dictionary["testgroup"]["logging"])

        # Teardown
        ut_cleanup()

    def test_4_disable_all(self):

        # Setup
        create_contact(["alice", "bob", "charlie"])
        create_group([("testgroup", ["alice", "bob"])])

        for a in ["alice@jabber.org", "bob@jabber.org", "charlie@jabber.org"]:
            c_dictionary[a]["logging"] = True
        g_dictionary["testgroup"]["logging"] = True

        # Test
        self.assertIsNone(change_logging(us.join(["CL", 'D'])))
        self.assertFalse(c_dictionary["alice@jabber.org"]["logging"])
        self.assertFalse(c_dictionary["bob@jabber.org"]["logging"])
        self.assertFalse(c_dictionary["charlie@jabber.org"]["logging"])
        self.assertFalse(g_dictionary["testgroup"]["logging"])

        # Teardown
        ut_cleanup()

    def test_5_enable_for_account(self):

        # Setup
        create_contact(["alice", "bob", "charlie"])
        create_group([("testgroup", ["alice", "bob"])])

        for a in ["alice@jabber.org", "bob@jabber.org", "charlie@jabber.org"]:
            c_dictionary[a]["logging"] = False
        g_dictionary["testgroup"]["logging"] = False

        # Test
        self.assertIsNone(change_logging(us.join(["CL", 'e',
                                                  "alice@jabber.org"])))
        self.assertTrue(c_dictionary["alice@jabber.org"]["logging"])
        self.assertFalse(c_dictionary["bob@jabber.org"]["logging"])
        self.assertFalse(c_dictionary["charlie@jabber.org"]["logging"])
        self.assertFalse(g_dictionary["testgroup"]["logging"])

        # Teardown
        ut_cleanup()

    def test_6_enable_for_group(self):

        # Setup
        create_contact(["alice", "bob", "charlie"])
        create_group([("testgroup", ["alice", "bob"])])

        for a in ["alice@jabber.org", "bob@jabber.org", "charlie@jabber.org"]:
            c_dictionary[a]["logging"] = False
        g_dictionary["testgroup"]["logging"] = False

        # Test
        self.assertIsNone(change_logging(us.join(["CL", 'e',
                                                  "testgroup"])))
        self.assertFalse(c_dictionary["alice@jabber.org"]["logging"])
        self.assertFalse(c_dictionary["bob@jabber.org"]["logging"])
        self.assertFalse(c_dictionary["charlie@jabber.org"]["logging"])
        self.assertTrue(g_dictionary["testgroup"]["logging"])

        # Teardown
        ut_cleanup()

    def test_7_disable_for_account(self):

        # Setup
        create_contact(["alice", "bob", "charlie"])
        create_group([("testgroup", ["alice", "bob"])])

        for a in ["alice@jabber.org", "bob@jabber.org", "charlie@jabber.org"]:
            c_dictionary[a]["logging"] = True
        g_dictionary["testgroup"]["logging"] = True

        # Test
        self.assertIsNone(change_logging(us.join(["CL", 'd',
                                                  "alice@jabber.org"])))
        self.assertFalse(c_dictionary["alice@jabber.org"]["logging"])
        self.assertTrue(c_dictionary["bob@jabber.org"]["logging"])
        self.assertTrue(c_dictionary["charlie@jabber.org"]["logging"])
        self.assertTrue(g_dictionary["testgroup"]["logging"])

        # Teardown
        ut_cleanup()

    def test_8_disable_for_group(self):

        # Setup
        create_contact(["alice", "bob", "charlie"])
        create_group([("testgroup", ["alice", "bob"])])

        for a in ["alice@jabber.org", "bob@jabber.org", "charlie@jabber.org"]:
            c_dictionary[a]["logging"] = True
            g_dictionary["testgroup"]["logging"] = True

        # Test
        self.assertIsNone(change_logging(us.join(["CL", 'd', "testgroup"])))
        self.assertTrue(c_dictionary["alice@jabber.org"]["logging"])
        self.assertTrue(c_dictionary["bob@jabber.org"]["logging"])
        self.assertTrue(c_dictionary["charlie@jabber.org"]["logging"])
        self.assertFalse(g_dictionary["testgroup"]["logging"])

        # Teardown
        ut_cleanup()


class TestControlStoring(ExtendedTestCase):

    def test_1_input_parameter(self):
        for a in not_str:
            with self.assertRaises(SystemExit):
                control_settings(a)

    def test_2_invalid_command(self):
        self.assertFR("Error: Invalid command.", control_settings, '')

    def test_3_enable_storing_for_all(self):

        # Setup
        create_contact(["alice", "bob", "charlie"])

        for a in ["alice@jabber.org", "bob@jabber.org", "charlie@jabber.org"]:
            c_dictionary[a]["storing"] = False

        # Test
        self.assertIsNone(control_settings(us.join(["CF", 'E'])))
        self.assertTrue(c_dictionary["alice@jabber.org"]["storing"])
        self.assertTrue(c_dictionary["bob@jabber.org"]["storing"])
        self.assertTrue(c_dictionary["charlie@jabber.org"]["storing"])

        # Teardown
        ut_cleanup()

    def test_4_disable_storing_for_all(self):

        # Setup
        create_contact(["alice", "bob", "charlie"])

        for a in ["alice@jabber.org", "bob@jabber.org", "charlie@jabber.org"]:
            c_dictionary[a]["storing"] = True

        # Test
        self.assertIsNone(control_settings(us.join(["CF", 'D'])))
        self.assertFalse(c_dictionary["alice@jabber.org"]["storing"])
        self.assertFalse(c_dictionary["bob@jabber.org"]["storing"])
        self.assertFalse(c_dictionary["charlie@jabber.org"]["storing"])

        # Teardown
        ut_cleanup()

    def test_5_enable_storing_for_account(self):

        # Setup
        create_contact(["alice", "bob", "charlie"])

        for a in ["alice@jabber.org", "bob@jabber.org", "charlie@jabber.org"]:
            c_dictionary[a]["storing"] = False

        # Test
        self.assertIsNone(control_settings(us.join(["CF", 'e',
                                                    "alice@jabber.org"])))
        self.assertTrue(c_dictionary["alice@jabber.org"]["storing"])
        self.assertFalse(c_dictionary["bob@jabber.org"]["storing"])
        self.assertFalse(c_dictionary["charlie@jabber.org"]["storing"])

        # Teardown
        ut_cleanup()

    def test_6_disable_storing_for_account(self):

        # Setup
        create_contact(["alice", "bob", "charlie"])

        for a in ["alice@jabber.org", "bob@jabber.org", "charlie@jabber.org"]:
            c_dictionary[a]["storing"] = True

        # Test
        self.assertIsNone(control_settings(us.join(["CF", 'd',
                                                    "alice@jabber.org"])))
        self.assertFalse(c_dictionary["alice@jabber.org"]["storing"])
        self.assertTrue(c_dictionary["bob@jabber.org"]["storing"])
        self.assertTrue(c_dictionary["charlie@jabber.org"]["storing"])

        # Teardown
        ut_cleanup()

    def test_7_invalid_key(self):
        self.assertFR("Error: Invalid key in command.", control_settings,
                      us.join(["CD", 'd' "alice@jabber.org"]))


###############################################################################
#                                  PROCESSES                                  #
###############################################################################

class TestNHPacketLoadingProcess(ExtendedTestCase):
    """
    This function doesn't have any tests yet.
    """


class TestMainLoopProcess(ExtendedTestCase):
    """
    This function doesn't have any tests yet.
    """

###############################################################################
#                                     MAIN                                    #
###############################################################################

if __name__ == "__main__":

    Rx.unit_test = True
    os.chdir(sys.path[0])

    try:
        print('')
        if not ut_yes("Running this unittest overwrites all "
                      "existing TFC user data. Proceed?", 1):
            print("\nExiting.\n")
            exit()

    except KeyboardInterrupt:
        print("\n\nExiting.\n")
        exit()

    pname = subprocess.check_output(["grep", "PRETTY_NAME", "/etc/os-release"])
    rpi_os = "Raspbian GNU/Linux" in pname

    try:
        os.remove("Rx.pyc")
    except OSError:
        pass

    ut_cleanup()
    unittest.main(exit=False)

    try:
        os.remove("Rx.pyc")
    except OSError:
        pass
