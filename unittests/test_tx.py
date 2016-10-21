#!/usr/bin/env python
# -*- coding: utf-8 -*-

# TFC 0.16.10 || test_tx.py

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

import Tx
from Tx import *
import binascii
import os.path
import os
import re
import shutil
import sys
import unittest


###############################################################################
#                               UNITTEST HELPERS                              #
###############################################################################

Tx.trickle_connection = False
Tx.m_members_in_group = 20
Tx.m_number_of_groups = 20
Tx.m_number_of_accnts = 20

Tx.master_key = 64 * 'f'
Tx.rpi_os = False
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

    def assertPacketOutput(self, i, t):

        data = bytearray(b64d(open("unitt_txm_out_%s" % i).readline()))
        data = str(reed_solomon.decode(data))

        self.assertEqual(data[0], '1')
        self.assertEqual(data[1], 'N')

        if t == 'l':
            self.assertEqual(data[2], 'L')
            self.assertEqual(len(data), 173)

        if t == 'm':
            self.assertEqual(data[2], 'M')

        if t == 'c':
            self.assertEqual(len(data), 357)
            self.assertEqual(data[2], 'C')
            self.assertEqual(data[-11:], "local" + us + "local")

        if t == 'e':
            self.assertEqual(data, "1NUEX")

        if t == 'd':
            self.assertEqual(data[2], 'U')
            self.assertTrue(data[3:5] in ["SC", "SR"])

        if t == 'p':
            self.assertEqual(data[2], 'P')
            self.assertTrue(ut_validate_key(data[3:67]))
            u, a = data[67:].split(us)
            self.assertTrue(re.match("(^.[^/:,]*@.[^/:,]*\.[^/:,]*.$)", u))
            self.assertTrue(re.match("(^.[^/:,]*@.[^/:,]*\.[^/:,]*.$)", a))


def create_contact(nick_list, user="user@jabber.org",
                   key=64 * 'a', hek=64 * 'b', store=False):
    """
    Add entry to contact database.

    :param nick_list: List of nicks based on which accounts are created
    :param user:      Account of user associated with contact's account
    :param key:       Forward secret key
    :param hek:       Static header encryption key
    :param store:     When True, writes database to file
    :return:          None
    """

    for nick in nick_list:

        if nick == "local":
            c_dictionary["local"] = dict(user="local", nick="local",
                                         harac=1, 
                                         key=key, hek=hek,
                                         txpk="psk", rxpk="psk",
                                         logging=Tx.txm_side_m_logging)

        else:
            c_dictionary["%s@jabber.org" % nick] = \
                dict(user=user, nick=nick, 
                     harac=1, 
                     key=key, hek=hek,
                     txpk="psk", rxpk="psk", 
                     logging=Tx.txm_side_m_logging)

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
        g_dictionary[group_name] = dict(logging=Tx.txm_side_m_logging,
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

    for directory in ["unittest_directory", "keys_to_contact"]:
        try:
            shutil.rmtree(directory)
        except OSError:
            pass

    for f in [Tx.ssh_l_file, Tx.login_file, Tx.datab_file,
              Tx.group_file, Tx.txlog_file, "tfc_unittest_doc.txt"]:
        try:
            os.remove(f)
        except OSError:
            pass

    for ut_f in os.listdir('.'):
        if ut_f.startswith("unitt_txm_out_"):
            os.remove(ut_f)

    for key in g_dictionary.keys():
        del g_dictionary[key]

    for key in c_dictionary.keys():
        del c_dictionary[key]


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

        self.assertEqual(pbkdf2_hmac_sha256("password", 1, "salt"),
                         "120fb6cffcf8b32c43e7225256c4f837"
                         "a86548c92ccc35480805987cb70be17b")

        self.assertEqual(pbkdf2_hmac_sha256("password", 4096, "salt"),
                         "c5e478d59288c841aa530db6845c4c8d"
                         "962893a001ce4e11a4963873aa98134a")


class TestEncryptAndSign(ExtendedTestCase):

    def test_1_input_parameters(self):
        for a in not_str:
            for b in not_str:
                for c in not_str:
                    for d in not_bool:
                        with self.assertRaises(SystemExit):
                            encrypt_and_sign(a, b, c, d)

    def test_2_ct_length(self):
        """
        len(nonce)           == 24
        len("plaintext msg") == 13
        len(tag)             == 16
                                53 in total.
        """

        output = encrypt_and_sign("plaintext msg", key=(64 * 'f'), pad=False)

        self.assertEqual(len(base64.b64decode(output)), 53)

    def test_3_next_key(self):

        # Setup
        create_contact(["bob"])

        o_nacl_utils_random = Tx.nacl.utils.random
        Tx.nacl.utils.random = lambda x: 24 * 'a'

        # Test
        encrypt_and_sign("plaintext message", "bob@jabber.org")

        next_key = c_dictionary["bob@jabber.org"]["key"]

        self.assertEqual(next_key, pbkdf2_hmac_sha256(64 * 'a', rounds=1))

        # Teardown
        ut_cleanup()
        Tx.nacl.utils.random = o_nacl_utils_random

    def test_4_official_test_vectors(self):
        """
        Test vectors:

        https://cr.yp.to/highspeed/naclcrypto-20090310.pdf // page 35
        """

        # Setup
        nonce = ("69696ee955b62b73"
                 "cd62bda875fc73d6"
                 "8219e0036b7a0b37")

        o_nacl_utils_random = Tx.nacl.utils.random
        Tx.nacl.utils.random = lambda x: binascii.unhexlify(nonce)

        # Test
        key_tv_hex = ("1b27556473e985d4"
                      "62cd51197a9a46c7"
                      "6009549eac6474f2"
                      "06c4ee0844f68389")

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

        ct_purp_b64 = encrypt_and_sign(binascii.unhexlify(pt_tv_hex),
                                       key=key_tv_hex,
                                       pad=False)

        ct_purp_hex = binascii.hexlify(base64.b64decode(ct_purp_b64))
        self.assertEqual(ct_purp_hex, (nonce + ct_tv_hex))

        # Teardown
        Tx.nacl.utils.random = o_nacl_utils_random
        ut_cleanup()


class TestPadding(ExtendedTestCase):

    def test_1_input_parameters(self):
        for a in not_str:
            for b in not_bool:
                with self.assertRaises(SystemExit):
                    padding(a, b)

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

    def test_4_padding_with_no_length_check(self):
        for s in range(0, 1000):
            string = s * 'm'
            padded = padding(string, len_check=False)
            self.assertTrue(len(padded) % 255 == 0)

            # Verify removal of padding doesn't alter the string.
            self.assertEqual(string, padded[:-ord(padded[-1:])])


class TestRmPadding(unittest.TestCase):

    def test_1_input_parameter(self):
        for a in not_str:
            with self.assertRaises(SystemExit):
                rm_padding(a)

    def test_2_padding_removal(self):
        for i in range(0, 1000):
            string = i * 'm'
            length_of_padding = 255 - (len(string) % 255)
            padded_string = string + length_of_padding * chr(length_of_padding)
            self.assertEqual(rm_padding(padded_string), string)


class TestEncryptData(ExtendedTestCase):

    def test_1_input_parameters(self):
        for a in not_str:
            for b in not_str:
                for c in not_str:
                    for d in not_str:
                        with self.assertRaises(SystemExit):
                            encrypt_data(a, b, c, d)

    def test_2_no_path(self):

        # Test
        self.assertIsNone(encrypt_data("bob@jabber.org.psk",
                                       (64 * 'a'), Tx.master_key))

        key_from_file = open("bob@jabber.org.psk").readline()
        self.assertEqual(len(key_from_file), 140)

        # Teardown
        os.remove("bob@jabber.org.psk")
        ut_cleanup()

    def test_3_with_path(self):

        # Setup
        ut_ensure_dir("unittest_directory/")

        # Test
        self.assertIsNone(encrypt_data("unittest_directory/bob@jabber.org.psk",
                                       (64 * 'a')))

        key_from_file = open("unittest_directory/"
                             "bob@jabber.org.psk").readline()
        self.assertEqual(len(key_from_file), 140)

        # Teardown
        ut_cleanup()

    def test_4_with_path_and_salt(self):

        # Setup
        ut_ensure_dir("unittest_directory/")

        # Test
        self.assertIsNone(encrypt_data("unittest_directory/bob@jabber.org.psk",
                                       (64 * 'a'), salt="saltsalt"))

        key_from_file = open("unittest_directory/"
                             "bob@jabber.org.psk").readline()

        self.assertEqual(len(key_from_file), 148)
        self.assertEqual(key_from_file[:8], "saltsalt")

        # Teardown
        ut_cleanup()


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
        o_master_key = Tx.master_key

        # Test
        nonce = ("69696ee955b62b73"
                 "cd62bda875fc73d6"
                 "8219e0036b7a0b37")

        iv_bin = binascii.unhexlify(nonce)

        Tx.master_key = ("1b27556473e985d4"
                         "62cd51197a9a46c7"
                         "6009549eac6474f2"
                         "06c4ee0844f68389")

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

        ct_tv_bin = binascii.unhexlify(ct_tv_hex)

        pt = decrypt_data(base64.b64encode(iv_bin + ct_tv_bin))

        self.assertEqual(binascii.hexlify(pt), pt_tv_hex)

        with self.assertRaises(SystemExit):
            decrypt_data(base64.b64encode(iv_bin + ct_tv_bin + 'a'))

        with self.assertRaises(SystemExit):
            decrypt_data(base64.b64encode('€' + iv_bin + ct_tv_bin))

        # Teardown
        Tx.master_key = o_master_key


###############################################################################
#                                KEY GENERATION                               #
###############################################################################

class TestNativeSampler(ExtendedTestCase):

    def test_1_input_parameters(self):
        for a in not_str:
            for b in not_int:
                with self.assertRaises(SystemExit):
                    native_sampler(a, b)

    def test_2_invalid_ent_size(self):
        for i in [255, 511, 767]:
            with self.assertRaises(AssertionError):
                native_sampler("test", i)

    def test_3_mock_hwrng_input(self):

        # Setup
        class GPIOMock(object):

            def __init__(self):
                pass

            @staticmethod
            def setmode(_):
                pass

            @staticmethod
            def BCM():
                pass

            @staticmethod
            def setup(port, inp, pull_up_down):
                _ = port
                _ = inp
                _ = pull_up_down
                return None

            @staticmethod
            def IN():
                pass

            @staticmethod
            def PUD_DOWN():
                pass

            @staticmethod
            def input(_):
                return ord(os.urandom(1)) % 2

            @staticmethod
            def cleanup():
                pass

        Tx.sample_delay = 0.0001
        o_gpio = Tx.GPIO
        Tx.GPIO = GPIOMock

        # Test
        ent = native_sampler("test", 256)
        self.assertTrue(ut_validate_key(ent[0]))

        ent = native_sampler("test", 512)
        self.assertTrue(ut_validate_key(ent[0]))
        self.assertTrue(ut_validate_key(ent[1]))

        ent = native_sampler("test", 768)
        self.assertTrue(ut_validate_key(ent[0]))
        self.assertTrue(ut_validate_key(ent[1]))
        self.assertTrue(ut_validate_key(ent[2]))

        # Teardown
        Tx.GPIO = o_gpio


class TestFixedAESNew(ExtendedTestCase):
    """
    This function doesn't have any tests yet.
    """


class TestSSHpwd(ExtendedTestCase):

    def test_1_input_parameter(self):
        for a in not_bool:
            with self.assertRaises(SystemExit):
                ssh_pwd(a)

    def test_2_new_password(self):

        # Setup
        o_new_password = Tx.new_password
        Tx.new_password = lambda x: "testpassword"

        # Test
        loaded = ssh_pwd()
        self.assertEqual(loaded, "testpassword")

        # Teardown
        ut_cleanup()
        Tx.new_password = o_new_password

    def test_3_long_password(self):

        # Setup
        o_new_password = Tx.new_password
        Tx.new_password = lambda x: 500 * 'a'

        # Test
        loaded = ssh_pwd()
        self.assertEqual(loaded, 500 * 'a')

        # Teardown
        ut_cleanup()
        Tx.new_password = o_new_password

    def test_4_existing_password(self):

        # Setup
        pwd_ct = ("F9TpSQAMHplT5xYjXy5Bxh3WnbuiOp9l5Z+UBsY0D6mm7y3SIc/+PelT+Rx"
                  "1LnZM8r1J72KwzR3I39SketrtqsERR2soVM72sT/1emIrGtlVP9HKG6lOYQ"
                  "28pWLUkxqj+ZCNm5JijsKkr9N0KXh5Ev7dVnlouDFq5Pk/X+yXsLRzGPKr2"
                  "AkxrjZB28gC327sPuRKxJxjLyHm5DDz8VjaTYIi1EP0B2Wmq1kszEJmoaSd"
                  "ZgrpMsOqTsSJyaYMZmy2q+upzFglFwkqKK0tUgKM5qW7EtxGbCP6uxo5tHt"
                  "Bi2G26G7lyXDWdtv2C5m9Ly49tUZ9mbqJUwqTvawkJyqnHMKC5380C8Gf+8"
                  "zUcqUtQO2TB7jnoy2c/Du9LVEtL20y35ha25467g==")

        open(Tx.ssh_l_file, "w+").write(pwd_ct)

        # Test
        self.assertEqual(ssh_pwd(), "testpassword")

        # Teardown
        ut_cleanup()

    def test_5_invalid_login_data_exits(self):

        # Setup
        pwd_ct = ("A9TpSQAMHplT5xYjXy5Bxh3WnbuiOp9l5Z+UBsY0D6mm7y3SIc/+PelT+Rx"
                  "1LnZM8r1J72KwzR3I39SketrtqsERR2soVM72sT/1emIrGtlVP9HKG6lOYQ"
                  "28pWLUkxqj+ZCNm5JijsKkr9N0KXh5Ev7dVnlouDFq5Pk/X+yXsLRzGPKr2"
                  "AkxrjZB28gC327sPuRKxJxjLyHm5DDz8VjaTYIi1EP0B2Wmq1kszEJmoaSd"
                  "ZgrpMsOqTsSJyaYMZmy2q+upzFglFwkqKK0tUgKM5qW7EtxGbCP6uxo5tHt"
                  "Bi2G26G7lyXDWdtv2C5m9Ly49tUZ9mbqJUwqTvawkJyqnHMKC5380C8Gf+8"
                  "zUcqUtQO2TB7jnoy2c/Du9LVEtL20y35ha25467g==")

        open(Tx.ssh_l_file, "w+").write(pwd_ct)

        # Test
        with self.assertRaises(SystemExit):
            ssh_pwd()

        # Teardown
        ut_cleanup()

    def test_6_invalid_login_data_encoding_exits(self):

        # Setup
        pwd_ct = ("€9TpSQAMHplT5xYjXy5Bxh3WnbuiOp9l5Z+UBsY0D6mm7y3SIc/+PelT+Rx"
                  "1LnZM8r1J72KwzR3I39SketrtqsERR2soVM72sT/1emIrGtlVP9HKG6lOYQ"
                  "28pWLUkxqj+ZCNm5JijsKkr9N0KXh5Ev7dVnlouDFq5Pk/X+yXsLRzGPKr2"
                  "AkxrjZB28gC327sPuRKxJxjLyHm5DDz8VjaTYIi1EP0B2Wmq1kszEJmoaSd"
                  "ZgrpMsOqTsSJyaYMZmy2q+upzFglFwkqKK0tUgKM5qW7EtxGbCP6uxo5tHt"
                  "Bi2G26G7lyXDWdtv2C5m9Ly49tUZ9mbqJUwqTvawkJyqnHMKC5380C8Gf+8"
                  "zUcqUtQO2TB7jnoy2c/Du9LVEtL20y35ha25467g==")

        open(Tx.ssh_l_file, "w+").write(pwd_ct)

        # Test
        with self.assertRaises(SystemExit):
            ssh_pwd()

        # Teardown
        ut_cleanup()


class TestSamplingOverSSH(ExtendedTestCase):

    def test_1_input_parameters(self):
        for a in not_str:
            for b in not_int:
                with self.assertRaises(SystemExit):
                    sampling_over_ssh(a, b)

    def test_2_invalid_ent_size(self):
        for i in [255, 511, 767]:
            with self.assertRaises(AssertionError):
                sampling_over_ssh("test", i)

    def test_3_sample_loading(self):

        # Setup
        class MockParamiko(object):

            @staticmethod
            def AutoAddPolicy():
                pass

            class util(object):

                @staticmethod
                def log_to_file(target_f):
                    _ = target_f

            class SSHClient(object):

                def __init__(self):
                    self.shell_cmd = ''

                @staticmethod
                def connect(hostname, username, password):
                    _ = hostname
                    _ = username
                    _ = password

                @staticmethod
                def set_missing_host_key_policy(policy):
                    _ = policy

                def exec_command(self, shell_cmd):
                    self.shell_cmd = shell_cmd
                    ent_size = int(shell_cmd.split()[1])

                    class STDINMock(object):

                        def __init__(self):
                            pass

                        @staticmethod
                        def flush():
                            pass

                    class STDOUTMock(object):

                        def __init__(self):
                            pass

                        def generator(self, size):
                            ent_str = size * 'N'
                            ent_str += binascii.hexlify(os.urandom(size / 8))
                            for c in ent_str:
                                yield c

                        g = generator(self, ent_size)

                        @staticmethod
                        def read(_):
                            return STDOUTMock.g.next()

                    return STDINMock(), STDOUTMock(), ''

                def get_cmd(self):
                    return self.shell_cmd

        o_paramiko = None
        if not rpi_os:
            o_paramiko = Tx.paramiko
        Tx.paramiko = MockParamiko

        o_new_password = Tx.new_password
        Tx.new_password = lambda x: "test"

        # Test
        ent1 = sampling_over_ssh("test", 256)
        self.assertTrue(ut_validate_key(ent1[0]))

        ent1, ent2 = sampling_over_ssh("test", 512)
        self.assertTrue(ut_validate_key(ent1))
        self.assertTrue(ut_validate_key(ent2))

        ent1, ent2, ent3 = sampling_over_ssh("test", 768)
        self.assertTrue(ut_validate_key(ent1))
        self.assertTrue(ut_validate_key(ent2))
        self.assertTrue(ut_validate_key(ent3))

        # Teardown
        ut_cleanup()
        Tx.new_password = o_new_password
        if not rpi_os:
            Tx.paramiko = o_paramiko


class TestCSPRNGSampler(ExtendedTestCase):

    def test_1_input_parameters(self):
        for a in not_str:
            for b in not_int:
                with self.assertRaises(SystemExit):
                    csprng_sampler(a, b)

    def test_2_invalid_ent_size(self):
        for i in [255, 511, 767]:
            with self.assertRaises(AssertionError):
                csprng_sampler("test", i)

    def test_3_valid_entropy(self):

        # Test
        key1 = csprng_sampler("test", 256)
        self.assertTrue(ut_validate_key(key1[0]))

        key1, key2 = csprng_sampler("test", 512)
        self.assertTrue(ut_validate_key(key1))
        self.assertTrue(ut_validate_key(key2))

        key1, key2, key3 = csprng_sampler("test", 768)
        self.assertTrue(ut_validate_key(key1))
        self.assertTrue(ut_validate_key(key2))
        self.assertTrue(ut_validate_key(key3))


class TestGenerateKey(ExtendedTestCase):

    def test_1_input_parameter(self):
        for a in not_str:
            with self.assertRaises(SystemExit):
                generate_key(a)

    def test_2_csprng_standard_key(self):

        # Setup
        Tx.ssh_hwrng_sampling = False

        # Test
        key = generate_key("private key")
        self.assertTrue(ut_validate_key(key[0]))

    def test_3_PSK_keys(self):

        # Setup
        Tx.ssh_hwrng_sampling = False

        # Test
        key1, key2 = generate_key("PSK")
        self.assertTrue(ut_validate_key(key1))
        self.assertTrue(ut_validate_key(key2))

    def test_4_csprng_local_keys(self):

        # Setup
        Tx.ssh_hwrng_sampling = False

        # Test
        key1, key2, key3 = generate_key("local key")
        self.assertTrue(ut_validate_key(key1))
        self.assertTrue(ut_validate_key(key2))
        self.assertTrue(ut_validate_key(key3))


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
        o_new_password = Tx.new_password
        Tx.new_password = lambda x: "test"

        # Test
        new_master_pwd()
        data = open(Tx.login_file).readline()
        rounds, salt, keyh = data.split('|')

        self.assertTrue(str(rounds).isdigit())
        self.assertTrue(ut_validate_key(salt))
        self.assertTrue(ut_validate_key(keyh))

        # Teardown
        Tx.new_password = o_new_password
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

        Tx.pwd_queue = QueueMock()
        Tx.key_queue = QueueMock()

        data = ("262144|"
                "79e098346bd45faf91bc599f2579c06f"
                "0a2b22a4b83cc3f25a5123380a3cc7b2|"
                "4ea8a5662ac638819789dc84104aa320"
                "d53a6bb633603771054b1332d29e9384")

        open(Tx.login_file, "w+").write(data)

        # Test
        check_master_pwd()
        tv = "346e12134edf2c4105be018745cd80f5a50041d21b771e1c6fd3f9151cfc1a08"
        key = Tx.key_queue.test()
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

        Tx.pwd_queue = QueueMock()
        Tx.key_queue = QueueMock()

        data = ("262144|"
                "79e098346bd45faf91bc599f2579c06f"
                "0a2b22a4b83cc3f25a5123380a3cc7b2|"
                "4ea8a5662ac638819789dc84104aa320"
                "d53a6bb633603771054b1332d29e9384")

        open(Tx.login_file, "w+").write(data)

        # Test
        check_master_pwd()
        key = Tx.key_queue.test()
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

        open(Tx.login_file, "w+").write(data)

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

        open(Tx.login_file, "w+").write(data)

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

        open(Tx.login_file, "w+").write(data)

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

        open(Tx.login_file, "w+").write(data)

        # Test
        with self.assertRaises(AssertionError):
            check_master_pwd()

        # Teardown
        ut_cleanup()


###############################################################################
#                                 KEY EXCHANGE                                #
###############################################################################

# Local Key
class TestNHBypassMSG(ExtendedTestCase):

    def test_1_input_parameter(self):
        for a in not_str:
            with self.assertRaises(SystemExit):
                nh_bypass_msg(a)

    def test_2_bypass_start(self):

        # Setup
        Tx.nh_bypass_messages = True
        o_raw_input = __builtins__.raw_input
        __builtins__.raw_input = lambda x: ''

        # Test
        self.assertIsNone(nh_bypass_msg('s'))

        # Teardown
        __builtins__.raw_input = o_raw_input

    def test_3_bypass_finish(self):

        # Setup
        Tx.nh_bypass_messages = True
        o_raw_input = __builtins__.raw_input
        __builtins__.raw_input = lambda x: ''

        # Test
        self.assertIsNone(nh_bypass_msg('f'))

        # Teardown
        __builtins__.raw_input = o_raw_input


class TestPrintKDK(ExtendedTestCase):

    def test_1_input_parameter(self):
        for a in not_str:
            with self.assertRaises(SystemExit):
                print_kdk(a)

    def test_2_local_testing_on(self):
        Tx.local_testing_mode = True
        self.assertIsNone(print_kdk(binascii.hexlify(os.urandom(32))))

    def test_3_local_testing_off(self):
        Tx.local_testing_mode = False
        self.assertIsNone(print_kdk(binascii.hexlify(os.urandom(32))))


class TestAskConfirmationCode(ExtendedTestCase):

    def test_1_get_confirmation_code(self):

        # Setup
        o_raw_input = __builtins__.raw_input
        __builtins__.raw_input = lambda x: "Testinput"

        # Test
        self.assertEqual(ask_confirmation_code(), "Testinput")

        # Teardown
        __builtins__.raw_input = o_raw_input


class TestGenerateConfirmationCode(ExtendedTestCase):

    def test_1_generate_confirmation_code(self):
        conf_code = generate_confirmation_code()
        self.assertEqual(len(conf_code), 2)
        self.assertTrue(set(conf_code.lower()).issubset("0123456789abcdef"))

    def test_2_mock_result(self):

        # Setup
        o_os_urandom = os.urandom
        os.urandom = lambda x: 'a'

        # Test
        code = generate_confirmation_code()
        self.assertEqual(code, "61")

        # Teardown
        os.urandom = o_os_urandom


class TestNewContact(ExtendedTestCase):

    def test_1_input_parameters(self):
        for a in not_str:
            for b in not_str:
                for c in not_str:
                    for d in not_str:
                        for e in not_str:
                            for f in not_str:
                                for g in not_str:
                                    with self.assertRaises(SystemExit):
                                        new_contact(a, b, c, d, e, f, g)

    def test_2_no_previous_contact(self):

        # Setup
        Tx.txm_side_m_logging = True

        # Test
        self.assertIsNone(new_contact("bob@jabber.org", "user@jabber.org",
                                      "Bob", 64 * 'a', 64 * 'b', "psk", "psk"))

        self.assertEqual(c_dictionary["bob@jabber.org"],
                         dict(user="user@jabber.org", nick="Bob",
                              harac=1,
                              key=(64 * 'a'), hek=(64 * 'b'),
                              txpk="psk", rxpk="psk",
                              logging=True))

        # Teardown
        ut_cleanup()

    def test_3_previous_contact(self):

        # Setup
        Tx.txm_side_m_logging = True

        # Test
        self.assertIsNone(new_contact("bob@jabber.org", "user@jabber.org",
                                      "Bob", 64 * 'a', 64 * 'b', "psk", "psk"))

        c_dictionary["bob@jabber.org"]["logging"] = False
        c_dictionary["bob@jabber.org"]["harac"] = 5

        self.assertIsNone(new_contact("bob@jabber.org", "user@jabber.org",
                                      "Bob", 64 * 'a', 64 * 'b', "psk", "psk"))

        self.assertEqual(c_dictionary["bob@jabber.org"],
                         dict(user="user@jabber.org", nick="Bob",
                              harac=1,
                              key=(64 * 'a'), hek=(64 * 'b'),
                              txpk="psk", rxpk="psk",
                              logging=False))
        # Teardown
        ut_cleanup()


class TestNewLocalKey(ExtendedTestCase):

    def test_1_new_local_key(self):

        # Setup
        Tx.ssh_hwrng_sampling = False
        Tx.txm_side_m_logging = False

        o_generate_key = Tx.generate_key
        Tx.generate_key = lambda x: 3 * [64 * 'a']

        o_generate_confirmation_code = Tx.generate_confirmation_code
        Tx.generate_confirmation_code = lambda: "ff"

        o_raw_input = __builtins__.raw_input
        __builtins__.raw_input = lambda x: ''

        o_ask_confirmation_code = Tx.ask_confirmation_code
        Tx.ask_confirmation_code = lambda: "ff"

        # Test
        self.assertIsNone(new_local_key())

        self.assertPacketOutput(0, 'l')
        self.assertPacketOutput(1, 'c')

        tdb = contact_db()
        self.assertEqual(tdb["local"]["nick"], "local")
        self.assertEqual(tdb["local"]["harac"], 2)

        self.assertEqual(tdb["local"]["key"],
                         "34f944624b341062a06e9afd4b00e041"
                         "5817414e4c4463fb2c5d7079b312bda8")

        self.assertEqual(tdb["local"]["hek"],
                         "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                         "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")

        self.assertEqual(tdb["local"]["txpk"], "psk")
        self.assertEqual(tdb["local"]["rxpk"], "psk")
        self.assertEqual(tdb["local"]["logging"], False)

        # Teardown
        ut_cleanup()

        Tx.ask_confirmation_code = o_ask_confirmation_code
        __builtins__.raw_input = o_raw_input
        Tx.generate_confirmation_code = o_generate_confirmation_code
        Tx.generate_key = o_generate_key


# ECDHE
class TestGetContactPublicKey(ExtendedTestCase):

    def test_1_input_parameter(self):
        for a in not_bool:
            with self.assertRaises(SystemExit):
                get_contact_public_key(a)

    def test_2_return_value(self):

        # Setup
        o_raw_input = __builtins__.raw_input
        key = "2JAT9y2EcnV6DPUGikLJYjWwk5UmUEFXRiQVmTbfSLbL4A4CMp"
        __builtins__.raw_input = lambda x: key

        # Test
        self.assertEqual(get_contact_public_key(), 64 * 'a')

        # Teardown
        __builtins__.raw_input = o_raw_input


class TestVerifyPublicKeys(ExtendedTestCase):

    def test_1_input_parameters(self):
        for a in not_str:
            for b in not_str:
                for c in not_str:
                    with self.assertRaises(SystemExit):
                        verify_public_keys(a, b, c)

    def test_2_function(self):

        # Setup
        o_yes = Tx.yes
        Tx.yes = lambda x, y: True

        # Test
        a = verify_public_keys(64 * 'a', 64 * 'b', "alice@jabber.org")
        self.assertEqual(a, 64 * 'b')

        # Teardown
        Tx.yes = o_yes


class TestStartKeyExchange(ExtendedTestCase):

    def test_1_input_parameters(self):
        for a in not_str:
            for b in not_str:
                for c in not_str:
                    with self.assertRaises(SystemExit):
                        start_key_exchange(a, b, c)

    def test_2_public_key(self):

        # Setup
        o_raw_input = __builtins__.raw_input
        pub_key = "2JAT9y2EcnV6DPUGikLJYjWwk5UmUEFXRiQVmTbfSLbL4A4CMp"
        __builtins__.raw_input = lambda x: pub_key

        Tx.txm_side_m_logging = True

        o_yes = Tx.yes
        Tx.yes = lambda x, y: True

        o_generate_key = Tx.generate_key
        Tx.generate_key = lambda x: [64 * 'a']

        Tx.active_c['a'] = "bob@jabber.org"

        create_contact(["local", "bob"])

        # Test
        self.assertIsNone(start_key_exchange("bob@jabber.org",
                                             "david@jabber.org",
                                             "bob"))
        self.assertPacketOutput(0, 'p')
        self.assertPacketOutput(1, 'c')
        self.assertPacketOutput(2, 'c')

        self.assertTrue(ut_validate_key(c_dictionary["bob@jabber.org"]["key"]))
        self.assertEqual(c_dictionary["bob@jabber.org"]["nick"], "bob")
        self.assertEqual(c_dictionary["bob@jabber.org"]["harac"], 1)
        self.assertEqual(c_dictionary["bob@jabber.org"]["logging"], True)

        # Teardown
        ut_cleanup()

        Tx.generate_key = o_generate_key
        Tx.yes = o_yes
        __builtins__.raw_input = o_raw_input
        Tx.txm_side_m_logging = False


# PSK
class TestNewPSK(ExtendedTestCase):

    def test_1_input_parameters(self):
        for a in not_str:
            for b in not_str:
                for c in not_str:
                    with self.assertRaises(SystemExit):
                        new_psk(a, b, c)

    def test_2_function(self):

        # Setup
        Tx.disable_gui_dialog = False
        Tx.txm_side_m_logging = True

        create_contact(["local", "alice"])

        Tx.active_c['a'] = "alice@jabber.org"
        Tx.active_c['n'] = "Alice"

        o_generate_key = Tx.generate_key
        Tx.generate_key = lambda x: [64 * 'a', 64 * 'a']

        o_new_password = Tx.new_password
        Tx.new_password = lambda x: "test"

        o_ask_path_gui = Tx.ask_path_gui
        Tx.ask_path_gui = lambda x: "keys_to_contact/"

        # Test
        self.assertIsNone(new_psk("bob@jabber.org", "user@jabber.org", "bob"))

        kf = "user@jabber.org.psk - Give to bob@jabber.org"
        contact_key = open("keys_to_contact/%s" % kf).readline()

        self.assertEqual(len(contact_key), 288)

        self.assertPacketOutput(0, 'c')

        self.assertEqual(c_dictionary["bob@jabber.org"]["key"], 64 * 'a')
        self.assertEqual(c_dictionary["bob@jabber.org"]["nick"], "bob")
        self.assertEqual(c_dictionary["bob@jabber.org"]["harac"], 1)
        self.assertEqual(c_dictionary["bob@jabber.org"]["logging"], True)
        self.assertEqual(Tx.active_c['n'], "Alice")

        # Teardown
        ut_cleanup()

        Tx.ask_path_gui = o_ask_path_gui
        Tx.new_password = o_new_password
        Tx.generate_key = o_generate_key

        Tx.txm_side_m_logging = False
        Tx.disable_gui_dialog = True


###############################################################################
#                               SECURITY RELATED                              #
###############################################################################

class TestPubKeys(ExtendedTestCase):

    def test_1_group_selected(self):

        # Setup
        active_c['g'] = "testgroup"

        # Test
        self.assertFR("Error: Group is selected.", pub_keys)

    def test_2_psk(self):

        # Setup
        create_contact(["bob"])
        active_c['g'] = ''
        active_c['a'] = "bob@jabber.org"

        # Test
        self.assertIsNone(pub_keys())

    def test_3_ecdhe(self):

        # Setup
        create_contact(["bob"])
        c_dictionary["bob@jabber.org"]["txpk"] = 64 * 'a'
        c_dictionary["bob@jabber.org"]["rxpk"] = 64 * 'b'
        Tx.active_c['g'] = ''
        Tx.active_c['a'] = "bob@jabber.org"

        # Test
        self.assertIsNone(pub_keys())


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

    def test_1_input_parameter(self):
        for a in not_str:
            with self.assertRaises(SystemExit):
                graceful_exit(a)

    def test_2_function(self):
        with self.assertRaises(SystemExit):
            graceful_exit()


class TestWriteLogEntry(ExtendedTestCase):

    def test_1_input_parameters(self):
        for a in not_str:
            for b in not_str:
                with self.assertRaises(SystemExit):
                    write_log_entry(a, b)

    def test_2_log_entry(self):

        # Setup
        create_contact(["alice"])
        c_dictionary["alice@jabber.org"]["logging"] = True
        c_dictionary["alice@jabber.org"]["logging"] = True

        # Test
        self.assertIsNone(write_log_entry("alice@jabber.org", "aMessage"))
        logged = str(open(Tx.txlog_file).read().splitlines())

        self.assertEqual(len(logged), 1080)

        # Teardown
        ut_cleanup()


class TestAccessHistory(ExtendedTestCase):

    def test_1_input_parameter(self):
        for a in not_bool:
            with self.assertRaises(SystemExit):
                access_history(a)

    def test_2_user_cancels(self):

        # Setup
        o_yes = Tx.yes
        Tx.yes = lambda x: False
        Tx.active_c['a'] = "bob@jabber.org"

        # Test
        self.assertFR("Export aborted by user.", access_history, True)

        # Teardown
        ut_cleanup()
        Tx.yes = o_yes

    def test_3_no_log_file(self):

        # Setup
        create_contact(["local"])
        Tx.active_c['a'] = "bob@jabber.org"

        # Test
        self.assertFR("Error: Could not find '.tx_logs'.",
                      access_history)

        # Teardown
        ut_cleanup()

    def test_4_short_message_to_contact_print(self):

        # Setup
        create_contact(["local", "alice"])
        c_dictionary["alice@jabber.org"]["logging"] = True
        Tx.active_c['a'] = "alice@jabber.org"
        Tx.active_c['n'] = "alice"
        Tx.active_c['g'] = ''
        recipient_chooser("Short message", 'm')
        recipient_chooser("Short message", 'm')

        # Test
        self.assertIsNone(access_history())
        self.assertPacketOutput(2, 'c')

        # Teardown
        ut_cleanup()

    def test_5_short_message_to_group_print(self):

        # Setup
        create_contact(["local", "alice", "bob"])
        create_group([("testgroup", ["alice", "bob"])])
        g_dictionary["testgroup"]["logging"] = True

        Tx.active_c['a'] = ''
        Tx.active_c['g'] = "testgroup"

        recipient_chooser("Short message", 'm')

        # Test
        self.assertIsNone(access_history())

        # Teardown
        ut_cleanup()

    def test_6_long_message_to_contact_print(self):

        # Setup
        create_contact(["local", "bob"])
        Tx.active_c['a'] = "bob@jabber.org"
        Tx.active_c['g'] = ''
        c_dictionary["bob@jabber.org"]["logging"] = True

        long_message = ("Lorem ipsum dolor sit amet, consectetur adipiscing "
                        "elit. Suspendisse quis lacus euismod, gravida neque "
                        "non, scelerisque ex. Sed imperdiet elit nec enim "
                        "ultricies sodales. Nullam ipsum augue, egestas sit "
                        "amet eros at, facilisis scelerisque odio. Nulla nec "
                        "justo erat. Etiam id ultrices mi. Proin semper ex eu "
                        "justo tincidunt, eu volutpat libero venenatis. "
                        "Maecenas dignissim pharetra purus lacinia mattis. In "
                        "ligula dolor, viverra a diam fermentum, placerat "
                        "sodales magna. Vivamus ac tellus non velit porta "
                        "condimentum. Quisque iaculis metus sit amet "
                        "facilisis ullamcorper. Cum sociis natoque penatibus "
                        "et magnis dis parturient montes, nascetur ridiculus "
                        "mus.")

        recipient_chooser(long_message, 'm')
        recipient_chooser(long_message, 'm')

        # Test
        self.assertIsNone(access_history())

        # Teardown
        ut_cleanup()

    def test_7_long_message_to_group_print(self):

        # Setup
        create_contact(["local", "alice", "bob"])
        create_group([("testgroup", ["alice", "bob"])])

        g_dictionary["testgroup"]["logging"] = True
        Tx.active_c['a'] = ''
        Tx.active_c['g'] = "testgroup"

        long_message = ("Lorem ipsum dolor sit amet, consectetur adipiscing "
                        "elit. Suspendisse quis lacus euismod, gravida neque "
                        "non, scelerisque ex. Sed imperdiet elit nec enim "
                        "ultricies sodales. Nullam ipsum augue, egestas sit "
                        "amet eros at, facilisis scelerisque odio. Nulla nec "
                        "justo erat. Etiam id ultrices mi. Proin semper ex eu "
                        "justo tincidunt, eu volutpat libero venenatis. "
                        "Maecenas dignissim pharetra purus lacinia mattis. In "
                        "ligula dolor, viverra a diam fermentum, placerat "
                        "sodales magna. Vivamus ac tellus non velit porta "
                        "condimentum. Quisque iaculis metus sit amet "
                        "facilisis ullamcorper. Cum sociis natoque penatibus "
                        "et magnis dis parturient montes, nascetur ridiculus "
                        "mus.")

        recipient_chooser(long_message, 'm')
        recipient_chooser(long_message, 'm')

        # Test
        self.assertIsNone(access_history())

        # Teardown
        ut_cleanup()

    def test_8_long_message_to_group_export(self):

        # Setup
        create_contact(["local", "alice", "bob"])
        create_group([("testgroup", ["alice", "bob"])])

        g_dictionary["testgroup"]["logging"] = True
        Tx.active_c['a'] = ''
        Tx.active_c['g'] = "testgroup"

        o_yes = Tx.yes
        Tx.yes = lambda x: True

        long_message = ("Lorem ipsum dolor sit amet, consectetur adipiscing "
                        "elit. Suspendisse quis lacus euismod, gravida neque "
                        "non, scelerisque ex. Sed imperdiet elit nec enim "
                        "ultricies sodales. Nullam ipsum augue, egestas sit "
                        "amet eros at, facilisis scelerisque odio. Nulla nec "
                        "justo erat. Etiam id ultrices mi. Proin semper ex eu "
                        "justo tincidunt, eu volutpat libero venenatis. "
                        "Maecenas dignissim pharetra purus lacinia mattis. In "
                        "ligula dolor, viverra a diam fermentum, placerat "
                        "sodales magna. Vivamus ac tellus non velit porta "
                        "condimentum. Quisque iaculis metus sit amet "
                        "facilisis ullamcorper. Cum sociis natoque penatibus "
                        "et magnis dis parturient montes, nascetur ridiculus "
                        "mus.")

        recipient_chooser(long_message, 'm')
        recipient_chooser(long_message, 'm')

        # Test
        self.assertIsNone(access_history(export=True))
        self.assertTrue(os.path.isfile("TxM - Plaintext log (testgroup)"))

        # Teardown
        ut_cleanup()
        Tx.yes = o_yes
        os.remove("TxM - Plaintext log (testgroup)")


###############################################################################
#                             CONTACT MANAGEMENT                              #
###############################################################################

class TestSelectKeyExchange(ExtendedTestCase):

    def test_1_select_key_exchange(self):

        for a in ['e', "ecdhe"]:

            # Setup
            o_raw_input = __builtins__.raw_input
            __builtins__.raw_input = lambda x: a

            # Test
            self.assertEqual(select_key_exchange(), "ecdhe")

            # Teardown
            __builtins__.raw_input = o_raw_input

        for a in ['p', "psk"]:

            # Setup
            o_raw_input = __builtins__.raw_input
            __builtins__.raw_input = lambda x: a

            # Test
            self.assertEqual(select_key_exchange(), "psk")

            # Teardown
            __builtins__.raw_input = o_raw_input


class TestAddNewContact(ExtendedTestCase):

    def test_1_input_parameter(self):
        for a in not_str:
            with self.assertRaises(SystemExit):
                add_new_contact(a)

    def test_2_full_contact_list(self):

        # Setup
        o_m_number_of_accnts = Tx.m_number_of_accnts
        Tx.m_number_of_accnts = 2

        create_contact(["alice", "bob"])

        # Test
        self.assertFR("Error: TFC settings only allow 2 contacts.",
                      add_new_contact, "/add charlie@jabber.org")

        # Teardown
        ut_cleanup()
        Tx.m_number_of_accnts = o_m_number_of_accnts


class TestRmContact(ExtendedTestCase):

    def test_1_input_parameter(self):
        for a in not_str:
            with self.assertRaises(SystemExit):
                rm_contact(a)

    def test_2_missing_account(self):
        self.assertFR("Error: No account specified.", rm_contact, "/rm")

    def test_3_invalid_account(self):
        self.assertFR("Invalid account", rm_contact, "/rm alicejabber.org")

    def test_4_user_aborted_remove(self):

        # Setup
        o_yes = Tx.yes
        Tx.yes = lambda x: False

        create_contact(["bob", "local"])

        # Test
        self.assertFR("Removal of contact aborted.", rm_contact,
                      "/rm bob@jabber.org")

        # Teardown
        ut_cleanup()
        Tx.yes = o_yes

    def test_5_rm_non_existing_contact_no_group_file(self):

        # Setup
        o_yes = Tx.yes
        Tx.yes = lambda x: True

        create_contact(["alice", "local"])

        # Test
        self.assertIsNone(rm_contact("/rm bob@jabber.org"))

        # Teardown
        ut_cleanup()
        Tx.yes = o_yes

    def test_6_rm_non_existing_contact_with_group_file(self):

        # Setup
        o_yes = Tx.yes
        Tx.yes = lambda x: True

        create_contact(["alice", "local"])
        create_group([("testgroup", ["bob"])])

        # Test
        self.assertIsNone(rm_contact("/rm bob@jabber.org"))
        self.assertTrue("bob@jabber.org"
                        not in g_dictionary["testgroup"]["members"])
        # Teardown
        ut_cleanup()
        Tx.yes = o_yes

    def test_7_rm_existing_contact(self):

        # Setup
        create_contact(["alice", "bob", "local"])
        create_group([("testgroup1", ["alice", "bob"]),
                      ("testgroup2", ["alice"]),
                      ("testgroup3", ["bob"])])

        o_yes = Tx.yes
        Tx.yes = lambda x: True

        # Test
        self.assertIsNone(rm_contact("/rm bob@jabber.org"))

        for g in ["testgroup1", "testgroup2", "testgroup3"]:
            members = g_dictionary[g]["members"]
            self.assertTrue("bob@jabber.org" not in members)

        self.assertPacketOutput(0, 'c')

        # Teardown
        ut_cleanup()
        Tx.yes = o_yes


class TestGetNickInput(ExtendedTestCase):

    def test_1_input_parameter(self):
        for a in not_str:
            with self.assertRaises(SystemExit):
                get_nick_input(a)

    def test_2_valid_nickname(self):

        # Setup
        o_raw_input = __builtins__.raw_input
        __builtins__.raw_input = lambda x: "ALICE"

        # Test
        self.assertEqual(get_nick_input("alice@jabber.org"), "ALICE")

        # Teardown
        __builtins__.raw_input = o_raw_input

    def test_3_default_nickname(self):

        # Setup
        o_raw_input = __builtins__.raw_input
        __builtins__.raw_input = lambda x: ''

        # Test
        self.assertEqual(get_nick_input("alice@jabber.org"), "Alice")

        # Teardown
        __builtins__.raw_input = o_raw_input


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
                  "%s@jabber.org" % (245 * 'a'), "bob\x1f@jabber.org"]:
            self.assertFalse(validate_account(a))


class TestValidateNick(ExtendedTestCase):

    def test_1_input_parameters(self):
        for a in not_str:
            for b in not_str:
                with self.assertRaises(SystemExit):
                    validate_nick(a, b)

    def test_2_invalid_nick(self):

        # Setup
        create_contact(["alice"])
        create_group([("testgroup", ["alice"])])

        # Test
        for n in [255 * 'a', "Alice\x1f", '', "me", "ME", "Me", "local",
                  "local", "alice@jabber.org", "alice", "testgroup"]:
            self.assertFalse(validate_nick(n, print_m=False))

        # Teardown
        ut_cleanup()


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

class TestChangeRecipient(ExtendedTestCase):

    def test_1_input_parameter(self):
        for a in not_str:
            with self.assertRaises(SystemExit):
                change_recipient(a)

    def test_2_no_contact_specified(self):
        self.assertFR("Error: Invalid command.", change_recipient, "/msg ")

    def test_3_non_existing_account(self):

        # Setup
        create_contact(["alice", "bob", "local"])
        Tx.active_c['a'] = "alice@jabber.org"
        Tx.active_c['n'] = "alice"
        Tx.active_c['g'] = ''

        # Test
        self.assertFR("Error: Invalid contact / group selection.",
                      change_recipient, "/msg charlie@jabber.org")
        Tx.active_c['a'] = "alice@jabber.org"
        Tx.active_c['n'] = "alice"
        Tx.active_c['g'] = ''

        # Teardown
        ut_cleanup()

    def test_4_existing_account(self):

        # Setup
        create_contact(["alice", "bob", "local"])
        Tx.active_c['a'] = "alice@jabber.org"
        Tx.active_c['n'] = "alice"
        Tx.active_c['g'] = ''

        # Test
        self.assertIsNone(change_recipient("/msg bob@jabber.org"))
        self.assertEqual(Tx.active_c['a'], "bob@jabber.org")
        self.assertEqual(Tx.active_c['n'], "bob")
        self.assertEqual(Tx.active_c['g'], '')

        # Teardown
        ut_cleanup()

    def test_5_existing_group(self):

        # Setup
        create_contact(["alice", "bob", "local"])
        create_group([("testgroup", ["alice", "bob"])])
        Tx.active_c['a'] = "alice@jabber.org"
        Tx.active_c['n'] = "alice"
        Tx.active_c['g'] = ''

        # Test
        self.assertIsNone(change_recipient("/msg testgroup"))
        self.assertEqual(Tx.active_c['a'], '')
        self.assertEqual(Tx.active_c['n'], "testgroup")
        self.assertEqual(Tx.active_c['g'], "testgroup")

        # Teardown
        ut_cleanup()


class TestPrintContactList(ExtendedTestCase):

    def test_1_input_parameter(self):
        for a in not_bool:
            with self.assertRaises(SystemExit):
                print_contact_list(a)

    def test_2_with_spacing(self):

        # Setup
        create_contact(["alice", "bob", "charlie"])
        create_group([("testgroup1", ["alice", "bob"]),
                      ("testgroup2", ["alice", "bob"])])

        c_dictionary["bob@jabber.org"]["txpk"] = 64 * 'a'
        c_dictionary["bob@jabber.org"]["rxpk"] = 64 * 'b'
        c_dictionary["bob@jabber.org"]["logging"] = True

        # Test
        self.assertIsNone(print_contact_list(spacing=True))
        self.assertIsNone(print_contact_list())

        # Teardown
        ut_cleanup()


class TestSelectContact(ExtendedTestCase):

    def setUp(self):
        create_contact(["alice", "bob"])
        create_group([("testgroup", ["alice", "bob"])])

    def tearDown(self):
        ut_cleanup()

    def test_1_input_parameters(self):
        for a in not_str:
            for b in not_bool:
                with self.assertRaises(SystemExit):
                    select_contact(a, b)

    def test_2_alice(self):

        Tx.active_c['a'] = ''
        Tx.active_c['n'] = ''
        Tx.active_c['g'] = ''

        self.assertIsNone(select_contact("alice@jabber.org", False))
        self.assertEqual(Tx.active_c['a'], "alice@jabber.org")
        self.assertEqual(Tx.active_c['n'], "alice")

    def test_3_bob(self):

        Tx.active_c['a'] = "alice@jabber.org"
        Tx.active_c['n'] = "alice"
        Tx.active_c['g'] = ''

        self.assertIsNone(select_contact("bob@jabber.org", False))
        self.assertEqual(Tx.active_c['a'], "bob@jabber.org")
        self.assertEqual(Tx.active_c['n'], "bob")
        self.assertEqual(Tx.active_c['g'], '')

    def test_4_invalid_contact(self):
        with self.assertRaises(ValueError):
            select_contact("jack@jabber.org", False)
            select_contact("group", False)

    def test_5_group(self):
        self.assertIsNone(select_contact("testgroup", False))
        self.assertEqual(Tx.active_c['a'], '')
        self.assertEqual(Tx.active_c['g'], "testgroup")
        self.assertEqual(Tx.active_c['n'], "testgroup")

    def test_6_nick(self):

        Tx.active_c['a'] = "alice@jabber.org"
        Tx.active_c['n'] = "alice"
        Tx.active_c['g'] = ''

        self.assertIsNone(select_contact("bob", False))
        self.assertEqual(Tx.active_c['a'], "bob@jabber.org")
        self.assertEqual(Tx.active_c['n'], "bob")
        self.assertEqual(Tx.active_c['g'], '')


###############################################################################
#                             DATABASE MANAGEMENT                             #
###############################################################################

class TestContactDB(ExtendedTestCase):

    def test_1_database_content(self):

        # Setup
        Tx.txm_side_m_logging = True

        # Test
        a_data = dict(user="user@jabber.org", nick="Alice",
                      harac=1,
                      key=64 * 'a', hek=64 * 'b',
                      txpk=64 * 'c', rxpk=64 * 'd',
                      logging=True)
        c_data = dict(user="user@jabber.org", nick="Charlie",
                      harac=1,
                      key=64 * 'a', hek=64 * 'b',
                      txpk=64 * 'c', rxpk=64 * 'd',
                      logging=True)

        acco_dict = {"alice@jabber.org": a_data,
                     "charlie@jabber.org": c_data}

        self.assertIsNone(contact_db(write_db=acco_dict))

        data = contact_db()

        self.assertEqual(data["alice@jabber.org"], a_data)
        self.assertEqual(data["charlie@jabber.org"], c_data)

        f_data = open(datab_file).read()
        db_len = len(base64.b64encode(
            ((m_number_of_accnts * 9 * 255) + 16 + 24) * 'a'))
        self.assertEqual(len(f_data), db_len)

        # Teardown
        ut_cleanup()

    def test_2_increased_database(self):

        # Setup
        o_m_number_of_accnts = Tx.m_number_of_accnts
        Tx.m_number_of_accnts = 3

        # Test
        a_data = dict(user="user@jabber.org", nick="Alice",
                      harac=1,
                      key=64 * 'a', hek=64 * 'b',
                      txpk=64 * 'c', rxpk=64 * 'd',
                      logging=True)
        c_data = dict(user="user@jabber.org", nick="Charlie",
                      harac=1,
                      key=64 * 'a', hek=64 * 'b',
                      txpk=64 * 'c', rxpk=64 * 'd',
                      logging=True)
        l_data = dict(user="local", nick="local",
                      harac=1,
                      key=64 * 'a', hek=64 * 'b',
                      txpk="psk", rxpk="psk",
                      logging=False)

        acco_dict = {"alice@jabber.org": a_data,
                     "charlie@jabber.org": c_data,
                     "local": l_data}

        self.assertIsNone(contact_db(write_db=acco_dict))

        self.assertEqual(len(open(Tx.datab_file).read()), 9236)

        Tx.m_number_of_accnts = 6
        data = contact_db()
        self.assertEqual(set(data.keys()),
                         {"alice@jabber.org", "charlie@jabber.org", "local"})
        self.assertEqual(len(open(Tx.datab_file).read()), 18416)

        # Teardown
        ut_cleanup()
        Tx.m_number_of_accnts = o_m_number_of_accnts

    def test_3_reduced_database(self):

        # Setup
        o_m_number_of_accnts = Tx.m_number_of_accnts
        Tx.m_number_of_accnts = 3

        # Test
        a_data = dict(user="user@jabber.org", nick="Alice",
                      harac=1,
                      key=64 * 'a', hek=64 * 'b',
                      txpk=64 * 'c', rxpk=64 * 'd',
                      logging=True)
        c_data = dict(user="user@jabber.org", nick="Charlie",
                      harac=1,
                      key=64 * 'a', hek=64 * 'b',
                      txpk=64 * 'c', rxpk=64 * 'd',
                      logging=True)
        l_data = dict(user="local", nick="local",
                      harac=1,
                      key=64 * 'a', hek=64 * 'b',
                      txpk="psk", rxpk="psk",
                      logging=False)

        acco_dict = {"alice@jabber.org": a_data,
                     "charlie@jabber.org": c_data,
                     "local": l_data}

        self.assertIsNone(contact_db(write_db=acco_dict))

        self.assertEqual(len(open(Tx.datab_file).read()), 9236)

        Tx.m_number_of_accnts = 1

        with self.assertRaises(SystemExit):
            contact_db()

        # Teardown
        ut_cleanup()
        Tx.m_number_of_accnts = o_m_number_of_accnts


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

    def test_2_increased_number_of_groups(self):

        # Setup
        o_m_number_of_groups = Tx.m_number_of_groups
        Tx.m_number_of_groups = 2

        # Test
        g1_data = dict(logging=True, members=["alice@jabber.org",
                                              "bob@jabber.org"])
        g2_data = dict(logging=False, members=["charlie@jabber.org",
                                               "bob@jabber.org"])
        group_dict = dict()
        group_dict["testgroup1"] = g1_data
        group_dict["testgroup2"] = g2_data

        self.assertIsNone(group_db(write_db=group_dict))

        self.assertEqual(len(open(Tx.group_file).read()), 20060)

        Tx.m_number_of_groups = 4
        data = group_db()

        self.assertEqual(len(data.keys()), 2)
        self.assertEqual(len(open(Tx.group_file).read()), 40064)

        # Teardown
        Tx.m_number_of_groups = o_m_number_of_groups

    def test_3_reduced_number_of_groups(self):

        # Setup
        o_m_number_of_groups = Tx.m_number_of_groups
        Tx.m_number_of_groups = 2

        # Test
        g1_data = dict(logging=True, members=["alice@jabber.org",
                                              "bob@jabber.org"])
        g2_data = dict(logging=False, members=["charlie@jabber.org",
                                               "bob@jabber.org"])
        group_dict = dict()
        group_dict["testgroup1"] = g1_data
        group_dict["testgroup2"] = g2_data

        self.assertIsNone(group_db(write_db=group_dict))

        self.assertEqual(len(open(Tx.group_file).read()), 20060)

        Tx.m_number_of_groups = 1

        with self.assertRaises(SystemExit):
            group_db()

        # Teardown
        Tx.m_number_of_groups = o_m_number_of_groups

    def test_4_increased_number_of_members(self):

        # Setup
        o_m_members_in_group = Tx.m_members_in_group
        o_m_number_of_groups = Tx.m_number_of_groups
        Tx.m_number_of_groups = 2
        Tx.m_members_in_group = 2

        # Test
        g1_data = dict(logging=True, members=["alice@jabber.org",
                                              "bob@jabber.org"])
        g2_data = dict(logging=False, members=["charlie@jabber.org",
                                               "bob@jabber.org"])
        group_dict = dict()
        group_dict["testgroup1"] = g1_data
        group_dict["testgroup2"] = g2_data

        self.assertIsNone(group_db(write_db=group_dict))
        self.assertEqual(len(open(Tx.group_file).read()), 3692)

        Tx.m_members_in_group = 3

        data = group_db()

        self.assertEqual(len(data.keys()), 2)
        self.assertEqual(len(data["testgroup1"]["members"]), 3)
        self.assertEqual(len(open(Tx.group_file).read()), 4600)

        # Teardown
        Tx.m_members_in_group = o_m_members_in_group
        Tx.m_number_of_groups = o_m_number_of_groups

    def test_5_reduced_number_of_members(self):

        # Setup
        o_m_members_in_group = Tx.m_members_in_group
        o_m_number_of_groups = Tx.m_number_of_groups
        Tx.m_number_of_groups = 2
        Tx.m_members_in_group = 2

        # Test
        g1_data = dict(logging=True, members=["alice@jabber.org",
                                              "bob@jabber.org"])
        g2_data = dict(logging=False, members=["charlie@jabber.org",
                                               "bob@jabber.org"])
        group_dict = dict()
        group_dict["testgroup1"] = g1_data
        group_dict["testgroup2"] = g2_data

        self.assertIsNone(group_db(write_db=group_dict))

        self.assertEqual(len(open(Tx.group_file).read()), 3692)

        Tx.m_members_in_group = 1

        with self.assertRaises(SystemExit):
            group_db()

        # Teardown
        Tx.m_members_in_group = o_m_members_in_group
        Tx.m_number_of_groups = o_m_number_of_groups


###############################################################################
#                               LOCAL COMMANDS                                #
###############################################################################

class TestPrintAbout(ExtendedTestCase):

    def test_1_return_type(self):
        self.assertIsNone(print_about())


class TestPrintHelp(ExtendedTestCase):

    def test_1_print_help(self):

        for Tx.trickle_connection in [True, False]:

            # Setup
            o_get_tty_wh = Tx.get_tty_w
            Tx.get_tty_w = lambda: get_tty_w()

            # Test
            self.assertIsNone(print_help())

            # Teardown
            Tx.get_tty_w = o_get_tty_wh


###############################################################################
#                              ENCRYPTED COMMANDS                             #
###############################################################################

class TestChangeNick(ExtendedTestCase):

    def test_1_input_parameter(self):
        for a in not_str:
            with self.assertRaises(SystemExit):
                change_nick(a)

    def test_2_no_nick_specified(self):
        self.assertFR("Error: No nick specified.", change_nick, "/nick ")

    def test_3_group_is_active(self):

        # Setup
        create_contact(["alice"])
        Tx.active_c['a'] = ''
        Tx.active_c['n'] = "group"
        Tx.active_c['g'] = "group"

        # Test
        self.assertFR("Error: Group is selected.",
                      change_nick, "/nick Alice")

        self.assertEqual(Tx.active_c['a'], '')
        self.assertEqual(Tx.active_c['n'], "group")
        self.assertEqual(Tx.active_c['g'], "group")

        # Teardown
        ut_cleanup()

    def test_4_invalid_nick(self):

        # Setup
        create_contact(["alice", "local"])
        Tx.active_c['a'] = "alice@jabber.org"
        Tx.active_c['n'] = "alice"
        Tx.active_c['g'] = ''

        # Test
        self.assertFR("invalid nick", change_nick, "/nick alice@jabber.org")

        self.assertEqual(Tx.active_c['a'], "alice@jabber.org")
        self.assertEqual(Tx.active_c['n'], "alice")
        self.assertEqual(Tx.active_c['g'], '')

        # Teardown
        ut_cleanup()

    def test_5_nick_successful_change(self):

        # Setup
        create_contact(["alice", "local"])
        Tx.active_c['a'] = "alice@jabber.org"
        Tx.active_c['n'] = "alice"
        Tx.active_c['g'] = ''

        # Test
        self.assertIsNone(change_nick("/nick Alice"))
        self.assertEqual(Tx.active_c['a'], "alice@jabber.org")
        self.assertEqual(Tx.active_c['n'], "Alice")
        self.assertEqual(Tx.active_c['g'], '')

        self.assertPacketOutput(0, 'c')

        # Teardown
        ut_cleanup()


class TestChangeSetting(ExtendedTestCase):

    def test_01_input_parameter(self):
        for a in not_str:
            with self.assertRaises(SystemExit):
                change_setting(a)

    def test_02_invalid_commands(self):
        for s in ["/loging", "/logging", "/logging ", "/logging o"]:
            self.assertFR("Error: Invalid command.", change_setting, s)

    def test_03_invalid_second_parameter(self):
        self.assertFR("Error: Invalid command.",
                      change_setting, "/logging on bad")

    def test_04_enable_logging_for_account(self):

        # Setup
        create_contact(["local", "alice", "bob"])
        c_dictionary["alice@jabber.org"]["logging"] = False
        c_dictionary["bob@jabber.org"]["logging"] = False

        Tx.active_c['a'] = "alice@jabber.org"
        Tx.active_c['n'] = "alice"
        Tx.active_c['g'] = ''

        # Test
        self.assertIsNone(change_setting("/logging on"))
        self.assertTrue(c_dictionary["alice@jabber.org"]["logging"])
        self.assertFalse(c_dictionary["bob@jabber.org"]["logging"])
        self.assertPacketOutput(0, 'c')

        # Teardown
        ut_cleanup()

    def test_05_disable_logging_for_account(self):

        # Setup
        create_contact(["local", "alice", "bob"])
        c_dictionary["alice@jabber.org"]["logging"] = True
        c_dictionary["bob@jabber.org"]["logging"] = True

        Tx.active_c['a'] = "alice@jabber.org"
        Tx.active_c['n'] = "alice"
        Tx.active_c['g'] = ''

        # Test
        self.assertIsNone(change_setting("/logging off"))
        self.assertFalse(c_dictionary["alice@jabber.org"]["logging"])
        self.assertTrue(c_dictionary["bob@jabber.org"]["logging"])
        self.assertPacketOutput(0, 'c')

        # Teardown
        ut_cleanup()

    def test_06_enable_logging_for_group(self):

        # Setup
        create_contact(["local", "alice", "bob"])
        c_dictionary["alice@jabber.org"]["logging"] = False
        c_dictionary["bob@jabber.org"]["logging"] = False

        create_group([("testgroup", ["alice", "bob"])])
        g_dictionary["testgroup"]["logging"] = False

        Tx.active_c['a'] = ''
        Tx.active_c['n'] = "testgroup"
        Tx.active_c['g'] = "testgroup"

        # Test
        self.assertIsNone(change_setting("/logging on"))
        self.assertTrue(g_dictionary["testgroup"]["logging"])
        self.assertFalse(c_dictionary["alice@jabber.org"]["logging"])
        self.assertFalse(c_dictionary["bob@jabber.org"]["logging"])
        self.assertPacketOutput(0, 'c')

        # Teardown
        ut_cleanup()

    def test_07_disable_logging_for_group(self):

        # Setup
        create_contact(["local", "alice", "bob"])
        c_dictionary["alice@jabber.org"]["logging"] = True
        c_dictionary["bob@jabber.org"]["logging"] = True

        create_group([("testgroup", ["alice", "bob"])])
        g_dictionary["testgroup"]["logging"] = True

        Tx.active_c['a'] = ''
        Tx.active_c['n'] = "testgroup"
        Tx.active_c['g'] = "testgroup"

        # Test
        self.assertIsNone(change_setting("/logging off"))
        self.assertFalse(g_dictionary["testgroup"]["logging"])
        self.assertTrue(c_dictionary["alice@jabber.org"]["logging"])
        self.assertTrue(c_dictionary["bob@jabber.org"]["logging"])
        self.assertPacketOutput(0, 'c')

        # Teardown
        ut_cleanup()

    def test_08_enable_logging_for_all(self):

        # Setup
        create_contact(["local", "alice", "bob"])
        c_dictionary["alice@jabber.org"]["logging"] = False
        c_dictionary["bob@jabber.org"]["logging"] = False

        create_group([("testgroup1", ["alice", "bob"]),
                      ("testgroup2", ["alice", "bob"])])
        g_dictionary["testgroup1"]["logging"] = False
        g_dictionary["testgroup2"]["logging"] = False

        Tx.active_c['a'] = ''
        Tx.active_c['n'] = "testgroup"
        Tx.active_c['g'] = "testgroup"

        # Test
        self.assertIsNone(change_setting("/logging on all"))
        self.assertTrue(g_dictionary["testgroup1"]["logging"])
        self.assertTrue(g_dictionary["testgroup2"]["logging"])
        self.assertTrue(c_dictionary["alice@jabber.org"]["logging"])
        self.assertTrue(c_dictionary["bob@jabber.org"]["logging"])

        self.assertPacketOutput(0, 'c')

        # Teardown
        ut_cleanup()

    def test_09_disable_logging_for_all(self):

        # Setup
        create_contact(["local", "alice", "bob"])
        c_dictionary["alice@jabber.org"]["logging"] = True
        c_dictionary["bob@jabber.org"]["logging"] = True

        create_group([("testgroup1", ["alice", "bob"]),
                      ("testgroup2", ["alice", "bob"])])
        g_dictionary["testgroup1"]["logging"] = True
        g_dictionary["testgroup2"]["logging"] = True

        Tx.active_c['a'] = ''
        Tx.active_c['n'] = "testgroup1"
        Tx.active_c['g'] = "testgroup1"

        # Test
        self.assertIsNone(change_setting("/logging off all"))
        self.assertFalse(g_dictionary["testgroup1"]["logging"])
        self.assertFalse(g_dictionary["testgroup2"]["logging"])
        self.assertFalse(c_dictionary["alice@jabber.org"]["logging"])
        self.assertFalse(c_dictionary["bob@jabber.org"]["logging"])

        self.assertPacketOutput(0, 'c')

        # Teardown
        ut_cleanup()

    def test_10_change_store(self):

        for c in ["/store on", "/store on all",
                  "/store off", "/store off all"]:

            # Setup
            create_contact(["local", "alice", "bob"])
            c_dictionary["alice@jabber.org"]["logging"] = False
            c_dictionary["bob@jabber.org"]["logging"] = False

            create_group([("testgroup", ["alice", "bob"])])

            Tx.active_c['a'] = ''
            Tx.active_c['n'] = "testgroup"
            Tx.active_c['g'] = "testgroup"

            # Test
            self.assertIsNone(change_setting(c))
            self.assertFalse(g_dictionary["testgroup"]["logging"])
            self.assertFalse(c_dictionary["alice@jabber.org"]["logging"])
            self.assertFalse(c_dictionary["bob@jabber.org"]["logging"])

            self.assertPacketOutput(0, 'c')

            # Teardown
            ut_cleanup()


class TestClearDisplays(ExtendedTestCase):

    def test_1_input_parameter(self):
        for a in not_str:
            with self.assertRaises(SystemExit):
                clear_displays(a)

    def test_2_empty_group(self):
        for cmd in ["SC", "SR"]:

            # Setup
            create_contact(["local"])
            create_group([("testgroup", [])])
            Tx.active_c['a'] = ''
            Tx.active_c['n'] = "testgroup"
            Tx.active_c['g'] = "testgroup"

            # Test
            clear_displays(cmd)
            self.assertPacketOutput(0, 'c')

            # Teardown
            ut_cleanup()

    def test_3_account(self):
        for cmd in ["SC", "SR"]:

            # Setup
            create_contact(["local", "alice"])
            create_group([("testgroup", [])])
            Tx.active_c['a'] = "alice@jabber.org"
            Tx.active_c['g'] = ''

            # Test
            clear_displays(cmd)

            self.assertPacketOutput(0, 'c')
            self.assertPacketOutput(1, 'd')

            # Teardown
            ut_cleanup()


###############################################################################
#                    COMMAND / MESSAGE / FILE TRANSMISSION                    #
###############################################################################

class TestReadableSize(ExtendedTestCase):

    def test_1_input_parameter(self):
        for a in not_int:
            with self.assertRaises(SystemExit):
                readable_size(a)

    def test_2_prefixes(self):
        self.assertEqual(readable_size(1023), "1023.0B")
        self.assertEqual(readable_size(1024**1), "1.0KB")
        self.assertEqual(readable_size(1024**2), "1.0MB")
        self.assertEqual(readable_size(1024**3), "1.0GB")
        self.assertEqual(readable_size(1024**4), "1.0TB")
        self.assertEqual(readable_size(1024**5), "1.0PB")
        self.assertEqual(readable_size(1024**6), "1.0EB")
        self.assertEqual(readable_size(1024**7), "1.0ZB")
        self.assertEqual(readable_size(1024**8), "1.0YB")


class TestTtime(ExtendedTestCase):

    def test_1_input_parameter(self):
        for a in not_int:
            with self.assertRaises(SystemExit):
                t_time(a)

    def test_2_negative_packet_count(self):
        with self.assertRaises(AssertionError):
            t_time(-1)

    def test_3_single_recipient(self):

        # Setup
        Tx.trickle_connection = False
        Tx.fixed_packet_delay = 0.5
        Tx.long_packet_rand_d = True
        Tx.max_val_for_rand_d = 1.0
        Tx.active_c['a'] = "alice@jabber.org"
        Tx.active_c['n'] = "alice"
        Tx.active_c['g'] = ''

        # Test
        for i in range(500):
            self.assertIsInstance(t_time(i), tuple)

        # Teardown
        Tx.max_val_for_rand_d = 10.0
        Tx.long_packet_rand_d = False

    def test_4_multiple_recipient(self):

        # Setup
        Tx.trickle_connection = False
        Tx.fixed_packet_delay = 0.5
        Tx.long_packet_rand_d = True
        Tx.max_val_for_rand_d = 1.0

        create_group([("testgroup", ["alice", "bob"])])

        Tx.active_c['a'] = ''
        Tx.active_c['n'] = "testgroup"
        Tx.active_c['g'] = "testgroup"

        # Test
        Tx.active_c['a'] = "alice@jabber.org"
        Tx.active_c['n'] = "alice"
        Tx.active_c['g'] = ''

        for i in range(500):
            self.assertIsInstance(t_time(i), tuple)

        # Teardown
        Tx.max_val_for_rand_d = 10.0
        Tx.long_packet_rand_d = False


class TestLoadFileData(ExtendedTestCase):

    def test_1_input_parameter(self):
        for a in not_str:
            with self.assertRaises(SystemExit):
                load_file_data(a)

    def test_2_missing_file_aborts(self):

        # Setup
        Tx.confirm_file = False
        o_ask_path_gui = Tx.ask_path_gui
        Tx.ask_path_gui = lambda x, get_file: ''

        # Test
        self.assertFR("Error: File not found.", load_file_data, "/file")

        # Teardown
        Tx.ask_path_gui = o_ask_path_gui
        Tx.confirm_file = True

    def test_3_empty_file(self):

        # Setup
        Tx.confirm_file = False
        o_ask_path_gui = Tx.ask_path_gui
        Tx.ask_path_gui = lambda x, get_file: "tfc_unittest_doc.txt"
        open("tfc_unittest_doc.txt", "w+").close()

        # Test
        self.assertFR("Error: Target file is empty. No file was sent.",
                      load_file_data, "/file")

        # Teardown
        ut_cleanup()
        Tx.confirm_file = True
        Tx.ask_path_gui = o_ask_path_gui

    def test_4__short_file(self):

        # Setup
        Tx.confirm_file = False

        o_ask_path_gui = Tx.ask_path_gui
        Tx.ask_path_gui = lambda x, get_file: "tfc_unittest_doc.txt"

        o_yes = Tx.yes
        Tx.yes = lambda x: True

        o_os_urandom = os.urandom
        os.urandom = lambda x: 32 * 'f'

        o_nacl_utils_random = Tx.nacl.utils.random
        Tx.nacl.utils.random = lambda x: (24 * 'a')

        Tx.active_c['a'] = "alice@jabber.org"
        Tx.active_c['n'] = "alice"
        Tx.active_c['g'] = ''

        open("tfc_unittest_doc.txt", "w+").write("%s" % (20 * "data"))

        # Test
        file_data = load_file_data("/file")
        split_data = file_data.split('\x1f')
        self.assertEqual(split_data[0], "tfc_unittest_doc.txt")
        self.assertEqual(split_data[1], "80.0B")
        self.assertEqual(split_data[2], "00d 00h 00m 00s")
        self.assertEqual(len(split_data[3]), 140)

        # Teardown
        ut_cleanup()
        Tx.confirm_file = True
        Tx.yes = o_yes
        Tx.ask_path_gui = o_ask_path_gui
        Tx.nacl.utils.random = o_nacl_utils_random
        os.urandom = o_os_urandom

    def test_5_long_file(self):

        # Setup
        Tx.confirm_file = False

        o_ask_path_gui = Tx.ask_path_gui
        Tx.ask_path_gui = lambda x, get_file: "tfc_unittest_doc.txt"

        o_yes = Tx.yes
        Tx.yes = lambda x: True

        o_os_urandom = os.urandom
        os.urandom = lambda x: 32 * 'f'

        o_nacl_utils_random = Tx.nacl.utils.random
        Tx.nacl.utils.random = lambda x: (24 * 'a')

        open("tfc_unittest_doc.txt", "w+").write("%s" % (200000 * "data"))

        Tx.active_c['a'] = "alice@jabber.org"
        Tx.active_c['n'] = "alice"
        Tx.active_c['g'] = ''

        # Test
        file_data = load_file_data("/file tfc_unittest_doc.txt")
        split_data = file_data.split('\x1f')
        self.assertEqual(split_data[0], "tfc_unittest_doc.txt")
        self.assertEqual(split_data[1], "781.2KB")
        self.assertEqual(split_data[2], "00d 00h 00m 01s")

        self.assertEqual(len(split_data[3]), 1188)

        # Teardown
        ut_cleanup()
        Tx.confirm_file = True
        Tx.yes = o_yes
        Tx.ask_path_gui = o_ask_path_gui
        Tx.nacl.utils.random = o_nacl_utils_random
        os.urandom = o_os_urandom


class TestAddPacketAssemblyHeaders(ExtendedTestCase):

    def test_1_input_parameters(self):
        for a in not_str:
            for b in not_str:
                with self.assertRaises(SystemExit):
                    add_packet_assembly_headers(a, b)

    def test_2_invalid_header(self):
        with self.assertRaises(KeyError):
            add_packet_assembly_headers("test", 'a')

    def test_3_long_message_packet_splitting(self):

        # Setup
        o_os_urandom = os.urandom
        os.urandom = lambda x: 32 * 'f'

        o_nacl_utils_random = Tx.nacl.utils.random
        Tx.nacl.utils.random = lambda x: (24 * 'a')

        # Test
        splits = add_packet_assembly_headers("%s" % (550000 * 'x'), 'm')

        self.assertEqual(len(splits), 4)
        self.assertEqual(splits[0][0], 'b')
        self.assertEqual(splits[1][0], 'c')
        self.assertEqual(splits[2][0], 'c')
        self.assertEqual(splits[3][0], 'd')

        # Teardown
        os.urandom = o_os_urandom
        Tx.nacl.utils.random = o_nacl_utils_random

    def test_4_long_file_packet_splitting(self):

        splits = add_packet_assembly_headers("%s" % (900 * 'z'), 'f')

        self.assertEqual(len(splits), 4)
        self.assertEqual(splits[0][0], 'B')
        self.assertEqual(splits[1][0], 'C')
        self.assertEqual(splits[2][0], 'C')
        self.assertEqual(splits[3][0], 'D')

    def test_5_long_command_and_hash(self):

        splits = add_packet_assembly_headers("%s" % (900 * 'z'), 'c')

        self.assertEqual(len(splits), 4)
        self.assertEqual(splits[0][0], '1')
        self.assertEqual(splits[1][0], '2')
        self.assertEqual(splits[2][0], '2')
        self.assertEqual(splits[3][0], '3')
        self.assertEqual(splits[-1][-64:], sha3_256(900*'z'))


class TestRecipientChooser(ExtendedTestCase):

    def test_1_input_parameters(self):
        for a in not_str:
            for b in not_str:
                with self.assertRaises(SystemExit):
                    recipient_chooser(a, b)

    def test_2_invalid_header(self):
        with self.assertRaises(KeyError):
            recipient_chooser("TestMessage", 'a')

    def test_3_empty_group(self):

        # Setup
        Tx.active_c['g'] = "testgroup"
        create_contact(["alice", "bob"])
        create_group([("testgroup", [])])

        # Test
        self.assertFR("Group is empty. No message was sent.",
                      recipient_chooser, "Testmessage", 'm')

        # Teardown
        ut_cleanup()

    def test_4_msg_to_group(self):

        # Setup
        create_contact(["alice", "bob"])
        create_group([("testgroup", ["alice", "bob"])])
        g_dictionary["testgroup"]["logging"] = True

        Tx.active_c['a'] = ''
        Tx.active_c['n'] = "testgroup"
        Tx.active_c['g'] = "testgroup"

        # Test
        self.assertIsNone(recipient_chooser("Testmessage", 'm'))

        self.assertPacketOutput(0, 'm')
        self.assertPacketOutput(1, 'm')

        # Teardown
        ut_cleanup()

    def test_5_msg_to_contact(self):

        # Setup
        create_contact(["alice", "bob"])
        create_group([("testgroup", ["alice", "bob"])])
        c_dictionary["alice@jabber.org"]["logging"] = True

        Tx.active_c['a'] = "alice@jabber.org"
        Tx.active_c['n'] = "alice"
        Tx.active_c['g'] = ''

        # Test
        self.assertIsNone(recipient_chooser("Testmessage", 'm'))
        self.assertPacketOutput(0, 'm')

        # Teardown
        ut_cleanup()


class TestSendPacket(ExtendedTestCase):

    def test_1_input_parameters(self):
        for a in not_str:
            for b in not_str:
                for c in not_str:
                    with self.assertRaises(SystemExit):
                        send_packet(a, b, c)

    def test_2_key_error(self):
        with self.assertRaises(KeyError):
            send_packet("test", 'a')


class TestLongTransmit(ExtendedTestCase):

    def test_1_input_parameters(self):
        for a in not_str:
            for b in not_str:
                for c in not_str:
                    with self.assertRaises(SystemExit):
                        long_transmit(a, b, c)

    def test_2_function(self):

        # Setup
        create_contact(["alice"])
        Tx.long_packet_rand_d = False
        Tx.cancel_lt = False

        # Test
        l = ["bcSJQB+ezvoriJMlf4PIw9Io2xcjl5TrTSz0Nvk/CorTJMGNu/s8rErl/PeH9EUE"
             "exygtfCS1v1CaKCvB2ry7PjgCb1cOAKaDdz2yKDlFyjTYC0SMkivs3APAdx9BVJ1"
             "zhpT2yMe+uA01Dy6XpXQZakFx9Nd+zm1OM55EjZ4eqa4lleMEXMRZbGo47U958W6"
             "UkODdsndu2q1U8h988jQuxcq7m7lScJMcA41l/NWbPwOGqhxOLwgvqZdQzFW/B",
             "c6HZaoJYwCIzMENlIpfjSk9JG+3D/drXikvFL3TmCQUL304/+BjpsxJTCuLQy9/z"
             "lth/Bf9ns8FmYGP99ryYUDLUIoPnmcHoYevhwOOSIDt9OsQ+zYpANRyL5ynaeGts"
             "KA/CI//ianig1e4Rnx2h8nQax+dRiBfMczbbH/6+KZGKuSAKht9luHJUpmp5Nj10"
             "H+gxsDd/VJTeqvxxQdEJuf66H3HPM98a/YdXV+cIFTR8qzLCVN/TBdtNl9fWh2",
             "dIKK42929104604b9b22e941023454b6aebb3f7219f18f43f53e892af071662e"
             "37d71"]

        long_transmit(l, 'm', "alice@jabber.org")

        self.assertPacketOutput(0, 'm')
        self.assertPacketOutput(1, 'm')
        self.assertPacketOutput(2, 'm')

        # Teardown
        ut_cleanup()


class TestPacketThread(ExtendedTestCase):

    def test_1_input_parameters(self):
        for a in not_str:
            for b in not_str:
                with self.assertRaises(SystemExit):
                    packet_thread(a, b)

    def test_2_command(self):

        # Setup
        create_contact(["local"])

        # Test
        packet_thread("CL|E|alice@jabber.org")
        self.assertPacketOutput(0, 'c')

        # Teardown
        ut_cleanup()

    def test_3_message(self):

        # Setup
        create_contact(["alice"])
        Tx.active_c['a'] = "alice@jabber.org"
        c_dictionary["alice@jabber.org"]["logging"] = False

        # Test
        packet_thread("plaintext message", "alice@jabber.org")
        self.assertPacketOutput(0, 'm')

        # Teardown
        ut_cleanup()


class TestExitProgram(ExtendedTestCase):

    def test_1_function(self):

        # Setup
        create_contact(["local"])

        # Test
        with self.assertRaises(SystemExit):
            exit_program()

        self.assertPacketOutput(0, 'c')
        self.assertPacketOutput(1, 'e')

        # Teardown
        ut_cleanup()


###############################################################################
#                            REED SOLOMON ENCODING                            #
###############################################################################

class TestRSEncode(ExtendedTestCase):

    def test_1_correction(self):

        string = 10 * "Testmessage"
        print("Original: %s" % string)

        encoded = reed_solomon.encode(string)
        print ("After encoding: %s" % encoded)

        error = Tx.e_correction_ratio
        altered = os.urandom(error) + encoded[error:]
        print("After errors: %s" % altered)

        corrected = reed_solomon.decode(altered)
        print("Corrected: %s" % corrected)

        self.assertEqual(corrected, string)


class TestTransmit(ExtendedTestCase):

    def test_1_input_parameter(self):
        for a in not_str:
            with self.assertRaises(SystemExit):
                transmit(a)

    def test_2_checksum(self):

        # Test
        transmit("teststring")
        packetdata = bytearray(b64d(open("unitt_txm_out_0").read()))
        decoded = reed_solomon.decode(packetdata)
        self.assertEqual(decoded, bytearray("1Nteststring"))

        # Teardown
        ut_cleanup()


###############################################################################
#                              GROUP MANAGEMENT                               #
###############################################################################

class TestGroupCreate(ExtendedTestCase):

    def test_01_input_parameter(self):
        for a in not_str:
            with self.assertRaises(SystemExit):
                group_create(a)

    def test_02_missing_group_name(self):

        # Setup
        create_contact(["local"])

        # Test
        self.assertFR("No group name specified.",
                      group_create, "/group create")

        # Teardown
        ut_cleanup()

    def test_03_group_name_is_not_printable(self):

        # Setup
        create_contact(["local"])

        # Test
        self.assertFR("Group name must be printable.",
                      group_create, "/group create a\x1f")

        # Teardown
        ut_cleanup()

    def test_04_group_name_too_long(self):

        # Setup
        create_contact(["local"])

        # Test
        self.assertFR("Group name must be less than 255 chars long.",
                      group_create, "/group create %s" % (255 * 'g'))

        # Teardown
        ut_cleanup()

    def test_05_group_name_refers_to_dummy(self):

        # Setup
        create_contact(["local"])

        # Test
        self.assertFR("Group can't use the name reserved for padding.",
                      group_create, "/group create dummy_group")

        # Teardown
        ut_cleanup()

    def test_06_group_name_is_group_management_command(self):

        for g_name in ["create", "add", "rm"]:

            # Setup
            create_contact(["local"])

            # Test
            self.assertFR("Group name can't be a group management command.",
                          group_create, "/group create %s" % g_name)

            # Teardown
            ut_cleanup()

    def test_07_group_name_is_account(self):

        # Setup
        create_contact(["local", "alice"])

        # Test
        self.assertFR("Group name can't be an account.",
                      group_create, "/group create alice@jabber.org")
        # Teardown
        ut_cleanup()

    def test_08_group_name_is_nick(self):

        # Setup
        create_contact(["local", "alice"])

        # Test
        self.assertFR("Group name can't be nick of contact.",
                      group_create, "/group create alice")
        # Teardown
        ut_cleanup()

    def test_09_user_refuses_to_overwrite_group(self):

        # Setup
        o_yes = Tx.yes
        Tx.yes = lambda x: False

        create_contact(["local", "alice", "bob"])
        create_group([("testgroup", ["bob"])])

        # Test
        self.assertFR("Group creation aborted.", group_create,
                      "/group create testgroup alice@jabber.org")

        self.assertEqual(g_dictionary["testgroup"]["members"],
                         ["bob@jabber.org"]
                         + (m_members_in_group - 1) * ["dummy_member"])

        # Teardown
        Tx.yes = o_yes
        ut_cleanup()

    def test_10_successful_group_creation_no_members(self):

        # Setup
        create_contact(["local", "alice"])

        # Test
        self.assertIsNone(group_create("/group create testgroup"))

        self.assertEqual(g_dictionary["testgroup"]["members"],
                         20 * ["dummy_member"])

        for i in range(m_number_of_groups - 1):
            self.assertEqual(g_dictionary["dummy_group_%s" % i]["members"],
                             20 * ["dummy_member"])
        # Teardown
        ut_cleanup()

    def test_11_successful_group_creation_with_one_contact(self):

        # Setup
        o_yes = Tx.yes
        Tx.yes = lambda x: True

        create_contact(["local", "alice"])
        c_dictionary["alice@jabber.org"]["logging"] = False
        Tx.active_c['a'] = "alice@jabber.org"

        # Test
        self.assertIsNone(
            group_create("/group create testgroup alice@jabber.org"))

        self.assertEqual(g_dictionary["testgroup"]["members"],
                         ["alice@jabber.org"]
                         + 19 * ["dummy_member"])

        for i in range(m_number_of_groups - 1):
            self.assertEqual(g_dictionary["dummy_group_%s" % i]["members"],
                             20 * ["dummy_member"])

        self.assertPacketOutput(0, 'c')
        self.assertPacketOutput(1, 'm')

        # Teardown
        Tx.yes = o_yes
        ut_cleanup()

    def test_12_add_contact_and_nonexistent(self):

        # Setup
        o_yes = Tx.yes
        Tx.yes = lambda x: True

        create_contact(["local", "alice"])

        # Test
        self.assertIsNone(group_create(
            "/group create testgroup alice@jabber.org bob@jabber.org"))

        self.assertEqual(g_dictionary["testgroup"]["members"],
                         ["alice@jabber.org"]
                         + 19 * ["dummy_member"])

        for i in range(m_number_of_groups - 1):
            self.assertEqual(g_dictionary["dummy_group_%s" % i]["members"],
                             20 * ["dummy_member"])

        self.assertPacketOutput(0, 'c')
        self.assertPacketOutput(1, 'm')

        # Teardown
        Tx.yes = o_yes
        ut_cleanup()

    def test_13_overwrite_existing_group(self):

        # Setup
        o_yes = Tx.yes
        Tx.yes = lambda x: True

        create_contact(["local", "alice", "bob"])
        create_group([("testgroup", ["bob"])])

        # Test
        self.assertIsNone(group_create(
            "/group create testgroup alice@jabber.org"))

        self.assertPacketOutput(0, 'c')
        self.assertPacketOutput(1, 'm')

        self.assertEqual(g_dictionary["testgroup"]["members"],
                         ["alice@jabber.org"]
                         + 19 * ["dummy_member"])

        for i in range(m_number_of_groups - 1):
            self.assertEqual(g_dictionary["dummy_group_%s" % i]["members"],
                             20 * ["dummy_member"])

        # Teardown
        Tx.yes = o_yes
        ut_cleanup()

    def test_14_too_many_members(self):

        # Setup
        o_yes = Tx.yes
        Tx.yes = lambda x: True
        o_m_members_in_group = Tx.m_members_in_group
        Tx.m_members_in_group = 2

        create_contact(["local", "alice", "bob", "charlie"])
        c_dictionary["alice@jabber.org"]["logging"] = False
        Tx.active_c['a'] = "alice@jabber.org"

        # Test
        self.assertFR("Error: TFC settings only allow 2 members per group.",
                      group_create, "/group create testgroup alice@jabber.org "
                                    "bob@jabber.org charlie@jabber.org")

        # Teardown
        ut_cleanup()
        Tx.yes = o_yes
        Tx.m_members_in_group = o_m_members_in_group

    def test_15_too_many_groups(self):

        # Setup
        o_yes = Tx.yes
        Tx.yes = lambda x: True
        o_m_number_of_groups = Tx.m_number_of_groups
        Tx.m_number_of_groups = 2

        create_contact(["local", "alice", "bob", "charlie"])
        create_group([("testgroup1", ["alice"]),
                      ("testgroup2", ["bob"])])
        Tx.active_c['a'] = "alice@jabber.org"

        # Test
        self.assertFR("Error: TFC settings only allow 2 groups.",
                      group_create, "/group create testgroup3 bob@jabber.org")

        # Teardown
        ut_cleanup()
        Tx.yes = o_yes
        Tx.m_number_of_groups = o_m_number_of_groups


class TestGroupAddMember(ExtendedTestCase):

    def test_1_input_parameter(self):
        for a in not_str:
            with self.assertRaises(SystemExit):
                group_add_member(a)

    def test_2_no_group_name_specified(self):

        # Setup
        create_contact(["local"])

        # Test
        self.assertFR("Error: No group name specified.",
                      group_add_member, "/group add")

        # Teardown
        ut_cleanup()

    def test_3_unknown_group(self):

        # Setup
        create_contact(["local"])
        create_group([("testgroup", ["alice", "bob"])])

        # Test
        self.assertFR("Error: Unknown group.",
                      group_add_member, "/group add testroup ")

        # Teardown
        ut_cleanup()

    def test_4_no_members(self):

        # Setup
        create_contact(["local"])
        create_group([("testgroup", ["alice", "bob"])])

        # Test
        self.assertFR("Error: No members to add specified.",
                      group_add_member, "/group add testgroup ")

        # Teardown
        ut_cleanup()

    def test_5_group_add_existing_contact_no_notify(self):

        # Setup
        create_contact(["local", "alice", "bob", "charlie"])
        create_group([("testgroup", ["alice", "bob"])])
        o_yes = Tx.yes
        Tx.yes = lambda x: False

        # Test
        self.assertIsNone(group_add_member(
            "/group add testgroup charlie@jabber.org"))

        self.assertEqual(g_dictionary["testgroup"]["members"],
                         ["alice@jabber.org",
                          "bob@jabber.org",
                          "charlie@jabber.org"]
                         + 17 * ["dummy_member"])

        for i in range(m_number_of_groups - 1):
            self.assertEqual(g_dictionary["dummy_group_%s" % i]["members"],
                             20 * ["dummy_member"])

        self.assertPacketOutput(0, 'c')

        # Teardown
        ut_cleanup()
        Tx.yes = o_yes

    def test_6_group_add_existing_contact_notify(self):

        # Setup
        create_contact(["local", "alice", "bob", "charlie"])
        create_group([("testgroup", ["alice", "bob"])])
        o_yes = Tx.yes
        Tx.yes = lambda x: True

        # Test
        self.assertIsNone(group_add_member(
            "/group add testgroup charlie@jabber.org"))

        self.assertEqual(g_dictionary["testgroup"]["members"],
                         ["alice@jabber.org",
                          "bob@jabber.org",
                          "charlie@jabber.org"]
                         + 17 * ["dummy_member"])

        for i in range(m_number_of_groups - 1):
            self.assertEqual(g_dictionary["dummy_group_%s" % i]["members"],
                             20 * ["dummy_member"])

        self.assertPacketOutput(0, 'c')
        self.assertPacketOutput(1, 'm')
        self.assertPacketOutput(2, 'm')

        # Teardown
        ut_cleanup()
        Tx.yes = o_yes

    def test_7_group_add_existing_and_unknown_contact(self):

        # Setup
        create_contact(["local", "alice", "bob", "charlie"])
        create_group([("testgroup", ["alice", "bob"])])
        o_yes = Tx.yes
        Tx.yes = lambda x: False

        # Test
        self.assertIsNone(
            group_add_member("/group add testgroup charlie@jabber.org david"))

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
        Tx.yes = o_yes

    def test_8_too_many_members(self):

        # Setup
        o_yes = Tx.yes
        Tx.yes = lambda x: True
        o_m_members_in_group = Tx.m_members_in_group
        Tx.m_members_in_group = 2

        create_contact(["local", "alice", "bob", "charlie"])
        create_group([("testgroup", ["alice", "bob"])])
        c_dictionary["alice@jabber.org"]["logging"] = False
        Tx.active_c['a'] = "alice@jabber.org"

        # Test
        self.assertFR("Error: TFC settings only allow 2 members per group.",
                      group_add_member,
                      "/group add testgroup charlie@jabber.org")

        # Teardown
        ut_cleanup()
        Tx.yes = o_yes
        Tx.m_members_in_group = o_m_members_in_group


class TestGroupRmMember(ExtendedTestCase):

    def test_1_input_parameter(self):
        for a in not_str:
            with self.assertRaises(SystemExit):
                group_rm_member(a)

    def test_2_missing_group_name(self):

        # Setup
        create_contact(["local"])

        # Test
        self.assertFR("No group name specified.", group_rm_member, "/group rm")

        # Teardown
        ut_cleanup()

    def test_3_remove_group_no(self):

        # Setup
        create_contact(["local", "alice", "bob"])
        create_group([("testgroup", ["alice", "bob"])])
        o_yes = Tx.yes
        Tx.yes = lambda x: False

        # Test
        self.assertFR("Group removal aborted.", group_rm_member,
                      "/group rm testgroup")

        self.assertTrue("testgroup" in g_dictionary.keys())

        # Teardown
        ut_cleanup()
        Tx.yes = o_yes

    def test_4_remove_group_yes_not_on_txm(self):

        # Setup
        create_contact(["local", "alice", "bob"])
        create_group([("differentgroup", ["alice", "bob"])])
        o_yes = Tx.yes
        Tx.yes = lambda x: True

        # Test
        self.assertFR("TxM has no group testgroup to remove.",
                      group_rm_member, "/group rm testgroup")

        self.assertPacketOutput(0, 'c')

        # Teardown
        ut_cleanup()
        Tx.yes = o_yes

    def test_5_remove_group_member(self):

        # Setup
        create_contact(["local", "alice", "bob"])
        create_group([("testgroup", ["alice", "bob"])])

        o_yes = Tx.yes
        Tx.yes = lambda x: False

        # Test
        self.assertIsNone(
            group_rm_member("/group rm testgroup alice@jabber.org"))

        self.assertFalse("alice@jabber.org" in
                         g_dictionary["testgroup"]["members"])

        self.assertEqual(g_dictionary["testgroup"]["members"],
                         ["bob@jabber.org"]
                         + 19 * ["dummy_member"])

        for i in range(m_number_of_groups - 1):
            self.assertEqual(g_dictionary["dummy_group_%s" % i]["members"],
                             20 * ["dummy_member"])

        self.assertPacketOutput(0, 'c')

        # Teardown
        ut_cleanup()
        Tx.yes = o_yes

    def test_6_remove_unknown(self):

        # Setup
        create_contact(["local", "alice", "bob"])
        create_group([("testgroup", ["alice", "bob"])])
        o_yes = Tx.yes
        Tx.yes = lambda x: False

        # Test
        self.assertIsNone(
            group_rm_member("/group rm testgroup charlie@jabber.org"))

        self.assertEqual(g_dictionary["testgroup"]["members"],
                         ["alice@jabber.org", "bob@jabber.org"]
                         + 18 * ["dummy_member"])

        for i in range(m_number_of_groups - 1):
            self.assertEqual(g_dictionary["dummy_group_%s" % i]["members"],
                             20 * ["dummy_member"])

        self.assertPacketOutput(0, 'c')

        # Teardown
        ut_cleanup()
        Tx.yes = o_yes

    def test_7_remove_group_yes(self):

        # Setup
        create_contact(["local", "alice", "bob"])
        create_group([("testgroup", ["alice", "bob"])])
        o_yes = Tx.yes
        Tx.yes = lambda x: True

        # Test
        self.assertFR("Removed group testgroup.", group_rm_member,
                      "/group rm testgroup")

        self.assertFalse("testgroup" in g_dictionary.keys())

        self.assertPacketOutput(0, 'c')
        self.assertPacketOutput(1, 'm')
        self.assertPacketOutput(2, 'm')

        # Teardown
        ut_cleanup()
        Tx.yes = o_yes


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


class TestPrintGroupDetails(ExtendedTestCase):

    def test_1_input_parameters(self):
        for a in not_str:
            for b in not_bool:
                for c in not_bool:
                    with self.assertRaises(SystemExit):
                        print_group_details(a, b, c)

    def test_2_no_groups(self):
        self.assertFR("There are currently no groups.", print_group_details,
                      '', True, False)

    def test_3_list_of_groups(self):

        # Setup
        create_contact(["alice", "bob", "charlie"])

        create_group([("testgroup1", ["alice"]),
                      ("testgroup2", ["bob"]),
                      ("testgroup3", ["alice", "bob"]),
                      ("testgroup4", [])])

        # Test
        self.assertIsNone(print_group_details(all_g=True))

        # Teardown
        ut_cleanup()

    def test_4_no_specified_group(self):
        self.assertFR("No group specified.", print_group_details,
                      "/group", False, False)

    def test_5_no_specified_group(self):
        self.assertFR("Group testgroup does not exist.", print_group_details,
                      "/group testgroup", False, False)

    def test_6_no_members_in_group(self):

        # Setup
        create_group([("testgroup", [])])

        # Test
        self.assertFR("Group testgroup is empty.", print_group_details,
                      "/group testgroup", False, False)
        # Teardown
        ut_cleanup()

    def test_7_list_members(self):

        # Setup
        create_contact(["alice", "bob"])

        create_group([("testgroup", ["alice", "bob"])])

        # Test
        self.assertIsNone(print_group_details("/group testgroup"))

        # Teardown
        ut_cleanup()


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


class TestCprint(ExtendedTestCase):

    def test_1_input_paramter(self):
        for a in not_str:
            for b in not_bool:
                with self.assertRaises(SystemExit):
                    c_print(a, b)

    def test_2_function(self):
        self.assertIsNone(c_print("test string"))


class TestEnsureDir(ExtendedTestCase):

    def test_1_input_parameter(self):
        for a in not_str:
            with self.assertRaises(SystemExit):
                ensure_dir(a)

    def test_2_empty_dir_parameter(self):
        with self.assertRaises(OSError):
            ensure_dir('')

    def test_3_function(self):

        # Test
        ensure_dir("unittest_directory/")
        self.assertTrue(os.path.exists(os.path.dirname("unittest_directory/")))

        # Teardown
        ut_cleanup()


class TestYes(ExtendedTestCase):

    def test_1_input_parameters(self):
        for a in not_str:
            for b in not_int:
                with self.assertRaises(SystemExit):
                    yes(a, b)

    def test_2_yes(self):

        # Setup
        o_raw_input = __builtins__.raw_input

        # Test
        for s in ["yes", "YES", 'y', 'Y']:
            __builtins__.raw_input = lambda x: s
            self.assertTrue(yes("test prompt"))

        # Teardown
        __builtins__.raw_input = o_raw_input

    def test_3_no(self):

        # Setup
        o_raw_input = __builtins__.raw_input

        # Test
        for s in ["no", "NO", 'n', 'N']:
            __builtins__.raw_input = lambda x: s
            self.assertFalse(yes("test prompt"))

        # Teardown
        __builtins__.raw_input = o_raw_input


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


class TestPrintOnPreviousLine(ExtendedTestCase):

    def test_1_function(self):
        self.assertIsNone(print_on_previous_line())


class TestB58e(ExtendedTestCase):

    def test_1_input_parameter(self):
        for a in not_str:
            with self.assertRaises(SystemExit):
                b58e(a)

    def test_2_hash_and_encode(self):
        """
        Test vectors from https://en.bitcoin.it/wiki/Wallet_import_format
        """

        p_key = binascii.unhexlify("807542FB6685F9FD8F37D56FAF62F0BB45"
                                   "63684A51539E4B26F0840DB361E0027C")

        tv = "5JhvsapkHeHjy2FiUQYwXh1d74evuMd3rGcKGnifCdFR5G8e6nH"

        self.assertEqual(b58e(p_key), tv)


class TestB58d(ExtendedTestCase):

    def test_1_input_parameter(self):
        for a in not_str:
            with self.assertRaises(SystemExit):
                b58d(a)

    def test_2_valid_input(self):
        """
        Test vectors from https://en.bitcoin.it/wiki/Wallet_import_format
        """

        tv = "5JhvsapkHeHjy2FiUQYwXh1d74evuMd3rGcKGnifCdFR5G8e6nH"

        p_key = binascii.unhexlify("807542FB6685F9FD8F37D56FAF62F0BB45"
                                   "63684A51539E4B26F0840DB361E0027C")

        self.assertEqual(b58d(tv), p_key)

    def test_3_invalid_input(self):

        with self.assertRaises(ValueError):
            b58d("2JhvsapkHeHjy2FiUQYwXh1d74evuMd3rGcKGnifCdFR5G8e6nH")


class TestB64e(ExtendedTestCase):

    def test_1_input_parameter(self):
        for a in not_str:
            with self.assertRaises(SystemExit):
                b64e(a)


class TestB64d(ExtendedTestCase):

    def test_1_input_parameter(self):
        for a in not_str:
            with self.assertRaises(SystemExit):
                b64e(a)


class TestEstablishSocket(ExtendedTestCase):
    """
    This function doesn't have any tests yet
    """


class TestSearchSerialInterfaces(ExtendedTestCase):

    def test_1_usb_iface(self):

        # Setup
        Tx.serial_usb_adapter = True

        o_os_listdir = os.listdir
        os.listdir = lambda x: ["ttyUSB0"]

        # Test
        self.assertEqual(search_serial_interfaces(), "/dev/ttyUSB0")

        # Teardown
        os.listdir = o_os_listdir

    def test_2_no_integrated_iface(self):

        # Setup
        Tx.serial_usb_adapter = False

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
        Tx.rpi_os = True

        o_subprocess_check_output = subprocess.check_output
        subprocess.check_output = lambda x: "Raspbian GNU/Linux"

        Tx.serial_usb_adapter = False

        # Test
        self.assertEqual(search_serial_interfaces(), "/dev/serial0")

        # Teardown
        Tx.rpi_os = False
        subprocess.check_output = o_subprocess_check_output
        os.listdir = o_os_listdir

    def test_4_integrated_RPI_iface(self):

        # Setup
        o_os_listdir = os.listdir
        os.listdir = lambda x: ["ttyS0"]

        Tx.serial_usb_adapter = False

        # Test
        self.assertEqual(search_serial_interfaces(), "/dev/ttyS0")

        # Teardown
        os.listdir = o_os_listdir


class TestEstablishSerial(ExtendedTestCase):
    """
    This function doesn't have any tests yet.
    """


class TestTabComplete(ExtendedTestCase):
    """
    This function doesn't have any tests yet.
    """


class TestGetTabCompleteList(ExtendedTestCase):

    def test_1_get_defaults(self):

        # Test
        tab_complete_list = get_tab_complete_list()
        tc_list = ["about", "add ", "all", "clear", "cmd", "create ", "exit",
                   "export", "file", "group ", "help", "history", "localkey",
                   "logging ", "msg ", "names", "nick ", "paste", "psk",
                   "pubkeys", "reset", "rm ", "store ", "unread", "winpriv"]
        self.assertTrue(set(tc_list).issubset(tab_complete_list))

        # Teardown
        ut_cleanup()

    def test_2_get_defaults_and_accounts(self):

        # Setup
        create_contact(["alice", "bob"])

        # Test
        tab_complete_list = get_tab_complete_list()
        tc_list = ["about", "add ", "all", "clear", "cmd", "create ", "exit",
                   "export", "file", "group ", "help", "history", "localkey",
                   "logging ", "msg ", "names", "nick ", "paste", "psk",
                   "pubkeys", "reset", "rm ", "store ", "unread", "winpriv",
                   "alice@jabber.org ", "bob@jabber.org "]

        self.assertTrue(set(tc_list).issubset(tab_complete_list))

        # Teardown
        ut_cleanup()

    def test_3_get_defaults_accounts_and_groups(self):

        # Setup
        create_group([("testgroup", ["alice", "bob"])])
        create_contact(["alice", "bob"])

        # Test
        tab_complete_list = set(get_tab_complete_list())
        tc_list = ["about", "add ", "all", "clear", "cmd", "create ", "exit",
                   "export", "file", "group ", "help", "history", "localkey",
                   "logging ", "msg ", "names", "nick ", "paste", "psk",
                   "pubkeys", "reset", "rm ", "store ", "unread", "winpriv",
                   "alice@jabber.org ", "bob@jabber.org ", "testgroup "]
        self.assertTrue(set(tc_list).issubset(tab_complete_list))

        # Teardown
        ut_cleanup()

    def test_4_get_defaults_accounts_and_groups_and_nicks(self):

        # Setup
        create_group([("testgroup", ["alice", "bob"])])
        create_contact(["alice", "bob"])

        # Test
        tab_complete_list = set(get_tab_complete_list())
        tc_list = ["about", "add ", "all", "clear", "cmd", "create ", "exit",
                   "export", "file", "group ", "help", "history", "localkey",
                   "logging ", "msg ", "names", "nick ", "paste", "psk",
                   "pubkeys", "reset", "rm ", "store ", "unread", "winpriv",
                   "alice@jabber.org ", "bob@jabber.org ", "testgroup ",
                   "alice ", "bob "]
        self.assertTrue(set(tc_list).issubset(tab_complete_list))

        # Teardown
        ut_cleanup()


###############################################################################
#                               FILE SELECTION                                #
###############################################################################

class TestAskPathGUI(ExtendedTestCase):

    def test_1_input_parameters(self):
        for a in not_str:
            for b in not_bool:
                with self.assertRaises(SystemExit):
                    ask_path_gui(a, b)

    def test_2_guidir(self):

        if not rpi_os:
            # Setup
            Tx.disable_gui_dialog = False

            o_tkfilefialog_askdirectory = tkFileDialog.askdirectory
            tkFileDialog.askdirectory = lambda title: "/home/"

            # Test
            t_dir = ask_path_gui("test")
            self.assertEqual(t_dir, "/home/")

            # Teardown
            tkFileDialog.askdirectory = o_tkfilefialog_askdirectory

    def test_3_guifile(self):

        if not rpi_os:
            # Setup
            Tx.disable_gui_dialog = False

            o_tkfilefialog_askopenfilename = tkFileDialog.askopenfilename
            tkFileDialog.askopenfilename = lambda title: "testfile"

            # Test
            t_dir = ask_path_gui("test", get_file=True)
            self.assertEqual(t_dir, "testfile")

            # Teardown
            tkFileDialog.askopenfilename = o_tkfilefialog_askopenfilename


class TestAskPathCLI(ExtendedTestCase):

    def test_1_input_parameters(self):
        for a in not_str:
            for b in not_bool:
                with self.assertRaises(SystemExit):
                    ask_path_cli(a, b)

    def test_2_guidir(self):

        # Setup
        o_raw_input = __builtins__.raw_input
        __builtins__.raw_input = lambda x: "/home"
        import readline
        Tx.default_delims = readline.get_completer_delims()

        # Test
        t_dir = ask_path_cli("test")
        self.assertEqual(t_dir, "/home/")

        # Teardown
        __builtins__.raw_input = o_raw_input

    def test_3_guifile(self):

        # Setup
        o_raw_input = __builtins__.raw_input
        __builtins__.raw_input = lambda x: "tfc_unittest_doc.txt"
        import readline
        Tx.default_delims = readline.get_completer_delims()

        open("tfc_unittest_doc.txt", "w+").write("test")

        # Test
        t_dir = ask_path_cli("test", get_f=True)
        self.assertEqual(t_dir, "tfc_unittest_doc.txt")

        # Teardown
        ut_cleanup()
        __builtins__.raw_input = o_raw_input


###############################################################################
#                               TRICKLE CONNECTION                            #
###############################################################################

class TestConstantTime(ExtendedTestCase):
    """
    This function doesn't have any tests yet.
    """


class TestSenderProcess(ExtendedTestCase):
    """
    This function doesn't have any tests yet.
    """


class TestNoiseProcess(ExtendedTestCase):
    """
    This function doesn't have any tests yet.
    """


class TestInputProcess(ExtendedTestCase):
    """
    This function doesn't have any tests yet.
    """


###############################################################################
#                             STANDARD CONNECTION                             #
###############################################################################

class TestGetNormalInput(ExtendedTestCase):

    def test_1_function(self):

        # Setup
        Tx.active_c['g'] = ''
        Tx.active_c['a'] = "alice@jabber.org"
        Tx.active_c['n'] = "Alice"
        Tx.paste = False

        o_raw_input = __builtins__.raw_input
        __builtins__.raw_input = lambda x: "testinput"

        # Test
        self.assertEqual(get_normal_input(), "testinput")

        # Teardown
        __builtins__.raw_input = o_raw_input


class TestMainLoop(ExtendedTestCase):
    """
    This function doesn't have any tests yet.
    """

###############################################################################
#                                     MAIN                                    #
###############################################################################

if __name__ == "__main__":

    Tx.unit_test = True
    os.chdir(sys.path[0])

    try:
        print('')
        if not yes("Running this unittest overwrites all "
                   "existing TFC user data. Proceed?", 1):
            print("\nExiting.\n")
            exit()

    except KeyboardInterrupt:
        print("\n\nExiting.\n")
        exit()

    pname = subprocess.check_output(["grep", "PRETTY_NAME", "/etc/os-release"])
    rpi_os = "Raspbian GNU/Linux" in pname

    try:
        os.remove("Tx.pyc")
    except OSError:
        pass

    ut_cleanup()
    unittest.main(exit=False)

    try:
        os.remove("Tx.pyc")
    except OSError:
        pass
