#!/usr/bin/env python
# -*- coding: utf-8 -*-

# TFC-NaCl 0.16.05 || test_tx.py

"""
GPL License

This software is part of the TFC application, which is free software: You can
redistribute it and/or modify it under the terms of the GNU General Public
License as published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.

TFC is distributed in the hope that it will be useful, but WITHOUT ANY
WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
A PARTICULAR PURPOSE. See the GNU General Public License for more details. For
a copy of the GNU General Public License, see <http://www.gnu.org/licenses/>.
"""

import Tx
from Tx import *
import binascii
import os.path
import os
import shutil
import sys
import time
import unittest

# Import crypto libraries
import hashlib
import simplesha3


###############################################################################
#                               UNITTEST HELPERS                              #
###############################################################################

def create_test_keys(nick_list, key=(64*'a')):
    """
    Create test keyfiles.

    :param nick_list: List of nicks based on what accounts are created.
    :param key:       Keys to write into keyfiles.
    :return:          None
    """

    ut_ensure_dir("keys/")

    for nick in nick_list:
        if nick == "local":
            open("keys/tx.local.e", "w+").write(key)
        else:
            open("keys/tx.%s@jabber.org.e" % nick, "w+").write(key)
    return None


def create_contact_db(nick_list):
    """
    Create contact database.

    :param nick_list:  List of nicks based on what accounts are created.
    :return:           None
    """

    with open(".tx_contacts", "w+") as f:
        for nick in nick_list:
            if nick == "local":
                f.write("%s,%s,1\n" % (nick, nick))
            else:
                f.write("%s@jabber.org,%s,1\n" % (nick, nick))
    return None


def create_group_db(group_name, nick_list):
    """
    Create group database.

    :param group_name: Name of created group.
    :param nick_list:  List of nicks based on what accounts are created.
    :return:           None
    """

    ut_ensure_dir("groups/")

    with open("groups/g.%s.tfc" % group_name, "w+") as f:
        for nick in nick_list:
            f.write("%s@jabber.org\n" % nick)
    return None


def ut_validate_key(key):
    """
    Test key is valid.

    :param key: Key to test.
    :return:    Boolean on test success.
    """

    if not set(key.lower()).issubset("abcdef0123456789"):
        return False
    if len(key) != 64:
        return False
    return True


def ut_sha3_256(message):
    """
    SHA3-256 digest.

    :param message: Message to calculate digest from.
    :return:        Digest (hex format).
    """

    return binascii.hexlify(simplesha3.sha3256(message))


def ut_sha2_256(message):
    """
    SHA256 digest.

    :param message: Message to calculate digest from.
    :return:        Digest (hex format).
    """

    h_function = hashlib.sha256()
    h_function.update(message)
    return binascii.hexlify(h_function.digest())


def ut_ensure_dir(directory):
    """
    Ensure directory.

    :param directory: Directory the existence of which to ensure.
    :return:          None
    """

    name = os.path.dirname(directory)
    if not os.path.exists(name):
        os.makedirs(name)


###############################################################################
#                                CRYPTOGRAPHY                                 #
###############################################################################

class TestSHA256(unittest.TestCase):

    def test_1_input_parameter(self):
        for a in [1, 1.0, True]:
            with self.assertRaises(SystemExit):
                sha2_256(a)

    def test_2_SHA256_vector(self):
        """
        Test SHA256 with official test vector:
        http://csrc.nist.gov/groups/ST/toolkit/
        documents/Examples/SHA_All.pdf // page 14
        """

        self.assertEqual(sha2_256("abc"), "ba7816bf8f01cfea414140de5dae2223"
                                          "b00361a396177a9cb410ff61f20015ad")


class TestSHA3256(unittest.TestCase):

    def test_1_input_parameter(self):
        for a in [1, 1.0, True]:
            with self.assertRaises(SystemExit):
                sha3_256(a)

    def test_2_SHA3_256_vector(self):
        """
        Test SHA3-256 with official test vector:
        http://csrc.nist.gov/groups/ST/toolkit/
        documents/Examples/SHA3-256_Msg0.pdf
        """

        self.assertEqual(sha3_256(''),
                         "a7ffc6f8bf1ed76651c14756a061d662"
                         "f580ff4de43b49fa82d80a4b80f8434a")


class TestPBKDF2HMACSHA256(unittest.TestCase):

    def test_1_input_parameters(self):
        for a in [1, 1.0, True]:
            for b in ["string", 1.0, True]:
                for c in [1, 1.0, True]:
                    with self.assertRaises(SystemExit):
                        pbkdf2_hmac_sha256(a, b, c)

    def test_2_no_rounds(self):
        with self.assertRaises(SystemExit):
            pbkdf2_hmac_sha256("password", 0, "salt")

    def test_3_negative_rounds(self):
        with self.assertRaises(SystemExit):
            pbkdf2_hmac_sha256("password", -1, "salt")

    def test_4_pbkdf2_hmac_sha256_test_vectors(self):
        """
        Testing with only vectors that could be found:
        https://stackoverflow.com/questions/5130513/
        pbkdf2-hmac-sha2-test-vectors/5136918#5136918
        """

        self.assertEqual(pbkdf2_hmac_sha256("password", 1, "salt"),
                         "120fb6cffcf8b32c43e7225256c4f837"
                         "a86548c92ccc35480805987cb70be17b")

        self.assertEqual(pbkdf2_hmac_sha256("password", 4096, "salt"),
                         "c5e478d59288c841aa530db6845c4c8d"
                         "962893a001ce4e11a4963873aa98134a")


class TestEncryptAndSign(unittest.TestCase):

    def test_1_input_parameters(self):
        for a in [1, 1.0, True]:
            for b in [1, 1.0, True]:
                with self.assertRaises(SystemExit):
                    encrypt_and_sign(a, b)

    def test_2_ct_length(self):
        """
        len(nonce) == 24,
        len(tag)   == 16,
        len(CT)    == 17.
                      57 in total.
        Padding is done separately, so len(PT) == len(CT).
        """

        # Setup
        create_test_keys(["bob"])
        create_contact_db(["bob"])

        # Test
        output = encrypt_and_sign("bob@jabber.org", "plaintext message")
        self.assertEqual(len(output), 57)

        # Teardown
        shutil.rmtree("keys")
        os.remove(".tx_contacts")

    def test_3_next_key(self):

        # Setup
        create_test_keys(["bob"])
        create_contact_db(["bob"])

        # Test
        encrypt_and_sign("bob@jabber.org", "plaintext message")
        next_key = open("keys/tx.bob@jabber.org.e").readline()
        self.assertEqual(next_key, "93539718242c02c6698778c25a292a11"
                                   "4c42df327db8be31d5a0cf303573923e")

        # Teardown
        shutil.rmtree("keys")
        os.remove(".tx_contacts")

    def test_4_official_test_vectors(self):
        """
        Test vectors:
        https://cr.yp.to/highspeed/naclcrypto-20090310.pdf // page 35
        """

        # Test
        original_naclrandom = Tx.nacl.utils.random

        iv_hex = "69696ee955b62b73cd62bda875fc73d68219e0036b7a0b37"
        iv_bin = binascii.unhexlify(iv_hex)
        Tx.nacl.utils.random = lambda x: iv_bin

        key_hex = ("1b27556473e985d462cd51197a9a46c7"
                   "6009549eac6474f206c4ee0844f68389")

        create_test_keys(['bob'], key_hex)
        create_contact_db(['bob'])

        pt_tv_hex = ("be075fc53c81f2d5cf141316"
                     "ebeb0c7b5228c52a4c62cbd4"
                     "4b66849b64244ffce5ecbaaf"
                     "33bd751a1ac728d45e6c6129"
                     "6cdc3c01233561f41db66cce"
                     "314adb310e3be8250c46f06d"
                     "ceea3a7fa1348057e2f6556a"
                     "d6b1318a024a838f21af1fde"
                     "048977eb48f59ffd4924ca1c"
                     "60902e52f0a089bc76897040"
                     "e082f937763848645e0705")

        ct_tv_hex = ("f3ffc7703f9400e52a7dfb4b"
                     "3d3305d98e993b9f48681273"
                     "c29650ba32fc76ce48332ea7"
                     "164d96a4476fb8c531a1186a"
                     "c0dfc17c98dce87b4da7f011"
                     "ec48c97271d2c20f9b928fe2"
                     "270d6fb863d51738b48eeee3"
                     "14a7cc8ab932164548e526ae"
                     "90224368517acfeabd6bb373"
                     "2bc0e9da99832b61ca01b6de"
                     "56244a9e88d5f9b37973f622"
                     "a43d14a6599b1f654cb45a74"
                     "e355a5")

        ct_purp_bin = encrypt_and_sign("bob@jabber.org",
                                       binascii.unhexlify(pt_tv_hex))
        ct_purp_hex = binascii.hexlify(ct_purp_bin)
        self.assertEqual(ct_purp_hex, (iv_hex + ct_tv_hex))

        # Teardown
        Tx.nacl.utils.random = original_naclrandom
        shutil.rmtree("keys")
        os.remove(".tx_contacts")


###############################################################################
#                                KEY MANAGEMENT                               #
###############################################################################

class TestGetKeyfileList(unittest.TestCase):

    def setUp(self):
        ut_ensure_dir("keys/")
        open("keys/tx.1.e", "w+").close()
        open("keys/tx.2.e", "w+").close()
        open("keys/tx.3.e", "w+").close()
        open("keys/me.3.e", "w+").close()
        open("keys/rx.3.e", "w+").close()
        open("keys/tx.local.e", "w+").close()
        open("keys/rx.local.e", "w+").close()
        open("keys/me.local.e", "w+").close()

    def tearDown(self):
        shutil.rmtree("keys")

    def test_1_input_parameter(self):
        for a in ["string", 1, 1.0]:
            with self.assertRaises(SystemExit):
                get_keyfile_list(a)

    def test_2_keyfile_loading(self):

        self.assertEqual(get_keyfile_list(),
                         ["tx.1.e", "tx.2.e", "tx.3.e"])

        self.assertEqual(get_keyfile_list(include_local=True),
                         ["tx.1.e", "tx.2.e", "tx.3.e", "tx.local.e"])


class TestGetKey(unittest.TestCase):

    def test_1_input_parameter(self):
        for a in [1, 1.0, True]:
            with self.assertRaises(SystemExit):
                get_key(a)

    def test_2_no_key(self):

        # Test
        with self.assertRaises(SystemExit):
            get_key("bob@jabber.org")

    def test_3_valid_key(self):

        # Setup
        create_test_keys(["bob"])

        # Test
        self.assertEqual(get_key("bob@jabber.org"), "%s" % (64 * 'a'))

        # Teardown
        shutil.rmtree("keys")

    def test_4_short_key(self):

        # Setup
        create_test_keys(["bob"], (63 * 'a'))

        # Test
        with self.assertRaises(SystemExit):
            get_key("bob@jabber.org")

        # Teardown
        shutil.rmtree("keys")

    def test_5_long_key(self):

        # Setup
        create_test_keys(["bob"], (65 * 'a'))

        # Test
        with self.assertRaises(SystemExit):
            get_key("bob@jabber.org")

        # Teardown
        shutil.rmtree("keys")

    def test_6_invalid_key_content(self):

        # Setup
        create_test_keys(["bob"], ("%sg" % (63 * 'a')))

        # Test
        with self.assertRaises(SystemExit):
            get_key("bob@jabber.org")

        # Teardown
        shutil.rmtree("keys")


class TestKeyWriter(unittest.TestCase):

    def test_1_input_parameters(self):
        for a in [1, 1.0, True]:
            for b in [1, 1.0, True]:
                with self.assertRaises(SystemExit):
                    key_writer(a, b)

    def test_2_key_writing(self):

        # Test
        self.assertIsNone(key_writer("bob@jabber.org", (64 * 'a')))
        key_from_file = open("keys/tx.bob@jabber.org.e").readline()
        self.assertEqual(key_from_file, (64 * 'a'))

        # Teardown
        shutil.rmtree("keys")

    def test_3_path_as_account(self):

        # Setup
        ut_ensure_dir("utest/")

        # Test
        self.assertIsNone(key_writer("utest/tx.bob@jabber.org.e", (64 * 'a')))
        key_from_file = open("utest/tx.bob@jabber.org.e").readline()
        self.assertEqual(key_from_file, (64 * 'a'))

        # Teardown
        shutil.rmtree("utest")

    def test_4_invalid_key_exits(self):

        # Test
        with self.assertRaises(SystemExit):
            key_writer("bob@jabber.org", (64 * 'g'))


class TestRotateKey(unittest.TestCase):

    def setUp(self):
        create_test_keys(["bob"])

    def tearDown(self):
        shutil.rmtree("keys")

    def test_1_input_parameter(self):
        for a in [1, 1.0, True]:
            with self.assertRaises(SystemExit):
                rotate_key(a)

    def test_2_function(self):
        self.assertIsNone(rotate_key("bob@jabber.org"))

        new_key = open("keys/tx.bob@jabber.org.e").readline()
        self.assertEqual(new_key, "93539718242c02c6698778c25a292a11"
                                  "4c42df327db8be31d5a0cf303573923e")


class TestNewPSK(unittest.TestCase):

    def test_1_input_parameters(self):
        for a in [1, 1.0, True]:
            for b in [1.0, 1, "string"]:
                with self.assertRaises(SystemExit):
                    new_psk(a, b)

    def test_2_no_account(self):

        # Test
        self.assertIsNone(new_psk("/psk"))
        self.assertIsNone(new_psk("/psk "))

    def test_3_invalid_account_chars(self):

        # Test
        self.assertIsNone(new_psk("/psk alice:@jabber.org"))
        self.assertIsNone(new_psk("/psk alice/@jabber.org"))

    def test_3_test_key_generation_predetermined_nick(self):

        # Setup
        Tx.local_testing = True
        Tx.show_file_prompts = False
        Tx.unittesting = True
        Tx.txm_side_logging = True
        Tx.use_ssh_hwrng = False

        Tx.acco_store_l["bob@jabber.org"] = False
        Tx.recipient_acco = "bob@jabber.org"
        Tx.recipient_nick = "Robert"

        origin_raw_input = __builtins__.raw_input
        __builtins__.raw_input = lambda x: "alice@jabber.org"

        original_genkey = Tx.generate_key
        Tx.generate_key = lambda x: 64 * 'a'

        create_contact_db(["local", "bob"])
        create_test_keys(["local", "bob"])

        # Create PSKs
        self.assertIsNone(new_psk("/psk bob@jabber.org"))

        # Test validity of contact's key
        kf = "rx.alice@jabber.org.e - Give this file to bob@jabber.org"
        contact_key = open("keys_to_contact/%s" % kf).readline()
        self.assertTrue(ut_validate_key(contact_key))

        # Test RxM packet content
        rxm_packet = open("unitt_txm_out").readline()
        s, t, v, p, ct, i, c = rxm_packet.split('|')
        self.assertEqual(s, "TFC")
        self.assertEqual(t, 'N')
        self.assertEqual(v, str(Tx.int_version))
        self.assertEqual(p, 'C')
        self.assertEqual(len(ct), 392)
        self.assertEqual(i, '1')
        self.assertEqual(len(c.strip('\n')), 8)

        # Test TxM side key
        user_key = open("keys/tx.bob@jabber.org.e").readline()
        self.assertTrue(ut_validate_key(user_key))

        # Test contact database
        written = open(".tx_contacts").readlines()
        self.assertTrue("bob@jabber.org,bob,1\r\n" in written or
                        "bob@jabber.org,bob,1\n" in written or
                        "bob@jabber.org,bob,1\r" in written or
                        "bob@jabber.org,bob,1" in written)

        # Test logging dictionary
        self.assertTrue(Tx.acco_store_l["bob@jabber.org"])

        # Test change of global nick
        self.assertEqual(Tx.recipient_nick, "bob")

        # Teardown
        shutil.rmtree("keys")
        shutil.rmtree("keys_to_contact")
        os.remove(".tx_contacts")
        os.remove("unitt_txm_out")
        __builtins__.raw_input = origin_raw_input
        Tx.generate_key = original_genkey
        Tx.acco_store_l["bob@jabber.org"] = False
        Tx.local_testing = False
        Tx.show_file_prompts = True
        Tx.unittesting = False
        Tx.txm_side_logging = False

    def test_4_test_key_generation_nick_from_parameter(self):

        # Setup
        Tx.local_testing = True
        Tx.show_file_prompts = False
        Tx.unittesting = True
        Tx.use_ssh_hwrng = False
        Tx.txm_side_logging = False

        Tx.acco_store_l["bob@jabber.org"] = True
        Tx.recipient_acco = "bob@jabber.org"
        Tx.recipient_nick = "Robert"

        origin_raw_input = __builtins__.raw_input
        __builtins__.raw_input = lambda x: "alice@jabber.org"

        original_genkey = Tx.generate_key
        Tx.generate_key = lambda x: 64 * 'a'

        create_contact_db(["local"])
        create_test_keys(["local"])

        # Create PSKs
        self.assertIsNone(new_psk("/psk bob@jabber.org bob", True))

        # Test validity of contact's key
        kf = "rx.alice@jabber.org.e - Give this file to bob@jabber.org"
        contact_key = open("keys_to_contact/%s" % kf).readline()
        self.assertTrue(ut_validate_key(contact_key))

        # Test RxM packet content
        rxm_packet = open("unitt_txm_out").readline()
        s, t, v, p, ct, i, c = rxm_packet.split('|')
        self.assertEqual(s, "TFC")
        self.assertEqual(t, 'N')
        self.assertEqual(v, str(Tx.int_version))
        self.assertEqual(p, 'C')
        self.assertEqual(len(ct), 392)
        self.assertEqual(i, '1')
        self.assertEqual(len(c.strip('\n')), 8)

        # Test TxM side key
        user_key = open("keys/tx.bob@jabber.org.e").readline()
        self.assertTrue(ut_validate_key(user_key))

        # Test contact database
        written = open(".tx_contacts").readlines()
        self.assertTrue("bob@jabber.org,bob,1\r\n" in written or
                        "bob@jabber.org,bob,1\n" in written or
                        "bob@jabber.org,bob,1\r" in written or
                        "bob@jabber.org,bob,1" in written)

        # Test logging dictionary
        self.assertFalse(Tx.acco_store_l["bob@jabber.org"])

        # Test nick has not changed.
        self.assertEqual(Tx.recipient_nick, "Robert")

        # Teardown
        shutil.rmtree("keys")
        shutil.rmtree("keys_to_contact")
        os.remove(".tx_contacts")
        os.remove("unitt_txm_out")
        __builtins__.raw_input = origin_raw_input
        Tx.generate_key = original_genkey
        Tx.acco_store_l["bob@jabber.org"] = False
        Tx.local_testing = False
        Tx.show_file_prompts = True
        Tx.unittesting = False


class TestDigitsToBytes(unittest.TestCase):

    def test_1_input_parameter(self):
        for a in [1, 1.0, True]:
            with self.assertRaises(SystemExit):
                digits_to_bytes(a)

    def test_2_test_valid_decode(self):

        # Test
        self.assertEqual(digits_to_bytes('010101000100011001000011'), 'TFC')

    def test_2_test_invalid_decode(self):

        # Test
        self.assertNotEqual(digits_to_bytes('010101000100011001000010'), 'TFC')


class TestGenerateKey(unittest.TestCase):

    def test_1_input_parameter(self):
        for a in [1.0, 1, True]:
            with self.assertRaises(SystemExit):
                generate_key(a)

    def test_2_return_valid_key_when_no_hwrng(self):

        # Setup
        Tx.use_ssh_hwrng = False
        original_yes = Tx.yes
        Tx.yes = lambda x, y: False

        # Test
        self.assertTrue(ut_validate_key(generate_key("test")))

        # Teardown
        Tx.yes = original_yes


class TestNewLocalKey(unittest.TestCase):

        def test_1_input_parameter(self):
            for a in [1.0, 1, "string"]:
                with self.assertRaises(SystemExit):
                    new_local_key(a)

        def test_2_new_local_key(self):
            """
            Device code verification is disabled during unittesting
            as mock input of random device code would be difficult.
            """

            # Setup
            Tx.unittesting = True
            Tx.local_testing = True
            Tx.use_ssh_hwrng = False
            origin_raw_input = __builtins__.raw_input
            __builtins__.raw_input = lambda x: ''

            original_genkey = Tx.generate_key
            Tx.generate_key = lambda x: 64 * 'a'

            # Test command returns None
            self.assertIsNone(new_local_key())

            # Test RxM packet content
            rxm_packet = open("unitt_txm_out").readline()
            s, t, v, p, ct, c = rxm_packet.split('|')
            self.assertEqual(s, "TFC")
            self.assertEqual(t, 'N')
            self.assertEqual(v, str(Tx.int_version))
            self.assertEqual(p, 'L')
            self.assertEqual(len(ct), 392)
            self.assertEqual(len(c.strip('\n')), 8)

            # Test local key
            localkey = open("keys/tx.local.e").readline()
            ut_validate_key(localkey)

            # Test contact database
            written = open(".tx_contacts").readlines()
            self.assertTrue("local,local,1\n" in written)

            # Teardown
            shutil.rmtree("keys")
            os.remove(".tx_contacts")
            os.remove("unitt_txm_out")
            Tx.local_testing = False
            Tx.unittesting = False
            Tx.generate_key = original_genkey
            __builtins__.raw_input = origin_raw_input


###############################################################################
#                               SECURITY RELATED                              #
###############################################################################

class TestFixedAESkey(unittest.TestCase):
    """
    This function doesn't have any tests yet.
    """


class TestGracefulExit(unittest.TestCase):

    def test_1_input_parameters(self):
        for a in [1, 1.0, True]:
            for b in [1, 1.0, "string"]:
                with self.assertRaises(SystemExit):
                    graceful_exit(a, b)

    def test_2_function(self):

        # Setup
        Tx.trickle_connection = False

        # Test
        with self.assertRaises(SystemExit):
            graceful_exit()


class TestValidateKey(unittest.TestCase):

    def test_1_input_parameter(self):
        for a in [1, 1.0, True]:
            for b in [1, 1.0, True]:
                with self.assertRaises(SystemExit):
                    validate_key(a, b)

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


class TestKeySearcher(unittest.TestCase):

    def test_1_input_parameter(self):
        for a in [1, 1.0, True]:
            with self.assertRaises(SystemExit):
                key_searcher(a)

    def test_2_bounds(self):
        for l in range(0, 63):
            self.assertFalse(key_searcher("teststring%s" % (l * 'a')))

        for l in range(63, 74):
            self.assertTrue(key_searcher("teststring%s" % (l * 'a')))

        for l in range(74, 250):
            self.assertFalse(key_searcher("teststring%s" % (l * 'a')))


class TestWriteLogEntry(unittest.TestCase):

    def test_1_input_parameters(self):
        for a in [1, 1.0, True]:
            for b in [1, 1.0, True]:
                for c in [1, 1.0, True]:
                    for d in [1, 1.0, True]:
                        for e in [1, 1.0, True]:
                            with self.assertRaises(SystemExit):
                                write_log_entry(a, b, c, d, e)

    def test_2_log_entry(self):

        # Test
        write_log_entry("alice@jabber.org", "alice", "message")
        logged = str(open("logs/TxM - logs.alice@jabber.org.tfc").readline())
        split = logged.split()
        self.assertEqual(split[2], "Me")
        self.assertEqual(split[3], '>')
        self.assertEqual(split[4], "alice:")
        self.assertEqual(split[5], "message")

        # Teardown
        shutil.rmtree("logs")

    def test_3_write_key_exchange(self):

        # Test
        write_log_entry("alice@jabber.org", pk_user=(64*'a'),
                        pk_contact=(64*'b'))

        logf = open("logs/TxM - logs.alice@jabber.org.tfc").read().splitlines()

        self.assertEqual(logf[2], "       My pub key:  "
                                  "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                                  "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")

        self.assertEqual(logf[3], "Contact's pub key:  "
                                  "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                                  "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")

        # Teardown
        shutil.rmtree("logs")


class TestGetContactPublicKeyHex(unittest.TestCase):

    def test_1_return_value(self):

        # Setup
        origin_raw_input = __builtins__.raw_input
        __builtins__.raw_input = lambda x: \
            "2bd5ddebf03917df47cece8044e4f2dc81a4" \
            "7ecd61cdb590266b59fa7610b901e6c132e3"

        # Test
        self.assertEqual(get_contact_public_key_hex(),
                         "2bd5ddebf03917df47cece8044e4f2dc"
                         "81a47ecd61cdb590266b59fa7610b901")

        # Teardown
        __builtins__.raw_input = origin_raw_input


class TestManualPublicKeyEntry(unittest.TestCase):

    def test_1_return_value(self):

        # Setup
        origin_raw_input = __builtins__.raw_input
        original_yes = Tx.yes
        Tx.yes = lambda x: True
        __builtins__.raw_input = lambda x: \
            "2bd5ddebf03917df47cece8044e4f2dc81a4" \
            "7ecd61cdb590266b59fa7610b901e6c132e3"

        # Test
        self.assertEqual(manual_public_key_entry(),
                         "2bd5ddebf03917df47cece8044e4f2dc"
                         "81a47ecd61cdb590266b59fa7610b901")

        # Teardown
        __builtins__.raw_input = origin_raw_input
        Tx.yes = original_yes


class TestVerifyPublicKeys(unittest.TestCase):

    def test_1_input_parameters(self):
        for a in [1, 1.0, True]:
            for b in [1, 1.0, True]:
                for c in [1, 1.0, True]:
                    with self.assertRaises(SystemExit):
                        verify_public_keys(a, b, c)

    def test_2_public_key_successful_verification(self):

        # Setup
        original_yes = Tx.yes
        Tx.yes = lambda x, y: True

        # Test
        self.assertEqual(verify_public_keys(64 * 'a', 64 * 'b',
                                            "bob@jabber.org"), 64 * 'b')

        # Teardown
        Tx.yes = original_yes


class TestStartKeyExchange(unittest.TestCase):

    def test_1_input_parameters(self):
        for a in [1, 1.0, True]:
            for b in [1, 1.0, "string"]:
                with self.assertRaises(SystemExit):
                    start_key_exchange(a, b)

    def test_2_invalid_commands(self):

        # Setup
        ut_ensure_dir("keys/")

        # Test
        self.assertIsNone(start_key_exchange("/dh"))
        self.assertIsNone(start_key_exchange("/dh "))

        # Teardown
        shutil.rmtree("keys")

    def test_3_public_key(self):

        # Setup
        origin_raw_input = __builtins__.raw_input
        __builtins__.raw_input = lambda x: \
            "2bd5ddebf03917df47cece8044e4f2dc81a4" \
            "7ecd61cdb590266b59fa7610b901e6c132e3"
        original_yes = Tx.yes
        Tx.yes = lambda x, y: True

        original_genkey = Tx.generate_key
        Tx.generate_key = lambda x: 64 * 'a'

        Tx.recipient_acco = "bob@jabber.org"
        Tx.unittesting = True
        create_test_keys(["bob", "local"])
        create_contact_db(["bob", "local"])

        # Create public keys
        self.assertIsNone(start_key_exchange("/dh bob@jabber.org"))

        # Verify public key packet content
        ssk_data = open("unitt_txm_out").readline()
        header, model, ver, p_type, ct, account, chksum = ssk_data.split('|')
        self.assertEqual(header, "TFC")
        self.assertEqual(model, 'N')
        self.assertEqual(ver, str(Tx.int_version))

        # Verify public key packet hash
        calc = ut_sha2_256("%s|%s|%s|%s|%s|%s"
                           % (header, model, ver, p_type,
                              ct, account))[:Tx.checksum_len]
        self.assertEqual(chksum, calc + '\n')

        # Verify public keys were written to TxM side logfile
        logdata = open("logs/TxM - logs.bob@jabber.org.tfc").readlines()
        self.assertTrue(ut_validate_key(str(logdata[2]).split()[3]))
        self.assertTrue(ut_validate_key(str(logdata[3]).split()[3]))
        self.assertNotEqual(str(logdata[2]).split()[3],
                            str(logdata[3]).split()[3])

        # Teardown
        __builtins__.raw_input = origin_raw_input
        Tx.generate_key = original_genkey
        Tx.yes = original_yes
        os.remove("unitt_txm_out")
        os.remove(".tx_contacts")
        shutil.rmtree("logs")
        shutil.rmtree("keys")
        Tx.unittesting = False


###############################################################################
#                             CONTACT MANAGEMENT                              #
###############################################################################

class TestChangeRecipient(unittest.TestCase):

    def setUp(self):
        create_test_keys(["alice", "bob"])
        create_group_db("testgroup", ["alice", "bob"])
        create_contact_db(["alice", "bob"])

        Tx.recipient_acco = ''
        Tx.recipient_nick = ''
        Tx.group = ''

    def tearDown(self):
        shutil.rmtree("keys")
        os.remove(".tx_contacts")

    def test_1_input_parameter(self):
        for a in [1, 1.0, True]:
            with self.assertRaises(SystemExit):
                change_recipient(a)

    def test_2_function(self):

        # Test invalid commands
        for p in ["/m", "/ms", "/msg", "/msg ",
                  "/msg -1", "/msg one", "/msg 3"]:
            self.assertEqual(change_recipient("/msg %s" % p), ('', '', ''))

        # Test recipient changing
        self.assertEqual(change_recipient("/msg bob@jabber.org"),
                         ("bob@jabber.org", "bob", ''))

        self.assertEqual(change_recipient("/msg alice@jabber.org"),
                         ("alice@jabber.org", "alice", ''))

        self.assertEqual(change_recipient("/msg jack@jabber.org"),
                         ('', '', ''))

        self.assertEqual(change_recipient("/msg 1"),
                         ("bob@jabber.org", "bob", ''))

        self.assertEqual(change_recipient("/msg 0"),
                         ("alice@jabber.org", "alice", ''))

        self.assertEqual(change_recipient("/msg testgroup"),
                         ('', "testgroup", "testgroup"))

        # Switch away from group
        self.assertEqual(change_recipient("/msg alice@jabber.org"),
                         ("alice@jabber.org", "alice", ''))

        # Test trickle_connection prevents selecting group
        Tx.trickle_connection = True
        self.assertEqual(change_recipient("/msg testgroup"), ('', '', ''))
        Tx.trickle_connection = False

        # Test test non-existing groups are not selected
        shutil.rmtree("groups")
        ut_ensure_dir("groups/")
        self.assertEqual(change_recipient("/msg testgroup"), ('', '', ''))

        shutil.rmtree("groups")
        self.assertEqual(change_recipient("/msg testgroup"), ('', '', ''))


class TestGetContactQuantity(unittest.TestCase):

    def test_1_no_members(self):

        # Setup
        open(".tx_contacts", "w+").close()

        # Test
        self.assertEqual(get_contact_quantity(), 0)

        # Teardown
        os.remove(".tx_contacts")

    def test_2_single_member(self):

        # Setup
        create_contact_db(["alice"])

        # Test
        self.assertEqual(get_contact_quantity(), 1)

        # Teardown
        os.remove(".tx_contacts")

    def test_3_two_members(self):

        # Setup
        create_contact_db(["alice", "bob"])

        # Test
        self.assertEqual(get_contact_quantity(), 2)

        # Teardown
        os.remove(".tx_contacts")

    def test_4_two_members_and_local(self):

        # Setup
        create_contact_db(["alice", "bob", "local"])

        # Test
        self.assertEqual(get_contact_quantity(), 2)

        # Teardown
        os.remove(".tx_contacts")


class TestGetListOfAccounts(unittest.TestCase):

    def setUp(self):
        ut_ensure_dir("keys/")
        open("keys/tx.1.e", "w+").close()
        open("keys/tx.2.e", "w+").close()
        open("keys/tx.3.e", "w+").close()
        open("keys/me.3.e", "w+").close()
        open("keys/rx.3.e", "w+").close()
        open("keys/tx.local.e", "w+").close()
        open("keys/rx.local.e", "w+").close()
        open("keys/me.local.e", "w+").close()

    def tearDown(self):
        shutil.rmtree("keys")

    def test_1_function(self):
        self.assertEqual(get_list_of_accounts(), ['1', '2', '3'])


class TestPrintContactList(unittest.TestCase):

    def test_1_input_parameter(self):
        for a in [1, 1.0, "string"]:
            with self.assertRaises(SystemExit):
                print_contact_list(a)

    def test_2_with_spacing(self):

        # Setup
        create_test_keys(["alice", "bob", "charlie"])
        create_contact_db(["alice", "bob", "charlie"])

        # Test
        self.assertIsNone(print_contact_list(spacing=True))

        # Teardown
        shutil.rmtree("keys")
        os.remove(".tx_contacts")

    def test_3_without_spacing(self):

        # Setup
        create_test_keys(["alice", "bob", "charlie"])
        create_contact_db(["alice", "bob", "charlie"])

        # Test
        self.assertEqual(print_contact_list(), 21)

        # Teardown
        shutil.rmtree("keys")
        os.remove(".tx_contacts")

    def test_4_no_accounts(self):

        # Setup
        ut_ensure_dir("keys/")

        # Test
        self.assertIsNone(print_contact_list(True))
        self.assertEqual(print_contact_list(), 0)

        # Teardown
        shutil.rmtree("keys")


class TestPrintSelectionError(unittest.TestCase):

    def test_1_input_parameter(self):
        for a in [1, 1.0, True]:
            with self.assertRaises(SystemExit):
                print_selection_error(a)

    def test_2_functioN(self):

        # Setup
        ut_ensure_dir("keys/")

        # Test
        self.assertIsNone(print_selection_error("invalid"))

        # Teardown
        shutil.rmtree("keys")


class TestSelectContact(unittest.TestCase):

    def setUp(self):
        create_test_keys(["alice", "bob"])
        create_contact_db(["alice", "bob"])

    def tearDown(self):
        shutil.rmtree("keys")
        os.remove(".tx_contacts")

    def test_1_input_parameters(self):
        for a in ["string", 0.0, True]:
            for b in [0, 0.0, True]:
                for c in ["string", 0.0, 0]:
                    with self.assertRaises(SystemExit):
                        select_contact(a, b, c)

    def test_1_no_0(self):
        self.assertEqual(select_contact(selection='0',
                                        menu=False),
                         ("alice@jabber.org", "alice"))

    def test_2_no_1(self):
        self.assertEqual(select_contact(selection='1',
                                        menu=False),
                         ("bob@jabber.org", "bob"))

    def test_3_alice(self):
        self.assertEqual(select_contact(selection="alice@jabber.org",
                                        menu=False),
                         ("alice@jabber.org", "alice"))

    def test_4_bob(self):
        self.assertEqual(select_contact(selection="bob@jabber.org",
                                        menu=False),
                         ("bob@jabber.org", "bob"))

    def test_5_invalid_numbers(self):
        for i in ["-1", '2', '3', '4']:
            with self.assertRaises(ValueError):
                select_contact(selection=i, menu=False)

    def test_6_invalid_contact(self):
        with self.assertRaises(ValueError):
            select_contact(selection="jack@jabber.org", menu=False)


class TestGetListOfTargets(unittest.TestCase):

    def setUp(self):
        create_test_keys(["alice", "bob"])
        create_contact_db(["alice", "bob"])
        create_group_db("testgroup", ["alice", "bob"])

    def tearDown(self):
        shutil.rmtree("groups")
        shutil.rmtree("keys")
        os.remove(".tx_contacts")

    def test_1_groups_and_accounts_are_found(self):
        self.assertEqual(get_list_of_targets(), ["alice", "bob", "testgroup"])


# .tx_contacts management
class TestAddFirstContact(unittest.TestCase):
    """
    This function doesn't have any tests yet.
    """


class TestAddContact(unittest.TestCase):

    def test_1_input_parameters(self):
        for a in [1, 1.0, True]:
            for b in [1, 1.0, True]:
                with self.assertRaises(SystemExit):
                    add_contact(a, b)

    def test_2_valid_contact_adding(self):

        # Setup
        add_contact("alice@jabber.org", "alice")

        # Test
        csv_data = open(".tx_contacts").readline()
        self.assertEqual(csv_data, "alice@jabber.org,alice,1\n")

        # Teardown
        os.remove(".tx_contacts")

    def test_3_contact_reset(self):

        # Setup
        open(".tx_contacts", "w+").write("alice@jabber.org,alice,5\n")

        # Test
        add_contact("alice@jabber.org", "alice")
        csv_data = open(".tx_contacts").readline()
        self.assertEqual(csv_data, "alice@jabber.org,alice,1\r\n")

        # Teardown
        os.remove(".tx_contacts")


class TestAddKeyfiles(unittest.TestCase):

    def test_1_function(self):

        # Setup
        origin_raw_input = __builtins__.raw_input
        __builtins__.raw_input = lambda x: "bob"
        create_test_keys(["bob"])

        # Test
        add_keyfiles()
        contact_db = open(".tx_contacts").readline()
        self.assertEqual(contact_db, "bob@jabber.org,bob,1\n")

        # Teardown
        __builtins__.raw_input = origin_raw_input
        shutil.rmtree("keys")
        os.remove(".tx_contacts")


class TestGetKeyID(unittest.TestCase):

    def test_1_input_parameter(self):
        for a in [1, 1.0, True]:
            with self.assertRaises(SystemExit):
                get_keyid(a)

    def test_2_missing_keyID(self):

        # Setup
        open(".tx_contacts", "w+").write("alice@jabber.org,alice")

        # Test
        with self.assertRaises(SystemExit):
            get_keyid("alice@jabber.org")

        # Teardown
        os.remove(".tx_contacts")

    def test_3_invalid_keyID_value(self):

        # Setup
        open(".tx_contacts", "w+").write("alice@jabber.org,alice,a")

        # Test
        with self.assertRaises(SystemExit):
            get_keyid("alice@jabber.org")

        # Teardown
        os.remove(".tx_contacts")

    def test_4_keyID_zero(self):

        # Setup
        open(".tx_contacts", "w+").write("alice@jabber.org,alice,0")

        # Test
        with self.assertRaises(SystemExit):
            get_keyid("alice@jabber.org")

        # Teardown
        os.remove(".tx_contacts")

    def test_5_correct_keyID(self):

        # Setup
        open(".tx_contacts", "w+").write("alice@jabber.org,alice,1")

        # Test
        self.assertEqual(get_keyid("alice@jabber.org"), 1)

        # Teardown
        os.remove(".tx_contacts")


class TestGetNick(unittest.TestCase):

    def test_1_input_parameter(self):
        for a in [1, 1.0, True]:
            with self.assertRaises(SystemExit):
                get_nick(a)

    def test_2_missing_nick(self):
        for p in ['', ',']:

            # Setup
            open(".tx_contacts", "w+").write("alice@jabber.org%s,1" % p)

            # Test
            with self.assertRaises(SystemExit):
                get_nick("alice@jabber.org")

            # Teardown
            os.remove(".tx_contacts")

    def test_3_correct_nick(self):

        # Setup
        create_contact_db(["alice"])

        # Test
        self.assertEqual(get_nick("alice@jabber.org"), "alice")

        # Teardown
        os.remove(".tx_contacts")


class TestGetNickInput(unittest.TestCase):

    def test_1_function(self):

        # Setup
        ut_ensure_dir("keys/")
        origin_raw_input = __builtins__.raw_input

        # Test user entered nickname
        __builtins__.raw_input = lambda x: "robert"
        self.assertEqual(get_nick_input("bob@jabber.org"), "robert")

        # Test automatic nickname parsing
        __builtins__.raw_input = lambda x: ''
        self.assertEqual(get_nick_input("bob@jabber.org"), "Bob")

        # Teardown
        __builtins__.raw_input = origin_raw_input
        shutil.rmtree("keys")


class TestWriteKeyID(unittest.TestCase):

    def setUp(self):
        create_contact_db(["alice"])

    def tearDown(self):
        os.remove(".tx_contacts")

    def test_1_input_parameters(self):
        for a in [1, 1.0, True]:
            for b in ["string", 1.0, True]:
                with self.assertRaises(SystemExit):
                    write_keyid(a, b)

    def test_2_keyID_less_than_one(self):
        for i in [-1, 0]:
            with self.assertRaises(SystemExit):
                write_keyid("alice@jabber.org", i)

    def test_3_valid_keyid(self):
        write_keyid("alice@jabber.org", 2)
        written_data = open(".tx_contacts").readline()
        self.assertEqual(written_data, "alice@jabber.org,alice,2\r\n")


class TestWriteNick(unittest.TestCase):

    def test_1_input_parameters(self):
        for a in [1, 1.0, True]:
            for b in [1, 1.0, True]:
                with self.assertRaises(SystemExit):
                    write_nick(a, b)

    def test_2_no_db_gracefully_exits(self):
        with self.assertRaises(SystemExit):
            write_nick("alice@jabber.org", "alice")

    def test_3_correct_nick_writing(self):

        # Setup
        create_contact_db(["alice"])

        # Test
        write_nick("alice@jabber.org", "ALICE")
        written_data = open(".tx_contacts").readline()
        self.assertEqual(written_data, "alice@jabber.org,ALICE,1\r\n")

        # Teardown
        os.remove(".tx_contacts")


class TestRmContact(unittest.TestCase):

    def test_1_input_parameter(self):
        for a in [1, 1.0, True]:
            with self.assertRaises(SystemExit):
                rm_contact(a)

    def test_2_function(self):

        # Setup
        create_test_keys(["alice", "bob"])
        create_contact_db(["alice", "bob"])
        create_group_db("test_group1", ["alice", "bob"])
        create_group_db("test_group2", ["alice"])
        create_group_db("test_group3", ["bob"])
        original_yes = Tx.yes
        Tx.yes = lambda x: True

        # Test invalid commands return None
        self.assertIsNone(rm_contact("/rm"))
        self.assertIsNone(rm_contact("/rm "))
        self.assertIsNone(rm_contact("/rm lo"))
        self.assertIsNone(rm_contact("/rm local"))
        self.assertIsNone(rm_contact("/rm me.local"))
        self.assertIsNone(rm_contact("/rm bob@jabber.org"))

        # Test that command removes Bob's kf and data from .tx_contacts/groups.
        rm_success = True
        for f in ["groups/g.test_group1.tfc",
                  "groups/g.test_group2.tfc",
                  "groups/g.test_group3.tfc",
                  ".tx_contacts"]:
            members = open(f).read().splitlines()
            for m in members:
                if "bob" in m:
                    rm_success = False
            self.assertTrue(rm_success)
        self.assertFalse(os.path.isfile("keys/tx.bob@jabber.org.e"))

        # Teardown
        shutil.rmtree("keys")
        shutil.rmtree("groups")
        os.remove(".tx_contacts")
        Tx.yes = original_yes


###############################################################################
#                               MSG PROCESSING                                #
###############################################################################

class TestLongTpreProcess(unittest.TestCase):

    def test_1_input_parameter(self):
        for a in [1, 1.0, True]:
            with self.assertRaises(SystemExit):
                long_t_pre_process(a)

    def test_2_invalid_header(self):
        with self.assertRaises(SystemExit):
            long_t_pre_process('a')

    def test_3_long_message_packet_splitting(self):

        self.assertEqual(long_t_pre_process("m%s" % (900 * 'x')),
                         ["lxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
                          "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
                          "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
                          "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
                          "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
                          "xxx",
                          "axxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
                          "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
                          "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
                          "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
                          "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
                          "xxx",
                          "axxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
                          "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
                          "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
                          "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
                          "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
                          "xxx",
                          "exxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
                          "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
                          "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
                          "dc5ef393e71ae0f98bd6a72ecb7a0d7e"
                          "1698756ea1a9605ad7846e68c7a251e2"])

    def test_4_long_file_packet_splitting(self):

        self.assertEqual(long_t_pre_process("f%s" % (900 * 'z')),
                         ["Lzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"
                          "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"
                          "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"
                          "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"
                          "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"
                          "zzz",
                          "Azzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"
                          "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"
                          "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"
                          "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"
                          "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"
                          "zzz",
                          "Azzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"
                          "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"
                          "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"
                          "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"
                          "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"
                          "zzz",
                          "Ezzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"
                          "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"
                          "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"
                          "3ce204a25f89be1ca7877aea8c09d141"
                          "cf7916851fd06c6cb722af1fd3d0b0fb"])


class TestPadding(unittest.TestCase):

    def test_1_input_parameter(self):
        for a in [1, 1.0, True]:
            with self.assertRaises(SystemExit):
                padding(a)

    def test_2_oversize_pt_detection(self):
        for s in range(255, 260):
            with self.assertRaises(SystemExit):
                padding(255 * 'm')

    def test_3_padding(self):
        for s in range(0, 254):
            self.assertEqual(len(padding(s * 'm')), 254)


###############################################################################
#                              ENCRYPTED COMMANDS                             #
###############################################################################

class TestChangeLogging(unittest.TestCase):

    def test_1_input_parameters(self):
        for a in [1, 1.0, True]:
            for b in ["string", 1, 1.0]:
                with self.assertRaises(SystemExit):
                    change_logging(a, b)

    def test_2_missing_local_key(self):
        with self.assertRaises(NoLocalKeyError):
            change_logging("/logging on")

    def test_3_invalid_commands(self):
        for s in ['', ' ', 'o']:
            self.assertIsNone(change_logging("/logging%s" % s))

    def test_4_logging_enable_with_kf(self):

        # Setup
        create_test_keys(["local", "alice", "bob"])
        create_contact_db(["local", "alice", "bob"])
        Tx.acco_store_l["alice@jabber.org"] = False
        Tx.acco_store_l["bob@jabber.org"] = False

        # Test
        self.assertEqual(change_logging("/logging on", ret=True),
                         "C|LOGGING|ENABLE")
        self.assertTrue(Tx.acco_store_l["alice@jabber.org"])
        self.assertTrue(Tx.acco_store_l["bob@jabber.org"])

        # Teardown
        shutil.rmtree("keys")
        os.remove(".tx_contacts")

    def test_5_logging_disable_with_kf(self):

        # Setup
        create_test_keys(["local", "alice", "bob"])
        create_contact_db(["local", "alice", "bob"])
        Tx.acco_store_l["alice@jabber.org"] = True
        Tx.acco_store_l["bob@jabber.org"] = True

        # Test
        self.assertEqual(change_logging("/logging off", ret=True),
                         "C|LOGGING|DISABLE")
        self.assertFalse(Tx.acco_store_l["alice@jabber.org"])
        self.assertFalse(Tx.acco_store_l["bob@jabber.org"])

        # Teardown
        shutil.rmtree("keys")
        os.remove(".tx_contacts")

    def test_6_logging_enable_for_contact(self):

        # Setup
        create_test_keys(["local", "alice", "bob"])
        create_contact_db(["local", "alice", "bob"])
        Tx.acco_store_l["alice@jabber.org"] = False
        Tx.acco_store_l["bob@jabber.org"] = False

        # Test
        self.assertEqual(change_logging("/logging on bob@jabber.org",
                                        ret=True),
                         "C|LOGGING|ENABLE|me.bob@jabber.org")
        self.assertFalse(Tx.acco_store_l["alice@jabber.org"])
        self.assertTrue(Tx.acco_store_l["bob@jabber.org"])

        # Teardown
        shutil.rmtree("keys")
        os.remove(".tx_contacts")

    def test_7_logging_enable_for_contact(self):

        # Setup
        create_test_keys(["local", "alice", "bob"])
        create_contact_db(["local", "alice", "bob"])
        Tx.acco_store_l["alice@jabber.org"] = True
        Tx.acco_store_l["bob@jabber.org"] = True

        # Test
        self.assertEqual(change_logging("/logging off bob@jabber.org",
                                        ret=True),
                         "C|LOGGING|DISABLE|me.bob@jabber.org")
        self.assertTrue(Tx.acco_store_l["alice@jabber.org"])
        self.assertFalse(Tx.acco_store_l["bob@jabber.org"])

        # Teardown
        shutil.rmtree("keys")
        os.remove(".tx_contacts")


class TestChangeNick(unittest.TestCase):

    def test_1_input_parameters(self):
        for a in [1, 1.0, True]:
            for b in [1, 1.0, True]:
                for c in ["string", 1, 1.0]:
                    with self.assertRaises(SystemExit):
                        change_nick(a, b, c)

    def test_2_function_returns_none_when_group_is_selected(self):

        # Setup
        create_test_keys(["alice"])
        create_contact_db(["alice"])
        Tx.group = "group"
        Tx.recipient_nick = "group"

        # Test
        self.assertIsNone(change_nick("alice@jabber.org", "/nick Alice",
                                      ret=True))
        self.assertEqual(Tx.group, "group")
        self.assertEqual(Tx.recipient_nick, "group")

        # Teardown
        shutil.rmtree("keys")
        os.remove(".tx_contacts")
        Tx.group = ''

    def test_3_no_keyfile(self):

        # Setup
        create_test_keys(["alice"])
        create_contact_db(["alice"])

        # Test
        with self.assertRaises(NoLocalKeyError):
            change_nick("alice@jabber.org", "/nick Alice", ret=True)

        # Teardown
        shutil.rmtree("keys")
        os.remove(".tx_contacts")

    def test_4_none_when_no_nick_is_specified(self):

        # Setup
        create_test_keys(["alice", "local"])
        create_contact_db(["local", "alice"])

        # Test
        for c in ["/nick", "/nick "]:
            self.assertIsNone(change_nick("alice@jabber.org", c, ret=True))

        # Teardown
        shutil.rmtree("keys")
        os.remove(".tx_contacts")

    def test_5_too_long_nick(self):
        """
        Nick length depends on new account creation. Combined maximum length of
        nick and account is 121 chars.
        """

        # Setup
        create_test_keys(["alice", "local"])
        create_contact_db(["alice", "local"])

        # Test
        self.assertEqual(change_nick("alice@jabber.org", "/nick %s"
                                     % (106 * 'n'), ret=True), '')

        # Teardown
        shutil.rmtree("keys")
        os.remove(".tx_contacts")

    def test_6_success_with_max_length_nick(self):

        # Setup
        create_test_keys(["alice", "local"])
        create_contact_db(["alice", "local"])

        # Test
        self.assertEqual(change_nick("alice@jabber.org", "/nick %s"
                                     % (105 * 'n'), ret=True),
                         "C|NICK|me.alice@jabber.org|%s" % (105 * 'n'))

        # Teardown
        shutil.rmtree("keys")
        os.remove(".tx_contacts")

    def test_7_local_can_not_be_nick(self):

        # Setup
        create_test_keys(["alice", "local"])
        create_contact_db(["alice", "local"])

        # Test
        self.assertEqual(change_nick("alice@jabber.org",
                                     "/nick local", ret=True), '')

        # Teardown
        shutil.rmtree("keys")
        os.remove(".tx_contacts")

    def test_8_disallowed_chars(self):

        # Setup
        create_test_keys(["alice", "local"])
        create_contact_db(["alice", "local"])

        # Test
        for c in [',', '|']:
            self.assertEqual(change_nick("alice@jabber.org", "/nick alice%s"
                                         % c, ret=True), '')
        # Teardown
        shutil.rmtree("keys")
        os.remove(".tx_contacts")

    def test_9_nick_not_account(self):

        # Setup
        create_test_keys(["alice", "local"])
        create_contact_db(["alice", "local"])

        # Test
        self.assertEqual(change_nick("alice@jabber.org",
                                     "/nick alice@jabber.org", ret=True), '')

        # Teardown
        shutil.rmtree("keys")
        os.remove(".tx_contacts")


class TestChangeFileStoring(unittest.TestCase):

    def test_1_input_parameters(self):
        for a in [1, 1.0, True]:
            for b in ["string", 1, 1.0]:
                with self.assertRaises(SystemExit):
                    change_file_storing(a, b)

    def test_2_no_local_kf(self):
        for b in [True, False]:
            with self.assertRaises(NoLocalKeyError):
                change_file_storing("/store on", ret=b)

    def test_3_invalid_commands(self):

        # Setup
        create_test_keys(["local"])

        # Test
        self.assertEqual(change_file_storing("/store", ret=True), '')
        self.assertEqual(change_file_storing("/store ", ret=True), '')
        self.assertIsNone(change_file_storing("/store"))
        self.assertIsNone(change_file_storing("/store "))

        # Teardown
        shutil.rmtree("keys")

    def test_4_store_on(self):

        # Setup
        create_test_keys(["local"])

        # Test
        self.assertEqual(change_file_storing("/store on", ret=True),
                         "C|STORE|ENABLE")

        # Teardown
        shutil.rmtree("keys")

    def test_5_store_off(self):

        # Setup
        create_test_keys(["local"])

        # Test
        self.assertEqual(change_file_storing("/store off", ret=True),
                         "C|STORE|DISABLE")

        # Teardown
        shutil.rmtree("keys")

    def test_6_store_on_for_contact(self):

        # Setup
        create_test_keys(["local", "bob"])

        # Test
        self.assertEqual(change_file_storing("/store on bob@jabber.org",
                                             ret=True),
                         "C|STORE|ENABLE|rx.bob@jabber.org")
        # Teardown
        shutil.rmtree("keys")

    def test_7_store_off_for_contact(self):

        # Setup
        create_test_keys(["local", "bob"])

        # Test
        self.assertEqual(change_file_storing("/store off bob@jabber.org",
                                             ret=True),
                         "C|STORE|DISABLE|rx.bob@jabber.org")

        # Teardown
        shutil.rmtree("keys")


class TestClearDisplays(unittest.TestCase):

    def test_1_input_parameters(self):
        for a in [1, 1.0, True]:
            for b in ["string", 1.0]:
                with self.assertRaises(SystemExit):
                    clear_displays(a, b)

    def test_2_no_local_kf(self):
        with self.assertRaises(NoLocalKeyError):
            clear_displays(trickle=True)

    def test_3_test_unencrypted_clearing(self):
        self.assertEqual(clear_displays("alice@jabber.org"),
                         "TFC|N|%s|U|CLEAR|%s" % (Tx.int_version,
                                                  "alice@jabber.org"))

    def test_4_test_encrypted_clearing(self):

        # Setup
        create_test_keys(["local"])

        # Test
        self.assertEqual(clear_displays(trickle=True), "C|CLEAR")

        # Teardown
        shutil.rmtree("keys")


###############################################################################
#                    COMMAND / MESSAGE / FILE TRANSMISSION                    #
###############################################################################

class TestCommandThread(unittest.TestCase):

    def test_1_input_parameters(self):
        for a in [1, 1.0, True]:
            for b in [1, 1.0, True]:
                with self.assertRaises(SystemExit):
                    command_thread(a, b)

    def test_2_packet_content(self):

        # Setup
        Tx.unittesting = True
        create_test_keys(["local"])
        create_contact_db(["local"])

        # Send command
        command_thread("STORE|ENABLE|RECEPTION")

        # Test packet content
        packetdata = open("unitt_txm_out").readline()
        hd, sw, ver, p_type, ct, k_id, chksum = packetdata.split('|')
        calc = ut_sha2_256(packetdata[:-10])[:Tx.checksum_len]

        self.assertEqual(len(packetdata), 417)
        self.assertEqual(hd, "TFC")
        self.assertEqual(sw, 'N')
        self.assertEqual(p_type, 'C')
        self.assertEqual(ver, str(Tx.int_version))
        self.assertEqual(k_id, '1')
        self.assertEqual(chksum, calc + '\n')

        # Teardown
        shutil.rmtree("keys")
        os.remove(".tx_contacts")
        os.remove("unitt_txm_out")
        Tx.unittesting = False


class TestCommandTransmit(unittest.TestCase):

    def test_1_input_parameter(self):
        for a in [1, 1.0, True]:
            with self.assertRaises(SystemExit):
                command_transmit(a)

    def test_2_run_thread(self):

        # Setup
        Tx.unittesting = True
        create_test_keys(["local"])
        create_contact_db(["local"])

        # Test
        self.assertIsNone(command_transmit("Testcommand"))

        # Teardown
        shutil.rmtree("keys")
        os.remove(".tx_contacts")
        os.remove("unitt_txm_out")
        Tx.unittesting = False


class TestMessageThread(unittest.TestCase):

    def test_1_input_parameters(self):
        for a in [1, 1.0, True]:
            for b in [1, 1.0, True]:
                with self.assertRaises(SystemExit):
                    message_thread(a, b)

    def test_2_packet_content(self):

        # Setup
        Tx.unittesting = True
        create_test_keys(["alice"])
        create_contact_db(["alice"])

        # Send message
        message_thread("plaintextmessage", "alice@jabber.org")

        # Test packet content
        packetdata = open("unitt_txm_out").readline()
        hd, sw, ver, p_type, ct, k_id, accoun, chksum = packetdata.split('|')
        calc = ut_sha2_256(packetdata[:-10])[:Tx.checksum_len]

        self.assertEqual(len(packetdata), 434)
        self.assertEqual(hd, "TFC")
        self.assertEqual(sw, 'N')
        self.assertEqual(ver, str(Tx.int_version))
        self.assertEqual(p_type, 'M')
        self.assertEqual(k_id, '1')
        self.assertEqual(accoun, "alice@jabber.org")
        self.assertEqual(chksum, calc + '\n')

        # Teardown
        shutil.rmtree("keys")
        os.remove(".tx_contacts")
        os.remove("unitt_txm_out")
        Tx.unittesting = False


class TestMessageTransmit(unittest.TestCase):

    def test_1_input_parameters(self):
        for a in [1, 1.0, True]:
            for b in [1, 1.0, True]:
                with self.assertRaises(SystemExit):
                    message_transmit(a, b)

    def test_2_run_thread(self):

        # Setup
        Tx.unittesting = True
        create_test_keys(["alice"])
        create_contact_db(["alice"])

        # Test
        self.assertIsNone(message_transmit("plaintextmessage",
                                           "alice@jabber.org"))
        # Teardown
        shutil.rmtree("keys")
        os.remove(".tx_contacts")
        os.remove("unitt_txm_out")
        Tx.unittesting = False


class TestLongMsgTransmit(unittest.TestCase):

    def test_1_input_parameters(self):
        for a in [1, 1.0, True]:
            for b in [1, 1.0, True]:
                with self.assertRaises(SystemExit):
                    long_msg_transmit(a, b)

    def test_2_function(self):
        """
        Send only one packet as it needs to be read from file.
        Pre-processing of long messages is tested separately.
        """

        # Setup
        Tx.unittesting = True
        create_test_keys(["alice"])
        create_contact_db(["alice"])

        # Test
        long_msg_transmit("m%s" % (150 * 'G'), "alice@jabber.org")
        packetdata = open("unitt_txm_out").readline()
        hd, sw, ver, p_type, ct, k_id, accoun, chksum = packetdata.split('|')
        calc = ut_sha2_256(packetdata[:-10])[:Tx.checksum_len]

        self.assertEqual(len(packetdata), 434)
        self.assertEqual(hd, "TFC")
        self.assertEqual(sw, 'N')
        self.assertEqual(ver, str(Tx.int_version))
        self.assertEqual(p_type, 'M')
        self.assertEqual(k_id, '1')
        self.assertEqual(accoun, "alice@jabber.org")
        self.assertEqual(chksum, calc + '\n')

        # Teardown
        shutil.rmtree("keys")
        os.remove(".tx_contacts")
        os.remove("unitt_txm_out")
        Tx.unittesting = False


class TestTransmitExit(unittest.TestCase):

    def test_1_function(self):

        # Setup
        Tx.unittesting = True

        # Test function raises SystemExit
        with self.assertRaises(SystemExit):
            transmit_exit()
        Tx.unittesting = False

        # Test function output packet
        packetdata = open("unitt_txm_out").readline()
        hd, sw, ver, p_type, pt, chksum = packetdata.split('|')
        calc = ut_sha2_256(packetdata[:-10])[:Tx.checksum_len]

        self.assertEqual(hd, "TFC")
        self.assertEqual(sw, 'N')
        self.assertEqual(ver, str(Tx.int_version))
        self.assertEqual(p_type, 'U')
        self.assertEqual(pt, "EXIT")
        self.assertEqual(chksum, calc + '\n')

        # Teardown
        os.remove("unitt_txm_out")
        Tx.unittesting = False


class TestRecipientChooser(unittest.TestCase):

    def test_1_input_parameter(self):
        for a in [1, 1.0, True]:
            with self.assertRaises(SystemExit):
                recipient_chooser(a)

    def test_2_empty_group(self):

        # Setup
        Tx.unittesting = True
        Tx.group = "test_group"
        create_contact_db(["alice", "bob"])
        create_test_keys(["alice", "bob"])
        create_group_db("test_group", [])

        # Test
        self.assertIsNone(recipient_chooser("Testmessage"))
        self.assertFalse(os.path.isfile("unitt_txm_out"))

        # Teardown
        Tx.unittesting = False
        os.remove(".tx_contacts")
        shutil.rmtree("groups")
        shutil.rmtree("keys")


class TestLoadFileData(unittest.TestCase):

    def test_1_input_parameter(self):
        for a in [1, 1.0, True]:
            with self.assertRaises(SystemExit):
                load_file_data(a)

    def test_2_missing_filename_aborts(self):

        # Setup
        Tx.confirm_file = False

        # Test
        self.assertEqual(load_file_data("/file "), "ABORT")

        # Teardown
        Tx.confirm_file = True

    def test_3_empty_file(self):

        # Setup
        Tx.confirm_file = False
        open("doc.txt", "w+").close()

        # Test
        self.assertEqual(load_file_data("/file doc.txt"), "ABORT")

        # Teardown
        os.remove("doc.txt")
        Tx.confirm_file = True

    def test_4_test_file_loading(self):

        # Setup
        original_yes = Tx.yes
        Tx.yes = lambda x: True
        open("doc.txt", "w+").write("%s" % (20 * "data"))

        # Test
        filedata = load_file_data("/file doc.txt")
        split_data = filedata.split('|')

        self.assertEqual(split_data[0], "doc.txt")
        self.assertEqual(split_data[1], "80.0B")
        self.assertEqual(split_data[2], '1')

        self.assertEqual(split_data[4], "ZGF0YWRhdGFkYXRhZGF0YWRhdGFkYXRhZGF0Y"
                                        "WRhdGFkYXRhZGF0YWRhdGFkYXRhZGF0YWRhdG"
                                        "Fk\nYXRhZGF0YWRhdGFkYXRhZGF0YWRhdGE="
                                        "\n")

        self.assertFalse(os.path.isfile(".tfc_tmp_file"))

        # Teardown
        Tx.yes = original_yes
        os.remove("doc.txt")


class TestTransmit(unittest.TestCase):

    def test_1_input_parameter(self):
        for a in [1, 1.0, True]:
            with self.assertRaises(SystemExit):
                transmit(a)

    def test_2_checksum(self):

        # Setup
        Tx.unittesting = True

        # Test
        transmit("plaintext")
        packetdata = open("unitt_txm_out").readline()
        content, checksum = packetdata.split('|')
        self.assertEqual(ut_sha2_256(content)[:Tx.checksum_len] + '\n',
                         checksum)

        # Teardown
        os.remove("unitt_txm_out")
        Tx.unittesting = False


###############################################################################
#                              GROUP MANAGEMENT                               #
###############################################################################

class TestGetGroupMembers(unittest.TestCase):

    def test_1_input_parameter(self):
        for a in [1, 1.0, True]:
            with self.assertRaises(SystemExit):
                get_group_members(a)

    def test_2_no_members(self):

        # Setup
        ut_ensure_dir("groups/")
        open("groups/g.testgroup.tfc", "w+").close()

        # Test
        self.assertEqual(get_group_members("testgroup"), [])

        # Teardown
        shutil.rmtree("groups")

    def test_3_load_members(self):

        # Setup
        create_group_db("testgroup", ["alice", "bob", "charlie"])

        # Test
        self.assertEqual(get_group_members("testgroup"),
                         ["alice@jabber.org",
                          "bob@jabber.org",
                          "charlie@jabber.org"])
        # Teardown
        shutil.rmtree("groups")


class TestGetListOfGroups(unittest.TestCase):

    def test_1_no_groups_folder(self):
        self.assertEqual(get_list_of_groups(), [])

    def test2_get_list(self):

        # Setup
        create_group_db("group1", ["alice", "bob", "charlie"])
        create_group_db("group2", ["alice", "bob", "charlie"])
        create_group_db("group3", ["alice", "bob", "charlie"])

        # Test
        self.assertEqual(get_list_of_groups(), ["group1", "group2", "group3"])

        # Teardown
        shutil.rmtree("groups")


class TestGroupCreate(unittest.TestCase):

    def test_01_input_parameters(self):
        for a in [1, 1.0, True]:
            with self.assertRaises(SystemExit):
                group_create(a)

    def test_02_missing_group_name(self):
        with self.assertRaises(GroupError):
            group_create("/group create ")

    def test_03_overwrite_group_no(self):

        # Setup
        raw_input_original = __builtins__.raw_input
        __builtins__.raw_input = lambda x: "no"
        create_group_db("test", ["bob@jabber.org"])

        # Test
        self.assertIsNone(group_create("/group create test alice@jabber.org"))

        # Teardown
        __builtins__.raw_input = raw_input_original
        shutil.rmtree("groups")

    def test_04_overwrite_group_yes(self):

        # Setup
        raw_input_original = __builtins__.raw_input
        __builtins__.raw_input = lambda x: "yes"
        create_test_keys(["alice", "bob"])
        create_contact_db(["alice", "bob"])
        create_group_db("test", ["bob@jabber.org"])

        # Test
        self.assertIsNone(group_create("/group create test alice@jabber.org"))
        groupfiledata = open("groups/g.test.tfc").read().splitlines()
        self.assertEqual(groupfiledata, ["alice@jabber.org"])

        # Teardown
        __builtins__.raw_input = raw_input_original
        shutil.rmtree("groups")
        shutil.rmtree("keys")
        os.remove(".tx_contacts")

    def test_05_group_name_is_command(self):

        for g_name in ["create", "add", "rm"]:
            with self.assertRaises(GroupError):
                group_create("/group create %s" % g_name)

    def test_06_group_name_is_empty(self):

        with self.assertRaises(GroupError):
            group_create("/group create ")

    def test_07_group_name_is_nick(self):

        # Setup
        create_contact_db(["alice"])
        create_test_keys(["alice"])

        # Test
        with self.assertRaises(GroupError):
            group_create("/group create alice")

        # Teardown
        shutil.rmtree("keys")
        os.remove(".tx_contacts")

    def test_08_group_name_is_account(self):

        # Setup
        create_contact_db(["alice"])
        create_test_keys(["alice"])

        # Test
        with self.assertRaises(GroupError):
            group_create("/group create alice@jabber.org")

        # Teardown
        shutil.rmtree("keys")
        os.remove(".tx_contacts")

    def test_09_group_name_is_keyfile(self):

        # Setup
        create_contact_db(["alice"])
        create_test_keys(["alice"])

        # Test
        with self.assertRaises(GroupError):
            group_create("/group create tx.alice@jabber.org.e")

        # Teardown
        shutil.rmtree("keys")
        os.remove(".tx_contacts")

    def test_10_successful_group_creation_no_members(self):

        # Setup
        create_contact_db(["alice"])
        create_test_keys(["alice"])

        # Test
        group_create("/group create testgroup")
        group_content = open("groups/g.testgroup.tfc").readlines()
        self.assertEqual(group_content, [])

        # Setup
        shutil.rmtree("groups")
        shutil.rmtree("keys")
        os.remove(".tx_contacts")

    def test_11_successful_group_creation_add_contact(self):

        # Setup
        create_contact_db(["alice"])
        create_test_keys(["alice"])

        # Test
        group_create("/group create testgroup alice@jabber.org")
        group_content = open("groups/g.testgroup.tfc").read().splitlines()
        self.assertEqual(group_content, ["alice@jabber.org"])

        # Teardown
        shutil.rmtree("groups")
        shutil.rmtree("keys")
        os.remove(".tx_contacts")

    def test_12_add_contact_and_nonexistent(self):

        # Setup
        create_contact_db(["alice"])
        create_test_keys(["alice"])

        # Test
        group_create("/group create testgroup alice@jabber.org bob@jabber.org")
        group_content = open("groups/g.testgroup.tfc").read().splitlines()
        self.assertEqual(group_content, ["alice@jabber.org"])

        # Teardown
        shutil.rmtree("groups")
        shutil.rmtree("keys")
        os.remove(".tx_contacts")

    def test_13_add_contact_and_local(self):

        # Setup
        create_contact_db(["alice"])
        create_test_keys(["alice"])

        # Test
        group_create("/group create testgroup alice@jabber.org local")
        group_content = open("groups/g.testgroup.tfc").read().splitlines()
        self.assertEqual(group_content, ["alice@jabber.org"])

        # Teardown
        shutil.rmtree("groups")
        shutil.rmtree("keys")
        os.remove(".tx_contacts")


class TestGroupAddMember(unittest.TestCase):

    def test_1_input_parameter(self):
        for a in [1, 1.0, True]:
            with self.assertRaises(SystemExit):
                group_add_member(a)

    def test_2_missing_group_name(self):
        for s in ['', ' ']:
            with self.assertRaises(GroupError):
                group_add_member("/group add%s" % s)

    def test_3_missing_members(self):
        for s in ['', ' ']:
            with self.assertRaises(GroupError):
                group_add_member("/group add testgroup%s" % s)

    def test_4_group_add_existing_contact(self):

        # Setup
        create_test_keys(["alice", "bob", "charlie"])
        create_contact_db(["alice", "bob", "charlie"])
        create_group_db("testgroup", ["alice", "bob"])

        # Test
        group_add_member("/group add testgroup charlie@jabber.org")
        grouplist = open("groups/g.testgroup.tfc").read().splitlines()
        self.assertEqual(grouplist, ["alice@jabber.org", "bob@jabber.org",
                                     "charlie@jabber.org"])
        # Teardown
        shutil.rmtree("keys")
        shutil.rmtree("groups")
        os.remove(".tx_contacts")

    def test_5_group_add_existing_and_unknown_contact(self):

        # Setup
        create_test_keys(["alice", "bob", "charlie"])
        create_contact_db(["alice", "bob", "charlie"])
        create_group_db("testgroup", ["alice", "bob"])

        # Test
        group_add_member("/group add testgroup "
                         "charlie@jabber.org david@jabber.org")

        grouplist = open("groups/g.testgroup.tfc").read().splitlines()
        self.assertEqual(grouplist, ["alice@jabber.org", "bob@jabber.org",
                                     "charlie@jabber.org"])

        # Teardown
        shutil.rmtree("keys")
        shutil.rmtree("groups")
        os.remove(".tx_contacts")

    def test_6_group_add_existing_unknown_and_group_member(self):

        # Setup
        create_test_keys(["alice", "bob", "charlie"])
        create_contact_db(["alice", "bob", "charlie"])
        create_group_db("testgroup", ["alice", "bob"])

        # Test
        group_add_member("/group add testgroup "
                         "charlie@jabber.org david@jabber.org bob@jabber.org")
        grouplist = open("groups/g.testgroup.tfc").read().splitlines()
        self.assertEqual(grouplist, ["alice@jabber.org", "bob@jabber.org",
                                     "charlie@jabber.org"])

        # Teardown
        shutil.rmtree("keys")
        shutil.rmtree("groups")
        os.remove(".tx_contacts")

    def test_7_group_add_existing_and_local(self):

        # Setup
        create_test_keys(["alice", "bob", "charlie"])
        create_contact_db(["alice", "bob", "charlie"])
        create_group_db("testgroup", ["alice", "bob"])

        # Test
        group_add_member("/group add testgroup "
                         "charlie@jabber.org local")
        grouplist = open("groups/g.testgroup.tfc").read().splitlines()
        self.assertEqual(grouplist, ["alice@jabber.org", "bob@jabber.org",
                                     "charlie@jabber.org"])
        # Teardown
        shutil.rmtree("keys")
        shutil.rmtree("groups")
        os.remove(".tx_contacts")

    def test_8_no_existing_group_no_creation(self):

        # Setup
        create_test_keys(["alice", "bob", "charlie"])
        create_contact_db(["alice", "bob", "charlie"])
        raw_input_original = __builtins__.raw_input
        __builtins__.raw_input = lambda x: "no"

        # Test
        self.assertIsNone(group_add_member(
                "/group add testgroup bob@jabber.org"))

        # Teardown
        __builtins__.raw_input = raw_input_original
        shutil.rmtree("keys")
        os.remove(".tx_contacts")

    def test_9_no_existing_group_create(self):

        # Setup
        create_test_keys(["alice", "bob", "charlie"])
        create_contact_db(["alice", "bob", "charlie"])
        raw_input_original = __builtins__.raw_input
        __builtins__.raw_input = lambda x: "yes"

        # Test
        group_add_member("/group add testgroup bob@jabber.org")
        grouplist = open("groups/g.testgroup.tfc").read().splitlines()
        self.assertEqual(grouplist, ["bob@jabber.org"])

        # Teardown
        __builtins__.raw_input = raw_input_original
        shutil.rmtree("keys")
        shutil.rmtree("groups")
        os.remove(".tx_contacts")


class TestGroupRmMember(unittest.TestCase):

    def test_1_input_parameter(self):
        for a in [1, 1.0, True]:
            with self.assertRaises(SystemExit):
                group_rm_member(a)

    def test_2_missing_group_name(self):
        for s in ['', ' ']:
            with self.assertRaises(GroupError):
                group_rm_member("/group rm%s" % s)

    def test_3_remove_group_member(self):

        # Setup
        create_test_keys(["alice", "bob"])
        create_contact_db(["alice", "bob"])
        create_group_db("testgroup", ["alice", "bob"])

        # Test
        group_rm_member("/group rm testgroup alice@jabber.org")
        grouplist = open("groups/g.testgroup.tfc").readlines()
        self.assertEqual(grouplist, ["bob@jabber.org\n"])

        # Teardown
        shutil.rmtree("keys")
        shutil.rmtree("groups")
        os.remove(".tx_contacts")

    def test_4_remove_contact_not_in_group(self):

        # Setup
        create_test_keys(["alice", "bob"])
        create_contact_db(["alice", "bob"])
        create_group_db("testgroup", ["alice"])

        # Test
        group_rm_member("/group rm testgroup bob@jabber.org")
        grouplist = open("groups/g.testgroup.tfc").readlines()
        self.assertEqual(grouplist, ["alice@jabber.org\n"])

        # Teardown
        shutil.rmtree("keys")
        shutil.rmtree("groups")
        os.remove(".tx_contacts")

    def test_5_remove_unknown_contact(self):

        # Setup
        create_test_keys(["alice", "bob"])
        create_contact_db(["alice", "bob"])
        create_group_db("testgroup", ["alice", "bob"])

        # Test
        group_rm_member("/group rm testgroup charlie@jabber.org")
        grouplist = open("groups/g.testgroup.tfc").readlines()
        self.assertEqual(grouplist, ["alice@jabber.org\n", "bob@jabber.org\n"])

        # Teardown
        shutil.rmtree("keys")
        shutil.rmtree("groups")
        os.remove(".tx_contacts")

    def test_6_remove_group_no(self):

        # Setup
        create_test_keys(["alice", "bob"])
        create_contact_db(["alice", "bob"])
        create_group_db("testgroup", ["alice", "bob"])
        raw_input_original = __builtins__.raw_input
        __builtins__.raw_input = lambda x: "no"

        group_rm_member("/group rm testgroup")
        self.assertTrue(os.path.isfile("groups/g.testgroup.tfc"))

        # Teardown
        shutil.rmtree("keys")
        shutil.rmtree("groups")
        os.remove(".tx_contacts")
        __builtins__.raw_input = raw_input_original

    def test_7_remove_group_yes(self):

        # Setup
        create_test_keys(["alice", "bob"])
        create_contact_db(["alice", "bob"])
        create_group_db("testgroup", ["alice", "bob"])
        raw_input_original = __builtins__.raw_input
        __builtins__.raw_input = lambda x: "yes"

        group_rm_member("/group rm testgroup")
        self.assertFalse(os.path.isfile("groups/g.testgroup.tfc"))

        # Teardown
        shutil.rmtree("keys")
        shutil.rmtree("groups")
        os.remove(".tx_contacts")
        __builtins__.raw_input = raw_input_original


class TestPrintGroupList(unittest.TestCase):

    def test_1_function(self):

        # Setup
        Tx.group = ''
        create_group_db("testgroup", ["alice", "bob"])

        # Test
        self.assertIsNone(print_group_list())

        # Teardown
        shutil.rmtree("groups")


class TestPrintGroupMembers(unittest.TestCase):

    def test_1_input_parameters(self):
        for a in [1, 1.0, True]:
            for b in ["string", 1, 1.0]:
                with self.assertRaises(SystemExit):
                    print_group_members(a, b)

    def test_2_no_group(self):
        Tx.group = ''
        self.assertIsNone(print_group_members(''))

    def test_3_group_list_printing(self):

        # Setup
        create_test_keys(["alice", "bob"])
        create_contact_db(["alice", "bob"])
        create_group_db("testgroup", ["alice", "bob"])

        # Test
        self.assertIsNone(print_group_members("/group testgroup"))

        # Teardown
        shutil.rmtree("keys")
        shutil.rmtree("groups")
        os.remove(".tx_contacts")


class TestSortGroup(unittest.TestCase):

    def test_1_input_parameter(self):
        for a in [1, 1.0, True]:
            with self.assertRaises(SystemExit):
                sort_group(a)

    def test_2_no_group(self):

        # Setup
        ut_ensure_dir("groups/")

        # Test
        with self.assertRaises(SystemExit):
            sort_group("testgroup")

        # Teardown
        shutil.rmtree("groups")

    def test_3_one_contact(self):

        # Setup
        create_group_db("testgroup", ["alice"])

        # Test
        sort_group("testgroup")
        groupdata = open("groups/g.testgroup.tfc").read().splitlines()
        self.assertEqual(groupdata, ["alice@jabber.org"])

        # Teardown
        shutil.rmtree("groups")

    def test_4_three_contacts(self):

        # Setup
        create_group_db("testgroup", ["bob", "charlie", "alice"])

        # Test
        sort_group("testgroup")
        groupdata = open("groups/g.testgroup.tfc").read().splitlines()
        self.assertEqual(groupdata, ["alice@jabber.org", "bob@jabber.org",
                                     "charlie@jabber.org"])

        # Teardown
        shutil.rmtree("groups")


###############################################################################
#                                    MISC                                     #
###############################################################################

class TestEnsureDir(unittest.TestCase):

    def test_1_input_parameter(self):
        for a in [1, 1.0, True]:
            with self.assertRaises(SystemExit):
                ensure_dir(a)

    def test_2_empty_dir_parameter(self):
        with self.assertRaises(SystemExit):
            ensure_dir('')

    def test_3_function(self):
        ensure_dir("directory/")
        self.assertTrue(os.path.exists(os.path.dirname("directory/")))

        # Teardown
        shutil.rmtree("directory")


class TestPrintAbout(unittest.TestCase):

    def test_return_type(self):
        self.assertIsNone(print_about())


class TestPrintHelp(unittest.TestCase):

    def test_1_narrow(self):
        # Setup
        original_get_tty_wh = Tx.get_tty_wh
        Tx.get_tty_wh = lambda wo: 80

        # Test
        self.assertIsNone(print_help())

        # Teardown
        Tx.get_tty_wh = original_get_tty_wh

    def test_2_wide(self):

        # Setup
        original_get_tty_wh = Tx.get_tty_wh
        Tx.get_tty_wh = lambda wo: 81

        # Test
        self.assertIsNone(print_help())

        # Teardown
        Tx.get_tty_wh = original_get_tty_wh


class TestTabComplete(unittest.TestCase):
    """
    This function doesn't have any tests yet.
    """


class TestGetTabCompleteList(unittest.TestCase):

    def test_1_get_defaults(self):

        # Test
        tab_complete_list = get_tab_complete_list()
        lst = ["about", "add ", "clear", "create ", "exit", "file ", "group ",
               "help", "logging ", "msg ", "nick ", "quit", "rm ", "select ",
               "store "]
        self.assertTrue(set(lst).issubset(tab_complete_list))

        # Teardown
        shutil.rmtree("keys")
        shutil.rmtree("groups")

    def test_2_get_defaults_and_accounts(self):

        # Setup
        create_test_keys(["alice", "bob"])

        # Test
        tab_complete_list = get_tab_complete_list()
        lst = ["about", "add ", "clear", "create ", "exit", "file ", "group ",
               "help", "logging ", "msg ", "nick ", "quit", "rm ", "select ",
               "store ", "alice@jabber.org ", "bob@jabber.org "]
        self.assertTrue(set(lst).issubset(tab_complete_list))

        # Teardown
        shutil.rmtree("keys")
        shutil.rmtree("groups")

    def test_3_get_defaults_accounts_and_groups(self):

        # Setup
        create_group_db("testgroup", ["alice", "bob"])
        create_test_keys(["alice", "bob"])

        # Test
        tab_complete_list = set(get_tab_complete_list())
        lst = ["about", "add ", "clear", "create ", "exit", "file ", "group ",
               "help", "logging ", "msg ", "nick ", "quit", "rm ", "select ",
               "store ", "alice@jabber.org ", "bob@jabber.org ", "testgroup "]
        self.assertTrue(set(lst).issubset(tab_complete_list))

        # Teardown
        shutil.rmtree("keys")
        shutil.rmtree("groups")


class TestReadableSize(unittest.TestCase):

    def test_1_input_parameter(self):
        for a in ["string", 1.0]:
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


class TestYes(unittest.TestCase):

    def test_1_input_parameter(self):
        for a in [1, 1.0, True]:
            for b in ["string", 1.0, True]:
                with self.assertRaises(SystemExit):
                    yes(a, b)

    def test_2_yes(self):

        # Setup
        origin_raw_input = __builtins__.raw_input

        # Test
        for s in ["yes", "YES", 'y', 'Y']:
            __builtins__.raw_input = lambda x: s
            self.assertTrue(yes("test prompt"))

        # Teardown
        __builtins__.raw_input = origin_raw_input

    def test_3_no(self):

        # Setup
        origin_raw_input = __builtins__.raw_input

        # Test
        for s in ["no", "NO", 'n', 'N']:
            __builtins__.raw_input = lambda x: s
            self.assertFalse(yes("test prompt"))

        # Teardown
        __builtins__.raw_input = origin_raw_input


class TestPhase(unittest.TestCase):

    def test_1_input_parameters(self):
        for a in [1, 1.0, True]:
            for b in ["string", 1.0, True]:
                with self.assertRaises(SystemExit):
                    phase(a, b)

    def test_2_output_type(self):
        self.assertIsNone(phase("test", 10))


class TestGetTTyWH(unittest.TestCase):

    def test_output_types(self):
        w, h = get_tty_wh()

        self.assertTrue(isinstance(w, int))
        self.assertTrue(isinstance(h, int))


class TestPrintBanner(unittest.TestCase):

    def test_output_type(self):
        self.assertIsNone(print_banner())


class TestProcessArguments(unittest.TestCase):
    """
    This function doesn't have any tests yet.
    """


class TestSearchInterfaces(unittest.TestCase):
    """
    This function doesn't have any tests yet.
    """


###############################################################################
#                               TRICKLE CONNECTION                            #
###############################################################################

class TestHeads(unittest.TestCase):

    def test_1_output_type(self):
        self.assertTrue(isinstance(heads(), bool))


class TestGetMS(unittest.TestCase):

    def test_1_output_type(self):
        self.assertTrue(isinstance(get_ms(), (int, long)))

    def test_2_output_len(self):
        self.assertEqual(len(str(get_ms())), 13)


class TestTrickleDelay(unittest.TestCase):

    def test_1_constant_time_sleep(self):

        # Setup
        Tx.trickle_r_delay = 0.0

        # Test
        time_before_test = int(round(time.time() * 1000))

        trickle_delay(time_before_test)

        time_after_test = int(round(time.time() * 1000))
        error = time_after_test - time_before_test

        self.assertTrue(2000 <= error <= 2005)  # milliseconds.

        # Teardown
        Tx.trickle_r_delay = 1.0


class TestSenderProcess(unittest.TestCase):
    """
    This function doesn't have any tests yet.
    """


class TestInputProcess(unittest.TestCase):
    """
    This function doesn't have any tests yet.
    """


###############################################################################
#                             STANDARD CONNECTION                             #
###############################################################################

class TestGetNormalInput(unittest.TestCase):
    """
    This function doesn't have any tests yet.
    """


class TestMainLoop(unittest.TestCase):
    """
    This function doesn't have any tests yet.
    """

###############################################################################
#                                     MAIN                                    #
###############################################################################

if __name__ == "__main__":

    os.chdir(sys.path[0])

    try:
        shutil.rmtree("keys")
        shutil.rmtree("groups")
        shutil.rmtree("logs")
        shutil.rmtree("files")
        os.remove(".tx_contacts")
        os.remove(".rx_contacts")
        os.remove("unitt_txm_out")
    except OSError:
        pass

    unittest.main(exit=False)
