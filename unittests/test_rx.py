#!/usr/bin/env python
# -*- coding: utf-8 -*-

# TFC-NaCl 0.16.05 || test_rx.py

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

import Rx
from Rx import *
import base64
import binascii
import os.path
import os
import shutil
import sys
import unittest

# Import crypto libraries
import hashlib
import simplesha3


###############################################################################
#                               UNITTEST HELPERS                              #
###############################################################################

def create_me_keys(nick_list, key=(64 * 'a')):
    """
    Create local decryption test keyfiles.

    :param nick_list: List of nicks based on what accounts are created.
    :param key:       Keys to write into keyfiles.
    :return:          None
    """

    ut_ensure_dir("keys/")

    for nick in nick_list:
        if nick == "local":
            open("keys/me.local.e", "w+").write(key)
        else:
            open("keys/me.%s@jabber.org.e" % nick, "w+").write(key)


def create_rx_keys(nick_list, key=(64 * 'a')):
    """
    Create decryption test keyfiles.

    :param nick_list: List of nicks based on what accounts are created.
    :param key:       Keys to write into keyfiles.
    :return:          None
    """

    ut_ensure_dir("keys/")

    for nick in nick_list:
        if nick == "local":
            pass
        else:
            open("keys/rx.%s@jabber.org.e" % nick, "w+").write(key)


def create_contact_db(nick_list, keyid='1'):
    with open(".rx_contacts", "w+") as f:
        for nick in nick_list:
            if nick == "local":
                f.write("me.%s,%s,%s\n" % (nick, nick, keyid))
            else:
                f.write("me.%s@jabber.org,%s,%s\n" % (nick, nick, keyid))
                f.write("rx.%s@jabber.org,%s,%s\n" % (nick, nick, keyid))


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

Rx.unittesting = True


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

    def test_3_pbkdf2_hmac_sha256_test_vectors(self):
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


class TestAuthAndDecrypt(unittest.TestCase):

    def test_1_input_parameters(self):
        for a in [1, 1.0, True]:
            for b in [1, 1.0, True]:
                for c in ["string", 1.0, True]:
                    with self.assertRaises(SystemExit):
                        auth_and_decrypt(a, b, c)

    def test_2_auth_and_decrypt(self):

        # Setup
        create_me_keys(["bob"])
        create_rx_keys(["bob"])
        create_contact_db(["bob"])

        # Test
        ct_and_tag = base64.b64decode(
            "UWVmcPLGyf0BH3OZG6VUI06G8N6fYMD4z0LX1ER"
            "JBiMx9Tu1Wcca+C+L8EMpEaPOfrLA0vcJF83CQp"
            "64K9xo9DHBNjDEVM/NEnrplBX3rIsFPsZQBlLEF"
            "sM6OpUne2w/p8ZRB8ZjPFDGnHKegF4w/o/9GJnl"
            "xt9gsBCNCZRxJ6MTEQgg1H7s0izCnczH2eE670e"
            "PQen6OQtD1Zpchqm9hALi9Vd3uKyQAP7WTpvvBS"
            "VkiSVyBkCopwIz+SkrlEME7AVMUZOLcHxXIlXUU"
            "HIxLX422jaX4dfHv6EcNjBZyNr1SxnhOT03tl6T"
            "bSowsX6jEAcbx5BVdB1gA/4bnmBAxZ0dvNAJdAL"
            "oczdbVkKoiV3MPuh+3NF4O5Nbq6dc/kzyyVW7Wm"
            "Pd")

        auth_bool, pt = auth_and_decrypt("rx.bob@jabber.org", ct_and_tag, 1)

        pt = rm_padding(pt)

        self.assertTrue(auth_bool)
        self.assertEqual(pt, "splaintext")

        ct_and_tag = base64.b64decode(
            "VWVmcPLGyf0BH3OZG6VUI06G8N6fYMD4z0LX1ERJBiMx9T"
            "u1Wcca+C+L8EMpEaPOfrLA0vcJF83CQp64K9xo9DHBNjDE"
            "VM/NEnrplBX3rIsFPsZQBlLEFsM6OpUne2w/p8ZRB8ZjPF"
            "DGnHKegF4w/o/9GJnlxt9gsBCNCZRxJ6MTEQgg1H7s0izC"
            "nczH2eE670ePQen6OQtD1Zpchqm9hALi9Vd3uKyQAP7WTp"
            "vvBSVkiSVyBkCopwIz+SkrlEME7AVMUZOLcHxXIlXUUHIx"
            "LX422jaX4dfHv6EcNjBZyNr1SxnhOT03tl6TbSowsX6jEA"
            "cbx5BVdB1gA/4bnmBAxZ0dvNAJdALoczdbVkKoiV3MPuh+"
            "3NF4O5Nbq6dc/kzyyVW7WmPd")

        auth_bool, pt = auth_and_decrypt("rx.bob@jabber.org", ct_and_tag, 1)

        self.assertFalse(auth_bool)
        self.assertEqual(pt, "MAC_FAIL")

        # Teardown
        shutil.rmtree("keys")
        os.remove(".rx_contacts")

    def test_3_official_test_vectors(self):

        # Test
        iv_hex = "69696ee955b62b73cd62bda875fc73d68219e0036b7a0b37"
        iv_bin = binascii.unhexlify(iv_hex)

        key_hex = ("1b27556473e985d462cd51197a9a46c7"
                   "6009549eac6474f206c4ee0844f68389")

        create_me_keys(['bob'], key_hex)
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

        ct_tv_bin = binascii.unhexlify(ct_tv_hex)

        auth_bool, pt = auth_and_decrypt("me.bob@jabber.org",
                                         iv_bin + ct_tv_bin, 1)

        self.assertTrue(auth_bool)
        self.assertEqual(binascii.hexlify(pt), pt_tv_hex)

        # Teardown
        shutil.rmtree("keys")
        os.remove(".rx_contacts")


###############################################################################
#                                KEY MANAGEMENT                               #
###############################################################################

class TestGetKeyfileList(unittest.TestCase):

    def test_1_keyfile_loading(self):

        # Setup
        ut_ensure_dir("keys/")
        open("keys/me.1.e", "w+").close()
        open("keys/me.2.e", "w+").close()
        open("keys/rx.1.e", "w+").close()
        open("keys/rx.2.e", "w+").close()
        open("keys/tx.1.e", "w+").close()
        open("keys/tx.local.e", "w+").close()
        open("keys/me.local.e", "w+").close()

        # Test
        self.assertEqual(get_keyfile_list(),
                         ["me.1.e", "me.2.e", "me.local.e",
                          "rx.1.e", "rx.2.e"])

        # Teardown
        shutil.rmtree("keys")


class TestGetKey(unittest.TestCase):

    def test_1_input_parameter(self):
        for a in [1, 1.0, True]:
            with self.assertRaises(SystemExit):
                get_key(a)

    def test_2_no_key(self):
        with self.assertRaises(SystemExit):
            get_key("bob@jabber.org")

    def test_3_valid_key(self):

        # Setup
        create_me_keys(["bob"])

        # Test
        self.assertEqual(get_key("me.bob@jabber.org"), "%s" % (64 * 'a'))

        # Teardown
        shutil.rmtree("keys")

    def test_4_too_short_key(self):

        # Setup
        create_me_keys(["bob"], (63 * 'a'))

        # Test
        with self.assertRaises(SystemExit):
            get_key("me.bob@jabber.org")

        # Teardown
        shutil.rmtree("keys")

    def test_5_too_long_key(self):

        # Setup
        create_me_keys(["bob"], (65 * 'a'))

        # Test
        with self.assertRaises(SystemExit):
            get_key("me.bob@jabber.org")

        # Teardown
        shutil.rmtree("keys")

    def test_6_invalid_key_content(self):

        # Setup
        create_me_keys(["bob"], ("%sg" % (63 * 'a')))

        # Test
        with self.assertRaises(SystemExit):
            get_key("me.bob@jabber.org")

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
        self.assertIsNone(key_writer("me.bob@jabber.org", (64 * 'a')))
        key_from_file = open("keys/me.bob@jabber.org.e").readline()
        self.assertEqual(key_from_file, (64 * 'a'))

        # Teardown
        shutil.rmtree("keys")


class TestAddRxKeyfile(unittest.TestCase):

    def test_1_no_path(self):

        # Setup
        original_aofn = tkFileDialog.askopenfilename
        tkFileDialog.askopenfilename = lambda title: ''

        # Test
        self.assertIsNone(add_rx_keyfile())

        # Teardown
        tkFileDialog.askopenfilename = original_aofn

    def test_2_valid_path(self):

        # Setup
        ut_ensure_dir("test_dir/")
        ut_ensure_dir("keys/")
        test_set = []
        for c in range(8):
            test_set.append(128 * str(c))
        fname = "rx.bob@jabber.org.e - Give this file to alice@jabber.org"
        open("test_dir/%s" % fname, 'w+').write('\n'.join(test_set))

        Rx.file_saving = False
        Rx.log_messages = True

        Rx.l_msg_coming["rx.bob@jabber.org"] = True
        Rx.msg_received["rx.bob@jabber.org"] = True
        Rx.m_dictionary["rx.bob@jabber.org"] = 'a'

        Rx.l_file_onway["rx.bob@jabber.org"] = True
        Rx.filereceived["rx.bob@jabber.org"] = True
        Rx.f_dictionary["rx.bob@jabber.org"] = 'a'
        Rx.acco_store_f["me.bob@jabber.org"] = False
        Rx.acco_store_f["me.bob@jabber.org"] = True
        Rx.acco_store_l["rx.bob@jabber.org"] = False
        Rx.acco_store_l["me.bob@jabber.org"] = False

        original_aofn = tkFileDialog.askopenfilename
        tkFileDialog.askopenfilename = lambda title: 'test_dir/%s' % fname

        # Test
        self.assertIsNone(add_rx_keyfile())
        self.assertFalse(os.path.isfile("test_dir/%s" % fname))
        self.assertTrue(os.path.isfile("keys/rx.bob@jabber.org.e"))
        written = open("keys/rx.bob@jabber.org.e").read().splitlines()
        self.assertEqual(written, test_set)

        self.assertFalse(Rx.l_msg_coming["rx.bob@jabber.org"])
        self.assertFalse(Rx.msg_received["rx.bob@jabber.org"])
        self.assertEqual(Rx.m_dictionary["rx.bob@jabber.org"], '')

        self.assertFalse(Rx.l_file_onway["rx.bob@jabber.org"])
        self.assertFalse(Rx.filereceived["rx.bob@jabber.org"])
        self.assertEqual(Rx.f_dictionary["rx.bob@jabber.org"], '')

        self.assertTrue(Rx.acco_store_f["me.bob@jabber.org"])
        self.assertFalse(Rx.acco_store_f["rx.bob@jabber.org"])
        self.assertTrue(Rx.acco_store_l["me.bob@jabber.org"])
        self.assertTrue(Rx.acco_store_l["rx.bob@jabber.org"])

        # Teardown
        tkFileDialog.askopenfilename = original_aofn
        shutil.rmtree("test_dir")
        shutil.rmtree("keys")


class TestPSKCommand(unittest.TestCase):

    def test_1_input_parameter(self):
        for a in [1, 1.0, True]:
            with self.assertRaises(SystemExit):
                psk_command(a)

    def test_2_invalid_packets(self):
        self.assertIsNone(psk_command("PSK|bob@jabber.org|bob|%s"
                                      % (63 * 'a')))

        self.assertIsNone(psk_command("PSK|bob@jabber.org|%s" % (64 * 'a')))

    def test_3_function(self):

        # Setup
        Rx.log_messages = False
        Rx.file_saving = False

        # Test valid PSK packet creates keys
        self.assertIsNone(psk_command("PSK|bob@jabber.org|bob|%s"
                                      % (64 * 'a')))

        self.assertFalse(Rx.l_msg_coming["me.bob@jabber.org"])
        self.assertFalse(Rx.l_msg_coming["me.bob@jabber.org"])
        key = open("keys/me.bob@jabber.org.e").readline()
        self.assertEqual(key, (64 * 'a'))

        # Test valid PSK packet creates database
        c_db = open(".rx_contacts").read().splitlines()
        self.assertEqual(c_db, ["me.bob@jabber.org,bob,1"])

        # Test valid PSK packet creates dictionaries
        self.assertFalse(Rx.l_msg_coming["me.bob@jabber.org"])
        self.assertFalse(Rx.msg_received["me.bob@jabber.org"])
        self.assertEqual(Rx.m_dictionary["me.bob@jabber.org"], '')

        self.assertFalse(Rx.l_file_onway["me.bob@jabber.org"])
        self.assertFalse(Rx.filereceived["me.bob@jabber.org"])
        self.assertEqual(Rx.f_dictionary["me.bob@jabber.org"], '')

        self.assertTrue(Rx.acco_store_f["me.bob@jabber.org"])
        self.assertFalse(Rx.acco_store_l["me.bob@jabber.org"])

        # Teardown
        shutil.rmtree("keys")
        os.remove(".rx_contacts")


class TestRotateKey(unittest.TestCase):
    def test_1_input_parameters(self):
        for a in [1, 1.0, True]:
            for b in [1, 1.0, True]:
                with self.assertRaises(SystemExit):
                    rotate_key(a, b)

    def test_2_function(self):

        # Setup
        create_me_keys(["bob"])

        # Test
        rotate_key("me.bob@jabber.org", (64 * 'a'))
        new_key = open("keys/me.bob@jabber.org.e").readline()
        self.assertEqual(new_key, "93539718242c02c6698778c25a292a11"
                                  "4c42df327db8be31d5a0cf303573923e")

        # Teardown
        shutil.rmtree("keys")


class TestRemoveInstructions(unittest.TestCase):
    def test_1_function(self):

        # Setup
        ut_ensure_dir("keys/")
        open("keys/rx.alice@jabber.org.e - Give this file to bob@jabber.org",
             "w+").close()

        # Test
        remove_instructions()
        self.assertTrue(os.path.isfile("keys/rx.alice@jabber.org.e"))

        # Teardown
        shutil.rmtree("keys")


class TestDisplayPubKey(unittest.TestCase):
    def test_1_input_parameter(self):
        for a in [1, 1.0, True]:
            with self.assertRaises(SystemExit):
                display_pub_key(a)

    def test_2_invalid_packet(self):
        self.assertIsNone(display_pub_key("TFC|N|%s|P|"
                                          "7743b4ddf00d6e8eb8fbbe0603d90948"
                                          "c04663731795fae5eab5f1cba8ed1b36"
                                          "rx.alice@jabber.org"
                                          % Rx.int_version))

    def test_3_invalid_key(self):
        self.assertIsNone(display_pub_key("TFC|N|%s|P|"
                                          "Q743b4ddf00d6e8eb8fbbe0603d90948"
                                          "c04663731795fae5eab5f1cba8ed1b36"
                                          "|rx.alice@jabber.org"
                                          % Rx.int_version))

    def test_4_valid_packet_from_contact(self):
        self.assertIsNone(display_pub_key("TFC|N|%s|P|"
                                          "7743b4ddf00d6e8eb8fbbe0603d90948"
                                          "c04663731795fae5eab5f1cba8ed1b36"
                                          "|rx.alice@jabber.org"
                                          % Rx.int_version))

    def test_5_valid_packet_from_user(self):
        self.assertIsNone(display_pub_key("TFC|N|%s|P|"
                                          "7743b4ddf00d6e8eb8fbbe0603d90948"
                                          "c04663731795fae5eab5f1cba8ed1b36"
                                          "|me.alice@jabber.org"
                                          % Rx.int_version))


class TestECDHECommand(unittest.TestCase):
    def test_1_input_parameter(self):
        for a in [1, 1.0, True]:
            with self.assertRaises(SystemExit):
                ecdhe_command(a)

    def test_2_function(self):

        # Setup
        Rx.log_messages = False
        Rx.file_saving = False

        # Test key writing and dictionaries
        self.assertIsNone(ecdhe_command("A|bob@jabber.org|Bob|%s|%s"
                                        % ((64 * 'a'), (64 * 'b'))))
        key1 = open("keys/me.bob@jabber.org.e").readline()
        key2 = open("keys/rx.bob@jabber.org.e").readline()
        c_db = open(".rx_contacts").read().splitlines()

        self.assertEqual(key1, (64 * 'a'))
        self.assertEqual(key2, (64 * 'b'))

        self.assertEqual(c_db, ["me.bob@jabber.org,Bob,1",
                                "rx.bob@jabber.org,Bob,1"])

        self.assertFalse(Rx.l_msg_coming["me.bob@jabber.org"])
        self.assertFalse(Rx.l_msg_coming["rx.bob@jabber.org"])
        self.assertFalse(Rx.msg_received["me.bob@jabber.org"])
        self.assertFalse(Rx.msg_received["rx.bob@jabber.org"])
        self.assertEqual(Rx.m_dictionary["me.bob@jabber.org"], '')
        self.assertEqual(Rx.m_dictionary["rx.bob@jabber.org"], '')

        self.assertFalse(Rx.l_file_onway["me.bob@jabber.org"])
        self.assertFalse(Rx.l_file_onway["rx.bob@jabber.org"])
        self.assertFalse(Rx.filereceived["me.bob@jabber.org"])
        self.assertFalse(Rx.filereceived["rx.bob@jabber.org"])
        self.assertEqual(Rx.f_dictionary["me.bob@jabber.org"], '')
        self.assertEqual(Rx.f_dictionary["rx.bob@jabber.org"], '')

        self.assertFalse(Rx.acco_store_l["me.bob@jabber.org"])
        self.assertFalse(Rx.acco_store_l["rx.bob@jabber.org"])

        self.assertTrue(Rx.acco_store_f["me.bob@jabber.org"])
        self.assertFalse(Rx.acco_store_f["rx.bob@jabber.org"])

        # Teardown
        os.remove(".rx_contacts")
        shutil.rmtree("keys")


###############################################################################
#                               SECURITY RELATED                              #
###############################################################################

class TestPrintOpsecWarning(unittest.TestCase):

    def test_1_printing(self):
        self.assertIsNone(print_opsec_warning())


class TestPacketAnomaly(unittest.TestCase):

    def test_1_input_parameters(self):
        for a in [1, 1.0, True]:
            for b in [1, 1.0, True]:
                with self.assertRaises(SystemExit):
                    packet_anomaly(a, b)

    def test_2_invalid_MAC(self):

        # Test
        self.assertIsNone(packet_anomaly("MAC", "message"))
        warning = open("syslog.tfc").readline()
        splitlist = warning.split()
        timestampless = splitlist[2:]
        timestampless = ' '.join(timestampless)
        self.assertEqual(timestampless, "Automatic log entry: "
                                        "MAC of message failed.")
        # Teardown
        os.remove("syslog.tfc")

    def test_3_replayed_packet(self):

        # Test
        self.assertIsNone(packet_anomaly("replay", "message"))
        warning = open("syslog.tfc").readline()
        splitlist = warning.split()
        timestampless = splitlist[2:]
        timestampless = ' '.join(timestampless)
        self.assertEqual(timestampless, "Automatic log entry: "
                                        "Replayed message.")
        # Teardown
        os.remove("syslog.tfc")

    def test_4_tampered_packet(self):

        # Test
        self.assertIsNone(packet_anomaly("tamper", "message"))
        warning = open("syslog.tfc").readline()
        splitlist = warning.split()
        timestampless = splitlist[2:]
        timestampless = ' '.join(timestampless)
        self.assertEqual(timestampless, "Automatic log entry: "
                                        "Tampered / malformed message.")
        # Teardown
        os.remove("syslog.tfc")

    def test_5_checksum_error(self):

        # Test
        self.assertIsNone(packet_anomaly("checksum", "message"))
        warning = open("syslog.tfc").readline()
        splitlist = warning.split()
        timestampless = splitlist[2:]
        timestampless = ' '.join(timestampless)
        self.assertEqual(timestampless, "Automatic log entry: "
                                        "Checksum error in message.")
        # Teardown
        os.remove("syslog.tfc")

    def test_6_hash_of_long_msg_failed(self):

        # Test
        self.assertIsNone(packet_anomaly("hash", "message"))
        warning = open("syslog.tfc").readline()
        splitlist = warning.split()
        timestampless = splitlist[2:]
        timestampless = ' '.join(timestampless)
        self.assertEqual(timestampless, "Automatic log entry: "
                                        "Invalid hash in long message.")
        # Teardown
        os.remove("syslog.tfc")

    def test_7_invalid_error_type(self):
        with self.assertRaises(SystemExit):
            packet_anomaly("test", "message")


class TestGracefulExit(unittest.TestCase):

    def test_1_function(self):
        # Setup
        Rx.unittesting = False

        # Test
        with self.assertRaises(SystemExit):
            graceful_exit()

        # Teardown
        Rx.unittesting = True


class TestValidateKey(unittest.TestCase):

    def test_1_input_parameter(self):
        for a in [1, 1.0, True]:
            with self.assertRaises(SystemExit):
                validate_key(a)

    def test_2_illegal_key_length(self):
        for b in range(0, 63):
            self.assertFalse(validate_key(b * 'a'))

        for b in range(65, 250):
            self.assertFalse(validate_key(b * 'a'))

    def test_3_illegal_key_content(self):
        self.assertFalse(validate_key("%sg" % (63 * 'a')))

    def test_4_hex_char_keys_are_valid(self):
        for c in ['0', '1', '2', '3', '4',
                  '5', '6', '7', '8', '9',
                  'A', 'B', 'C', 'D', 'E', 'F',
                  'a', 'b', 'c', 'd', 'e', 'f']:
            self.assertTrue(validate_key(64 * c))


###############################################################################
#                             CONTACT MANAGEMENT                              #
###############################################################################

class TestAddContact(unittest.TestCase):

    def test_1_input_parameters(self):
        for a in [1, 1.0, True]:
            for b in [1, 1.0, True]:
                with self.assertRaises(SystemExit):
                    add_contact(a, b)

    def test_2_new_contact(self):

        # Test
        add_contact("me.alice@jabber.org", "alice")
        csv_data = open(".rx_contacts").read().splitlines()
        self.assertEqual(csv_data, ["me.alice@jabber.org,alice,1"])

        # Teardown
        os.remove(".rx_contacts")

    def test_3_reset_existing_contact(self):

        # Setup
        create_contact_db(['alice'])
        write_keyid("me.alice@jabber.org", 5)
        write_keyid("rx.alice@jabber.org", 5)

        # Test
        add_contact("me.alice@jabber.org", "ALICE")
        add_contact("rx.alice@jabber.org", "ALICE")
        csv_data = open(".rx_contacts").read().splitlines()
        self.assertEqual(csv_data,
                         ["me.alice@jabber.org,ALICE,1",
                          "rx.alice@jabber.org,ALICE,1"])

        # Teardown
        os.remove(".rx_contacts")


class TestAddKeyfiles(unittest.TestCase):

    def test_1_function(self):

        # Setup
        create_rx_keys(["alice", "bob"])
        create_me_keys(["alice", "local"])
        raw_input_original = __builtins__.raw_input
        __builtins__.raw_input = lambda x: "ALICE"

        # Test
        add_keyfiles()
        data = open(".rx_contacts").read().splitlines()

        self.assertEqual(data, ["me.alice@jabber.org,ALICE,1",
                                "me.local,local,1",
                                "rx.alice@jabber.org,alice,1",
                                "rx.bob@jabber.org,bob,1"])
        # Teardown
        os.remove(".rx_contacts")
        shutil.rmtree("keys")
        __builtins__.raw_input = raw_input_original


class TestGetKeyID(unittest.TestCase):

    def test_1_input_parameters(self):
        for a in [1, 1.0, True]:
            with self.assertRaises(SystemExit):
                get_keyid(a)

    def test_2_missing_keyID(self):

        # Setup
        open(".rx_contacts", "w+").write("me.alice@jabber.org,alice")

        # Test
        with self.assertRaises(SystemExit):
            get_keyid("me.alice@jabber.org")

        # Teardown
        os.remove(".rx_contacts")

    def test_3_invalid_keyID_value(self):

        # Setup
        open(".rx_contacts", "w+").write("me.alice@jabber.org,alice,a")

        # Test
        with self.assertRaises(SystemExit):
            get_keyid("me.alice@jabber.org")

        # Teardown
        os.remove(".rx_contacts")

    def test_4_keyID_zero(self):

        # Setup
        open(".rx_contacts", "w+").write("me.alice@jabber.org,alice,0")

        # Test
        with self.assertRaises(SystemExit):
            get_keyid("me.alice@jabber.org")

        # Teardown
        os.remove(".rx_contacts")

    def test_5_correct_keyID(self):

        # Setup
        open(".rx_contacts", "w+").write("me.alice@jabber.org,alice,1")

        # Test
        self.assertEqual(get_keyid("me.alice@jabber.org"), 1)

        # Teardown
        os.remove(".rx_contacts")

    def test_6_no_contact(self):

        # Setup
        open(".rx_contacts", "w+").write("me.alice@jabber.org,alice,1")

        # Test
        self.assertEqual(get_keyid("me.bob@jabber.org"), -1)

        # Teardown
        os.remove(".rx_contacts")


class TestGetNick(unittest.TestCase):

    def test_1_input_parameter(self):
        for a in [1, 1.0, True]:
            with self.assertRaises(SystemExit):
                get_nick(a)

    def test_2_missing_nick(self):
        for p in ['', ',']:

            # Setup
            open(".rx_contacts", "w+").write("%sme.alice@jabber.org,1" % p)

            # Test
            with self.assertRaises(SystemExit):
                get_nick("me.alice@jabber.org")

            # Teardown
            os.remove(".rx_contacts")

    def test_3_no_contact(self):

        # Setup
        create_contact_db(["alice"])

        with self.assertRaises(SystemExit):
            get_nick("me.bob@jabber.org")

        # Teardown
        os.remove(".rx_contacts")

    def test_4_correct_nick(self):

        # Setup
        create_contact_db(["alice"])

        # Test
        self.assertEqual(get_nick("me.alice@jabber.org"), "alice")

        # Teardown
        os.remove(".rx_contacts")


class TestWriteKeyID(unittest.TestCase):

    def test_1_input_parameters(self):
        for a in [1, 1.0, True]:
            for b in ["string", 1.0, True]:
                with self.assertRaises(SystemExit):
                    write_keyid(a, b)

    def test_2_no_db_gracefully_exits(self):
        with self.assertRaises(SystemExit):
            write_keyid("me.alice@jabber.org", 2)

    def test_3_keyID_less_than_one(self):

        # Setup
        create_contact_db(["alice"])

        # Test
        with self.assertRaises(SystemExit):
            write_keyid("me.alice@jabber.org", 0)

        # Teardown
        os.remove(".rx_contacts")

    def test_4_correct_keyID_writing(self):

        # Setup
        create_contact_db(["alice"])

        # Test
        write_keyid("me.alice@jabber.org", 2)
        written_data = open(".rx_contacts").read().splitlines()
        self.assertEqual(written_data, ["me.alice@jabber.org,alice,2",
                                        "rx.alice@jabber.org,alice,1"])

        # Teardown
        os.remove(".rx_contacts")

    def test_5_no_account(self):
        with self.assertRaises(SystemExit):
            write_keyid("me.bob@jabber.org", 2)


class TestWriteNick(unittest.TestCase):

    def test_1_input_parameters(self):
        for a in [1, 1.0, True]:
            for b in [1, 1.0, True]:
                with self.assertRaises(SystemExit):
                    write_nick(a, b)

    def test_2_no_db_gracefully_exits(self):
        with self.assertRaises(SystemExit):
            write_nick("me.alice@jabber.org", "alice")

    def test_3_correct_nick_writing(self):

        # Setup
        create_contact_db(["alice"])

        # Test
        write_nick("me.alice@jabber.org", "ALICE")
        written_data = open(".rx_contacts").read().splitlines()
        self.assertEqual(written_data, ["me.alice@jabber.org,ALICE,1",
                                        "rx.alice@jabber.org,alice,1"])

        # Teardown
        os.remove(".rx_contacts")

    def test_4_no_account(self):
        with self.assertRaises(SystemExit):
            write_nick("me.bob@jabber.org", "bob")


class TestGetListOfAccounts(unittest.TestCase):

    def setUp(self):
        ut_ensure_dir("keys/")
        open("keys/tx.1.e", "w+").close()
        open("keys/tx.2.e", "w+").close()
        open("keys/tx.3.e", "w+").close()
        open("keys/me.1.e", "w+").close()
        open("keys/rx.1.e", "w+").close()
        open("keys/tx.local.e", "w+").close()
        open("keys/me.local.e", "w+").close()

    def tearDown(self):
        shutil.rmtree("keys")

    def test_1_function(self):
        self.assertEqual(get_list_of_accounts(), ["me.1", "me.local", "rx.1"])


class TestCheckKeyfileParity(unittest.TestCase):

    def setUp(self):
        ut_ensure_dir("keys/")

    def tearDown(self):
        shutil.rmtree("keys")

    def test_1_function(self):

        # Check function returns None
        self.assertIsNone(check_keyfile_parity())


class TestRMContact(unittest.TestCase):

    def test_1_input_parameter(self):
        for a in [1, 1.0, True]:
            with self.assertRaises(SystemExit):
                rm_contact(a)

    def test_2_missing_accont(self):

        # Setup
        open(".rx_contacts", "w+").close()

        # Test
        self.assertIsNone(rm_contact("REMOVE|"))

        # Teardown
        os.remove(".rx_contacts")

    def test_3_remove_contact(self):

        # Setup
        original_yes = Rx.yes
        Rx.yes = lambda x: True
        create_contact_db(["alice", "bob"])
        create_me_keys(["alice", "bob"])
        create_rx_keys(["alice", "bob"])

        # Remove contacts
        rm_contact("REMOVE|alice@jabber.org")

        # Test keyfiles were removed
        self.assertFalse(os.path.isfile("keys/me.alice@jabber.org.e"))
        self.assertFalse(os.path.isfile("keys/rx.alice@jabber.org.e"))

        # Test Alice was removed from .rx_contacts
        contact_db = open(".rx_contacts").read().splitlines()
        for contact in contact_db:
            self.assertFalse("alice" in contact)

        # Teardown
        Rx.yes = original_yes
        os.remove(".rx_contacts")
        shutil.rmtree("keys")


###############################################################################
#                               MSG PROCESSING                                #
###############################################################################

class TestBase64Decode(unittest.TestCase):

    def test_1_input_parameter(self):
        for a in [1, 1.0, True]:
            with self.assertRaises(SystemExit):
                base64_decode(a)

    def test_2_decode_error(self):
        self.assertEqual(base64_decode("badEncoding"), "B64D_ERROR")

    def test_3_successful_decode(self):
        self.assertEqual(base64_decode("cGxhaW50ZXh0"), "plaintext")


class TestRMPadding(unittest.TestCase):

    def test_1_input_parameter(self):
        for a in [1, 1.0, True]:
            with self.assertRaises(SystemExit):
                rm_padding(a)

        dep = rm_padding("plaintext plaintext plaintext plaintext plaintext "
                         "plaintext plaintext plaintext plaintext plaintext "
                         "plaintext plaintext plaintext}}}}}}}}}}}}}}}}}}}}}"
                         "}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}"
                         "}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}"
                         "}}}}")

        self.assertEqual(dep, "plaintext plaintext plaintext plaintext "
                              "plaintext plaintext plaintext plaintext "
                              "plaintext plaintext plaintext plaintext "
                              "plaintext")


###############################################################################
#                                    MISC                                     #
###############################################################################

class TestWriteLogEntry(unittest.TestCase):

    def test_1_input_parameters(self):
        for a in [1, 1.0, True]:
            for b in [1, 1.0, True]:
                for c in [1, 1.0, True]:
                    for d in [1, 1.0, True]:
                        with self.assertRaises(SystemExit):
                            write_log_entry(a, b, c, d)

    def test_2_log_entry(self):

        # Test
        write_log_entry("alice", "alice@jabber.org", "message")
        logged = str(open("logs/RxM - logs.alice@jabber.org.tfc").readline())
        split = logged.split()

        self.assertEqual(split[2], "alice:")
        self.assertEqual(split[3], "message")

        # Teardown
        shutil.rmtree("logs")

    def test_3_missing_sent(self):

        # Test
        write_log_entry('', "me.alice@jabber.org", '', '3')
        logged = str(open("logs/RxM - logs.alice@jabber.org.tfc").read())
        self.assertEquals(logged, "\n3 (noise) messages /file packets to"
                                  " alice@jabber.org were dropped.\n\n")
        # Teardown
        shutil.rmtree("logs")

    def test_4_missing_received(self):
        write_log_entry('', "rx.alice@jabber.org", '', '4')
        logged = str(open("logs/RxM - logs.alice@jabber.org.tfc").read())
        self.assertEquals(logged, "\n4 (noise) messages /file packets from"
                                  " alice@jabber.org were dropped.\n\n")
        # Teardown
        shutil.rmtree("logs")


class TestYes(unittest.TestCase):

    def test_1_input_parameter(self):
        for a in [1, 1.0, True]:
            with self.assertRaises(SystemExit):
                yes(a)

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


class TestVerifyChecksum(unittest.TestCase):

    def test_1_input_parameter(self):
        for a in [1, 1.0, True]:
            with self.assertRaises(SystemExit):
                verify_checksum(a)

    def test_2_verification_success(self):
        pt = "test_packet"
        tv = ut_sha2_256(pt)
        self.assertTrue(verify_checksum("%s|%s" % (pt, tv[:Rx.checksum_len])))

    def test_3_verification_fail(self):
        pt = "test_packet"
        tv = "aaaaaaaa"
        self.assertFalse(verify_checksum("%s|%s" % (pt, tv[:Rx.checksum_len])))


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

        shutil.rmtree("directory")


class TestPrintHeaders(unittest.TestCase):

    def test_1_function(self):
        self.assertIsNone(print_headers())


class TestProcessArguments(unittest.TestCase):
    """
    This function doesn't have any tests yet.
    """


class TestSearchSerialInterfaces(unittest.TestCase):
    """
    This function doesn't have any tests yet.
    """


###############################################################################
#                     PROCESS COMMAND/MSG HEADER                              #
###############################################################################

class TestNoisePacket(unittest.TestCase):

    def test_1_input_parameter(self):
        for a in [1, 1.0, True]:
            with self.assertRaises(SystemExit):
                noise_packet(a)

    def test_2_sent_noise_packet(self):

        # Setup
        create_contact_db(["alice"])
        Rx.l_msg_coming["me.alice@jabber.org"] = True
        Rx.msg_received["me.alice@jabber.org"] = False
        Rx.m_dictionary["me.alice@jabber.org"] = "test"

        # Test
        self.assertIsNone(noise_packet("me.alice@jabber.org"))
        self.assertTrue(Rx.msg_received["me.alice@jabber.org"])
        self.assertFalse(Rx.l_msg_coming["me.alice@jabber.org"])
        self.assertEqual(Rx.m_dictionary["me.alice@jabber.org"], '')

        # Teardown
        os.remove(".rx_contacts")

    def test_3_received_noise_packet(self):

        # Setup
        create_contact_db(["alice"])
        Rx.l_msg_coming["rx.alice@jabber.org"] = True
        Rx.msg_received["rx.alice@jabber.org"] = False
        Rx.m_dictionary["rx.alice@jabber.org"] = "test"

        # Test
        self.assertIsNone(noise_packet("rx.alice@jabber.org"))
        self.assertTrue(Rx.msg_received["rx.alice@jabber.org"])
        self.assertFalse(Rx.l_msg_coming["rx.alice@jabber.org"])
        self.assertEqual(Rx.m_dictionary["rx.alice@jabber.org"], '')

        # Teardown
        os.remove(".rx_contacts")


class TestCancelMessage(unittest.TestCase):

    def test_1_input_parameter(self):
        for a in [1, 1.0, True]:
            with self.assertRaises(SystemExit):
                cancel_message(a)

    def test_2_sent_cancel_message(self):

        # Setup
        create_contact_db(["alice"])
        Rx.l_msg_coming["me.alice@jabber.org"] = True
        Rx.msg_received["me.alice@jabber.org"] = True
        Rx.m_dictionary["me.alice@jabber.org"] = "test"

        # Test
        self.assertIsNone(cancel_message("me.alice@jabber.org"))
        self.assertFalse(Rx.l_msg_coming["me.alice@jabber.org"])
        self.assertFalse(Rx.msg_received["me.alice@jabber.org"])
        self.assertEqual(Rx.m_dictionary["me.alice@jabber.org"], '')

        # Teardown
        os.remove(".rx_contacts")

    def test_3_received_cancel_message(self):

        # Setup
        create_contact_db(["alice"])
        Rx.l_msg_coming["rx.alice@jabber.org"] = True
        Rx.msg_received["rx.alice@jabber.org"] = True
        Rx.m_dictionary["rx.alice@jabber.org"] = "test"

        # Test
        self.assertIsNone(cancel_message("rx.alice@jabber.org"))
        self.assertFalse(Rx.l_msg_coming["rx.alice@jabber.org"])
        self.assertFalse(Rx.msg_received["rx.alice@jabber.org"])
        self.assertEqual(Rx.m_dictionary["rx.alice@jabber.org"], '')

        # Teardown
        os.remove(".rx_contacts")


class TestCancelFile(unittest.TestCase):

    def test_1_input_parameter(self):
        for a in [1, 1.0, True]:
            with self.assertRaises(SystemExit):
                cancel_file(a)

    def test_2_sent_cancel_file(self):

        # Setup
        create_contact_db(["alice"])
        Rx.acco_store_f["me.alice@jabber.org"] = True
        Rx.l_file_onway["me.alice@jabber.org"] = True
        Rx.filereceived["me.alice@jabber.org"] = True
        Rx.acco_store_f["me.alice@jabber.org"] = True
        Rx.f_dictionary["me.alice@jabber.org"] = "test"

        # Test
        self.assertIsNone(cancel_file("me.alice@jabber.org"))
        self.assertFalse(Rx.l_file_onway["me.alice@jabber.org"])
        self.assertFalse(Rx.filereceived["me.alice@jabber.org"])
        self.assertEqual(Rx.f_dictionary["me.alice@jabber.org"], '')

        # Teardown
        os.remove(".rx_contacts")

    def test_3_received_cancel_file(self):

        # Setup
        create_contact_db(["alice"])
        Rx.acco_store_f["rx.alice@jabber.org"] = True
        Rx.l_file_onway["rx.alice@jabber.org"] = True
        Rx.filereceived["rx.alice@jabber.org"] = True
        Rx.acco_store_f["rx.alice@jabber.org"] = True
        Rx.f_dictionary["rx.alice@jabber.org"] = "test"

        # Test
        self.assertIsNone(cancel_file("rx.alice@jabber.org"))
        self.assertFalse(Rx.l_file_onway["rx.alice@jabber.org"])
        self.assertFalse(Rx.filereceived["rx.alice@jabber.org"])
        self.assertEqual(Rx.f_dictionary["rx.alice@jabber.org"], '')

        # Teardown
        os.remove(".rx_contacts")


class TestShortMessage(unittest.TestCase):

    def test_1_input_parameters(self):
        for a in [1, 1.0, True]:
            for b in [1, 1.0, True]:
                with self.assertRaises(SystemExit):
                    short_message(a, b)

    def test_2_sent_short_message(self):

        # Setup
        create_contact_db(["alice"])
        Rx.l_msg_coming["me.alice@jabber.org"] = True
        Rx.msg_received["me.alice@jabber.org"] = False
        Rx.m_dictionary["me.alice@jabber.org"] = "test"

        # Test
        self.assertIsNone(short_message("me.alice@jabber.org", "stest"))
        self.assertTrue(Rx.msg_received["me.alice@jabber.org"])
        self.assertFalse(Rx.l_msg_coming["me.alice@jabber.org"])
        self.assertEqual(Rx.m_dictionary["me.alice@jabber.org"], "test")

        # Teardown
        os.remove(".rx_contacts")

    def test_3_received_short_message(self):

        # Setup
        create_contact_db(["alice"])
        Rx.l_msg_coming["rx.alice@jabber.org"] = True
        Rx.msg_received["rx.alice@jabber.org"] = False
        Rx.m_dictionary["rx.alice@jabber.org"] = "test"

        # Test
        self.assertIsNone(short_message("rx.alice@jabber.org", "stest"))
        self.assertTrue(Rx.msg_received["rx.alice@jabber.org"])
        self.assertFalse(Rx.l_msg_coming["rx.alice@jabber.org"])
        self.assertEqual(Rx.m_dictionary["rx.alice@jabber.org"], "test")

        # Teardown
        os.remove(".rx_contacts")


class TestShortFile(unittest.TestCase):

    def test_1_input_parameters(self):
        for a in [1, 1.0, True]:
            for b in [1, 1.0, True]:
                with self.assertRaises(SystemExit):
                    short_file(a, b)

    def test_2_sent_short_file(self):

        # Setup
        create_contact_db(["alice"])
        Rx.acco_store_f["me.alice@jabber.org"] = True
        Rx.filereceived["me.alice@jabber.org"] = False
        Rx.l_file_onway["me.alice@jabber.org"] = True
        Rx.f_dictionary["me.alice@jabber.org"] = "test"

        # Test
        self.assertIsNone(short_file("me.alice@jabber.org", "Sfiledata"))
        self.assertTrue(Rx.filereceived["me.alice@jabber.org"])
        self.assertFalse(Rx.l_file_onway["me.alice@jabber.org"])
        self.assertEqual(Rx.f_dictionary["me.alice@jabber.org"], "filedata")

        # Teardown
        os.remove(".rx_contacts")

    def test_3_received_short_file(self):

        # Setup
        create_contact_db(["alice"])
        Rx.acco_store_f["rx.alice@jabber.org"] = True
        Rx.filereceived["rx.alice@jabber.org"] = False
        Rx.l_file_onway["rx.alice@jabber.org"] = True
        Rx.f_dictionary["rx.alice@jabber.org"] = "test"

        # Test
        self.assertIsNone(short_file("rx.alice@jabber.org", "Sfiledata"))
        self.assertTrue(Rx.filereceived["rx.alice@jabber.org"])
        self.assertFalse(Rx.l_file_onway["rx.alice@jabber.org"])
        self.assertEqual(Rx.f_dictionary["rx.alice@jabber.org"], "filedata")

        # Teardown
        os.remove(".rx_contacts")


class TestLongMessageStart(unittest.TestCase):

    def test_1_input_parameters(self):
        for a in [1, 1.0, True]:
            for b in [1, 1.0, True]:
                with self.assertRaises(SystemExit):
                    long_message_start(a, b)

    def test_2_sent_long_message_start(self):

        # Setup
        create_contact_db(["alice"])
        Rx.l_msg_coming["me.alice@jabber.org"] = False
        Rx.msg_received["me.alice@jabber.org"] = False
        Rx.m_dictionary["me.alice@jabber.org"] = "ltest"

        # Test
        self.assertIsNone(long_message_start("me.alice@jabber.org", "lmsg"))
        self.assertFalse(Rx.msg_received["me.alice@jabber.org"])
        self.assertTrue(Rx.l_msg_coming["me.alice@jabber.org"])
        self.assertEqual(Rx.m_dictionary["me.alice@jabber.org"], "msg")

        # Teardown
        os.remove(".rx_contacts")

    def test_3_received_long_message_start(self):

        # Setup
        create_contact_db(["alice"])
        Rx.l_msg_coming["rx.alice@jabber.org"] = True
        Rx.msg_received["rx.alice@jabber.org"] = False
        Rx.m_dictionary["rx.alice@jabber.org"] = "ltest"

        # Test
        self.assertIsNone(long_message_start("rx.alice@jabber.org", "lmsg"))
        self.assertFalse(Rx.msg_received["rx.alice@jabber.org"])
        self.assertTrue(Rx.l_msg_coming["rx.alice@jabber.org"])
        self.assertEqual(Rx.m_dictionary["rx.alice@jabber.org"], "msg")

        # Teardown
        os.remove(".rx_contacts")


class TestLongFileStart(unittest.TestCase):

    def test_1_input_parameters(self):
        for a in [1, 1.0, True]:
            for b in [1, 1.0, True]:
                with self.assertRaises(SystemExit):
                    long_file_start(a, b)

    def test_2_sent_long_file_start(self):

        # Setup
        create_contact_db(["alice"])
        Rx.acco_store_f["me.alice@jabber.org"] = True
        Rx.l_file_onway["me.alice@jabber.org"] = True
        Rx.filereceived["me.alice@jabber.org"] = True
        Rx.f_dictionary["me.alice@jabber.org"] = ''

        # Test
        self.assertIsNone(long_file_start("me.alice@jabber.org",
                                          "Ldoc.txt|1.1KB|6|00m 01s|filedata"))
        self.assertFalse(Rx.filereceived["me.alice@jabber.org"])
        self.assertTrue(Rx.l_file_onway["me.alice@jabber.org"])
        self.assertEqual(Rx.f_dictionary["me.alice@jabber.org"],
                         "doc.txt|1.1KB|6|00m 01s|filedata")

        # Teardown
        os.remove(".rx_contacts")

    def test_3_received_long_file_start(self):

        # Setup
        create_contact_db(["alice"])
        Rx.acco_store_f["rx.alice@jabber.org"] = True
        Rx.l_file_onway["rx.alice@jabber.org"] = True
        Rx.filereceived["rx.alice@jabber.org"] = True
        Rx.f_dictionary["rx.alice@jabber.org"] = ''

        # Test
        self.assertIsNone(long_file_start("rx.alice@jabber.org",
                                          "Ldoc.txt|1.1KB|6|00m 01s|filedata"))
        self.assertFalse(Rx.filereceived["rx.alice@jabber.org"])
        self.assertTrue(Rx.l_file_onway["rx.alice@jabber.org"])
        self.assertEqual(Rx.f_dictionary["rx.alice@jabber.org"],
                         "doc.txt|1.1KB|6|00m 01s|filedata")

        # Teardown
        os.remove(".rx_contacts")


class TestLongMessageAppend(unittest.TestCase):

    def test_1_input_parameters(self):
        for a in [1, 1.0, True]:
            for b in [1, 1.0, True]:
                with self.assertRaises(SystemExit):
                    long_message_append(a, b)

    def test_2_sent_long_message_append(self):

        # Setup
        create_contact_db(["alice"])
        Rx.msg_received["me.alice@jabber.org"] = True
        Rx.l_msg_coming["me.alice@jabber.org"] = False
        Rx.m_dictionary["me.alice@jabber.org"] = "1st"

        # Test
        self.assertIsNone(long_message_append("me.alice@jabber.org", "a2nd"))
        self.assertFalse(Rx.msg_received["me.alice@jabber.org"])
        self.assertTrue(Rx.l_msg_coming["me.alice@jabber.org"])
        self.assertEqual(Rx.m_dictionary["me.alice@jabber.org"], "1st2nd")

        # Teardown
        os.remove(".rx_contacts")

    def test_3_received_long_message_append(self):

        # Setup
        create_contact_db(["alice"])
        Rx.msg_received["rx.alice@jabber.org"] = True
        Rx.l_msg_coming["rx.alice@jabber.org"] = False
        Rx.m_dictionary["rx.alice@jabber.org"] = "1st"

        # Test
        self.assertIsNone(long_message_append("rx.alice@jabber.org", "a2nd"))
        self.assertFalse(Rx.msg_received["rx.alice@jabber.org"])
        self.assertTrue(Rx.l_msg_coming["rx.alice@jabber.org"])
        self.assertEqual(Rx.m_dictionary["rx.alice@jabber.org"], "1st2nd")

        # Teardown
        os.remove(".rx_contacts")


class TestLongFileAppend(unittest.TestCase):

    def test_1_input_parameters(self):
        for a in [1, 1.0, True]:
            for b in [1, 1.0, True]:
                with self.assertRaises(SystemExit):
                    long_file_append(a, b)

    def test_2_sent_long_file_append(self):

        # Setup
        create_contact_db(["alice"])
        Rx.acco_store_f["me.alice@jabber.org"] = True
        Rx.filereceived["me.alice@jabber.org"] = True
        Rx.l_file_onway["me.alice@jabber.org"] = False
        Rx.f_dictionary["me.alice@jabber.org"] = "1st"

        # Test
        self.assertIsNone(long_file_append("me.alice@jabber.org", "A2nd"))
        self.assertFalse(Rx.filereceived["me.alice@jabber.org"])
        self.assertTrue(Rx.l_file_onway["me.alice@jabber.org"])
        self.assertEqual(Rx.f_dictionary["me.alice@jabber.org"], "1st2nd")

        # Teardown
        os.remove(".rx_contacts")

    def test_3_received_long_file_append(self):

        # Setup
        create_contact_db(["alice"])
        Rx.acco_store_f["rx.alice@jabber.org"] = True
        Rx.filereceived["rx.alice@jabber.org"] = True
        Rx.l_file_onway["rx.alice@jabber.org"] = False
        Rx.f_dictionary["rx.alice@jabber.org"] = "1st"

        # Test
        self.assertIsNone(long_file_append("rx.alice@jabber.org", "A2nd"))
        self.assertFalse(Rx.filereceived["rx.alice@jabber.org"])
        self.assertTrue(Rx.l_file_onway["rx.alice@jabber.org"])
        self.assertEqual(Rx.f_dictionary["rx.alice@jabber.org"], "1st2nd")

        # Teardown
        os.remove(".rx_contacts")


class TestLongMessageEnd(unittest.TestCase):

    def test_1_input_parameters(self):
        for a in [1, 1.0, True]:
            for b in [1, 1.0, True]:
                with self.assertRaises(SystemExit):
                    long_message_end(a, b)

    def test_2_sent_long_message_end(self):

        # Setup
        create_contact_db(["alice"])
        Rx.m_dictionary["me.alice@jabber.org"] = "1st2nd"
        Rx.msg_received["me.alice@jabber.org"] = False
        Rx.l_msg_coming["me.alice@jabber.org"] = True
        Rx.acco_store_f["me.alice@jabber.org"] = True
        Rx.filereceived["me.alice@jabber.org"] = True

        # Test
        h = "ed3a9fb03a8f93944334d49a3dd87122a8fd891512e8515e8cba59da4e9cdcd7"
        self.assertIsNone(long_message_end("me.alice@jabber.org", "e3rd" + h))
        self.assertTrue(Rx.msg_received["me.alice@jabber.org"])
        self.assertFalse(Rx.l_msg_coming["me.alice@jabber.org"])
        self.assertEqual(Rx.m_dictionary["me.alice@jabber.org"], "1st2nd3rd")

        # Teardown
        os.remove(".rx_contacts")

    def test_3_received_long_message_end(self):

        # Setup
        create_contact_db(["alice"])
        Rx.m_dictionary["rx.alice@jabber.org"] = "1st2nd"
        Rx.msg_received["rx.alice@jabber.org"] = False
        Rx.l_msg_coming["rx.alice@jabber.org"] = True
        Rx.acco_store_f["rx.alice@jabber.org"] = True
        Rx.filereceived["rx.alice@jabber.org"] = True

        # Test
        h = "ed3a9fb03a8f93944334d49a3dd87122a8fd891512e8515e8cba59da4e9cdcd7"
        self.assertIsNone(long_message_end("rx.alice@jabber.org", "e3rd" + h))
        self.assertTrue(Rx.msg_received["rx.alice@jabber.org"])
        self.assertFalse(Rx.l_msg_coming["rx.alice@jabber.org"])
        self.assertEqual(Rx.m_dictionary["rx.alice@jabber.org"], "1st2nd3rd")

        # Teardown
        os.remove(".rx_contacts")


class TestLongFileEnd(unittest.TestCase):

    def test_1_input_parameters(self):
        for a in [1, 1.0, True]:
            for b in [1, 1.0, True]:
                with self.assertRaises(SystemExit):
                    long_file_end(a, b)

    def test_2_sent_long_file_end(self):

        # Setup
        create_contact_db(["alice"])
        Rx.f_dictionary["me.alice@jabber.org"] = "1st2nd"
        Rx.acco_store_f["me.alice@jabber.org"] = True
        Rx.filereceived["me.alice@jabber.org"] = False
        Rx.msg_received["me.alice@jabber.org"] = True
        Rx.l_file_onway["me.alice@jabber.org"] = True

        # Test
        h = "ed3a9fb03a8f93944334d49a3dd87122a8fd891512e8515e8cba59da4e9cdcd7"
        self.assertIsNone(long_file_end("me.alice@jabber.org", "E3rd" + h))
        self.assertTrue(Rx.filereceived["me.alice@jabber.org"])
        self.assertFalse(Rx.msg_received["me.alice@jabber.org"])
        self.assertFalse(Rx.l_file_onway["me.alice@jabber.org"])
        self.assertEqual(Rx.f_dictionary["me.alice@jabber.org"], "1st2nd3rd")

        # Teardown
        os.remove(".rx_contacts")

    def test_3_received_long_file_end(self):

        # Setup
        create_contact_db(["alice"])
        Rx.f_dictionary["me.alice@jabber.org"] = "1st2nd"
        Rx.acco_store_f["me.alice@jabber.org"] = True
        Rx.filereceived["me.alice@jabber.org"] = False
        Rx.msg_received["me.alice@jabber.org"] = True
        Rx.l_file_onway["me.alice@jabber.org"] = True

        # Test
        h = "ed3a9fb03a8f93944334d49a3dd87122a8fd891512e8515e8cba59da4e9cdcd7"
        self.assertIsNone(long_file_end("me.alice@jabber.org", "E3rd" + h))
        self.assertTrue(Rx.filereceived["me.alice@jabber.org"])
        self.assertFalse(Rx.msg_received["me.alice@jabber.org"])
        self.assertFalse(Rx.l_file_onway["me.alice@jabber.org"])
        self.assertEqual(Rx.f_dictionary["me.alice@jabber.org"], "1st2nd3rd")

        # Teardown
        os.remove(".rx_contacts")


class TestProcessReceivedMessages(unittest.TestCase):

    def test_1_input_parameter(self):
        for a in [1, 1.0, True]:
            with self.assertRaises(SystemExit):
                process_received_messages(a)

    def test_2_process_sent_message(self):

        # Setup
        create_contact_db(["alice"])
        Rx.m_dictionary["me.alice@jabber.org"] = "testmessage"
        Rx.acco_store_l["me.alice@jabber.org"] = True
        Rx.msg_received["me.alice@jabber.org"] = True

        # Test
        self.assertIsNone(process_received_messages("me.alice@jabber.org"))

        logged_data = open("logs/RxM - logs.alice@jabber.org.tfc").readline()
        self.assertTrue("Me: testmessage" in logged_data)

        # Teardown
        os.remove(".rx_contacts")
        shutil.rmtree("logs")

    def test_3_process_received_message(self):

        # Setup
        create_contact_db(["alice"])
        Rx.m_dictionary["rx.alice@jabber.org"] = "testmessage"
        Rx.acco_store_l["rx.alice@jabber.org"] = True
        Rx.msg_received["rx.alice@jabber.org"] = True

        # Test
        self.assertIsNone(process_received_messages("rx.alice@jabber.org"))

        logged_data = open("logs/RxM - logs.alice@jabber.org.tfc").readline()
        self.assertTrue("alice: testmessage" in logged_data)

        # Teardown
        os.remove(".rx_contacts")
        shutil.rmtree("logs")


class TestProcessSentFiles(unittest.TestCase):

    def test_1_input_parameter(self):
        for a in [1, 1.0, True]:
            with self.assertRaises(SystemExit):
                process_received_files(a)

    def test_2_process_sent_file_reception_off(self):

        # Setup
        create_contact_db(["alice"])
        Rx.keep_local_files = False
        Rx.acco_store_f["me.alice@jabber.org"] = True
        Rx.filereceived["me.alice@jabber.org"] = True
        Rx.f_dictionary["me.alice@jabber.org"] = \
            "doc.txt|1.1KB|6|00m 01s|filedata"

        # Test
        self.assertIsNone(process_received_files("me.alice@jabber.org"))
        ut_ensure_dir("files/")
        self.assertFalse(os.path.isfile("files/doc.txt"))

        # Teardown
        os.remove(".rx_contacts")
        shutil.rmtree("files")
        Rx.keep_local_files = True

    def test_3_process_sent_file_reception_on(self):

        # Setup
        Rx.keep_local_files = True
        create_contact_db(["alice"])
        Rx.acco_store_f["me.alice@jabber.org"] = True
        Rx.filereceived["me.alice@jabber.org"] = True
        Rx.f_dictionary["me.alice@jabber.org"] = \
            "doc.txt|1.1KB|6|00m 01s|filedata"

        # Test
        self.assertIsNone(process_received_files("me.alice@jabber.org"))
        self.assertTrue(os.path.isfile("files/Local copy - doc.txt"))

        # Teardown
        os.remove(".rx_contacts")
        shutil.rmtree("files")
        Rx.keep_local_files = False

    def test_4_process_sent_file_duplicate_reception_on(self):

        # Setup
        ut_ensure_dir("files/")
        open("files/Local copy - doc.txt", "w+").close()
        Rx.keep_local_files = True
        create_contact_db(["alice"])
        Rx.acco_store_f["me.alice@jabber.org"] = True
        Rx.filereceived["me.alice@jabber.org"] = True
        Rx.f_dictionary["me.alice@jabber.org"] = \
            "doc.txt|1.1KB|6|00m 01s|filedata"

        # Test
        self.assertIsNone(process_received_files("me.alice@jabber.org"))
        self.assertTrue(os.path.isfile("files/Local copy - doc(1).txt"))

        # Teardown
        os.remove(".rx_contacts")
        shutil.rmtree("files")


class TestProcessReceivedFiles(unittest.TestCase):

    def test_1_input_parameter(self):
        for a in [1, 1.0, True]:
            with self.assertRaises(SystemExit):
                process_received_files(a)

    def test_2_process_received_file_reception_off(self):

        # Setup
        create_contact_db(["alice"])
        Rx.acco_store_f["rx.alice@jabber.org"] = False
        Rx.filereceived["rx.alice@jabber.org"] = True
        Rx.f_dictionary["rx.alice@jabber.org"] = \
            "doc.txt|1.1KB|6|00m 01s|filedata"

        # Test
        self.assertIsNone(process_received_files("rx.alice@jabber.org"))
        ut_ensure_dir("files/")
        self.assertFalse(os.path.isfile("files/doc.txt"))

        # Teardown
        os.remove(".rx_contacts")
        shutil.rmtree("files")

    def test_3_process_received_file_reception_on(self):

        # Setup
        create_contact_db(["alice"])
        Rx.acco_store_f["rx.alice@jabber.org"] = True
        Rx.filereceived["rx.alice@jabber.org"] = True
        Rx.f_dictionary["rx.alice@jabber.org"] = \
            "doc.txt|1.1KB|6|00m 01s|filedata"

        # Test
        self.assertIsNone(process_received_files("rx.alice@jabber.org"))
        self.assertTrue(os.path.isfile("files/doc.txt"))

        # Teardown
        os.remove(".rx_contacts")
        shutil.rmtree("files")

    def test_4_process_received_file_duplicate_reception_on(self):

        # Setup
        ut_ensure_dir("files/")
        open("files/doc.txt", "w+").close()
        Rx.keep_local_files = True
        create_contact_db(["alice"])
        Rx.acco_store_f["rx.alice@jabber.org"] = True
        Rx.filereceived["rx.alice@jabber.org"] = True
        Rx.f_dictionary["rx.alice@jabber.org"] = \
            "doc.txt|1.1KB|6|00m 01s|filedata"

        # Test
        self.assertIsNone(process_received_files("rx.alice@jabber.org"))
        self.assertTrue(os.path.isfile("files/doc(1).txt"))

        # Teardown
        os.remove(".rx_contacts")
        shutil.rmtree("files")


###############################################################################
#                          RECEIVED DATA PROCESSING                           #
###############################################################################

class TestNHPacketLoadingProcess(unittest.TestCase):
    """
    This function doesn't have any tests yet.
    """


class TestMessagePacket(unittest.TestCase):

    def test_01_input_parameters(self):
        for a in [1, 1.0, True]:
            with self.assertRaises(SystemExit):
                message_packet(a)

    def test_02_invalid_packet(self):

        # Test
        packet = ("TFC|N|1605|M|S0/oPUk8UNKRpKddw6wfUw2tOTZA+SraOkP1wCzRBOaT0"
                  "BdWFEIl0Xhl4PdtrkGdMP8O4+skYSqnIvuB5vcfbN+QvjkVtquU1b74bve"
                  "880AdqM+1DHEWzdXsAbZW4z/p8iD+2S7WTXt67LA03XPzUhd8FnUIz6bF5"
                  "f7VTHNeG0rnJ6qyOofxroqpu4XjuWdXm8hSJv+ezPjUGviZlhNlhUT2vIC"
                  "k8daJs1+gBDcGOZIdIRrwnmTyk5v3QxeKcOjyDcOBTn5MFSGt2Q/WcRPcw"
                  "ph0cbJzaAVyQj1expHHnlksxJ7ac1MSEIvx5ykR/6TMMPzGqMtrNH0DpAQ"
                  "E00JmCyYoaZ1+LF8SmEQTI2i0NaTdKPpXa/wVDhvCbhQVIK9Fh0W7Tbo7|"
                  "a|alice@jabber.org")

        self.assertIsNone(message_packet(packet))

        # Teardown
        os.remove("syslog.tfc")

    def test_03_invalid_packet(self):

        # Test
        packet = ("N|1605|M|S0/oPUk8UNKRpKddw6wfUw2tOTZA+SraOkP1wCzRBOaT0"
                  "BdWFEIl0Xhl4PdtrkGdMP8O4+skYSqnIvuB5vcfbN+QvjkVtquU1b74bve"
                  "880AdqM+1DHEWzdXsAbZW4z/p8iD+2S7WTXt67LA03XPzUhd8FnUIz6bF5"
                  "f7VTHNeG0rnJ6qyOofxroqpu4XjuWdXm8hSJv+ezPjUGviZlhNlhUT2vIC"
                  "k8daJs1+gBDcGOZIdIRrwnmTyk5v3QxeKcOjyDcOBTn5MFSGt2Q/WcRPcw"
                  "ph0cbJzaAVyQj1expHHnlksxJ7ac1MSEIvx5ykR/6TMMPzGqMtrNH0DpAQ"
                  "E00JmCyYoaZ1+LF8SmEQTI2i0NaTdKPpXa/wVDhvCbhQVIK9Fh0W7Tbo7|"
                  "2|alice@jabber.org")

        self.assertIsNone(message_packet(packet))

        # Teardown
        os.remove("syslog.tfc")

    def test_04_b64_decode_error(self):

        # Test
        packet = ("TFC|N|1605|M|#0/oPUk8UNKRpKddw6wfUw2tOTZA+SraOkP1wCzRBOaT0"
                  "BdWFEIl0Xhl4PdtrkGdMP8O4+skYSqnIvuB5vcfbN+QvjkVtquU1b74bve"
                  "880AdqM+1DHEWzdXsAbZW4z/p8iD+2S7WTXt67LA03XPzUhd8FnUIz6bF5"
                  "f7VTHNeG0rnJ6qyOofxroqpu4XjuWdXm8hSJv+ezPjUGviZlhNlhUT2vIC"
                  "k8daJs1+gBDcGOZIdIRrwnmTyk5v3QxeKcOjyDcOBTn5MFSGt2Q/WcRPcw"
                  "ph0cbJzaAVyQj1expHHnlksxJ7ac1MSEIvx5ykR/6TMMPzGqMtrNH0DpAQ"
                  "E00JmCyYoaZ1+LF8SmEQTI2i0NaTdKPpXa/wVDhvCbhQVIK9Fh0W7Tbo7|"
                  "2|alice@jabber.org")

        self.assertIsNone(message_packet(packet))

        # Teardown
        os.remove("syslog.tfc")

    def test_05_no_keyfile(self):

        # Setup
        ut_ensure_dir("files/")
        create_contact_db(["bob"])

        # Test
        packet = ("TFC|N|1605|M|S0/oPUk8UNKRpKddw6wfUw2tOTZA+SraOkP1wCzRBOaT0"
                  "BdWFEIl0Xhl4PdtrkGdMP8O4+skYSqnIvuB5vcfbN+QvjkVtquU1b74bve"
                  "880AdqM+1DHEWzdXsAbZW4z/p8iD+2S7WTXt67LA03XPzUhd8FnUIz6bF5"
                  "f7VTHNeG0rnJ6qyOofxroqpu4XjuWdXm8hSJv+ezPjUGviZlhNlhUT2vIC"
                  "k8daJs1+gBDcGOZIdIRrwnmTyk5v3QxeKcOjyDcOBTn5MFSGt2Q/WcRPcw"
                  "ph0cbJzaAVyQj1expHHnlksxJ7ac1MSEIvx5ykR/6TMMPzGqMtrNH0DpAQ"
                  "E00JmCyYoaZ1+LF8SmEQTI2i0NaTdKPpXa/wVDhvCbhQVIK9Fh0W7Tbo7|"
                  "2|me.alice@jabber.org")

        self.assertIsNone(message_packet(packet))

        # Teardown
        os.remove(".rx_contacts")
        shutil.rmtree("files")

    def test_06_old_keyid(self):

        # Setup
        create_contact_db(["alice"], keyid='2')

        # Test
        packet = ("TFC|N|1605|M|S0/oPUk8UNKRpKddw6wfUw2tOTZA+SraOkP1wCzRBOaT0"
                  "BdWFEIl0Xhl4PdtrkGdMP8O4+skYSqnIvuB5vcfbN+QvjkVtquU1b74bve"
                  "880AdqM+1DHEWzdXsAbZW4z/p8iD+2S7WTXt67LA03XPzUhd8FnUIz6bF5"
                  "f7VTHNeG0rnJ6qyOofxroqpu4XjuWdXm8hSJv+ezPjUGviZlhNlhUT2vIC"
                  "k8daJs1+gBDcGOZIdIRrwnmTyk5v3QxeKcOjyDcOBTn5MFSGt2Q/WcRPcw"
                  "ph0cbJzaAVyQj1expHHnlksxJ7ac1MSEIvx5ykR/6TMMPzGqMtrNH0DpAQ"
                  "E00JmCyYoaZ1+LF8SmEQTI2i0NaTdKPpXa/wVDhvCbhQVIK9Fh0W7Tbo7|"
                  "1|me.alice@jabber.org")

        self.assertIsNone(message_packet(packet))

        # Teardown
        os.remove(".rx_contacts")
        os.remove("syslog.tfc")

    def test_07_invalid_keyid(self):

        # Setup
        create_contact_db(["alice"], keyid='a')

        # Test
        packet = ("TFC|N|1605|M|S0/oPUk8UNKRpKddw6wfUw2tOTZA+SraOkP1wCzRBOaT0"
                  "BdWFEIl0Xhl4PdtrkGdMP8O4+skYSqnIvuB5vcfbN+QvjkVtquU1b74bve"
                  "880AdqM+1DHEWzdXsAbZW4z/p8iD+2S7WTXt67LA03XPzUhd8FnUIz6bF5"
                  "f7VTHNeG0rnJ6qyOofxroqpu4XjuWdXm8hSJv+ezPjUGviZlhNlhUT2vIC"
                  "k8daJs1+gBDcGOZIdIRrwnmTyk5v3QxeKcOjyDcOBTn5MFSGt2Q/WcRPcw"
                  "ph0cbJzaAVyQj1expHHnlksxJ7ac1MSEIvx5ykR/6TMMPzGqMtrNH0DpAQ"
                  "E00JmCyYoaZ1+LF8SmEQTI2i0NaTdKPpXa/wVDhvCbhQVIK9Fh0W7Tbo7|"
                  "1|me.alice@jabber.org")

        with self.assertRaises(SystemExit):
            message_packet(packet)

        # Teardown
        os.remove(".rx_contacts")

    def test_08_missing_keyfile(self):

        # Setup
        create_contact_db(["alice"])

        # Test
        packet = ("TFC|N|1605|M|S0/oPUk8UNKRpKddw6wfUw2tOTZA+SraOkP1wCzRBOaT0"
                  "BdWFEIl0Xhl4PdtrkGdMP8O4+skYSqnIvuB5vcfbN+QvjkVtquU1b74bve"
                  "880AdqM+1DHEWzdXsAbZW4z/p8iD+2S7WTXt67LA03XPzUhd8FnUIz6bF5"
                  "f7VTHNeG0rnJ6qyOofxroqpu4XjuWdXm8hSJv+ezPjUGviZlhNlhUT2vIC"
                  "k8daJs1+gBDcGOZIdIRrwnmTyk5v3QxeKcOjyDcOBTn5MFSGt2Q/WcRPcw"
                  "ph0cbJzaAVyQj1expHHnlksxJ7ac1MSEIvx5ykR/6TMMPzGqMtrNH0DpAQ"
                  "E00JmCyYoaZ1+LF8SmEQTI2i0NaTdKPpXa/wVDhvCbhQVIK9Fh0W7Tbo7|"
                  "1|me.alice@jabber.org")

        self.assertIsNone(message_packet(packet))

        # Teardown
        os.remove(".rx_contacts")

    def test_09_keyIDOverflow(self):

        # Setup
        create_contact_db(["alice"])
        create_me_keys(["alice"])

        # Test
        packet = ("TFC|N|1605|M|S0/oPUk8UNKRpKddw6wfUw2tOTZA+SraOkP1wCzRBOaT0"
                  "BdWFEIl0Xhl4PdtrkGdMP8O4+skYSqnIvuB5vcfbN+QvjkVtquU1b74bve"
                  "880AdqM+1DHEWzdXsAbZW4z/p8iD+2S7WTXt67LA03XPzUhd8FnUIz6bF5"
                  "f7VTHNeG0rnJ6qyOofxroqpu4XjuWdXm8hSJv+ezPjUGviZlhNlhUT2vIC"
                  "k8daJs1+gBDcGOZIdIRrwnmTyk5v3QxeKcOjyDcOBTn5MFSGt2Q/WcRPcw"
                  "ph0cbJzaAVyQj1expHHnlksxJ7ac1MSEIvx5ykR/6TMMPzGqMtrNH0DpAQ"
                  "E00JmCyYoaZ1+LF8SmEQTI2i0NaTdKPpXa/wVDhvCbhQVIK9Fh0W7Tbo7|"
                  "400|me.alice@jabber.org")

        self.assertIsNone(message_packet(packet))

        # Teardown
        os.remove(".rx_contacts")
        shutil.rmtree("keys")
        os.remove("syslog.tfc")

    def test_10_incorrect_mac(self):

        # Setup
        create_contact_db(["alice"])
        create_me_keys(["alice"])

        # Test
        packet = ("TFC|N|1605|M|S0/oPUk8UNKRpKddw6wfUw2tOTZA+SraOkP1wCzRBOaT0"
                  "BdWFEIl0Xhl4PdtrkGdMP8O4+skYSqnIvuB5vcfbN+QvjkVtquU1b74bve"
                  "880AdqM+1DHEWzdXsAbZW4z/p8iD+2S7WTXt67LA03XPzUhd8FnUIz6bF5"
                  "f7VTHNeG0rnJ6qyOofxroqpu4XjuWdXm8hSJv+ezPjUGviZlhNlhUT2vIC"
                  "k8daJs1+gBDcGOZIdIRrwnmTyk5v3QxeKcOjyDcOBTn5MFSGt2Q/WcRPcw"
                  "ph0cbJzaAVyQj1expHHnlksxJ7ac1MSEIvx5ykR/6TMMPzGqMtrNH0DpAQ"
                  "E00JmCyYoaZ1+LF8SmEQTI2i0NaTdKPpXa/wVDhvCbhQVIK9Fh0W7Tbo7|"
                  "2|me.alice@jabber.org")

        self.assertIsNone(message_packet(packet))

        # Teardown
        os.remove(".rx_contacts")
        shutil.rmtree("keys")
        os.remove("syslog.tfc")


class TestProcessMessage(unittest.TestCase):

    def test_1_input_parameters(self):
        for a in [1, 1.0, True]:
            for b in [1, 1.0, True]:
                with self.assertRaises(SystemExit):
                    process_message(a, b)


class TestCommandPacket(unittest.TestCase):

    def test_01_input_parameter(self):
        for a in [1, 1.0, True]:
            with self.assertRaises(SystemExit):
                command_packet(a)

    def test_02_invalid_packet(self):

        # Test
        packet = ("TFC|N|1605|C|S0/oPUk8UNKRpKddw6wfUw2tOTZA+SraOkP1wCzRBOaT0"
                  "BdWFEIl0Xhl4PdtrkGdMP8O4+skYSqnIvuB5vcfbN+QvjkVtquU1b74bve"
                  "880AdqM+1DHEWzdXsAbZW4z/p8iD+2S7WTXt67LA03XPzUhd8FnUIz6bF5"
                  "f7VTHNeG0rnJ6qyOofxroqpu4XjuWdXm8hSJv+ezPjUGviZlhNlhUT2vIC"
                  "k8daJs1+gBDcGOZIdIRrwnmTyk5v3QxeKcOjyDcOBTn5MFSGt2Q/WcRPcw"
                  "ph0cbJzaAVyQj1expHHnlksxJ7ac1MSEIvx5ykR/6TMMPzGqMtrNH0DpAQ"
                  "E00JmCyYoaZ1+LF8SmEQTI2i0NaTdKPpXa/wVDhvCbhQVIK9Fh0W7Tbo7|"
                  "a")

        self.assertIsNone(command_packet(packet))

        # Teardown
        os.remove("syslog.tfc")

    def test_03_invalid_packet(self):

        # Test
        packet = ("N|1605|M|S0/oPUk8UNKRpKddw6wfUw2tOTZA+SraOkP1wCzRBOaT0"
                  "BdWFEIl0Xhl4PdtrkGdMP8O4+skYSqnIvuB5vcfbN+QvjkVtquU1b74bve"
                  "880AdqM+1DHEWzdXsAbZW4z/p8iD+2S7WTXt67LA03XPzUhd8FnUIz6bF5"
                  "f7VTHNeG0rnJ6qyOofxroqpu4XjuWdXm8hSJv+ezPjUGviZlhNlhUT2vIC"
                  "k8daJs1+gBDcGOZIdIRrwnmTyk5v3QxeKcOjyDcOBTn5MFSGt2Q/WcRPcw"
                  "ph0cbJzaAVyQj1expHHnlksxJ7ac1MSEIvx5ykR/6TMMPzGqMtrNH0DpAQ"
                  "E00JmCyYoaZ1+LF8SmEQTI2i0NaTdKPpXa/wVDhvCbhQVIK9Fh0W7Tbo7|"
                  "2")

        self.assertIsNone(command_packet(packet))

        # Teardown
        os.remove("syslog.tfc")

    def test_04_b64_decode_error(self):

        # Test
        packet = ("TFC|N|1605|M|#0/oPUk8UNKRpKddw6wfUw2tOTZA+SraOkP1wCzRBOaT0"
                  "BdWFEIl0Xhl4PdtrkGdMP8O4+skYSqnIvuB5vcfbN+QvjkVtquU1b74bve"
                  "880AdqM+1DHEWzdXsAbZW4z/p8iD+2S7WTXt67LA03XPzUhd8FnUIz6bF5"
                  "f7VTHNeG0rnJ6qyOofxroqpu4XjuWdXm8hSJv+ezPjUGviZlhNlhUT2vIC"
                  "k8daJs1+gBDcGOZIdIRrwnmTyk5v3QxeKcOjyDcOBTn5MFSGt2Q/WcRPcw"
                  "ph0cbJzaAVyQj1expHHnlksxJ7ac1MSEIvx5ykR/6TMMPzGqMtrNH0DpAQ"
                  "E00JmCyYoaZ1+LF8SmEQTI2i0NaTdKPpXa/wVDhvCbhQVIK9Fh0W7Tbo7|"
                  "2")

        self.assertIsNone(command_packet(packet))

        # Teardown
        os.remove("syslog.tfc")

    def test_05_no_keyfile(self):

        # Setup
        ut_ensure_dir("files/")
        create_contact_db(["bob"])

        # Test
        packet = ("TFC|N|1605|M|S0/oPUk8UNKRpKddw6wfUw2tOTZA+SraOkP1wCzRBOaT0"
                  "BdWFEIl0Xhl4PdtrkGdMP8O4+skYSqnIvuB5vcfbN+QvjkVtquU1b74bve"
                  "880AdqM+1DHEWzdXsAbZW4z/p8iD+2S7WTXt67LA03XPzUhd8FnUIz6bF5"
                  "f7VTHNeG0rnJ6qyOofxroqpu4XjuWdXm8hSJv+ezPjUGviZlhNlhUT2vIC"
                  "k8daJs1+gBDcGOZIdIRrwnmTyk5v3QxeKcOjyDcOBTn5MFSGt2Q/WcRPcw"
                  "ph0cbJzaAVyQj1expHHnlksxJ7ac1MSEIvx5ykR/6TMMPzGqMtrNH0DpAQ"
                  "E00JmCyYoaZ1+LF8SmEQTI2i0NaTdKPpXa/wVDhvCbhQVIK9Fh0W7Tbo7|"
                  "2")

        self.assertIsNone(command_packet(packet))

        # Teardown
        os.remove(".rx_contacts")
        shutil.rmtree("files")

    def test_06_old_keyid(self):

        # Setup
        create_contact_db(["local"], keyid='2')

        # Test
        packet = ("TFC|N|1605|M|S0/oPUk8UNKRpKddw6wfUw2tOTZA+SraOkP1wCzRBOaT0"
                  "BdWFEIl0Xhl4PdtrkGdMP8O4+skYSqnIvuB5vcfbN+QvjkVtquU1b74bve"
                  "880AdqM+1DHEWzdXsAbZW4z/p8iD+2S7WTXt67LA03XPzUhd8FnUIz6bF5"
                  "f7VTHNeG0rnJ6qyOofxroqpu4XjuWdXm8hSJv+ezPjUGviZlhNlhUT2vIC"
                  "k8daJs1+gBDcGOZIdIRrwnmTyk5v3QxeKcOjyDcOBTn5MFSGt2Q/WcRPcw"
                  "ph0cbJzaAVyQj1expHHnlksxJ7ac1MSEIvx5ykR/6TMMPzGqMtrNH0DpAQ"
                  "E00JmCyYoaZ1+LF8SmEQTI2i0NaTdKPpXa/wVDhvCbhQVIK9Fh0W7Tbo7|"
                  "1")

        self.assertIsNone(command_packet(packet))

        # Teardown
        os.remove(".rx_contacts")
        os.remove("syslog.tfc")

    def test_07_invalid_keyid(self):

        # Setup
        create_contact_db(["local"], keyid='a')

        # Test
        packet = ("TFC|N|1605|M|S0/oPUk8UNKRpKddw6wfUw2tOTZA+SraOkP1wCzRBOaT0"
                  "BdWFEIl0Xhl4PdtrkGdMP8O4+skYSqnIvuB5vcfbN+QvjkVtquU1b74bve"
                  "880AdqM+1DHEWzdXsAbZW4z/p8iD+2S7WTXt67LA03XPzUhd8FnUIz6bF5"
                  "f7VTHNeG0rnJ6qyOofxroqpu4XjuWdXm8hSJv+ezPjUGviZlhNlhUT2vIC"
                  "k8daJs1+gBDcGOZIdIRrwnmTyk5v3QxeKcOjyDcOBTn5MFSGt2Q/WcRPcw"
                  "ph0cbJzaAVyQj1expHHnlksxJ7ac1MSEIvx5ykR/6TMMPzGqMtrNH0DpAQ"
                  "E00JmCyYoaZ1+LF8SmEQTI2i0NaTdKPpXa/wVDhvCbhQVIK9Fh0W7Tbo7|"
                  "1")

        with self.assertRaises(SystemExit):
            command_packet(packet)

        # Teardown
        os.remove(".rx_contacts")

    def test_08_missing_keyfile(self):

        # Setup
        create_contact_db(["local"])

        # Test
        packet = ("TFC|N|1605|M|S0/oPUk8UNKRpKddw6wfUw2tOTZA+SraOkP1wCzRBOaT0"
                  "BdWFEIl0Xhl4PdtrkGdMP8O4+skYSqnIvuB5vcfbN+QvjkVtquU1b74bve"
                  "880AdqM+1DHEWzdXsAbZW4z/p8iD+2S7WTXt67LA03XPzUhd8FnUIz6bF5"
                  "f7VTHNeG0rnJ6qyOofxroqpu4XjuWdXm8hSJv+ezPjUGviZlhNlhUT2vIC"
                  "k8daJs1+gBDcGOZIdIRrwnmTyk5v3QxeKcOjyDcOBTn5MFSGt2Q/WcRPcw"
                  "ph0cbJzaAVyQj1expHHnlksxJ7ac1MSEIvx5ykR/6TMMPzGqMtrNH0DpAQ"
                  "E00JmCyYoaZ1+LF8SmEQTI2i0NaTdKPpXa/wVDhvCbhQVIK9Fh0W7Tbo7|"
                  "1")

        self.assertIsNone(command_packet(packet))

        # Teardown
        os.remove(".rx_contacts")

    def test_09_keyIDOverflow(self):

        # Setup
        create_contact_db(["local"])
        create_me_keys(["local"])

        # Test
        packet = ("TFC|N|1605|M|S0/oPUk8UNKRpKddw6wfUw2tOTZA+SraOkP1wCzRBOaT0"
                  "BdWFEIl0Xhl4PdtrkGdMP8O4+skYSqnIvuB5vcfbN+QvjkVtquU1b74bve"
                  "880AdqM+1DHEWzdXsAbZW4z/p8iD+2S7WTXt67LA03XPzUhd8FnUIz6bF5"
                  "f7VTHNeG0rnJ6qyOofxroqpu4XjuWdXm8hSJv+ezPjUGviZlhNlhUT2vIC"
                  "k8daJs1+gBDcGOZIdIRrwnmTyk5v3QxeKcOjyDcOBTn5MFSGt2Q/WcRPcw"
                  "ph0cbJzaAVyQj1expHHnlksxJ7ac1MSEIvx5ykR/6TMMPzGqMtrNH0DpAQ"
                  "E00JmCyYoaZ1+LF8SmEQTI2i0NaTdKPpXa/wVDhvCbhQVIK9Fh0W7Tbo7|"
                  "400")

        self.assertIsNone(command_packet(packet))

        # Teardown
        os.remove(".rx_contacts")
        shutil.rmtree("keys")
        os.remove("syslog.tfc")

    def test_10_incorrect_mac(self):

        # Setup
        create_contact_db(["local"])
        create_me_keys(["local"])

        # Test
        packet = ("TFC|N|1605|M|S0/oPUk8UNKRpKddw6wfUw2tOTZA+SraOkP1wCzRBOaT0"
                  "BdWFEIl0Xhl4PdtrkGdMP8O4+skYSqnIvuB5vcfbN+QvjkVtquU1b74bve"
                  "880AdqM+1DHEWzdXsAbZW4z/p8iD+2S7WTXt67LA03XPzUhd8FnUIz6bF5"
                  "f7VTHNeG0rnJ6qyOofxroqpu4XjuWdXm8hSJv+ezPjUGviZlhNlhUT2vIC"
                  "k8daJs1+gBDcGOZIdIRrwnmTyk5v3QxeKcOjyDcOBTn5MFSGt2Q/WcRPcw"
                  "ph0cbJzaAVyQj1expHHnlksxJ7ac1MSEIvx5ykR/6TMMPzGqMtrNH0DpAQ"
                  "E00JmCyYoaZ1+LF8SmEQTI2i0NaTdKPpXa/wVDhvCbhQVIK9Fh0W7Tbo7|"
                  "2")

        self.assertIsNone(command_packet(packet))

        # Teardown
        os.remove(".rx_contacts")
        shutil.rmtree("keys")
        os.remove("syslog.tfc")


class TestProcessCommand(unittest.TestCase):

    def test_01_input_parameters(self):
        for a in [1, 1.0, True]:
            with self.assertRaises(SystemExit):
                process_command(a)

    def test_02_noise_packet(self):
        Rx.print_noise_pkg = True
        self.assertIsNone(process_command('N'))

    def test_03_clear_display(self):
        self.assertIsNone(process_command("CLEAR"))

    def test_04_enable_logging(self):

        # Setup
        create_me_keys(["alice", "bob"])
        create_rx_keys(["alice", "bob"])
        Rx.acco_store_l["rx.alice@jabber.org"] = False
        Rx.acco_store_l["me.alice@jabber.org"] = False
        Rx.acco_store_l["rx.bob@jabber.org"] = False
        Rx.acco_store_l["me.bob@jabber.org"] = False

        # Test
        self.assertIsNone(process_command("LOGGING|ENABLE"))
        self.assertTrue(Rx.acco_store_l["rx.alice@jabber.org"])
        self.assertTrue(Rx.acco_store_l["me.alice@jabber.org"])
        self.assertTrue(Rx.acco_store_l["rx.bob@jabber.org"])
        self.assertTrue(Rx.acco_store_l["me.bob@jabber.org"])

        # Teardown
        shutil.rmtree("keys")

    def test_05_disable_logging(self):

        # Setup
        create_me_keys(["alice", "bob"])
        create_rx_keys(["alice", "bob"])
        Rx.acco_store_l["rx.alice@jabber.org"] = True
        Rx.acco_store_l["me.alice@jabber.org"] = True
        Rx.acco_store_l["rx.bob@jabber.org"] = True
        Rx.acco_store_l["me.bob@jabber.org"] = True

        # Test
        self.assertIsNone(process_command("LOGGING|DISABLE"))
        self.assertFalse(Rx.acco_store_l["rx.alice@jabber.org"])
        self.assertFalse(Rx.acco_store_l["me.alice@jabber.org"])
        self.assertFalse(Rx.acco_store_l["rx.bob@jabber.org"])
        self.assertFalse(Rx.acco_store_l["me.bob@jabber.org"])

        # Teardown
        shutil.rmtree("keys")

    def test_06_enable_logging_for_account(self):

        # Setup
        create_me_keys(["alice", "bob"])
        create_rx_keys(["alice", "bob"])
        Rx.acco_store_l["rx.alice@jabber.org"] = False
        Rx.acco_store_l["me.alice@jabber.org"] = False
        Rx.acco_store_l["rx.bob@jabber.org"] = False
        Rx.acco_store_l["me.bob@jabber.org"] = False

        # Test
        self.assertIsNone(process_command("LOGGING|ENABLE|me.bob@jabber.org"))
        self.assertFalse(Rx.acco_store_l["rx.alice@jabber.org"])
        self.assertFalse(Rx.acco_store_l["me.alice@jabber.org"])
        self.assertTrue(Rx.acco_store_l["rx.bob@jabber.org"])
        self.assertTrue(Rx.acco_store_l["me.bob@jabber.org"])

        # Teardown
        shutil.rmtree("keys")

    def test_07_disable_logging_for_contact(self):

        # Setup
        create_me_keys(["alice", "bob"])
        create_rx_keys(["alice", "bob"])
        Rx.acco_store_l["rx.alice@jabber.org"] = True
        Rx.acco_store_l["me.alice@jabber.org"] = True
        Rx.acco_store_l["rx.bob@jabber.org"] = True
        Rx.acco_store_l["me.bob@jabber.org"] = True

        # Test
        self.assertIsNone(process_command("LOGGING|DISABLE|me.bob@jabber.org"))
        self.assertTrue(Rx.acco_store_l["rx.alice@jabber.org"])
        self.assertTrue(Rx.acco_store_l["me.alice@jabber.org"])
        self.assertFalse(Rx.acco_store_l["rx.bob@jabber.org"])
        self.assertFalse(Rx.acco_store_l["me.bob@jabber.org"])

        # Teardown
        shutil.rmtree("keys")

    def test_08_enable_reception(self):

        # Setup
        create_me_keys(["alice", "bob"])
        create_rx_keys(["alice", "bob"])

        # Test
        self.assertIsNone(process_command("STORE|ENABLE"))
        self.assertFalse(Rx.l_file_onway["me.alice@jabber.org"])
        self.assertFalse(Rx.l_file_onway["rx.alice@jabber.org"])
        self.assertFalse(Rx.l_file_onway["me.bob@jabber.org"])
        self.assertFalse(Rx.l_file_onway["rx.bob@jabber.org"])

        self.assertFalse(Rx.filereceived["me.alice@jabber.org"])
        self.assertFalse(Rx.filereceived["rx.alice@jabber.org"])
        self.assertFalse(Rx.filereceived["me.bob@jabber.org"])
        self.assertFalse(Rx.filereceived["rx.bob@jabber.org"])

        self.assertTrue(Rx.acco_store_f["me.alice@jabber.org"])
        self.assertTrue(Rx.acco_store_f["rx.alice@jabber.org"])
        self.assertTrue(Rx.acco_store_f["me.bob@jabber.org"])
        self.assertTrue(Rx.acco_store_f["rx.bob@jabber.org"])

        self.assertEqual(Rx.f_dictionary["me.alice@jabber.org"], '')
        self.assertEqual(Rx.f_dictionary["rx.alice@jabber.org"], '')
        self.assertEqual(Rx.f_dictionary["me.bob@jabber.org"], '')
        self.assertEqual(Rx.f_dictionary["rx.bob@jabber.org"], '')

        # Teardown
        shutil.rmtree("keys")

    def test_09_disable_reception(self):

        # Setup
        create_me_keys(["alice", "bob"])
        create_rx_keys(["alice", "bob"])
        Rx.acco_store_f["me.alice@jabber.org"] = True
        Rx.acco_store_f["rx.alice@jabber.org"] = True
        Rx.acco_store_f["me.bob@jabber.org"] = True
        Rx.acco_store_f["rx.bob@jabber.org"] = True

        # Test
        self.assertIsNone(process_command("STORE|DISABLE"))
        self.assertFalse(Rx.acco_store_f["rx.alice@jabber.org"])
        self.assertFalse(Rx.acco_store_f["me.alice@jabber.org"])
        self.assertFalse(Rx.acco_store_f["rx.bob@jabber.org"])
        self.assertFalse(Rx.acco_store_f["me.bob@jabber.org"])

        # Teardown
        shutil.rmtree("keys")

    def test_10_enable_reception_for_contact(self):

        # Setup
        create_me_keys(["alice", "bob"])
        create_rx_keys(["alice", "bob"])
        Rx.acco_store_f["me.alice@jabber.org"] = False
        Rx.acco_store_f["rx.alice@jabber.org"] = False
        Rx.acco_store_f["me.bob@jabber.org"] = False
        Rx.acco_store_f["rx.bob@jabber.org"] = False

        # Test
        self.assertIsNone(process_command("STORE|ENABLE|rx.bob@jabber.org"))
        self.assertFalse(Rx.acco_store_f["rx.alice@jabber.org"])
        self.assertTrue(Rx.acco_store_f["rx.bob@jabber.org"])

        # Teardown
        shutil.rmtree("keys")

    def test_11_disable_reception_for_contact(self):

        # Setup
        create_me_keys(["alice", "bob"])
        create_rx_keys(["alice", "bob"])
        Rx.acco_store_f["me.alice@jabber.org"] = True
        Rx.acco_store_f["rx.alice@jabber.org"] = True
        Rx.acco_store_f["me.bob@jabber.org"] = True
        Rx.acco_store_f["rx.bob@jabber.org"] = True

        # Test
        self.assertIsNone(process_command("STORE|DISABLE|rx.bob@jabber.org"))
        self.assertTrue(Rx.acco_store_f["rx.alice@jabber.org"])
        self.assertFalse(Rx.acco_store_f["rx.bob@jabber.org"])

        # Teardown
        shutil.rmtree("keys")

    def test_12_change_nick(self):

        # Setup
        create_contact_db(["alice"])

        # Test
        self.assertIsNone(process_command("NICK|me.alice@jabber.org|ALICE"))
        contactdata = open(".rx_contacts").readline()
        self.assertEqual(contactdata, "me.alice@jabber.org,ALICE,1\r\n")

        # Teardown
        os.remove(".rx_contacts")


class TestControlLogging(unittest.TestCase):

    def test_1_input_parameter(self):
        for a in [1, 1.0, True]:
            with self.assertRaises(SystemExit):
                control_logging(a)

    def test_2_enable_logging(self):

        # Setup
        create_me_keys(["alice", "bob"])
        create_rx_keys(["alice", "bob"])
        Rx.acco_store_l["rx.alice@jabber.org"] = False
        Rx.acco_store_l["me.alice@jabber.org"] = False
        Rx.acco_store_l["rx.bob@jabber.org"] = False
        Rx.acco_store_l["me.bob@jabber.org"] = False

        # Test
        self.assertIsNone(process_command("LOGGING|ENABLE"))
        self.assertTrue(Rx.acco_store_l["rx.alice@jabber.org"])
        self.assertTrue(Rx.acco_store_l["me.alice@jabber.org"])
        self.assertTrue(Rx.acco_store_l["rx.bob@jabber.org"])
        self.assertTrue(Rx.acco_store_l["me.bob@jabber.org"])

        # Teardown
        shutil.rmtree("keys")

    def test_3_disable_logging(self):

        # Setup
        create_me_keys(["alice", "bob"])
        create_rx_keys(["alice", "bob"])
        Rx.acco_store_l["rx.alice@jabber.org"] = True
        Rx.acco_store_l["me.alice@jabber.org"] = True
        Rx.acco_store_l["rx.bob@jabber.org"] = True
        Rx.acco_store_l["me.bob@jabber.org"] = True

        # Test
        self.assertIsNone(process_command("LOGGING|DISABLE"))
        self.assertFalse(Rx.acco_store_l["rx.alice@jabber.org"])
        self.assertFalse(Rx.acco_store_l["me.alice@jabber.org"])
        self.assertFalse(Rx.acco_store_l["rx.bob@jabber.org"])
        self.assertFalse(Rx.acco_store_l["me.bob@jabber.org"])

        # Teardown
        shutil.rmtree("keys")

    def test_4_enable_logging_for_account(self):

        # Setup
        create_me_keys(["alice", "bob"])
        create_rx_keys(["alice", "bob"])
        Rx.acco_store_l["rx.alice@jabber.org"] = False
        Rx.acco_store_l["me.alice@jabber.org"] = False
        Rx.acco_store_l["rx.bob@jabber.org"] = False
        Rx.acco_store_l["me.bob@jabber.org"] = False

        # Test
        self.assertIsNone(process_command("LOGGING|ENABLE|me.bob@jabber.org"))
        self.assertFalse(Rx.acco_store_l["rx.alice@jabber.org"])
        self.assertFalse(Rx.acco_store_l["me.alice@jabber.org"])
        self.assertTrue(Rx.acco_store_l["rx.bob@jabber.org"])
        self.assertTrue(Rx.acco_store_l["me.bob@jabber.org"])

        # Teardown
        shutil.rmtree("keys")

    def test_5_disable_logging_for_contact(self):

        # Setup
        create_me_keys(["alice", "bob"])
        create_rx_keys(["alice", "bob"])
        Rx.acco_store_l["rx.alice@jabber.org"] = True
        Rx.acco_store_l["me.alice@jabber.org"] = True
        Rx.acco_store_l["rx.bob@jabber.org"] = True
        Rx.acco_store_l["me.bob@jabber.org"] = True

        # Test
        self.assertIsNone(process_command("LOGGING|DISABLE|me.bob@jabber.org"))
        self.assertTrue(Rx.acco_store_l["rx.alice@jabber.org"])
        self.assertTrue(Rx.acco_store_l["me.alice@jabber.org"])
        self.assertFalse(Rx.acco_store_l["rx.bob@jabber.org"])
        self.assertFalse(Rx.acco_store_l["me.bob@jabber.org"])

        # Teardown
        shutil.rmtree("keys")


class TestControlStoring(unittest.TestCase):

    def test_1_input_parameter(self):
        for a in [1, 1.0, True]:
            with self.assertRaises(SystemExit):
                control_storing(a)

    def test_2_enable_reception(self):

        # Setup
        create_me_keys(["alice", "bob"])
        create_rx_keys(["alice", "bob"])

        # Test
        Rx.l_file_onway["me.alice@jabber.org"] = False
        Rx.l_file_onway["rx.alice@jabber.org"] = False
        Rx.l_file_onway["me.bob@jabber.org"] = False
        Rx.l_file_onway["rx.bob@jabber.org"] = False

        Rx.filereceived["me.alice@jabber.org"] = False
        Rx.filereceived["rx.alice@jabber.org"] = False
        Rx.filereceived["me.bob@jabber.org"] = False
        Rx.filereceived["rx.bob@jabber.org"] = False

        Rx.acco_store_f["me.alice@jabber.org"] = False
        Rx.acco_store_f["rx.alice@jabber.org"] = False
        Rx.acco_store_f["me.bob@jabber.org"] = False
        Rx.acco_store_f["rx.bob@jabber.org"] = False

        Rx.f_dictionary["me.alice@jabber.org"] = ''
        Rx.f_dictionary["rx.alice@jabber.org"] = ''
        Rx.f_dictionary["me.bob@jabber.org"] = ''
        Rx.f_dictionary["rx.bob@jabber.org"] = ''

        self.assertIsNone(process_command("STORE|ENABLE"))
        self.assertFalse(Rx.l_file_onway["me.alice@jabber.org"])
        self.assertFalse(Rx.l_file_onway["rx.alice@jabber.org"])
        self.assertFalse(Rx.l_file_onway["me.bob@jabber.org"])
        self.assertFalse(Rx.l_file_onway["rx.bob@jabber.org"])

        self.assertFalse(Rx.filereceived["me.alice@jabber.org"])
        self.assertFalse(Rx.filereceived["rx.alice@jabber.org"])
        self.assertFalse(Rx.filereceived["me.bob@jabber.org"])
        self.assertFalse(Rx.filereceived["rx.bob@jabber.org"])

        self.assertTrue(Rx.acco_store_f["me.alice@jabber.org"])
        self.assertTrue(Rx.acco_store_f["rx.alice@jabber.org"])
        self.assertTrue(Rx.acco_store_f["me.bob@jabber.org"])
        self.assertTrue(Rx.acco_store_f["rx.bob@jabber.org"])

        self.assertEqual(Rx.f_dictionary["me.alice@jabber.org"], '')
        self.assertEqual(Rx.f_dictionary["rx.alice@jabber.org"], '')
        self.assertEqual(Rx.f_dictionary["me.bob@jabber.org"], '')
        self.assertEqual(Rx.f_dictionary["rx.bob@jabber.org"], '')

        # Teardown
        shutil.rmtree("keys")

    def test_3_disable_reception(self):

        # Setup
        create_me_keys(["alice", "bob"])
        create_rx_keys(["alice", "bob"])
        Rx.acco_store_f["me.alice@jabber.org"] = True
        Rx.acco_store_f["rx.alice@jabber.org"] = True
        Rx.acco_store_f["me.bob@jabber.org"] = True
        Rx.acco_store_f["rx.bob@jabber.org"] = True

        # Test
        self.assertIsNone(process_command("STORE|DISABLE"))
        self.assertFalse(Rx.acco_store_f["rx.alice@jabber.org"])
        self.assertFalse(Rx.acco_store_f["me.alice@jabber.org"])
        self.assertFalse(Rx.acco_store_f["rx.bob@jabber.org"])
        self.assertFalse(Rx.acco_store_f["me.bob@jabber.org"])

        # Teardown
        shutil.rmtree("keys")

    def test_4_enable_reception_for_contact(self):

        # Setup
        create_me_keys(["alice", "bob"])
        create_rx_keys(["alice", "bob"])
        Rx.acco_store_f["me.alice@jabber.org"] = False
        Rx.acco_store_f["rx.alice@jabber.org"] = False
        Rx.acco_store_f["me.bob@jabber.org"] = False
        Rx.acco_store_f["rx.bob@jabber.org"] = False

        # Test
        self.assertIsNone(process_command("STORE|ENABLE|rx.bob@jabber.org"))
        self.assertFalse(Rx.acco_store_f["rx.alice@jabber.org"])
        self.assertTrue(Rx.acco_store_f["rx.bob@jabber.org"])

        # Teardown
        shutil.rmtree("keys")

    def test_5_disable_reception_for_contact(self):

        # Setup
        create_me_keys(["alice", "bob"])
        create_rx_keys(["alice", "bob"])
        Rx.acco_store_f["me.alice@jabber.org"] = True
        Rx.acco_store_f["rx.alice@jabber.org"] = True
        Rx.acco_store_f["me.bob@jabber.org"] = True
        Rx.acco_store_f["rx.bob@jabber.org"] = True

        # Test
        self.assertIsNone(process_command("STORE|DISABLE|rx.bob@jabber.org"))
        self.assertTrue(Rx.acco_store_f["rx.alice@jabber.org"])
        self.assertFalse(Rx.acco_store_f["rx.bob@jabber.org"])

        # Teardown
        shutil.rmtree("keys")


class TestProcessLocalKey(unittest.TestCase):
    def test_1_input_parameters(self):
        for a in [1, 1.0, True]:
            for b in ["string", 1, 1.0]:
                with self.assertRaises(SystemExit):
                    process_local_key(a, b)

    def test_2_missing_parameter(self):

        packet = ("TFC|N|1605|L|S0/oPUk8UNKRpKddw6wfUw2tOTZA+SraOkP1wCzRBOaT0"
                  "BdWFEIl0Xhl4PdtrkGdMP8O4+skYSqnIvuB5vcfbN+QvjkVtquU1b74bve"
                  "880AdqM+1DHEWzdXsAbZW4z/p8iD+2S7WTXt67LA03XPzUhd8FnUIz6bF5"
                  "f7VTHNeG0rnJ6qyOofxroqpu4XjuWdXm8hSJv+ezPjUGviZlhNlhUT2vIC"
                  "k8daJs1+gBDcGOZIdIRrwnmTyk5v3QxeKcOjyDcOBTn5MFSGt2Q/WcRPcw"
                  "ph0cbJzaAVyQj1expHHnlksxJ7ac1MSEIvx5ykR/6TMMPzGqMtrNH0DpAQ"
                  "E00JmCyYoaZ1+LF8SmEQTI2i0NaTdKPpXa/wVDhvCbhQVIK9Fh0W7Tbo7|")

        self.assertIsNone(process_local_key(packet))

        # Teardown
        os.remove("syslog.tfc")

    def test_3_valid_packet_and_key(self):

        # Setup
        packet = ("TFC|N|1605|L|XWOoG8/0ZJd7zP56cMv48Cr/LyPYYP6PPtBp60IPkXQXz"
                  "9kR2pxJvAjA1Py70S3ffsmaNHeZ37q/qufQXB4IhCUoK0OJNZU+Me8XJQv"
                  "22NG5VPHMkffeVpBMybyeVs3A1wwDWajs/vPaEVaakMDirkbdzo9ONkqrH"
                  "FIDqJ2d2y8MOIkGjGz27WOj/Y2uHcpqF6KOCvpTkEzmZrAf4Ogby89e5aI"
                  "B5SvzrRJSwm7cihGfiPdcsRzfQ8pbiI584ZS99Jz8F2L4+03rIt+wuMC0b"
                  "/KgE9t1MDXRWEV3dNm7hMOzwbILe2GnAJX1HVSzEFkIBfGV8E19e2DnBJM"
                  "oP0hDiZxjWcQeiuCSX4qLU03opB+ENFYJK43o2+2wN4jZpzmb0tqJWtQu")
        original_raw_input = __builtins__.raw_input
        __builtins__.raw_input = lambda x: ((64 * 'b') + "f3ba0a38")

        # Test
        self.assertEquals(process_local_key(packet), "SUCCESS")
        local_key = open("keys/me.local.e").readline()
        self.assertEqual(local_key, 64 * 'a')

        # Teardown
        __builtins__.raw_input = original_raw_input
        shutil.rmtree('keys')
        os.remove(".rx_contacts")

    def test_4_b64_decoding_error(self):

        # Setup
        packet = ("TFC|N|1605|L|€WOoG8/0ZJd7zP56cMv48Cr/LyPYYP6PPtBp60IPkXQXz"
                  "9kR2pxJvAjA1Py70S3ffsmaNHeZ37q/qufQXB4IhCUoK0OJNZU+Me8XJQv"
                  "22NG5VPHMkffeVpBMybyeVs3A1wwDWajs/vPaEVaakMDirkbdzo9ONkqrH"
                  "FIDqJ2d2y8MOIkGjGz27WOj/Y2uHcpqF6KOCvpTkEzmZrAf4Ogby89e5aI"
                  "B5SvzrRJSwm7cihGfiPdcsRzfQ8pbiI584ZS99Jz8F2L4+03rIt+wuMC0b"
                  "/KgE9t1MDXRWEV3dNm7hMOzwbILe2GnAJX1HVSzEFkIBfGV8E19e2DnBJM"
                  "oP0hDiZxjWcQeiuCSX4qLU03opB+ENFYJK43o2+2wN4jZpzmb0tqJWtQu")

        original_raw_input = __builtins__.raw_input
        __builtins__.raw_input = lambda x: ((64 * 'b') + "f3ba0a38")

        # Test
        self.assertIsNone(process_local_key(packet))

        # Teardown
        __builtins__.raw_input = original_raw_input

    def test_5_mac_fail(self):

        # Setup
        packet = ("TFC|N|1605|L|aWOoG8/0ZJd7zP56cMv48Cr/LyPYYP6PPtBp60IPkXQXz"
                  "9kR2pxJvAjA1Py70S3ffsmaNHeZ37q/qufQXB4IhCUoK0OJNZU+Me8XJQv"
                  "22NG5VPHMkffeVpBMybyeVs3A1wwDWajs/vPaEVaakMDirkbdzo9ONkqrH"
                  "FIDqJ2d2y8MOIkGjGz27WOj/Y2uHcpqF6KOCvpTkEzmZrAf4Ogby89e5aI"
                  "B5SvzrRJSwm7cihGfiPdcsRzfQ8pbiI584ZS99Jz8F2L4+03rIt+wuMC0b"
                  "/KgE9t1MDXRWEV3dNm7hMOzwbILe2GnAJX1HVSzEFkIBfGV8E19e2DnBJM"
                  "oP0hDiZxjWcQeiuCSX4qLU03opB+ENFYJK43o2+2wN4jZpzmb0tqJWtQu")

        original_raw_input = __builtins__.raw_input
        __builtins__.raw_input = lambda x: ((64 * 'b') + "f3ba0a38")

        # Test
        self.assertIsNone(process_local_key(packet))

        # Teardown
        __builtins__.raw_input = original_raw_input

    def test_6_invalid_local_key(self):

        # Setup
        packet = ("TFC|N|1605|L|uvwEENF2ohEIG/CN/gqVZWK0Tqwc/zbcejmmqTU8cR3wQ"
                  "/BSWG5DFrfo7a69VaiPLkOgcxOnwdwmWwBtDp2ugphFAU9sm5PW7L6ojOe"
                  "Jd5WILMsqCorhx9uxZZUivCG8MZb+zF4C6cG11eZVbOHIpge4OwDDU49wn"
                  "LZ4sFO1t3TjVpq5Rm4WkDLeQb1Wloy784M4RCedLfb9YsYKPqmZ1AKHjww"
                  "LKiKs1n9xgXYclFnFsj2kMf4qXsQqyuPWfiXiMshCoJ/o0xOaB9c5jRAls"
                  "0zPuKCDL+VSz+0tBy9wf7/SOlKZ0plFlc+ddzc1P1Y0kM7kxoKcBGqHgJD"
                  "YlttunAAU79y9TDmw/rCt8rO0Ggk1N6k+AFe6hW8eE6NVJBN6JGgP8t/F")

        original_raw_input = __builtins__.raw_input
        __builtins__.raw_input = lambda x: ((64 * 'b') + "f3ba0a38")

        # Test
        self.assertIsNone(process_local_key(packet))

        # Teardown
        __builtins__.raw_input = original_raw_input


class TestGetLocalKeyPacket(unittest.TestCase):
    """
    This function doesn't have any tests yet.
    """


class TestMainLoopProcess(unittest.TestCase):
    """
    This function doesn't have any tests yet.
    """


class TestKDKInputProcess(unittest.TestCase):
    """
    This function doesn't have any tests yet.
    """


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
