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

import binascii
import os
import unittest

import nacl.exceptions
import nacl.utils

from src.common.crypto import sha3_256, blake2s, sha256, hash_chain, argon2_kdf, encrypt_and_sign, auth_and_decrypt
from src.common.crypto import unicode_padding, byte_padding, rm_padding_bytes, rm_padding_str, xor, keygen, init_entropy


class TestSHA3256(unittest.TestCase):

    def test_SHA3_256_KAT(self):
        """\
        Run sanity check with official SHA3-256 KAT:
        csrc.nist.gov/groups/ST/toolkit/documents/Examples/SHA3-256_Msg0.pdf
        """
        self.assertEqual(sha3_256(b''),
                         binascii.unhexlify("a7ffc6f8bf1ed76651c14756a061d662"
                                            "f580ff4de43b49fa82d80a4b80f8434a"))


class TestBlake2s(unittest.TestCase):

    def test_blake2s_KAT(self):
        """\
        Run sanity check with official Blake2s KAT:
        https://github.com/BLAKE2/BLAKE2/blob/master/testvectors/blake2s-kat.txt
        """
        data = key = binascii.unhexlify("000102030405060708090a0b0c0d0e0f"
                                        "101112131415161718191a1b1c1d1e1f")

        self.assertEqual(blake2s(data, key),
                         binascii.unhexlify("c03bc642b20959cbe133a0303e0c1abf"
                                            "f3e31ec8e1a328ec8565c36decff5265"))


class TestSHA256(unittest.TestCase):

    def test_SHA256_KAT(self):
        """\
        Run sanity check with official SHA256 KAT:
        http://csrc.nist.gov/groups/ST/toolkit/documents/Examples/SHA_All.pdf // page 14
        """
        self.assertEqual(sha256(b"abc"),
                         binascii.unhexlify("ba7816bf8f01cfea414140de5dae2223"
                                            "b00361a396177a9cb410ff61f20015ad"))


class TestHashChain(unittest.TestCase):

    def test_chain(self):
        """Sanity check after verifying function. No official vectors are available."""
        self.assertEqual(hash_chain(bytes(32)),
                         binascii.unhexlify("8d8c36497eb93a6355112e253f705a32"
                                            "85f3e2d82b9ac29461cd8d4f764e5d41"))


class TestArgon2KDF(unittest.TestCase):

    def test_Argon2_KAT(self):
        """\
        The Argon2 KAT vectors are available at
        https://tools.ietf.org/html/draft-irtf-cfrg-argon2-01#section-6.2

        However, the python bindings of argon2 package do not allow associated
        data to be input to the function, thus KAT can not be performed.
        """
        pass

    @unittest.skipIf("TRAVIS" in os.environ and os.environ["TRAVIS"] == "true", "Skipping this test on Travis CI.")
    def test_sanity_check(self):
        key, mem = argon2_kdf("test_password", salt=bytes(32), rounds=1, memory=128000, parallelism=1)

        self.assertEqual(mem, 128000)
        self.assertEqual(key.hex(), "73883b6b2ea60d0adf27fb52e1f41af4"
                                    "29bfe8a0d79ae4a2f87be6c4d73e6a11")

    def test_autoconf_sanity_check(self):
        key, mem = argon2_kdf("test_password", salt=bytes(32), rounds=1)

        self.assertIsInstance(key, bytes)
        self.assertIsInstance(mem, int)


    def test_local_testing_sanity_check(self):
        key, mem = argon2_kdf("test_password", salt=bytes(32), rounds=1, local_testing=True)

        self.assertIsInstance(key, bytes)
        self.assertIsInstance(mem, int)


class TestXSalsa20Poly1305(unittest.TestCase):
    """\
    Test vectors:
    https://cr.yp.to/highspeed/naclcrypto-20090310.pdf // page 35 
    """
    nonce = binascii.unhexlify("69696ee955b62b73"
                               "cd62bda875fc73d6"
                               "8219e0036b7a0b37")

    key_tv = binascii.unhexlify("1b27556473e985d4"
                                "62cd51197a9a46c7"
                                "6009549eac6474f2"
                                "06c4ee0844f68389")

    pt_tv = binascii.unhexlify("be075fc53c81f2d5"
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

    ct_tv = binascii.unhexlify("f3ffc7703f9400e5"
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

    def test_encrypt_and_sign_with_kat(self):
        """Test encryption with official test vectors"""
        # Setup
        o_nacl_utils_random = nacl.utils.random
        nacl.utils.random   = lambda x: self.nonce

        # Test
        self.assertEqual(encrypt_and_sign(self.pt_tv, self.key_tv), self.nonce + self.ct_tv)

        # Teardown
        nacl.utils.random = o_nacl_utils_random

    def test_auth_and_decrypt_with_kat(self):
        """Test decryption with official test vectors"""
        self.assertEqual(auth_and_decrypt(self.nonce + self.ct_tv, self.key_tv), self.pt_tv)

    def test_invalid_decryption_raises_critical_error(self):
        with self.assertRaises(SystemExit):
            self.assertEqual(auth_and_decrypt(self.nonce + self.ct_tv, bytes(32)), self.pt_tv)

    def test_invalid_decryption_raises_soft_error(self):
        with self.assertRaises(nacl.exceptions.CryptoError):
            self.assertEqual(auth_and_decrypt(self.nonce + self.ct_tv, bytes(32), soft_e=True), self.pt_tv)


class TestUnicodePadding(unittest.TestCase):

    def test_padding_with_length_check(self):
        for s in range(0, 255):
            string = s * 'm'
            padded = unicode_padding(string)
            self.assertEqual(len(padded), 255)

            # Verify removal of padding doesn't alter the string.
            self.assertEqual(string, padded[:-ord(padded[-1:])])

    def test_oversize_pt(self):
        for s in range(255, 260):
            with self.assertRaises(AssertionError):
                unicode_padding(s * 'm')


class TestBytePadding(unittest.TestCase):

    def test_padding_with_length_check(self):
        for s in range(0, 255):
            string = s * b'm'
            padded = byte_padding(string)
            self.assertEqual(len(padded), 255)

            # Verify removal of padding doesn't alter the string.
            self.assertEqual(string, padded[:-ord(padded[-1:])])


class TestRmPaddingBytes(unittest.TestCase):

    def test_function(self):
        for i in range(0, 1000):
            string = i * b'm'
            length = 255 - (len(string) % 255)
            padded = string + length * bytes([length])
            self.assertEqual(rm_padding_bytes(padded), string)


class TestRmPaddingStr(unittest.TestCase):

    def test_function(self):
        for i in range(0, 1000):
            string = i * 'm'
            length = 255 - (len(string) % 255)
            padded = string + length * chr(length)
            self.assertEqual(rm_padding_str(padded), string)


class TestXOR(unittest.TestCase):

    def test_length_mismatch(self):
        with self.assertRaises(SystemExit):
            xor(bytes(32), bytes(31))

    def test_function(self):
        b1 = b'\x00\x01\x00\x01\x01'
        b2 = b'\x00\x00\x01\x01\x02'
        b3 = b'\x00\x01\x01\x00\x03'
        self.assertEqual(xor(b1, b2), b3)


class TestKeyGen(unittest.TestCase):

    def test_function(self):
        self.assertEqual(len(keygen()), 32)
        self.assertIsInstance(keygen(), bytes)


class TestInitEntropy(unittest.TestCase):

    def test_function(self):
        self.assertIsNone(init_entropy())


if __name__ == '__main__':
    unittest.main(exit=False)
