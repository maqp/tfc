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
import multiprocessing
import os
import unittest

import nacl.bindings
import nacl.exceptions
import nacl.public
import nacl.utils

import argon2

from src.common.crypto  import sha3_256, blake2s, sha256, hash_chain, argon2_kdf
from src.common.crypto  import encrypt_and_sign, auth_and_decrypt
from src.common.crypto  import byte_padding, rm_padding_bytes, xor
from src.common.crypto  import csprng, check_kernel_entropy, check_kernel_version
from src.common.statics import *


class TestSHA3256(unittest.TestCase):

    def test_SHA3_256_KAT(self):
        """Run sanity check with official SHA3-256 KAT:
            csrc.nist.gov/groups/ST/toolkit/documents/Examples/SHA3-256_Msg0.pdf
        """
        self.assertEqual(sha3_256(b''),
                         binascii.unhexlify('a7ffc6f8bf1ed76651c14756a061d662'
                                            'f580ff4de43b49fa82d80a4b80f8434a'))


class TestBlake2s(unittest.TestCase):

    def test_blake2s_KAT(self):
        """Run sanity check with official Blake2s KAT:
            https://github.com/BLAKE2/BLAKE2/blob/master/testvectors/blake2s-kat.txt#L131

        in:   000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
        key:  000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
        hash: c03bc642b20959cbe133a0303e0c1abff3e31ec8e1a328ec8565c36decff5265
        """
        message = key = binascii.unhexlify('000102030405060708090a0b0c0d0e0f'
                                           '101112131415161718191a1b1c1d1e1f')

        self.assertEqual(blake2s(message, key),
                         binascii.unhexlify('c03bc642b20959cbe133a0303e0c1abf'
                                            'f3e31ec8e1a328ec8565c36decff5265'))


class TestSHA256(unittest.TestCase):

    def test_SHA256_KAT(self):
        """Run sanity check with official SHA256 KAT:
            http://csrc.nist.gov/groups/ST/toolkit/documents/Examples/SHA_All.pdf // page 14
        """
        self.assertEqual(sha256(b'abc'),
                         binascii.unhexlify('ba7816bf8f01cfea414140de5dae2223'
                                            'b00361a396177a9cb410ff61f20015ad'))


class TestHashChain(unittest.TestCase):

    def test_chain(self):
        """Sanity check after verifying function. No official test vectors exist."""
        self.assertEqual(hash_chain(bytes(32)),
                         binascii.unhexlify('8d8c36497eb93a6355112e253f705a32'
                                            '85f3e2d82b9ac29461cd8d4f764e5d41'))


class TestArgon2KDF(unittest.TestCase):

    def test_Argon2_KAT(self):
        """The official Argon2 implementation is at
                https://github.com/P-H-C/phc-winner-argon2#command-line-utility

        To re-produce the test vector, run
            $ wget https://github.com/P-H-C/phc-winner-argon2/archive/master.zip
            $ unzip master.zip
            $ cd phc-winner-argon2-master/
            $ make
            $ echo -n "password" | ./argon2 somesalt -t 1 -m 16 -p 4 -l 32 -d

        Expected output
            Type:		   Argon2d
            Iterations:	   1
            Memory:	       65536 KiB
            Parallelism:   4
            Hash:          7e12cb75695277c0ab974e4ae943b87da08e36dd065aca8de3ca009125ae8953
            Encoded:       $argon2d$v=19$m=65536,t=1,p=4$c29tZXNhbHQ$fhLLdWlSd8Crl05K6UO4faCONt0GWsqN48oAkSWuiVM
            0.231 seconds
            Verification ok
        """
        key = argon2.low_level.hash_secret_raw(secret=b'password', salt=b'somesalt', time_cost=1,
                                               memory_cost=65536, parallelism=4, hash_len=32, type=argon2.Type.D)
        self.assertEqual(binascii.hexlify(key), b'7e12cb75695277c0ab974e4ae943b87da08e36dd065aca8de3ca009125ae8953')

    def test_argon2_kdf(self):
        key, parallelism = argon2_kdf('password', ARGON2_SALT_LEN*b'a')
        self.assertIsInstance(key, bytes)
        self.assertEqual(len(key), KEY_LENGTH)
        self.assertEqual(parallelism, multiprocessing.cpu_count())

    def test_argon2_kdf_local_testing(self):
        key, parallelism = argon2_kdf('password', ARGON2_SALT_LEN*b'a', local_test=True)
        self.assertIsInstance(key, bytes)
        self.assertEqual(len(key), KEY_LENGTH)
        self.assertEqual(parallelism, max(multiprocessing.cpu_count()//2, 1))


class TestXSalsa20Poly1305(unittest.TestCase):
    """Test vectors:
        https://cr.yp.to/highspeed/naclcrypto-20090310.pdf // page 35
    """
    key_tv = binascii.unhexlify('1b27556473e985d4'
                                '62cd51197a9a46c7'
                                '6009549eac6474f2'
                                '06c4ee0844f68389')

    nonce_tv = binascii.unhexlify('69696ee955b62b73'
                                  'cd62bda875fc73d6'
                                  '8219e0036b7a0b37')

    pt_tv = binascii.unhexlify('be075fc53c81f2d5'
                               'cf141316ebeb0c7b'
                               '5228c52a4c62cbd4'
                               '4b66849b64244ffc'
                               'e5ecbaaf33bd751a'
                               '1ac728d45e6c6129'
                               '6cdc3c01233561f4'
                               '1db66cce314adb31'
                               '0e3be8250c46f06d'
                               'ceea3a7fa1348057'
                               'e2f6556ad6b1318a'
                               '024a838f21af1fde'
                               '048977eb48f59ffd'
                               '4924ca1c60902e52'
                               'f0a089bc76897040'
                               'e082f93776384864'
                               '5e0705')

    ct_tv = binascii.unhexlify('f3ffc7703f9400e5'
                               '2a7dfb4b3d3305d9'
                               '8e993b9f48681273'
                               'c29650ba32fc76ce'
                               '48332ea7164d96a4'
                               '476fb8c531a1186a'
                               'c0dfc17c98dce87b'
                               '4da7f011ec48c972'
                               '71d2c20f9b928fe2'
                               '270d6fb863d51738'
                               'b48eeee314a7cc8a'
                               'b932164548e526ae'
                               '90224368517acfea'
                               'bd6bb3732bc0e9da'
                               '99832b61ca01b6de'
                               '56244a9e88d5f9b3'
                               '7973f622a43d14a6'
                               '599b1f654cb45a74'
                               'e355a5')

    def test_encrypt_and_sign_with_kat(self):
        """Test encryption with official test vectors."""
        # Setup
        o_nacl_utils_random = nacl.utils.random
        nacl.utils.random   = lambda _: self.nonce_tv

        # Test
        self.assertEqual(encrypt_and_sign(self.pt_tv, self.key_tv), self.nonce_tv + self.ct_tv)

        # Teardown
        nacl.utils.random = o_nacl_utils_random

    def test_auth_and_decrypt_with_kat(self):
        """Test decryption with official test vectors."""
        self.assertEqual(auth_and_decrypt(self.nonce_tv + self.ct_tv, self.key_tv), self.pt_tv)

    def test_invalid_decryption_raises_critical_error(self):
        with self.assertRaises(SystemExit):
            self.assertEqual(auth_and_decrypt(self.nonce_tv + self.ct_tv, key=bytes(KEY_LENGTH)), self.pt_tv)

    def test_invalid_decryption_raises_soft_error(self):
        with self.assertRaises(nacl.exceptions.CryptoError):
            self.assertEqual(auth_and_decrypt(self.nonce_tv + self.ct_tv, key=bytes(KEY_LENGTH), soft_e=True), self.pt_tv)


class TestBytePadding(unittest.TestCase):

    def test_padding(self):
        for s in range(0, PADDING_LEN):
            string = s * b'm'
            padded = byte_padding(string)
            self.assertEqual(len(padded), PADDING_LEN)

            # Verify removal of padding doesn't alter the string
            self.assertEqual(string, padded[:-ord(padded[-1:])])

        for s in range(PADDING_LEN, 1000):
            string = s * b'm'
            padded = byte_padding(string)
            self.assertEqual(len(padded) % PADDING_LEN, 0)
            self.assertEqual(string, padded[:-ord(padded[-1:])])


class TestRmPaddingBytes(unittest.TestCase):

    def test_padding_removal(self):
        for i in range(0, 1000):
            string = os.urandom(i)
            length = PADDING_LEN - (len(string) % PADDING_LEN)
            padded = string + length * bytes([length])
            self.assertEqual(rm_padding_bytes(padded), string)


class TestXOR(unittest.TestCase):

    def test_length_mismatch_raises_critical_error(self):
        with self.assertRaises(SystemExit):
            xor(bytes(32), bytes(31))

    def test_xor_of_byte_strings(self):
        b1 = b'\x00\x01\x00\x01\x01'
        b2 = b'\x00\x00\x01\x01\x02'
        b3 = b'\x00\x01\x01\x00\x03'

        self.assertEqual(xor(b2, b3), b1)
        self.assertEqual(xor(b3, b2), b1)
        self.assertEqual(xor(b1, b3), b2)
        self.assertEqual(xor(b3, b1), b2)
        self.assertEqual(xor(b1, b2), b3)
        self.assertEqual(xor(b2, b1), b3)


class TestCSPRNG(unittest.TestCase):

    def test_travis_mock(self):
        # Setup
        o_environ  = os.environ
        os.environ = dict(TRAVIS='true')

        # Test
        self.assertEqual(len(csprng()), KEY_LENGTH)
        self.assertIsInstance(csprng(), bytes)

        # Teardown
        os.environ = o_environ

    def test_key_generation(self):
        self.assertEqual(len(csprng()), KEY_LENGTH)
        self.assertIsInstance(csprng(), bytes)


class TestCheckKernelEntropy(unittest.TestCase):

    def test_entropy_collection(self):
        self.assertIsNone(check_kernel_entropy())


class TestCheckKernelVersion(unittest.TestCase):

    def setUp(self):
        self.o_uname = os.uname

    def tearDown(self):
        os.uname = self.o_uname

    def test_invalid_kernel_versions_raise_critical_error(self):
        for version in ['3.9.0-52-generic', '4.7.0-52-generic']:
            os.uname = lambda: ['', '', version]

            with self.assertRaises(SystemExit):
                check_kernel_version()

    def test_valid_kernel_versions(self):
        for version in ['4.8.0-52-generic', '4.10.0-52-generic', '5.0.0-52-generic']:
            os.uname = lambda: ['', '', version]

            self.assertIsNone(check_kernel_version())


class TestX25519(unittest.TestCase):
    """\
    This test does not utilize functions in src.common.crypto
    module, but tests PyNaCl's X25519 used in key exchanges.

    Test vectors for X25519

        https://tools.ietf.org/html/rfc7748#section-6.1

        Alice's private key, a:
          77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a
        Alice's public key, X25519(a, 9):
          8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a
        Bob's private key, b:
          5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb
        Bob's public key, X25519(b, 9):
          de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f
        Their shared secret, K:
          4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742

    Quoting PyNaCl tests:
      "Since libNaCl/libsodium shared key generation adds an HSalsa20
       key derivation pass on the raw shared Diffie-Hellman key, which
       is not exposed by itself, we just check the shared key for equality."

    TOFU style, unofficial KAT / sanity check shared secret test vector is
      1b27556473e985d462cd51197a9a46c76009549eac6474f206c4ee0844f68389
    """

    def test_x25519(self):
        # Setup
        tv_sk_a = binascii.unhexlify('77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a')
        tv_pk_a = binascii.unhexlify('8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a')
        tv_sk_b = binascii.unhexlify('5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb')
        tv_pk_b = binascii.unhexlify('de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f')
        ssk     = binascii.unhexlify('1b27556473e985d462cd51197a9a46c76009549eac6474f206c4ee0844f68389')

        # Generate known key pair for Alice
        sk_alice = nacl.public.PrivateKey(tv_sk_a)
        self.assertEqual(sk_alice._private_key, tv_sk_a)
        self.assertEqual(bytes(sk_alice.public_key), tv_pk_a)

        # Generate known key pair for Bob
        sk_bob = nacl.public.PrivateKey(tv_sk_b)
        self.assertEqual(sk_bob._private_key, tv_sk_b)
        self.assertEqual(bytes(sk_bob.public_key), tv_pk_b)

        # Test shared secrets are equal
        dh_box_a = nacl.public.Box(sk_alice, sk_bob.public_key)
        dh_ssk_a = dh_box_a.shared_key()

        dh_box_b = nacl.public.Box(sk_bob, sk_alice.public_key)
        dh_ssk_b = dh_box_b.shared_key()

        self.assertEqual(dh_ssk_a, ssk)
        self.assertEqual(dh_ssk_b, ssk)


if __name__ == '__main__':
    unittest.main(exit=False)
