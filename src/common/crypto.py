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

import hashlib
import multiprocessing
import os

from typing import Tuple

import argon2
import nacl.encoding
import nacl.exceptions
import nacl.public
import nacl.secret
import nacl.utils

from src.common.exceptions import CriticalError
from src.common.misc       import ignored
from src.common.output     import c_print, clear_screen, phase, print_on_previous_line
from src.common.statics    import *


def sha3_256(message: bytes) -> bytes:
    """Generate SHA3-256 digest from message."""
    return hashlib.sha3_256(message).digest()


def blake2s(message: bytes, key: bytes = b'') -> bytes:
    """Generate Blake2s digest from message."""
    return hashlib.blake2s(message, key=key).digest()


def sha256(message: bytes) -> bytes:
    """Generate SHA256 digest from message."""
    return hashlib.sha256(message).digest()


def hash_chain(message: bytes) -> bytes:
    """Mix several hash functions to distribute trust.

    This construction remains secure in case a weakness is discovered
    in one of the hash functions (e.g. insecure algorithm that is not
    unpredictable or that has weak preimage resistance, or if the
    algorithm is badly implemented).

    In case where the implementation is malicious, this construction
    forces stateless implementations  -- that try to compromise mixing
    phase -- to guess it's position in the construction, which will
    eventually lead to key state mismatch and thus detection.
    """
    d1 = sha3_256(blake2s(sha256(message)))
    d2 = sha3_256(sha256(blake2s(message)))

    d3 = blake2s(sha3_256(sha256(message)))
    d4 = blake2s(sha256(sha3_256(message)))

    d5 = sha256(blake2s(sha3_256(message)))
    d6 = sha256(sha3_256(blake2s(message)))

    d7 = sha3_256(message)
    d8 = blake2s(message)
    d9 = sha256(message)

    # Mixing phase
    x1 = xor(d1, d2)
    x2 = xor(x1, d3)
    x3 = xor(x2, d4)
    x4 = xor(x3, d5)
    x5 = xor(x4, d6)
    x6 = xor(x5, d7)
    x7 = xor(x6, d8)
    x8 = xor(x7, d9)

    return x8


def argon2_kdf(password:    str,
               salt:        bytes,
               rounds:      int  = ARGON2_ROUNDS,
               memory:      int  = ARGON2_MIN_MEMORY,
               parallelism: int  = None,
               local_test:  bool = False) -> Tuple[bytes, int]:
    """Derive key from password and salt using Argon2d (PHC winner).

    :param password:    Password to derive key from
    :param salt:        Salt to derive key from
    :param rounds:      Number of iterations
    :param memory:      Memory usage
    :param parallelism: Number of threads to use
    :param local_test:  When True, splits parallelism to half
    :return:            Derived key, amount of memory and number of threads used
    """
    assert len(salt) == ARGON2_SALT_LEN

    if parallelism is None:
        parallelism = multiprocessing.cpu_count()
        if local_test:
            parallelism = max(1, parallelism // 2)

    key = argon2.low_level.hash_secret_raw(secret=password.encode(),
                                           salt=salt,
                                           time_cost=rounds,
                                           memory_cost=memory,
                                           parallelism=parallelism,
                                           hash_len=KEY_LENGTH,
                                           type=argon2.Type.D)
    return key, parallelism


def encrypt_and_sign(plaintext: bytes, key: bytes) -> bytes:
    """Encrypt plaintext with XSalsa20-Poly1305.

    :param plaintext: Plaintext to encrypt
    :param key:       32-byte key
    :return:          Ciphertext + tag
    """
    assert len(key) == KEY_LENGTH

    secret_box = nacl.secret.SecretBox(key)
    nonce      = nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE)
    return bytes(secret_box.encrypt(plaintext, nonce))


def auth_and_decrypt(nonce_ct_tag: bytes,
                     key:          bytes,
                     soft_e:       bool = False) -> bytes:
    """Authenticate and decrypt XSalsa20-Poly1305 ciphertext.

    :param nonce_ct_tag: Nonce, ciphertext and tag
    :param key:          32-byte key
    :param soft_e:       When True, raises soft error
    :return:             Plaintext
    """
    assert len(key) == KEY_LENGTH

    try:
        secret_box = nacl.secret.SecretBox(key)
        return secret_box.decrypt(nonce_ct_tag)
    except nacl.exceptions.CryptoError:
        if not soft_e:
            raise CriticalError("Ciphertext MAC fail.")
        raise


def byte_padding(string: bytes) -> bytes:
    """Pad byte string to next 255 bytes.

    Padding of output messages hides plaintext length and contributes
    to traffic flow confidentiality when traffic masking is enabled.

    :param string: String to be padded
    :return:       Padded string
    """
    length  = PADDING_LEN - (len(string) % PADDING_LEN)
    string += length * bytes([length])

    assert len(string) % PADDING_LEN == 0

    return string


def rm_padding_bytes(string: bytes) -> bytes:
    """Remove padding from plaintext.

    The length of padding is determined by the ord-value
    of last character that is always part of padding.

    :param string: String from which padding is removed
    :return:       String without padding
    """
    return string[:-ord(string[-1:])]


def xor(string1: bytes, string2: bytes) -> bytes:
    """XOR two byte strings together."""
    if len(string1) != len(string2):
        raise CriticalError("String length mismatch.")

    return b''.join([bytes([b1 ^ b2]) for b1, b2 in zip(string1, string2)])


def csprng() -> bytes:
    """Generate a cryptographically secure, 256-bit random key.

    Key is generated with kernel CSPRNG, the output of which is further
    compressed with hash_chain. This increases preimage resistance that
    protects the internal state of the entropy pool. Additional hashing
    is done as per the recommendation of djb:
        https://media.ccc.de/v/32c3-7210-pqchacks#video&t=1116

    Since Python3.6.0, os.urandom is a wrapper for best available
    CSPRNG. The 3.17 and earlier versions of Linux kernel do not support
    the GETRANDOM call, and Python3.6's os.urandom will in those cases
    fallback to non-blocking /dev/urandom that is not secure on live
    distros as they have low entropy at the start of the session.

    TFC uses os.getrandom(32, flags=0) explicitly. This forces use of
    recent enough Python interpreter (3.6 or later) and limits Linux
    kernel version to 3.17 or later.* The flag 0 will block urandom if
    internal state of CSPRNG has less than 128 bits of entropy.

    * Since kernel 4.8, ChaCha20 has replaced SHA-1 as the compressor
      for /dev/urandom. As a good practice, TFC runs the
      check_kernel_version to ensure minimum version is actually 4.8,
      not 3.17.

    :return: Cryptographically secure 256-bit random key
    """
    # As Travis CI lacks GETRANDOM syscall, fallback to urandom.
    if 'TRAVIS' in os.environ and os.environ['TRAVIS'] == 'true':
        entropy = os.urandom(KEY_LENGTH)
    else:
        entropy = os.getrandom(KEY_LENGTH, flags=0)

    assert len(entropy) == KEY_LENGTH

    return hash_chain(entropy)


def check_kernel_entropy() -> None:
    """Wait until Kernel CSPRNG is sufficiently seeded.

    Wait until entropy_avail file states that system has at least 512
    bits of entropy. The headroom allows room for error in accuracy of
    entropy collector's entropy estimator; As long as input has at least
    4 bits per byte of actual entropy, kernel CSPRNG will be sufficiently
    seeded when it generates 256-bit keys.
    """
    clear_screen()
    phase("Waiting for Kernel CSPRNG entropy pool to fill up", head=1)

    ent_avail = 0
    while ent_avail < ENTROPY_THRESHOLD:
        with ignored(EOFError, KeyboardInterrupt):
            with open('/proc/sys/kernel/random/entropy_avail') as f:
                value = f.read()
            ent_avail = int(value.strip())
            c_print(f"{ent_avail}/{ENTROPY_THRESHOLD}")
            print_on_previous_line(delay=0.1)

    print_on_previous_line()
    phase("Waiting for Kernel CSPRNG entropy pool to fill up")
    phase(DONE)


def check_kernel_version() -> None:
    """Check that the Linux kernel version is at least 4.8.

    This check ensures that TFC only runs on Linux kernels that use
    the new ChaCha20 based CSPRNG: https://lkml.org/lkml/2016/7/25/43
    """
    major_v, minor_v = [int(i) for i in os.uname()[2].split('.')[:2]]

    if major_v < 4 or (major_v == 4 and minor_v < 8):
        raise CriticalError("Insecure kernel CSPRNG version detected.")
