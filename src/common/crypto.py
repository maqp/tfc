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

from typing import Any, Optional, Tuple

import argon2
import nacl.encoding
import nacl.exceptions
import nacl.public
import nacl.secret
import nacl.utils

from src.common.errors import CriticalError
from src.common.misc   import clear_screen
from src.common.output import c_print, phase, print_on_previous_line


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
    """Distribute trust on possibly untrustworthy hash functions.

    In case where the the hash algorithm or implementation of it is not secure,
    this construction prevents single hash function that outputs a low entropy
    digest from compromising the entire construct. It also distributes trust
    of pre-image resistance on multiple algorithms. Finally, by creating digests
    in multiple orders, an individual malicious, stateless hash function is unable
    to reliably determine what kind of value it should output in order to
    compromise the mixing phase. A malicious algorithm guessing it's position
    in construction will eventually cause a key state mismatch.
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


def argon2_kdf(password:      str,
               salt:          bytes,
               rounds:        int,
               memory:        int  = None,
               parallelism:   int  = None,
               local_testing: bool = False) -> Tuple[Any, Optional[int]]:
    """Derive key from password and salt using Argon2 (PHC winner).

    Adjust parallelism and memory automatically.

    During local testing, drop resource requirements
    in half to allow simultaneous login on Tx/Rx side.
    """
    if parallelism is None:
        parallelism = multiprocessing.cpu_count()
        if local_testing:
            parallelism = max(1, parallelism // 2)

    if memory is None:
        with open('/proc/meminfo') as f:
            mem_avail = int(f.readlines()[2].split()[1])
            memory    = max(128000, mem_avail)  # Fail-safe in case available memory is low.
            if local_testing:
                memory //= 2

    # Reduce amount of memory required under Travis to avoid ARGON2_MEMORY_ALLOCATION_ERROR.
    if "TRAVIS" in os.environ and os.environ["TRAVIS"] == "true":
        memory = 1024

    return argon2.argon2_hash(password, salt, t=rounds, m=memory, p=parallelism, buflen=32), memory


def encrypt_and_sign(plaintext: bytes, key: bytes) -> bytes:
    """Encrypt plaintext string with XSalsa20-Poly1305 using 192-bit nonce and 256-bit key.

    :param plaintext: Plaintext to encrypt
    :param key:       32-byte key
    :return:          Ciphertext + tag
    """
    secret_box = nacl.secret.SecretBox(key)
    nonce      = nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE)
    return bytes(secret_box.encrypt(plaintext, nonce))


def auth_and_decrypt(nonce_ct_tag: bytes, key: bytes, soft_e: bool = False) -> bytes:
    """Authenticate and decrypt XSalsa20-Poly1305 ciphertext.

    :param nonce_ct_tag: Nonce, ciphertext and tag
    :param key:          32-byte key
    :param soft_e:       When True, raises CryptoError instead of graceful exit
    :return:             Plaintext
    """
    try:
        secret_box = nacl.secret.SecretBox(key)
        return secret_box.decrypt(nonce_ct_tag)
    except nacl.exceptions.CryptoError:
        if not soft_e:
            raise CriticalError("Ciphertext MAC fail.")
        raise


def unicode_padding(string: str) -> str:
    """Pad unicode string to 255 chars.

    Database fields are padded with unicode chars and then encoded
    with UTF-32 to hide any metadata about plaintext field length.

    :param string: String to be padded
    :return:       Padded string
    """
    assert len(string) <= 254

    length  = 255 - (len(string) % 255)
    string += length * chr(length)

    assert len(string) == 255

    return string


def byte_padding(string: bytes) -> bytes:
    """Pad input bytes to packet max size (255 bytes).

    Output data is encoded with UTF-8 to speed up transmission over serial
    interface. In normal mode padding hides maximum length of message and
    during trickle connection because each ciphertext will have constant
    length, it hides when data transmission takes place.

    :param string: String to be padded
    :return:       Padded string
    """
    length  = 255 - (len(string) % 255)
    string += length * bytes([length])

    assert len(string) % 255 == 0

    return string


def rm_padding_bytes(string: bytes) -> bytes:
    """Remove padding from plaintext.

    The length of padding is determined by the ord-value
    of last character that is always a padding character.

    :param string: String from which padding is removed
    :return:       String without padding
    """
    return string[:-ord(string[-1:])]


def rm_padding_str(string: str) -> str:
    """Remove padding from plaintext.

    :param string: String from which padding is removed
    :return:       String without padding
    """
    return string[:-ord(string[-1:])]


def xor(string1: bytes, string2: bytes) -> bytes:
    """XOR two byte-strings together."""
    if len(string1) != len(string2):
        raise CriticalError("String length mismatch.")

    parts = []
    for b1, b2 in zip(string1, string2):
        parts.append(bytes([b1 ^ b2]))
    return b''.join(parts)


def keygen() -> bytes:
    """Generate list of random keys for use in different encryption functions.

    Hash chain is used to add strong pre-image resistance to internal state or
    /dev/urandom that that only uses SHA1 to compress output.

    As of Python3.6.0, os.urandom is a wrapper for best available CSPRNG. Linux
    3.17 and older kernels do not support the GETRANDOM call, thus on such
    kernels, Python3.6's os.urandom will fallback to non-blocking /dev/urandom
    that is not secure on live distros that have low entropy at the start of
    session.

    TFC uses os.getrandom(32, flags=0) explicitly. This forces the version of
    Python interpreter to version 3.6 or later and Linux kernel version to 3.17
    or later. The flag 0 will block urandom if internal state has less than 128
    bits of entropy. Secure key entropy is thus enforced on all platforms.

    Since kernel 4.8, /dev/urandom has been upgraded to use ChaCha20 instead
    of SHA1.

    :return: Cryptographically secure 256-bit random key
    """
    # Fallback to urandom on Travis' Python3.6 that currently lacks os.getrandom call.
    if "TRAVIS" in os.environ and os.environ["TRAVIS"] == "true":
        return hash_chain(os.urandom(32))
    else:
        return hash_chain(os.getrandom(32, flags=0))


def init_entropy() -> None:
    """Wait until Kernel CSPRNG is sufficiently seeded.

    Wait until entropy_avail file states that system has at least 512 bits of
    entropy. The headroom allows room for error in accuracy of entropy
    collector's entropy estimator; As long as input has at least 4 bits per
    byte of actual entropy, /dev/urandom will be sufficiently seeded when
    it is allowed to generate keys.
    """
    clear_screen()
    phase("Waiting for Kernel CSPRNG random pool to fill up", head=1)

    ent_avail = 0
    threshold = 512

    while ent_avail < threshold:
        try:
            with open('/proc/sys/kernel/random/entropy_avail') as f:
                value = f.read()
            ent_avail = int(value.strip())
            c_print("{}/{}".format(ent_avail, threshold))
            print_on_previous_line(delay=0.01)
        except (KeyboardInterrupt, EOFError):
            pass

    print_on_previous_line()
    phase("Waiting for Kernel CSPRNG random pool to fill up")
    phase("Done")
