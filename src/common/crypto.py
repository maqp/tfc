#!/usr/bin/env python3.6
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

---

This module contains TFC's cryptographic functions. Most algorithms are 
based on the ChaCha20 stream cipher by Daniel J. Bernstein (djb).

X448
ChaCha20
├─ Linux kernel CSPRNG
├─ XChaCha20-Poly1305 (IETF) AEAD
└─ BLAKE2b cryptographic hash function
   └─ Argon2d key derivation function
"""

import hashlib
import os

import argon2
import nacl.bindings
import nacl.exceptions
import nacl.secret
import nacl.utils

from cryptography.hazmat.primitives.asymmetric.x448 import X448PrivateKey, X448PublicKey
from cryptography.hazmat.primitives.serialization   import Encoding, PublicFormat

from src.common.exceptions import CriticalError
from src.common.misc       import ignored, separate_header
from src.common.output     import m_print, phase, print_on_previous_line
from src.common.statics    import *


def blake2b(message:     bytes,                        # Message to hash
            key:         bytes = b'',                  # Key for keyed hashing
            salt:        bytes = b'',                  # Salt for randomized hashing
            person:      bytes = b'',                  # Personalization string
            digest_size: int   = BLAKE2_DIGEST_LENGTH  # Length of the digest
            ) -> bytes:                                # The BLAKE2b digest
    """Generate BLAKE2b digest (i.e. cryptographic hash) of a message.

    BLAKE2 is the successor of SHA3-finalist BLAKE*, designed by
    Jean-Philippe Aumasson, Samuel Neves, Zooko Wilcox-O'Hearn and
    Christian Winnerlein. The hash function is based on the ChaCha20
    stream cipher, designed by djb.

    * BLAKE was designed by Jean-Philippe Aumasson, Luca Henzen,
      Willi Meier, and Raphael C.-W. Phan.

    For more details, see
        https://blake2.net/
        https://leastauthority.com/blog/BLAKE2-harder-better-faster-stronger-than-MD5/

    The reasons for using BLAKE2b in TFC include

        o BLAKE received* more in-depth cryptanalysis than Keccak (SHA3):

          "Keccak received a significant amount of cryptanalysis,
           although not quite the depth of analysis applied to BLAKE,
           Grøstl, or Skein."
           (https://nvlpubs.nist.gov/nistpubs/ir/2012/NIST.IR.7896.pdf  # p. 13)

          * https://blake2.net/#cr

        o BLAKE shares design elements with SHA-2 that has 16 years of
          cryptanalysis behind it.
          (https://en.wikipedia.org/wiki/SHA-2#Cryptanalysis_and_validation)

        o 128-bit collision/preimage/second-preimage resistance against
          Grover's algorithm running on a quantum Turing machine.

        o The algorithm is bundled in Python3.6's hashlib.

        o Compared to SHA3-256, the algorithm runs faster on CPUs which
          means better hash ratchet performance.

        o Compared to SHA3-256, the algorithm runs slower on ASICs which
          means attacks by high-budget adversaries are slower.

    Note that while the default length of BLAKE2b (the implementation
    optimized for AMD64 systems) digest is 512 bits, the digest size is
    truncated to 256 bits for the use in TFC.

    The correctness of the BLAKE2b implementation* is tested by TFC unit
    tests. The testing is done in limited scope by using an official KAT.

    * https://github.com/python/cpython/tree/3.6/Modules/_blake2
      https://github.com/python/cpython/blob/3.6/Lib/hashlib.py
    """
    return hashlib.blake2b(message, digest_size=digest_size, key=key, salt=salt, person=person).digest()


def argon2_kdf(password:    str,                      # Password to derive the key from
               salt:        bytes,                    # Salt to derive the key from
               rounds:      int = ARGON2_ROUNDS,      # Number of iterations
               memory:      int = ARGON2_MIN_MEMORY,  # Amount of memory to use (in bytes)
               parallelism: int = 1                   # Number of threads to use
               ) -> bytes:                            # The derived key
    """Derive an encryption key from password and salt using Argon2d.

    Argon2 is a key derivation function (KDF) designed by Alex Biryukov,
    Daniel Dinu, and Dmitry Khovratovich from the University of
    Luxembourg. The algorithm is the winner of the 2015 Password Hashing
    Competition (PHC).

    For more details, see
        https://password-hashing.net/
        https://github.com/P-H-C/phc-winner-argon2/blob/master/argon2-specs.pdf
        https://en.wikipedia.org/wiki/Argon2

    The purpose of the KDF is to stretch a password into a 256-bit key.
    Argon2 features a slow, memory-hard hash function that consumes
    computational resources of an attacker that attempts a dictionary
    or a brute force attack. The accompanied 256-bit salt prevents
    rainbow-table attacks, forcing each attack to take place against an
    individual (physically compromised) TFC-endpoint, or PSK
    transmission media.

    The used Argon2 version is Argon2d that uses data-dependent memory
    access, which maximizes security against time-memory trade-off
    (TMTO) attacks at the risk of side-channel attacks. The IETF
    recommends using Argon2id (that is side-channel resistant and almost
    as secure as Argon2d against TMTO attacks) **except** when there is
    a reason to prefer Argon2d (or Argon2i). The reason TFC uses Argon2d
    is key derivation only takes place on Source and Destination
    Computer. As these computers are connected to the Networked Computer
    only via a data diode, they do not leak any information via
    side-channels to the adversary. The expected attacks are against
    physically compromised data storage devices where the encrypted data
    is at rest. In such situation, Argon2d is the most secure option.

    The correctness of the Argon2d implementation* is tested by TFC unit
    tests. The testing is done in limited scope by using an official KAT.

    * https://github.com/P-H-C/phc-winner-argon2
      https://github.com/hynek/argon2_cffi
    """
    if len(salt) != ARGON2_SALT_LENGTH:
        raise CriticalError("Invalid salt length.")

    key = argon2.low_level.hash_secret_raw(secret=password.encode(),
                                           salt=salt,
                                           time_cost=rounds,
                                           memory_cost=memory,
                                           parallelism=parallelism,
                                           hash_len=SYMMETRIC_KEY_LENGTH,
                                           type=argon2.Type.D)  # type: bytes
    return key


class X448(object):
    """
    X448 is the Diffie-Hellman function for Curve448-Goldilocks, a
    state-of-the-art elliptical curve designed by Mike Hamburg in 2014:
        https://eprint.iacr.org/2015/625.pdf

    The reasons for using X448 in TFC include

        o It meets the criterion for a safe curve.
          (https://safecurves.cr.yp.to/)

        o NIST has announced X448 will be included in the SP 800-186.
          (https://csrc.nist.gov/News/2017/Transition-Plans-for-Key-Establishment-Schemes)

        o It provides conservative 224 bits of symmetric security.

        o It is immune against invalid curve attacks: Its public keys do
          not require validation as long as the public key is not zero.

        o Its public keys are reasonably short (84 Base58 chars) to be
          manually typed from Networked Computer to Source Computer.

    The correctness of the X448 implementation* is tested by TFC unit
    tests. The testing is done in limited scope by using official test
    vectors.

    * https://github.com/openssl/openssl/tree/OpenSSL_1_1_1-stable/crypto/ec/curve448
      https://github.com/pyca/cryptography/blob/master/src/cryptography/hazmat/primitives/asymmetric/x448.py
    """
    @staticmethod
    def generate_private_key() -> 'X448PrivateKey':
        """Generate the X448 private key.

        The size of the private key is 56 bytes (448 bits).
        """
        return X448PrivateKey.generate()

    @staticmethod
    def derive_public_key(private_key: 'X448PrivateKey') -> bytes:
        """Derive public key from X448 private key."""
        public_key = private_key.public_key().public_bytes(encoding=Encoding.Raw,
                                                           format=PublicFormat.Raw)  # type: bytes
        return public_key

    @staticmethod
    def shared_key(private_key: 'X448PrivateKey', public_key: bytes) -> bytes:
        """Derive the X448 shared key.

        Since the shared secret is zero if contact's public key is zero,
        this function checks the public key is a valid non-zero
        bytestring.

        Because the raw bits of the X448 shared secret might not be
        uniformly distributed in the keyspace (i.e. bits might have bias
        towards 0 or 1), the raw shared secret is passed through BLAKE2b
        CSPRF to ensure uniformly random shared key.
        """
        if len(public_key) != TFC_PUBLIC_KEY_LENGTH:
            raise CriticalError("Invalid public key length.")

        if public_key == bytes(TFC_PUBLIC_KEY_LENGTH):
            raise CriticalError("Received zero public key.")

        shared_secret = private_key.exchange(X448PublicKey.from_public_bytes(public_key))
        return blake2b(shared_secret, digest_size=SYMMETRIC_KEY_LENGTH)


def encrypt_and_sign(plaintext: bytes,       # Plaintext to encrypt
                     key:       bytes,       # 32-byte symmetric key
                     ad:        bytes = b''  # Associated data
                     ) -> bytes:             # Nonce + ciphertext + tag
    """Encrypt plaintext with XChaCha20-Poly1305.

    ChaCha20 is a stream cipher published by Daniel J. Bernstein (djb)
    in 2008. The algorithm is an improved version of Salsa20 -- another
    stream cipher by djb -- selected by ECRYPT into the eSTREAM
    portfolio in 2008. The improvement in question is, ChaCha20
    increases the per-round diffusion compared to Salsa20 while
    maintaining or increasing speed.

    For more details, see
        https://cr.yp.to/chacha/chacha-20080128.pdf
        https://en.wikipedia.org/wiki/Salsa20#ChaCha_variant

    The Poly1305 is a Wegman-Carter Message Authentication Code also
    designed by djb. The MAC is provably secure if ChaCha20 is secure.
    The 128-bit tag space ensures the attacker's advantage to create an
    existential forgery is negligible.

    For more details, see
        https://cr.yp.to/mac.html

    The version used in TFC is the XChaCha20-Poly1305-IETF*, a variant
    of the ChaCha20-Poly1305-IETF (RFC 7539**). Quoting libsodium, the
    XChaCha20 (=eXtended-nonce ChaCha20) variant allows encryption of
    ~2^64 bytes per message, encryption of up to 2^64 messages per key,
    and safe use of random nonces due to the 192-bit nonce space***.

    *   https://tools.ietf.org/html/draft-arciszewski-xchacha-00
    **  https://tools.ietf.org/html/rfc7539
    *** https://download.libsodium.org/doc/secret-key_cryptography/aead/chacha20-poly1305#variants

    The reasons for using XChaCha20-Poly1305 in TFC include

        o The Salsa20 algorithm has 14 years of cryptanalysis behind it.
          (https://en.wikipedia.org/wiki/Salsa20#Cryptanalysis_of_Salsa20)

        o The increased diffusion over the well-received Salsa20.

        o The algorithm is much faster compared to AES (in cases where
          the CPU and/or implementation does not support AES-NI).

        o Security against cache-timing attacks on all CPUs (unlike AES
          on CPUs without AES-NI).

        o The good name of djb.

    The correctness of the XChaCha20-Poly1305 implementation* is tested
    by TFC unit tests. The testing is done in limited scope by using
    libsodium and IETF test vectors.

    * https://github.com/jedisct1/libsodium/tree/master/src/libsodium/crypto_aead/xchacha20poly1305/sodium
      https://github.com/pyca/pynacl/blob/master/src/nacl/bindings/crypto_aead.py
    """
    if len(key) != SYMMETRIC_KEY_LENGTH:
        raise CriticalError("Invalid key length.")

    nonce = csprng(XCHACHA20_NONCE_LENGTH)
    ct_tag = nacl.bindings.crypto_aead_xchacha20poly1305_ietf_encrypt(plaintext, ad, nonce, key)  # type: bytes

    return nonce + ct_tag


def auth_and_decrypt(nonce_ct_tag: bytes,       # Nonce + ciphertext + tag
                     key:          bytes,       # 32-byte symmetric key
                     database:     str   = '',  # When provided, gracefully exists TFC when the tag is invalid
                     ad:           bytes = b''  # Associated data
                     ) -> bytes:                # Plaintext
    """Authenticate and decrypt XChaCha20-Poly1305 ciphertext.

    The Poly1305 tag is checked using constant time `sodium_memcmp`:
        https://download.libsodium.org/doc/helpers#constant-time-test-for-equality

    When TFC decrypts ciphertext from an untrusted source (i.e., a
    contact), no `database` parameter is provided. In such situation, if
    the tag of the untrusted ciphertext is invalid, TFC discards the
    ciphertext and recovers appropriately.

    When TFC decrypts ciphertext from a trusted source (i.e., a
    database), the `database` parameter is provided, so the function
    knows which database is in question. In case the authentication
    fails due to invalid tag, the data is assumed to be either tampered
    or corrupted. TFC will in such case gracefully exit to avoid
    processing the unsafe data and warn the user in which database the
    issue was detected.
    """
    if len(key) != SYMMETRIC_KEY_LENGTH:
        raise CriticalError("Invalid key length.")

    nonce, ct_tag = separate_header(nonce_ct_tag, XCHACHA20_NONCE_LENGTH)

    try:
        plaintext = nacl.bindings.crypto_aead_xchacha20poly1305_ietf_decrypt(ct_tag, ad, nonce, key)  # type: bytes
        return plaintext
    except nacl.exceptions.CryptoError:
        if database:
            raise CriticalError(f"Authentication of data in database '{database}' failed.")
        raise


def byte_padding(bytestring: bytes  # Bytestring to be padded
                 ) -> bytes:        # Padded bytestring
    """Pad bytestring to next 255 bytes.

    TFC adds padding to messages it outputs. The padding ensures each
    assembly packet has a constant length. When traffic masking is
    disabled, because of padding the packet length reveals only the
    maximum length of the compressed message.

    When traffic masking is enabled, the padding contributes to traffic
    flow confidentiality: During traffic masking, TFC will output a
    constant stream of padded packets at constant intervals that hides
    metadata about message length (i.e., the adversary won't be able to
    distinguish when transmission of packet or series of packets starts
    and stops), as well as the type (message/file) of transferred data.

    TFC uses PKCS #7 padding scheme described in RFC 2315 and RFC 5652:
        https://tools.ietf.org/html/rfc2315#section-10.3
        https://tools.ietf.org/html/rfc5652#section-6.3

    For a better explanation, see
        https://en.wikipedia.org/wiki/Padding_(cryptography)#PKCS#5_and_PKCS#7
    """
    padding_len = PADDING_LENGTH - (len(bytestring) % PADDING_LENGTH)
    bytestring += padding_len * bytes([padding_len])

    if len(bytestring) % PADDING_LENGTH != 0:  # pragma: no cover
        raise CriticalError("Invalid padding length.")

    return bytestring


def rm_padding_bytes(bytestring: bytes  # Bytestring from which padding is removed
                     ) -> bytes:        # Bytestring without padding
    """Remove padding from plaintext.

    The length of padding is determined by the ord-value of the last
    byte that is always part of the padding.
    """
    length = ord(bytestring[-1:])
    return bytestring[:-length]


def csprng(key_length: int = SYMMETRIC_KEY_LENGTH) -> bytes:
    """Generate a cryptographically secure random key.

    The default key length is 256 bits.

    The key is generated by the Linux kernel's cryptographically secure
    pseudo-random number generator (CSPRNG).

    Since Python 3.6.0, `os.urandom` is a wrapper for best available
    CSPRNG. The 3.17 and earlier versions of Linux kernel do not support
    the GETRANDOM call, and Python 3.6's `os.urandom` will in those
    cases fall back to non-blocking `/dev/urandom` that is not secure on
    live distros as they have low entropy at the start of the session.

    TFC uses `os.getrandom(n, flags=0)` explicitly. This forces use of
    recent enough Python interpreter (3.6.0 or later) and limits Linux
    kernel version to 3.17 or later.* The flag 0 will block urandom if
    the internal state of the CSPRNG has less than 128 bits of entropy.
    See PEP 524 for more details:
        https://www.python.org/dev/peps/pep-0524/

    * The `/dev/urandom` was redesigned around ChaCha20 in the version
      4.8 of Linux kernel (https://lwn.net/Articles/686033/), so as a
      good practice TFC runs the `check_kernel_version` to ensure only
      the new design of the CSPRNG is used.

    Quoting PEP 524:
        "The os.getrandom() is a thin wrapper on the getrandom()
         syscall/C function and so inherit of its behaviour. For
         example, on Linux, it can return less bytes than
         requested if the syscall is interrupted by a signal."

    However, quoting (https://lwn.net/Articles/606141/) on GETRANDOM:
        "--reads of 256 bytes or less from /dev/urandom are guaranteed to
         return the full request once that device has been initialized."

    Since the largest key generated in TFC is the 56-byte X448 private
    key, GETRANDOM is guaranteed to always work. As a good practice
    however, TFC checks that the length of the obtained entropy is
    correct.

    The output of GETRANDOM is further compressed with BLAKE2b. The
    preimage resistance of the hash function protects the internal
    state of the entropy pool just in case some user decides to modify
    the source to accept pre-4.8 Linux Kernel that has no backtracking
    protection. Another reason for the hashing is its recommended by djb:
        https://media.ccc.de/v/32c3-7210-pqchacks#video&t=1116

    Since BLAKE2b only produces 1..64 byte digests, its use limits the
    size of the key to 64 bytes. This is not a problem for TFC because
    again, the largest key it generates is the 56-byte X448 private key.
    """
    if key_length > BLAKE2_DIGEST_LENGTH_MAX:
        raise CriticalError("Invalid key size.")

    entropy = os.getrandom(key_length, flags=0)

    if len(entropy) != key_length:
        raise CriticalError("GETRANDOM returned invalid amount of entropy.")

    compressed = blake2b(entropy, digest_size=key_length)

    if len(compressed) != key_length:
        raise CriticalError("Invalid final key size.")

    return compressed


def check_kernel_entropy() -> None:
    """Wait until the kernel CSPRNG is sufficiently seeded.

    Wait until the `entropy_avail` file states that kernel entropy pool
    has at least 512 bits of entropy. The waiting ensures the ChaCha20
    CSPRNG is fully seeded (i.e., it has the maximum of 384 bits of
    entropy) when it generates keys. The same entropy threshold is used
    by the GETRANDOM syscall in random.c:
        #define CRNG_INIT_CNT_THRESH (2*CHACHA20_KEY_SIZE)

    For more information on the kernel CSPRNG threshold, see
        https://security.stackexchange.com/a/175771/123524
        https://crypto.stackexchange.com/a/56377
    """
    message = "Waiting for kernel CSPRNG entropy pool to fill up"
    phase(message, head=1)

    ent_avail = 0
    while ent_avail < ENTROPY_THRESHOLD:
        with ignored(EOFError, KeyboardInterrupt):
            with open('/proc/sys/kernel/random/entropy_avail') as f:
                ent_avail = int(f.read().strip())
            m_print(f"{ent_avail}/{ENTROPY_THRESHOLD}")
            print_on_previous_line(delay=0.1)

    print_on_previous_line()
    phase(message)
    phase(DONE)


def check_kernel_version() -> None:
    """Check that the Linux kernel version is at least 4.8.

    This check ensures that TFC only runs on Linux kernels that use the
    new ChaCha20 based CSPRNG that among many things, adds backtracking
    protection:
        https://lkml.org/lkml/2016/7/25/43
    """
    major_v, minor_v = [int(i) for i in os.uname()[2].split('.')[:2]]

    if major_v < 4 or (major_v == 4 and minor_v < 8):
        raise CriticalError("Insecure kernel CSPRNG version detected.")
