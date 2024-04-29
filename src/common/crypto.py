#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
TFC - Onion-routed, endpoint secure messaging system
Copyright (C) 2013-2024  Markus Ottela

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
based on the ChaCha stream cipher by Daniel J. Bernstein (djb).

Curve448-Goldilocks
└─ X448 key exchange
ChaCha stream cipher
├─ BLAKE2b cryptographic hash function
|  └─ Argon2id password hashing function
└─ ChaCha20 stream cipher
   ├─ XChaCha20-Poly1305 AEAD (IETF variant)
   └─ Linux kernel primary DRNG
"""

import hashlib
import os

from typing import Tuple


# Ignore packages not used in relay program.
try:
    import argon2
except ImportError:
    pass

try:
    import nacl.bindings
    import nacl.exceptions
    import nacl.secret
    import nacl.utils
except ImportError:
    pass

from cryptography.hazmat.primitives                 import padding
from cryptography.hazmat.primitives.asymmetric.x448 import X448PrivateKey, X448PublicKey
from cryptography.hazmat.primitives.serialization   import Encoding, PublicFormat

from src.common.exceptions import CriticalError
from src.common.misc       import separate_header
from src.common.statics    import (BITS_PER_BYTE, BLAKE2_DIGEST_LENGTH, BLAKE2_DIGEST_LENGTH_MAX,
                                   BLAKE2_DIGEST_LENGTH_MIN, FINGERPRINT, FINGERPRINT_LENGTH, MESSAGE_KEY, HEADER_KEY,
                                   PADDING_LENGTH, SYMMETRIC_KEY_LENGTH, TFC_PUBLIC_KEY_LENGTH,
                                   X448_SHARED_SECRET_LENGTH, ARGON2_SALT_LENGTH, XCHACHA20_NONCE_LENGTH)


def blake2b(message:     bytes,                        # Message to hash
            key:         bytes = b'',                  # Key for keyed hashing
            salt:        bytes = b'',                  # Salt for randomized hashing
            person:      bytes = b'',                  # Personalization string
            digest_size: int   = BLAKE2_DIGEST_LENGTH  # Length of the digest
            ) -> bytes:                                # The BLAKE2b digest
    """Generate BLAKE2b digest (i.e. cryptographic hash) of a message.

    BLAKE2 is the successor of SHA3-finalist BLAKE*, designed by
    Jean-Philippe Aumasson, Samuel Neves, Zooko Wilcox-O'Hearn, and
    Christian Winnerlein. The hash function is based on the ChaCha
    stream cipher, designed by djb.

    * BLAKE was designed by Jean-Philippe Aumasson, Luca Henzen,
      Willi Meier, and Raphael C.-W. Phan.

    For more details, see
        https://blake2.net/
        https://tools.ietf.org/html/rfc7693.html
        https://docs.python.org/3.7/library/hashlib.html#blake2

    The reasons for using BLAKE2b in TFC include

        o BLAKE received more in-depth cryptanalysis[1] than Keccak (SHA3):

          "Keccak received a significant amount of cryptanalysis,
           although not quite the depth of analysis applied to BLAKE,
           Grøstl, or Skein."[2; p.13]

        o BLAKE shares design elements with SHA-2[3] that has 11 years
          of cryptanalysis[4] behind it.

        o 128-bit collision/preimage/second-preimage resistance against
          Grover's algorithm running on a quantum Turing machine.

        o The algorithm is bundled in Python3's hashlib.

        o Compared to SHA3-256, the algorithm runs faster on CPUs which
          means better hash ratchet performance:

          "The ARX-based algorithms, BLAKE and Skein, perform extremely
           well in software."[2; p.13]

        o Compared to SHA3-256, the algorithm runs slower on ASICs which
          means attacks by high-budget adversaries are slower:

          "Keccak has a clear advantage in throughput/area performance
           in hardware implementations."[2; p.13]

    Note that while the default digest length of BLAKE2b (the
    implementation optimized for AMD64 systems) is 512 bits, the digest
    length is truncated to 256 bits for the use in TFC.

    The correctness of the BLAKE2b implementation[5] is tested by TFC
    unit tests. The testing is done with the complete suite of BLAKE2b
    known answer tests (KATs).

     [1] https://blake2.net/#cr
     [2] https://nvlpubs.nist.gov/nistpubs/ir/2012/NIST.IR.7896.pdf
     [3] https://leastauthority.com/blog/BLAKE2-harder-better-faster-stronger-than-MD5/
     [4] https://en.wikipedia.org/wiki/SHA-2#Cryptanalysis_and_validation
     [5] https://github.com/python/cpython/tree/3.7/Modules/_blake2
         https://github.com/python/cpython/blob/3.7/Lib/hashlib.py
    """
    try:
        digest = hashlib.blake2b(message,
                                 digest_size=digest_size,
                                 key=key,
                                 salt=salt,
                                 person=person).digest()  # type: bytes
    except ValueError as e:
        raise CriticalError(str(e))

    if not isinstance(digest, bytes):
        raise CriticalError(f"BLAKE2b returned an invalid type ({type(digest)}) digest.")

    if len(digest) != digest_size:
        raise CriticalError(f"BLAKE2b digest had invalid length ({len(digest)} bytes).")

    return digest


def argon2_kdf(password:    str,    # Password to derive the key from
               salt:        bytes,  # Salt to derive the key from
               time_cost:   int,    # Number of iterations
               memory_cost: int,    # Amount of memory to use (in bytes)
               parallelism: int     # Number of threads to use
               ) -> bytes:          # The derived key
    """Derive an encryption key from password and salt using Argon2id.

    Argon2 is a password hashing function designed by Alex Biryukov,
    Daniel Dinu, and Dmitry Khovratovich from the University of
    Luxembourg. The algorithm is the winner of the 2015 Password Hashing
    Competition (PHC).

    For more details, see
        https://password-hashing.net/
        https://en.wikipedia.org/wiki/Argon2

    The reasons for using Argon2 in TFC include

        o PBKDF2 and bcrypt are not memory-hard, thus they are weak
          against massively parallel computing attacks with
          FPGAs/GPUs/ASICs.[1; p.2]

        o scrypt is very complex as it "combines two independent
          cryptographic primitives (the SHA256 hash function, and
          the Salsa20/8 core operation), and four generic operations
          (HMAC, PBKDF2, Block-Mix, and ROMix)."[2; p.10]
              Furthermore, scrypt is "vulnerable to trivial time-memory
          trade-off (TMTO) attacks that allows compact implementations
          with the same energy cost."[1; p.2]

        o Out of all the PHC finalists, only Catena and Argon2i offer
          complete cache-timing resistance by using data-independent
          memory access. Catena does not support parallelism[2; p.49],
          thus if it later turns out TFC needs stronger protection from
          cache-timing attacks, the selection of Argon2 (that always
          supports parallelism) is ideal, as switching from Argon2id
          to Argon2i is trivial.

        o More secure algorithms such as the Balloon hash function[3] do
          not have robust implementations.

    The purpose of Argon2 is to stretch a password into a 256-bit key.
    Argon2 features a slow, memory-hard hash function that consumes
    computational resources of an attacker that attempts a dictionary
    or a brute force attack.

    The function also takes a salt (256-bit random value in this case)
    that prevents rainbow-table attacks, and forces each attack to take
    place against an individual (physically compromised) TFC-endpoint,
    or PSK transmission media.

    The Argon2 version used is the Argon2id, that is the current
    recommendation of the draft RFC[4]. Argon2id uses data-independent
    memory access for the first half of the first iteration, and
    data-dependent memory access for the rest. This provides a lot of
    protection against TMTO attacks which is great because most of the
    expected attacks are against physically compromised data storage
    devices where the encrypted data is at rest.
        Argon2id also adds some security against side-channel attacks
    that malicious code injected to the Destination Computer might
    perform. Considering these two attacks, Argon2id is the most secure
    choice.

    The correctness of the Argon2id implementation[5] is tested by TFC
    unit tests. The testing is done by comparing the output of the
    argon2_cffi library with the output of the Argon2 reference
    command-line utility under randomized input parameters.

     [1] https://github.com/P-H-C/phc-winner-argon2/blob/master/argon2-specs.pdf
     [2] https://password-hashing.net/submissions/specs/Catena-v5.pdf
     [3] https://crypto.stanford.edu/balloon/
     [4] https://tools.ietf.org/html/draft-irtf-cfrg-argon2-12#section-7.4
     [5] https://github.com/P-H-C/phc-winner-argon2
         https://github.com/hynek/argon2_cffi
    """
    if len(salt) != ARGON2_SALT_LENGTH:
        raise CriticalError(f"Invalid salt length ({len(salt)} bytes).")

    try:
        key = argon2.low_level.hash_secret_raw(secret=password.encode(),
                                               salt=salt,
                                               time_cost=time_cost,
                                               memory_cost=memory_cost,
                                               parallelism=parallelism,
                                               hash_len=SYMMETRIC_KEY_LENGTH,
                                               type=argon2.Type.ID)  # type: bytes

    except argon2.exceptions.Argon2Error as e:
        raise CriticalError(str(e))

    if not isinstance(key, bytes):
        raise CriticalError(f"Argon2 returned an invalid type ({type(key)}) key.")

    if len(key) != SYMMETRIC_KEY_LENGTH:
        raise CriticalError(f"Derived an invalid length key from password ({len(key)} bytes).")

    return key


class X448(object):

    """\
    X448 is the Diffie-Hellman function for Curve448-Goldilocks, a
    state-of-the-art elliptical curve published by Mike Hamburg in 2014.

    For more details, see
        https://eprint.iacr.org/2015/625.pdf
        http://ed448goldilocks.sourceforge.net/
        https://en.wikipedia.org/wiki/Curve448

    The reasons for using X448 in TFC include

        o Curve448 meets the criterion for a SafeCurve[1]:

          Parameters

            - Use of large prime field (p = 2^448 - 2^224 - 1).

            - The Edwards curve (x^2+y^2 = 1-39081x^2y^2) is complete.

            - The base point (x_1,y_1) is on the curve.

          ECDLP security

            - 222.8-bit security against the Pollard's rho method.
                  This is important as the security of hash ratchet
              depends on the security of the root key. Curve25519 is
              thus less feasible choice. Curve448 is also likely to
              resist quantum computers and mathematical breakthroughs
              against ECC for a longer time.

            - Safe against additive and multiplicative transfer.

            - The complex-multiplication field discriminant is 2^447.5,
              which is much larger than the required minimum (2^100).

            - The curve-generation process is fully rigid, i.e. it has
              been completely explained. In comparison, NIST P-curves
              use coefficients generated by hashing unexplained seeds.

          ECC security

            - Use of Montgomery ladder that protects from side channel
              attacks by doing constant-time single-scalar multiplication.

            - 221.8-bit security against twist attacks (small-subgroup
              attack combined with invalid-curve attack).

            - Support for complete single-scalar and multi-scalar
              multiplication formulas.

            - Points on Curve448 (e.g. public keys) are
              indistinguishable from uniform random strings.

        o Safer curves (M-511 and E-521) do not have robust implementations.

        o NIST has announced X448 will be included in the SP 800-186.[2]

        o Its public keys do not require validation as long as the
          resulting shared secret is not zero:

          "[X448] is actually two curves, where any patterns of bits
           will be interpreted as a point on one of the curves or on the
           other."[3]

        o Its public keys are reasonably short (84 chars when WIF-encoded)
          to be manually typed from Networked Computer to Source Computer.

    The correctness of the X448 implementation[4] is tested by TFC unit
    tests. The testing is done in limited scope by using the official
    test vectors.

     [1] https://safecurves.cr.yp.to/
     [2] https://csrc.nist.gov/News/2017/Transition-Plans-for-Key-Establishment-Schemes
     [3] https://crypto.stackexchange.com/a/44348
     [4] https://github.com/openssl/openssl/tree/OpenSSL_1_1_1-stable/crypto/ec/curve448
         https://github.com/pyca/cryptography/blob/master/src/cryptography/hazmat/primitives/asymmetric/x448.py
    """

    @staticmethod
    def generate_private_key() -> 'X448PrivateKey':
        """Generate the X448 private key.

        The pyca/cryptography's key generation process is as follows:

        1. When `X448PrivateKey.generate()` is called by this method,
           the `generate()` class method imports the OpenSSL backend[1].

        2. Importing the backend causes Python to call the Backend
           class[2] that runs the `__init__()` method of the class[3],
           which then calls the `activate_osrandom_engine()` instance
           method[4].

         [1] https://github.com/pyca/cryptography/blob/3.1.1/src/cryptography/hazmat/primitives/asymmetric/x448.py#L39
         [2] https://github.com/pyca/cryptography/blob/3.1.1/src/cryptography/hazmat/backends/openssl/backend.py#L2708
         [3] https://github.com/pyca/cryptography/blob/3.1.1/src/cryptography/hazmat/backends/openssl/backend.py#L222
         [4] https://github.com/pyca/cryptography/blob/3.1.1/src/cryptography/hazmat/backends/openssl/backend.py#L238

        ---

        If the OpenSSL version is older than 1.1.1d:

        3. Calling the `activate_osrandom_engine()` disables the default
           OpenSSL CSPRNG, and activates the pyca/cryptography
           "OS random engine".[5]

        4. Unlike the old OpenSSL user-space CSPRNG that only seeds from
           /dev/urandom, the OS random engine uses the GETRANDOM(0)
           syscall that sources all of its entropy directly from the
           LRNG's ChaCha20 DRNG. The OS random engine does not suffer
           from the fork-weakness where forked process is not
           automatically reseeded, and it's also safe from issues with
           OpenSSL's CSPRNG initialization.[6]

        5. The fallback option (/dev/urandom) of OS random engine might
           be problematic on pre-3.17 kernels if the CSPRNG has not been
           properly seeded. However, TFC checks that the kernel version
           of the OS it's running on is at least 4.17. This means that
           the used source of entropy is always GETRANDOM(0).[7] This
           can be verified from the source code as well: The last
           parameter `0` of the GETRANDOM syscall[8] indicates
           GRND_NONBLOCK flag is not set. This means the ChaCha20 DRNG
           is used, and that it does not yield entropy until it has been
           fully seeded. This is the same case as with TFC's `csprng()`
           function.

         [5] https://cryptography.io/en/latest/hazmat/backends/openssl/#activate_osrandom_engine
         [6] https://cryptography.io/en/latest/hazmat/backends/openssl/#os-random-engine
         [7] https://cryptography.io/en/latest/hazmat/backends/openssl/#os-random-sources
         [8] https://github.com/pyca/cryptography/blob/3.1.1/src/_cffi_src/openssl/src/osrandom_engine.c#L396

        ---

        If the OpenSSL version used is 1.1.1d or newer:

        3. The Backend init method calls[9] the
           `activate_osrandom_engine` method, which will check[10]
           whether OS Random Engine is needed, and since with
           OpenSSL 1.1.1d+ it is not, the condition check will evaluate
           as `False`, which in turn means the entire method is skipped.

        4. The `generate` method will then call the
           `backend.x448_generate_key()`[11] which in turn will call
           the `_evp_pkey_keygen_gc` method[12].

        7. The `_evp_pkey_keygen_gc` calls the `EVP_PKEY_keygen`
           method[13], that given the context will generate the X448
           private key.

        8. To quote OpenSSL's change log[14]:

            "On older Linux systems where the getrandom() system call is
             not available, OpenSSL normally uses the /dev/urandom device
             for seeding its CSPRNG. Contrary to getrandom(), the
             /dev/urandom device will not block during early boot when
             the kernel CSPRNG has not been seeded yet."

           Again, as TFC checks that the kernel version of the OS it's
           running on is at least 4.17, the entropy source used by
           OpenSSL is always GETRANDOM(0).

         [9] https://github.com/pyca/cryptography/blob/3.1.1/src/cryptography/hazmat/backends/openssl/backend.py#L238
        [10] https://github.com/pyca/cryptography/blob/3.1.1/src/cryptography/hazmat/backends/openssl/backend.py#L288
        [11] https://github.com/pyca/cryptography/blob/3.1.1/src/cryptography/hazmat/primitives/asymmetric/x448.py#L46
        [12] https://github.com/pyca/cryptography/blob/3.1.1/src/cryptography/hazmat/backends/openssl/backend.py#L2365
        [13] https://github.com/pyca/cryptography/blob/3.1.1/src/cryptography/hazmat/backends/openssl/backend.py#L2326
        [14] https://www.openssl.org/news/changelog.html#openssl-111
        """
        return X448PrivateKey.generate()

    @staticmethod
    def derive_public_key(private_key: 'X448PrivateKey') -> bytes:
        """Derive public key from an X448 private key."""
        public_key = private_key.public_key().public_bytes(encoding=Encoding.Raw,
                                                           format=PublicFormat.Raw)  # type: bytes

        if not isinstance(public_key, bytes):
            raise CriticalError(f"Generated an invalid type ({type(public_key)}) public key.")

        if len(public_key) != TFC_PUBLIC_KEY_LENGTH:
            raise CriticalError(f"Generated an invalid size public key from private key ({len(public_key)} bytes).")

        return public_key

    @staticmethod
    def shared_key(private_key: 'X448PrivateKey', public_key: bytes) -> bytes:
        """Derive the X448 shared key.

        The pyca/cryptography library validates the length of the public
        key and verifies that the shared secret is not zero.

        The X448 shared secret is not a random byte string, but a random
        point on the curve. Thus, the raw bits of the shared secret
        might not be uniformly distributed in the keyspace, but have
        bias towards 0 or 1.
            To get rid of the bias, the raw shared secret is passed
        through a computational extractor (BLAKE2b CSPRF) to ensure
        a uniformly random shared key.

        While `shared secret` and `shared key` are used synonymously, in
        TFC we choose to distinguish between the raw shared secret and
        the BLAKE2b compressed shared secret by calling only the latter
        the `shared key`.

        Note that the shared key won't be used directly as a session
        key. Instead, it will be used as the key parameter in separate
        BLAKE2b instances where the hash function is used as a KDF to
        extract unidirectional message/header keys and fingerprints.
        """
        try:
            shared_secret = private_key.exchange(X448PublicKey.from_public_bytes(public_key))  # type: bytes
        except ValueError as e:
            raise CriticalError(str(e))

        if not isinstance(shared_secret, bytes):  # pragma: no cover
            raise CriticalError(f"Derived an invalid type ({type(shared_secret)}) shared secret.")

        if len(shared_secret) != X448_SHARED_SECRET_LENGTH:  # pragma: no cover
            raise CriticalError(f"Generated an invalid size shared secret ({len(shared_secret)} bytes).")

        return blake2b(shared_secret, digest_size=SYMMETRIC_KEY_LENGTH)

    @staticmethod
    def derive_subkeys(dh_shared_key:          bytes,
                       tfc_public_key_user:    bytes,
                       tfc_public_key_contact: bytes
                       ) -> Tuple[bytes, bytes, bytes, bytes, bytes, bytes]:
        """\
        Create domain separated message and header subkeys and fingerprints
        from the shared key.

        Domain separate unidirectional keys from shared key by using public
        keys as message and the context variable as personalization string.

        Domain separate fingerprints of public keys by using the shared
        secret as key and the context variable as personalization string.
        This way entities who might monitor fingerprint verification
        channel are unable to correlate spoken values with public keys
        that they might see on RAM or screen of Networked Computer:
        Public keys can not be derived from the fingerprints due to
        preimage resistance of BLAKE2b, and fingerprints can not be
        derived from public key without the X448 shared key. Using the
        context variable ensures fingerprints are distinct from derived
        message and header keys.
        """
        tx_mk = blake2b(tfc_public_key_contact, dh_shared_key, person=MESSAGE_KEY, digest_size=SYMMETRIC_KEY_LENGTH)
        rx_mk = blake2b(tfc_public_key_user,    dh_shared_key, person=MESSAGE_KEY, digest_size=SYMMETRIC_KEY_LENGTH)

        tx_hk = blake2b(tfc_public_key_contact, dh_shared_key, person=HEADER_KEY,  digest_size=SYMMETRIC_KEY_LENGTH)
        rx_hk = blake2b(tfc_public_key_user,    dh_shared_key, person=HEADER_KEY,  digest_size=SYMMETRIC_KEY_LENGTH)

        tx_fp = blake2b(tfc_public_key_user,    dh_shared_key, person=FINGERPRINT, digest_size=FINGERPRINT_LENGTH)
        rx_fp = blake2b(tfc_public_key_contact, dh_shared_key, person=FINGERPRINT, digest_size=FINGERPRINT_LENGTH)

        key_tuple = tx_mk, rx_mk, tx_hk, rx_hk, tx_fp, rx_fp

        if len(set(key_tuple)) != len(key_tuple):
            raise CriticalError("Derived subkeys were not unique.")

        return key_tuple


def encrypt_and_sign(plaintext: bytes,       # Plaintext to encrypt
                     key:       bytes,       # 32-byte symmetric key
                     ad:        bytes = b''  # Associated data
                     ) -> bytes:             # Nonce + ciphertext + tag
    """Encrypt plaintext with XChaCha20-Poly1305 (IETF variant).

    ChaCha20 is a stream cipher published by Daniel J. Bernstein (djb)
    in 2008. The algorithm is an improved version of Salsa20 -- another
    stream cipher by djb -- selected by ECRYPT into the eSTREAM
    portfolio in 2008. The improvement in question is, ChaCha20
    increases the per-round diffusion compared to Salsa20 while
    maintaining or increasing speed.

    For more details, see
        https://cr.yp.to/chacha.html
        https://cr.yp.to/snuffle.html
        https://cr.yp.to/snuffle/security.pdf
        https://en.wikipedia.org/wiki/Salsa20#ChaCha_variant

    The Poly1305 is a Wegman-Carter message authentication code (MAC)
    also designed by djb. The MAC is provably secure if ChaCha20 is
    secure. The 128-bit tag space ensures the attacker's advantage to
    create an existential forgery is negligible.

    For more details, see
        https://cr.yp.to/mac.html

    The version used in TFC is the XChaCha20-Poly1305-IETF[1], a variant
    of the ChaCha20-Poly1305-IETF (RFC 8439[2]). Quoting libsodium, the
    XChaCha20 (=eXtended-nonce ChaCha20) variant allows encryption of
    ~2^64 bytes per message, encryption of practically unlimited number
    of messages, and safe use of random nonces due to the 192-bit nonce
    space[3].

    The reasons for using XChaCha20-Poly1305 in TFC include

        o Conservative 256-bit key size[4] that matches the 222.8-bit
          security of X448, and BLAKE2b (with truncated, 256-bit hashes).

        o The Salsa20 algorithm has 14 years of cryptanalysis behind it[5]
          and ChaCha20 has resisted cryptanalysis as well[6][7]. Currently
          the best public attack[8] breaks ChaCha7 in 2^233 operations.

        o Security against differential and linear cryptanalysis.[9][10]

        o Security against cache-timing attacks on all CPUs (unlike AES
          on CPUs without AES-NI).[11; p.2]

        o The increased diffusion over the well-received Salsa20.[12]

        o The algorithm is much faster compared to AES (in cases where
          the CPU and/or implementation does not support AES-NI).[12]

        o The good name of djb.[13]

    The correctness of the XChaCha20-Poly1305 implementation[14] is
    tested by TFC unit tests. The testing is done in limited scope by
    using the libsodium and official IETF test vectors.

      [1] https://tools.ietf.org/html/draft-irtf-cfrg-xchacha-03
      [2] https://tools.ietf.org/html/rfc8439
      [3] https://download.libsodium.org/doc/secret-key_cryptography/aead/chacha20-poly1305/xchacha20-poly1305_construction
      [4] https://cr.yp.to/snuffle/keysizes.pdf
      [5] https://en.wikipedia.org/wiki/Salsa20#Cryptanalysis_of_Salsa20
      [6] https://eprint.iacr.org/2007/472.pdf
      [7] https://eprint.iacr.org/2015/698.pdf
      [8] https://eprint.iacr.org/2016/377.pdf
      [9] https://www.cryptrec.go.jp/exreport/cryptrec-ex-2601-2016.pdf
     [10] https://eprint.iacr.org/2013/328.pdf
     [11] https://cr.yp.to/antiforgery/cachetiming-20050414.pdf
     [12] https://cr.yp.to/chacha/chacha-20080128.pdf
     [13] https://www.eff.org/sv/deeplinks/2015/04/remembering-case-established-code-speech
     [14] https://github.com/jedisct1/libsodium/blob/master/src/libsodium/crypto_core/hchacha20/core_hchacha20.c
          https://github.com/jedisct1/libsodium/blob/master/src/libsodium/crypto_aead/xchacha20poly1305/sodium/aead_xchacha20poly1305.c
          https://github.com/pyca/pynacl/blob/master/src/nacl/bindings/crypto_aead.py#L349
    """
    if len(key) != SYMMETRIC_KEY_LENGTH:
        raise CriticalError(f"Invalid key length ({len(key)} bytes).")

    nonce = csprng(XCHACHA20_NONCE_LENGTH)

    try:
        ct_tag = nacl.bindings.crypto_aead_xchacha20poly1305_ietf_encrypt(plaintext, ad, nonce, key)  # type: bytes
    except nacl.exceptions.CryptoError as e:
        raise CriticalError(str(e))

    return nonce + ct_tag


def auth_and_decrypt(nonce_ct_tag: bytes,       # Nonce + ciphertext + tag
                     key:          bytes,       # 32-byte symmetric key
                     database:     str   = '',  # When provided, gracefully exits TFC when the tag is invalid
                     ad:           bytes = b''  # Associated data
                     ) -> bytes:                # Plaintext
    """Authenticate and decrypt XChaCha20-Poly1305 ciphertext.

    The Poly1305 tag is checked using constant time `sodium_memcmp`:
        https://download.libsodium.org/doc/helpers#constant-time-test-for-equality

    When TFC decrypts ciphertext from an untrusted source (i.e., a
    contact), no `database` parameter is provided. In such a situation,
    if the tag of the untrusted ciphertext is invalid, TFC discards the
    ciphertext and recovers appropriately.

    When TFC decrypts ciphertext from a trusted source (i.e., a
    database), the `database` parameter is provided, so the function
    knows which database is in question. In case the authentication
    fails due to invalid tag, the data is assumed to be either tampered
    with, or corrupted. TFC will in such a case gracefully exit to avoid
    processing the unsafe data and warn the user in which database the
    issue was detected.
    """
    if len(key) != SYMMETRIC_KEY_LENGTH:
        raise CriticalError(f"Invalid key length ({len(key)} bytes).")

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
    distinguish when transmission of packet or series of packets begins
    and ends), as well as the type (message/file) of transferred data.

    TFC uses the PKCS #7 padding scheme described in RFC 2315 and RFC 5652:
        https://tools.ietf.org/html/rfc2315#section-10.3
        https://tools.ietf.org/html/rfc5652#section-6.3

    For a better explanation, see
        https://en.wikipedia.org/wiki/Padding_(cryptography)#PKCS#5_and_PKCS#7
    """
    padder  = padding.PKCS7(PADDING_LENGTH * BITS_PER_BYTE).padder()
    padded  = padder.update(bytestring)  # type: bytes
    padded += padder.finalize()

    if not isinstance(padded, bytes):
        raise CriticalError(f"Padded message had invalid type ({type(padded)}).")

    if len(padded) % PADDING_LENGTH != 0:
        raise CriticalError(f"Padded message had an invalid length ({len(padded)}).")

    return padded


def rm_padding_bytes(bytestring: bytes  # Padded bytestring
                     ) -> bytes:        # Bytestring without padding
    """Remove padding from plaintext.

    The length of padding is determined by the ord-value of the last
    byte that is always part of the padding.
    """
    unpadder  = padding.PKCS7(PADDING_LENGTH * BITS_PER_BYTE).unpadder()
    unpadded  = unpadder.update(bytestring)  # type: bytes
    unpadded += unpadder.finalize()

    return unpadded


def csprng(key_length: int = SYMMETRIC_KEY_LENGTH  # Length of the key
           ) -> bytes:                             # The generated key
    """Generate a cryptographically secure random key.

    The default key length is 32 bytes (256 bits).

    The key is generated by the Linux kernel's modern, ChaCha20-based
    cryptographically secure pseudo-random number generator (CSPRNG),
    also known as the Linux-RNG, or LRNG.

    The LRNG is currently receiving a lot of love from Jason Donenfeld,
    and no documentation, not even the one maintained by the German
    BSI, is keeping up with the overhaul.

    The best resource to study the RNG functionality is for now, the source code itself:
        https://github.com/torvalds/linux/blob/master/drivers/char/random.c
    """
    if key_length < BLAKE2_DIGEST_LENGTH_MIN or key_length > BLAKE2_DIGEST_LENGTH_MAX:
        raise CriticalError(f"Invalid key size ({key_length} bytes).")

    entropy = os.getrandom(key_length, flags=0)  # type: bytes

    if not isinstance(entropy, bytes):
        raise CriticalError(f"GETRANDOM returned invalid type data ({type(entropy)}).")

    if len(entropy) != key_length:
        raise CriticalError(f"GETRANDOM returned invalid amount of entropy ({len(entropy)} bytes).")

    compressed = blake2b(entropy, digest_size=key_length)

    return compressed
