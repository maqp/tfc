#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
TFC - Onion-routed, endpoint secure messaging system
Copyright (C) 2013-2026  Markus Ottela

This file is part of TFC.
TFC is free software: you can redistribute it and/or modify it under the terms
of the GNU General Public License as published by the Free Software Foundation,
either version 3 of the License, or (at your option) any later version. TFC is
distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without
even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
See the GNU General Public License for more details. You should have received a
copy of the GNU General Public License along with TFC. If not, see
<https://www.gnu.org/licenses/>.
"""

import nacl
import nacl.bindings
import nacl.exceptions

from src.common.exceptions import CriticalError, ValidationError
from src.common.crypto.algorithms.csprng import csprng
from src.common.statics import KeyLength
from src.common.utils.strings import separate_header
from src.common.utils.validators import validate_bytes


def encrypt_and_sign(plaintext : bytes,       # Plaintext to encrypt
                     key       : bytes,       # 32-byte symmetric key
                     ad        : bytes = b''  # Associated data
                     ) -> bytes:              # Nonce + ciphertext + tag
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
    if nacl is None:
        raise CriticalError('PyNaCl library is not installed.')

    try:
        validate_bytes(key, key='key', is_length=KeyLength.SYMMETRIC_KEY.value, not_all_zeros=True)
    except ValidationError as e:
        raise CriticalError(str(e))

    nonce = csprng(KeyLength.XCHACHA20_NONCE)

    try:
        ct_tag = nacl.bindings.crypto_aead_xchacha20poly1305_ietf_encrypt(plaintext, ad, nonce, key)  # type: bytes
    except nacl.exceptions.CryptoError as e:
        raise CriticalError(str(e))

    return nonce + ct_tag


def auth_and_decrypt(nonce_ct_tag : bytes,       # Nonce + ciphertext + tag
                     key          : bytes,       # 32-byte symmetric key
                     database     : str   = '',  # When provided, gracefully exits TFC when the tag is invalid
                     ad           : bytes = b''  # Associated data
                     ) -> bytes:                 # Plaintext
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
    if nacl is None:
        raise CriticalError('PyNaCl library is not installed.')

    try:
        validate_bytes(key, key='key', is_length=KeyLength.SYMMETRIC_KEY.value, not_all_zeros=True)
    except ValidationError as e:
        raise CriticalError(str(e))

    nonce, ct_tag = separate_header(nonce_ct_tag, KeyLength.XCHACHA20_NONCE.value)

    try:
        plaintext = nacl.bindings.crypto_aead_xchacha20poly1305_ietf_decrypt(ct_tag, ad, nonce, key)  # type: bytes
        return plaintext
    except nacl.exceptions.CryptoError:
        if database:
            raise CriticalError(f"Authentication of data in database '{database}' failed.")
        raise
