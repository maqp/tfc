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

import hashlib

from src.common.exceptions import CriticalError
from src.common.statics import CryptoVarLength


def blake2b(message     : bytes,                                # Message to hash
            key         : bytes = b'',                          # Key for keyed hashing
            salt        : bytes = b'',                          # Salt for randomized hashing
            person      : bytes = b'',                          # Personalization string
            digest_size : int   = CryptoVarLength.BLAKE2_DIGEST # Length of the digest
            ) -> bytes:                                         # The BLAKE2b digest
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

          'Keccak received a significant amount of cryptanalysis,
           although not quite the depth of analysis applied to BLAKE,
           Grøstl, or Skein.'[2; p.13]

        o BLAKE shares design elements with SHA-2[3] that has 11 years
          of cryptanalysis[4] behind it.

        o 128-bit collision/preimage/second-preimage resistance against
          Grover's algorithm running on a quantum Turing machine.

        o The algorithm is bundled in Python3's hashlib.

        o Compared to SHA3-256, the algorithm runs faster on CPUs which
          means better hash ratchet performance:

          'The ARX-based algorithms, BLAKE and Skein, perform extremely
           well in software.'[2; p.13]

        o Compared to SHA3-256, the algorithm runs slower on ASICs which
          means attacks by high-budget adversaries are slower:

          'Keccak has a clear advantage in throughput/area performance
           in hardware implementations.'[2; p.13]

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
                                 digest_size = digest_size,
                                 key         = key,
                                 salt        = salt,
                                 person      = person).digest()  # type: bytes
    except ValueError as e:
        raise CriticalError(str(e))

    if not isinstance(digest, bytes):
        raise CriticalError(f'BLAKE2b returned an invalid type ({type(digest)}) digest.')

    if len(digest) != digest_size:
        raise CriticalError(f'BLAKE2b digest had invalid length ({len(digest)} bytes).')

    return digest
