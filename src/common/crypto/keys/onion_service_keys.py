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

import base64
import hashlib

from typing import Optional as O, TYPE_CHECKING

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from src.common.exceptions import ValidationError
from src.common.entities.confirm_code import ConfirmationCode
from src.common.crypto.algorithms.csprng import csprng
from src.common.statics import KeyLength, CryptoVarLength, FieldLength, OnionLiterals
from src.common.utils.validators import validate_bytes, validate_onion_addr

if TYPE_CHECKING:
    from src.common.crypto.keys.symmetric_key import BufferKey


class OnionServicePublicKey:
    """Type-safe, immutable Onion Service public key.

    As this is the only random 32-byte bytestring that gets exported
    to Relay Program as such, this value can only be generated from
        * an Ed25519PublicKey  that proves it's a public key,
        * an Ed25519PrivateKey that proves it's the public key derived from private key, or
        *  a v3 Onion Address  that proves it's parsed from an encoded public key (OnionPublicKeyContact sub-class only).
    """

    def __init__(self, public_key: Ed25519PublicKey | bytes) -> None:
        """Create new OnionServicePublicKey object."""
        if isinstance(public_key, bytes):
            self.validate_public_bytes(public_key)
            public_key = Ed25519PublicKey.from_public_bytes(public_key)

        if not isinstance(public_key, Ed25519PublicKey):
            raise ValidationError('The public key was not an Ed25519PublicKey key.')

        self.validate_public_bytes(public_key.public_bytes_raw())

        self.__public_key = public_key

    def __eq__(self, other: object) -> bool:
        """Return True if two onion public keys are equal."""
        return isinstance(other, OnionServicePublicKey) and self.public_bytes_raw == other.public_bytes_raw

    def __hash__(self) -> int:
        """Hash by raw public bytes to allow dict/set usage."""
        return hash(self.public_bytes_raw)

    def __reduce__(self) -> tuple[type['OnionServicePublicKey'], tuple[bytes]]:
        """Serialize by raw public bytes to support multiprocessing queues."""
        return type(self), (self.public_bytes_raw,)

    # ┌───────────────────────────────────────────────────────────────────────────┐
    # │                                 Validation                                │
    # └───────────────────────────────────────────────────────────────────────────┘

    @staticmethod
    def validate_public_bytes(public_bytes: bytes) -> None:
        """Validate the public key."""
        if not isinstance(public_bytes, bytes):
            raise ValidationError(f'The public key was not bytes: {type(public_bytes)}')
        if len(public_bytes) != CryptoVarLength.ONION_SERVICE_PUBLIC_KEY.value:
            raise ValidationError(f'The public key length was invalid: {len(public_bytes)}')
        if not any(public_bytes):
            raise ValidationError('The public key was all zeros.')

    # ┌───────────────────────────────────────────────────────────────────────────┐
    # │                                 Properties                                │
    # └───────────────────────────────────────────────────────────────────────────┘

    @property
    def onion_address(self) -> str:
        """Decode public key byte string to TFC account.

        This decoding is exactly the same process as conversion of Ed25519
        public key of v3 Onion Service into service ID:
            https://github.com/torproject/torspec/blob/main/rend-spec-v3.txt#L2259
        """
        checksum = hashlib.sha3_256(OnionLiterals.ONION_ADDRESS_CHECKSUM_ID.value
                                    + self.public_bytes_raw
                                    + OnionLiterals.ONION_SERVICE_VERSION.value
                                    ).digest()[:FieldLength.ONION_ADDRESS_CHECKSUM.value]

        return base64.b32encode(self.public_bytes_raw + checksum + OnionLiterals.ONION_SERVICE_VERSION).lower().decode()

    @property
    def short_address(self) -> str:
        """Get the short Onion Address for the Onion Service."""
        return self.onion_address[:FieldLength.ONION_ADDRESS_TRUNC]

    @property
    def ed_25519_pub_key(self) -> Ed25519PublicKey:
        """Return the Ed25519 public key object."""
        return self.__public_key

    @property
    def c_code(self) -> ConfirmationCode:
        """Generate deterministic confirmation code from public key."""
        return ConfirmationCode.from_onion_address(self.onion_address)

    @property
    def public_bytes_raw(self) -> bytes:
        """Return the raw bytes for the onion public key."""
        return self.__public_key.public_bytes_raw()

    def serialize(self) -> bytes:
        """Return the serialized bytes for the onion public key.

        To prevent mix-up with other raw byte-strings, we store the public keys as the ascii-representation
        of the v3 Onion Address, for example, b'4sci35xrhp2d45gbm3qpta7ogfedonuw2mucmc36jxemucd7fmgzj3ad'.

        This requires validation of any Onion Address upon loading from DB, and ensures
        Transmitter Program never accidentally outputs a symmetric key as a public key.
        """
        encoded_address = self.onion_address.encode()

        validate_bytes(encoded_address, is_length=FieldLength.ONION_ADDRESS)

        return encoded_address


# ┌─────────────┐
# │ Subclassing │
# └─────────────┘

class OnionPublicKeyUser(OnionServicePublicKey):
    pass

class OnionPublicKeyContact(OnionServicePublicKey):

    # noinspection PyPep8Naming
    @classmethod
    def from_onion_address(cls, onion_address: str, *, DO_NOT_VALIDATE: bool = False) -> 'OnionPublicKeyContact':
        """Encode onion address (=TFC account) to a public key byte string.

        The public key is the most compact possible representation of a TFC
        account, so it is useful when storing the address into databases.
        """
        if not DO_NOT_VALIDATE:
            validate_onion_addr(onion_address)

        checksum_len = FieldLength.ONION_ADDRESS_CHECKSUM.value
        version_len  = FieldLength.ONION_SERVICE_VERSION.value

        raw_pub_key      = base64.b32decode(onion_address.upper())[:-(checksum_len + version_len)]
        ed_25519_pub_key = Ed25519PublicKey.from_public_bytes(raw_pub_key)
        return cls(ed_25519_pub_key)

    @classmethod
    def from_onion_address_bytes(cls, onion_address_bytes: bytes) -> 'OnionPublicKeyContact':
        """Encode onion address (=TFC account) bytestring to a public key byte string."""
        return cls.from_onion_address(onion_address_bytes.decode())

    def derive_relay_buffer_sub_dir(self, buffer_key: 'BufferKey') -> str:
        """Derive keyed random directory name for the contact."""
        return hashlib.blake2b(self.public_bytes_raw,
                               key         = buffer_key.raw_bytes,
                               digest_size = CryptoVarLength.BLAKE2_DIGEST).hexdigest()


# ----------------------------------------------------------------------------------------------------------------------

class OnionServicePrivateKey:
    """OnionService private key.

    This class only provides type-safety and immutability.
    """

    def __init__(self, key_bytes: O[bytes] = None) -> None:
        """Create new OnionServicePrivateKey object."""
        key_bytes = key_bytes if key_bytes is not None else csprng(KeyLength.ONION_SERVICE_PRIVATE_KEY)

        self.validate_key_bytes(key_bytes)

        self.__private_key = Ed25519PrivateKey.from_private_bytes(key_bytes)
        self.__public_key  = self.__private_key.public_key()

    def __reduce__(self) -> tuple[type['OnionServicePrivateKey'], tuple[bytes]]:
        """Serialize by raw private bytes to support multiprocessing queues."""
        return type(self), (self.raw_private_bytes,)

    @staticmethod
    def validate_key_bytes(key_bytes: bytes) -> None:
        """Validate the key bytes."""
        try:
            validate_bytes(key_bytes, is_length=KeyLength.ONION_SERVICE_PRIVATE_KEY, not_all_zeros=True)
        except ValidationError as e:
            raise ValidationError(f"The private key of user's Onion Service failed validation: {e.args[0]}")

        private_key = Ed25519PrivateKey.from_private_bytes(key_bytes)
        public_key  = private_key.public_key().public_bytes_raw()

        try:
            validate_bytes(public_key, is_length=CryptoVarLength.ONION_SERVICE_PUBLIC_KEY, not_all_zeros=True)
        except ValidationError as e:
            raise ValidationError(f"The public key of user's Onion Service failed validation: {e.args[0]}")

    @property
    def onion_pub_key(self) -> OnionPublicKeyUser:
        """Get the Onion Service public key."""
        return OnionPublicKeyUser(self.__public_key.public_bytes_raw())

    @property
    def onion_addr(self) -> str:
        """Get the full length Onion Address for the Onion Service."""
        return self.onion_pub_key.onion_address

    @property
    def short_addr(self) -> str:
        """Get the short Onion Address for the Onion Service."""
        return self.onion_pub_key.short_address

    @property
    def raw_private_bytes(self) -> bytes:
        """Export the onion service private key."""
        return self.__private_key.private_bytes_raw()

    @property
    def stem_compatible_expanded_private_key(self) -> str:
        """Return Tor/Stem-compatible base64 for a v3 Onion Service Ed25519 private key.

        Overview:

        This function expands the raw 32-byte Ed25519 private key bytes into

            base64(secret_scalar_bytes || prefix_bytes)                                                                  [5]

        where
            * `secret_scalar_bytes` are used as the private scalar material in Ed25519, and
            * `prefix_bytes`        are used to derive the deterministic per-message nonce material with

                SHA512(prefix_bytes || message).

        The two values are produced as follows:

            hashed_seed         = SHA512(raw_ed25519_private_key_bytes)                                                  [1]
            lower_32_bytes      = hashed_seed[:32]                                                                       [2]
            prefix_bytes        = hashed_seed[32:]
            secret_scalar_bytes = clamp(lower_32_bytes)                                                                  [3]

        The clamped `secret_scalar_bytes` are then interpreted as a little-endian integer to form the secret scalar.     [4]

        During signing, the nonce scalar is derived from:
            nonce_hash   = SHA512(prefix_bytes || message)
            nonce_scalar = reduce_mod_group_order(nonce_hash)

        # ---

        As per RFC 8032 spec:

           [1] 'Hash the 32-byte private key using SHA-512'.
               https://www.rfc-editor.org/rfc/rfc8032.html#section-5.1.5

           [2] 'Only the lower 32 bytes are used for generating the public key.'
               https://www.rfc-editor.org/rfc/rfc8032.html#section-5.1.5

           [3] 'Prune the buffer: The lowest three bits of the first octet are
               cleared, the highest bit of the last octet is cleared, and the
               second highest bit of the last octet is set.
               https://www.rfc-editor.org/rfc/rfc8032.html#section-5.1.5

           [4] 'Interpret the buffer as the little-endian integer, forming a
               secret scalar s.'
               https://www.rfc-editor.org/rfc/rfc8032.html#section-5.1.5

           [5] Hash the private key, 32 octets, using SHA-512.  Let h denote the
               resulting digest.  Construct the secret scalar s from the first
               half of the digest, and the corresponding public key A, as
               described in the previous section.  Let prefix denote the second
               half of the hash digest, h[32],...,h[63].
               https://www.rfc-editor.org/rfc/rfc8032.html#section-5.1.6
        """

        def clamp_scalar_bytes(scalar_bytes: bytes) -> bytes:
            """Clamp the scalar bytes."""
            scalar_ba = bytearray(scalar_bytes)

            scalar_ba[ 0] &= 0b11111000  # 'The lowest three bits of the first octet are cleared'
            scalar_ba[31] &= 0b00111111  # 'The highest bit of the last octet is cleared' [Also zero the second highest bit for the next step]
            scalar_ba[31] |= 0b01000000  # 'The second highest bit of the last octet is set'

            return bytes(scalar_ba)

        def expand_ed25519_seed(seed: bytes) -> bytes:
            """Expand a 32-byte Ed25519 seed into clamped_scalar || prefix."""
            digest         = hashlib.sha512(seed).digest()
            scalar_bytes   = digest[  :32]
            prefix_bytes   = digest[32:64]
            clamped_scalar = clamp_scalar_bytes(scalar_bytes)

            return clamped_scalar + prefix_bytes

        expanded_secret = expand_ed25519_seed(self.__private_key.private_bytes_raw())
        return base64.b64encode(expanded_secret).decode()
