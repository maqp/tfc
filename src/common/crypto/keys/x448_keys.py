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

from typing import Callable

from cryptography.hazmat.primitives.asymmetric.x448 import X448PrivateKey, X448PublicKey

from src.common.exceptions import ValidationError
from src.common.statics import CryptoVarLength, KeyLength
from src.common.utils.validators import validate_bytes


class X448PubKey:
    """Type-safe, immutable wrapper for X448 public keys."""

    def __init__(self, public_key: X448PublicKey) -> None:
        """Create a new X448PubKey object."""
        if not isinstance(public_key, X448PublicKey):
            raise ValidationError('The public key was not an X448PublicKey key.')

        public_key_bytes = public_key.public_bytes_raw()
        self.validate_public_bytes(public_key_bytes)
        self.__public_key_bytes = public_key_bytes

    def __eq__(self, other: object) -> bool:
        """Return True if two X448 public keys are equal."""
        return isinstance(other, X448PubKey) and self.__public_key_bytes == other.__public_key_bytes

    def __hash__(self) -> int:
        """Hash by raw public bytes to allow dict/set usage."""
        return hash(self.__public_key_bytes)

    def __reduce__(self) -> tuple[Callable[[bytes], 'X448PubKey'], tuple[bytes]]:
        """Serialize by raw public bytes to support multiprocessing queues."""
        return type(self)._from_public_bytes, (self.__public_key_bytes,)

    @staticmethod
    def validate_public_bytes(public_key_bytes: bytes) -> None:
        """Validate raw X448 public key bytes."""
        try:
            validate_bytes(public_key_bytes,
                           is_length     = CryptoVarLength.X448_PUBLIC_KEY.value,
                           not_all_zeros = True)
        except ValidationError as exc:
            raise ValidationError(f'The X448 public key failed validation: {exc.args[0]}') from exc

    @classmethod
    def _from_public_bytes(cls, public_key_bytes: bytes) -> 'X448PubKey':
        """Reconstruct X448 public key from raw bytes."""
        cls.validate_public_bytes(public_key_bytes)
        return cls(X448PublicKey.from_public_bytes(public_key_bytes))

    @property
    def x448_public_key(self) -> X448PublicKey:
        """Re-generate the X448 public key object."""
        return X448PublicKey.from_public_bytes(self.__public_key_bytes)


class X448PrivKey:
    """Type-safe, immutable wrapper for X448 private keys."""

    def __init__(self, private_key: X448PrivateKey) -> None:
        """Create a new X448PrivKey object."""
        if not isinstance(private_key, X448PrivateKey):
            raise ValidationError('The private key was not an X448PrivateKey key.')

        private_key_bytes = private_key.private_bytes_raw()
        self.validate_private_bytes(private_key_bytes)
        X448PubKey.validate_public_bytes(private_key.public_key().public_bytes_raw())
        self.__private_key_bytes = private_key_bytes

    def __eq__(self, other: object) -> bool:
        """Return True if two X448 private keys are equal."""
        return isinstance(other, X448PrivKey) and self.__private_key_bytes == other.__private_key_bytes

    def __hash__(self) -> int:
        """Hash by raw private bytes to allow dict/set usage."""
        return hash(self.__private_key_bytes)

    def __reduce__(self) -> tuple[Callable[[bytes], 'X448PrivKey'], tuple[bytes]]:
        """Serialize by raw private bytes to support multiprocessing queues."""
        return type(self)._from_private_bytes, (self.__private_key_bytes,)

    @staticmethod
    def validate_private_bytes(private_key_bytes: bytes) -> None:
        """Validate raw X448 private key bytes."""
        try:
            validate_bytes(private_key_bytes,
                           is_length     = KeyLength.X448_PRIVATE_KEY.value,
                           not_all_zeros = True)
        except ValidationError as exc:
            raise ValidationError(f'The X448 private key failed validation: {exc.args[0]}') from exc

    @classmethod
    def _from_private_bytes(cls, private_key_bytes: bytes) -> 'X448PrivKey':
        """Reconstruct X448 private key from raw bytes."""
        cls.validate_private_bytes(private_key_bytes)
        return cls(X448PrivateKey.from_private_bytes(private_key_bytes))

    @property
    def x448_private_key(self) -> X448PrivateKey:
        """Re-generate the X448 private key object."""
        return X448PrivateKey.from_private_bytes(self.__private_key_bytes)

    @property
    def x448_pub_key(self) -> X448PubKey:
        """Derive the corresponding X448 public key."""
        return X448PubKey(self.x448_private_key.public_key())
