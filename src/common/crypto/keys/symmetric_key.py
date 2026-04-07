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

from typing import Generic, Optional as O, Self, TypeVar

from src.common.exceptions import CriticalError
from src.common.crypto.algorithms.aead import encrypt_and_sign, auth_and_decrypt
from src.common.crypto.pt_ct import (Ciphertext, CommandHeaderCT, CommandHeaderPT, FileInnerCT, FileInnerPT,
                                     LocalKeySetCT, LocalKeySetPT, MessageHeaderContactCT,
                                     MessageHeaderContactPT, MessageHeaderUserCT, MessageHeaderUserPT,
                                     MsgInnerCT, MsgInnerPT, PSKCT, PSKPT, Plaintext, MulticastFilePT,
                                     MulticastFileCT)
from src.common.statics import KeyLength
from src.common.utils.validators import validate_bytes
from src.common.crypto.algorithms.csprng import csprng


class SymmetricKey:
    """SymmetricKey object is a wrapper for symmetric keys.

    This object is used for type safety, and to encapsulate the key during use to prevent accidental exfiltration
    """

    def __init__(self,
                 key_bytes : O[bytes] = None,
                 *,
                 verify    : bool = True
                 ) -> None:
        """Create a new SymmetricKey object."""
        if key_bytes is None:
            key_bytes = csprng(KeyLength.SYMMETRIC_KEY)
        elif verify:
            self.validate_key_bytes(key_bytes)

        self.__key_bytes = key_bytes

    @staticmethod
    def validate_key_bytes(key_bytes: bytes) -> None:
        """Validate key bytes."""
        validate_bytes(key_bytes, key='key_bytes', is_length=KeyLength.SYMMETRIC_KEY, not_all_zeros=True)

    @classmethod
    def generate_zero_key(cls) -> Self:
        """Generate zero key.

        This key is used as a placeholder for contact's
        PSK, until the key-file has been exchanged.
        """
        return cls(bytes(KeyLength.SYMMETRIC_KEY), verify=False)

    @property
    def is_zero_key(self) -> bool:
        """Return True if the key is zero, otherwise False."""
        return all(byte == 0 for byte in self.raw_bytes)

    def encrypt_and_sign(self,
                         plaintext : bytes,
                         ad        : bytes = b'',
                         ) -> bytes:
        """Encrypt plaintext using the symmetric key."""
        if self.__key_bytes is None:
            raise CriticalError('Key bytes not set.')

        self.validate_key_bytes(self.__key_bytes)
        return encrypt_and_sign(plaintext=plaintext, key=self.__key_bytes, ad=ad)

    def auth_and_decrypt(self,
                         nonce_ct_tag : bytes,       # Nonce + ciphertext + tag
                         database     : str   = '',  # When provided, gracefully exits TFC when the tag is invalid
                         ad           : bytes = b'',
                         ) -> bytes:                 # Plaintext
        """Authenticate and decrypt ciphertext using the symmetric key."""
        if self.__key_bytes is None:
            raise CriticalError('Key bytes not set.')

        self.validate_key_bytes(self.__key_bytes)
        return auth_and_decrypt(nonce_ct_tag=nonce_ct_tag, key=self.__key_bytes, database=database, ad=ad)

    @property
    def raw_bytes(self) -> bytes:
        """Export the symmetric key. Note: This must ONLY be called by a KeySet object serializing the keys."""
        if self.__key_bytes is None:
            raise CriticalError('Key bytes not set.')

        return self.__key_bytes


# ┌──────────────────────┐
# │ Generic Type Wrapper │
# └──────────────────────┘

PT = TypeVar('PT', bound=Plaintext)
CT = TypeVar('CT', bound=Ciphertext)

class TypedSymmetricKey(Generic[PT, CT]):
    """Generic wrapper for Symmetric Keys with specific Plaintext/Ciphertext parameters and return types."""

    PLAINTEXT_TYPE  : type[PT]
    CIPHERTEXT_TYPE : type[CT]

    def __init__(self,
                 key_bytes : O[bytes] = None,
                 *,
                 verify    : bool = True
                 ) -> None:
        """Create a new typed symmetric key object."""
        if key_bytes is None:
            key_bytes = csprng(KeyLength.SYMMETRIC_KEY)
        elif verify:
            self.validate_key_bytes(key_bytes)

        self.__key_bytes = key_bytes

    @property
    def is_zero_key(self) -> bool:
        """Return True if the key is zero, otherwise False."""
        return all(byte == 0 for byte in self.raw_bytes)

    @staticmethod
    def validate_key_bytes(key_bytes: bytes) -> None:
        """Validate key bytes."""
        validate_bytes(key_bytes, key='key_bytes', is_length=KeyLength.SYMMETRIC_KEY, not_all_zeros=True)

    def encrypt_and_sign(self, plaintext: PT) -> CT:
        """Encrypt plaintext using the symmetric key."""
        if self.__key_bytes is None:
            raise CriticalError('Key bytes not set.')

        self.validate_key_bytes(self.__key_bytes)
        plaintext_wrapper: Plaintext = plaintext

        ciphertext = encrypt_and_sign(plaintext = plaintext_wrapper.pt_bytes,
                                      key       = self.__key_bytes)

        return self.CIPHERTEXT_TYPE(ciphertext)

    def auth_and_decrypt(self, nonce_ct_tag: CT, database: str = '') -> PT:
        """Authenticate and decrypt ciphertext using the symmetric key."""
        if self.__key_bytes is None:
            raise CriticalError('Key bytes not set.')

        self.validate_key_bytes(self.__key_bytes)
        ciphertext_wrapper: Ciphertext = nonce_ct_tag
        plaintext = auth_and_decrypt(nonce_ct_tag = ciphertext_wrapper.ct_bytes,
                                     key          = self.__key_bytes,
                                     database     = database)
        return self.PLAINTEXT_TYPE(plaintext)

    @property
    def raw_bytes(self) -> bytes:
        """Export the symmetric key bytes."""
        if self.__key_bytes is None:
            raise CriticalError('Key bytes not set.')

        return self.__key_bytes


# ┌─────────────┐
# │ Header Keys │
# └─────────────┘

class HeaderKey(TypedSymmetricKey[PT, CT], Generic[PT, CT]):
    """Generic base for header-key specializations."""
    pass

class LocalHeaderKey(HeaderKey[CommandHeaderPT, CommandHeaderCT]):
    """SymmetricKey object for command headers."""
    PLAINTEXT_TYPE  = CommandHeaderPT
    CIPHERTEXT_TYPE = CommandHeaderCT

class HeaderKeyUser(HeaderKey[MessageHeaderUserPT, MessageHeaderUserCT]):
    """The static symmetric key that encrypts/decrypts hash ratchet counter sent to contact."""
    PLAINTEXT_TYPE  = MessageHeaderUserPT
    CIPHERTEXT_TYPE = MessageHeaderUserCT

class HeaderKeyContact(HeaderKey[MessageHeaderContactPT, MessageHeaderContactCT]):
    """The static symmetric key that decrypts hash ratchet counter of message from contact."""
    PLAINTEXT_TYPE  = MessageHeaderContactPT
    CIPHERTEXT_TYPE = MessageHeaderContactCT

    @classmethod
    def generate_zero_key(cls) -> Self:
        """Generate zero key.

        This key is used as a placeholder for contact's
        PSK, until the key-file has been exchanged.
        """
        return cls(bytes(KeyLength.SYMMETRIC_KEY), verify=False)


# ┌──────────────────┐
# │ Long Packet Keys │
# └──────────────────┘

class LongFileKey(TypedSymmetricKey[FileInnerPT, FileInnerCT]):
    """Inner layer encryption key for long files.

    This key is used to provide an inner layer of encryption, which provides sender based control.
    If the user aborts sending the file before the last 1-2 datagrams (that contain FileKey) are
    sent, the recipient is not able to decrypt the received packet.
    """
    PLAINTEXT_TYPE  = FileInnerPT
    CIPHERTEXT_TYPE = FileInnerCT

class LongMessageKey(TypedSymmetricKey[MsgInnerPT, MsgInnerCT]):
    """Inner layer encryption key for long files."""
    PLAINTEXT_TYPE  = MsgInnerPT
    CIPHERTEXT_TYPE = MsgInnerCT


# ┌──────────────┐
# │ Message Keys │
# └──────────────┘

# Note: These keys are only used to move Ratchet Keys around, as real
# RatchetKeys required internal state setup during the initialization.

class MessageKey(SymmetricKey):
    """MessageKey is a RatchetKey instance used during generation and transport."""

class LocalMessageKey(SymmetricKey):
    """Forward Secret MessageKey that Transmitter Program uses encrypt commands to Receiver Program."""

class MessageKeyUser(MessageKey):
    """Forward Secret MessageKey that the user uses to encrypt messages/files to contact."""
    pass

class MessageKeyContact(MessageKey):
    """Forward Secret MessageKey that the contact uses to encrypt messages/files to user."""
    pass


# ┌───────────┐
# │ File Keys │
# └───────────┘
class MulticastFileKey(TypedSymmetricKey[MulticastFilePT, MulticastFileCT]):
    """MulticastFileKey is a symmetric key used to encrypt multicasted files sent to all window members."""
    PLAINTEXT_TYPE  = MulticastFilePT
    CIPHERTEXT_TYPE = MulticastFileCT


# ┌─────────────────────┐
# │ Key Encryption Keys │
# └─────────────────────┘

# Used for sending encrypted keys.

class LocalKeyEncryptionKey(TypedSymmetricKey[LocalKeySetPT, LocalKeySetCT]):
    """SymmetricKey object for local key encryption."""
    PLAINTEXT_TYPE  = LocalKeySetPT
    CIPHERTEXT_TYPE = LocalKeySetCT

class PSKEncryptionKey(TypedSymmetricKey[PSKPT, PSKCT]):
    """Symmetric key object for encrypting PSKs"""
    PLAINTEXT_TYPE  = PSKPT
    CIPHERTEXT_TYPE = PSKCT

class MasterKeyRekeying(SymmetricKey):
    """Master key delivered to sender process during rekeying."""
    pass


# ┌────────────────────┐
# │ Public Key Related │
# └────────────────────┘
class X448SharedKey(SymmetricKey):
    """X448 Shared Key object.

    Note: This must not be used before shared secret
          is compressed with the BLAKE2b KDF to 256 bits.
    """
    pass


# ┌───────────────┐
# │ Relay Program │
# └───────────────┘

class BufferKey(SymmetricKey):
    """BufferKey is a symmetric key used to encrypt outbound packets on Relay Program.

    This mostly prevents other applications from editing said data, viewing public keys etc.
    It also hides to whom each packet is queued to.
    """
    pass
