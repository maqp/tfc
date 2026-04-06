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

from typing import TYPE_CHECKING, Callable, Generic, Self

import nacl.exceptions

from src.common.crypto.keys.ratchet_state import RatchetState
from src.common.exceptions import ValidationError, SoftError
from src.common.crypto.algorithms.blake2b import blake2b
from src.common.crypto.algorithms.aead import auth_and_decrypt
from src.common.crypto.pt_ct import (
    CommandAssemblyPacketCT,
    CommandAssemblyPacketPT,
    MessageAssemblyPacketContactCT,
    MessageAssemblyPacketContactPT,
    MessageAssemblyPacketUserCT,
    MessageAssemblyPacketUserPT,
    MessageHeaderUserPT,
)
from src.common.crypto.keys.symmetric_key import CT, PT, TypedSymmetricKey
from src.common.statics import EncodingLiteral, KeyLength
from src.common.utils.encoding import int_to_bytes
from src.common.utils.validators import validate_int

if TYPE_CHECKING:
    from src.common.crypto.pt_ct import Ciphertext


class RatchetKey(TypedSymmetricKey[PT, CT], Generic[PT, CT]):
    """RatchetKey represents a symmetric key that has forward-secrecy via hash ratchet."""

    def __init__(self,
                 key_bytes     : bytes,
                 ratchet_state : RatchetState,
                 store_keys    : Callable[..., None]
                 ) -> None:
        """Create a new RatchetKey object."""
        super().__init__(key_bytes)

        self.__ratchet_state = ratchet_state
        self.store_keys      = store_keys

    @staticmethod
    def _derive_next_key(key_bytes: bytes, ratchet_state: RatchetState) -> bytes:
        """Derive the next key in the hash ratchet."""
        return blake2b(key_bytes + int_to_bytes(ratchet_state.value),
                       digest_size=KeyLength.SYMMETRIC_KEY)

    def next_key(self) -> Self:
        """Return the next ratchet key.

        Replacing the key with its hash provides per-message forward
        secrecy for sent messages. The hash ratchet used is also known
        as the SCIMP Ratchet[1], and it is widely used, e.g., as part of
        Signal's Double Ratchet[2].

        To ensure the hash ratchet does not fall into a short cycle of
        keys, the harac (that is a non-repeating value) is used as an
        additional input when deriving the next key.

        [1] (pp. 17-18) https://netzpolitik.org/wp-upload/SCIMP-paper.pdf
        [2] https://signal.org/blog/advanced-ratcheting/
        """
        next_ratchet_state = RatchetState(self.__ratchet_state.value)
        next_ratchet_state.increment()
        return self.__class__(self._derive_next_key(self.raw_bytes, self.__ratchet_state),
                              next_ratchet_state,
                              self.store_keys)

    def __catch_up(self, offset: int) -> tuple[bytes, int]:
        """Catch up with the state of sending device's ratchet."""
        try:
            validate_int(offset, key='offset', min_value=0, max_value=EncodingLiteral.MAX_INT)
        except ValidationError:
            # Output is disabled to not litter Receiver Program with false positives when autoreplaying older packets.
            raise SoftError('Message key had invalid offset.', output=False)

        purp_key_bytes     = self.raw_bytes
        cur_value          = self.__ratchet_state.value
        purp_ratchet_state = cur_value

        for harac_value in range(cur_value, cur_value + offset):
            purp_key_bytes = self._derive_next_key(purp_key_bytes, RatchetState(harac_value))
            purp_ratchet_state += 1

        return purp_key_bytes, purp_ratchet_state

    def catch_up_and_decrypt(self,
                             nonce_ct_tag : CT,
                             offset       : int   = 0
                             ) -> tuple[PT, Self]:
        """Auth and decrypt forward secret packet and return the next usable ratchet key."""
        purp_key_bytes, purp_ratchet_state = self.__catch_up(offset)

        try:
            ciphertext_wrapper: 'Ciphertext' = nonce_ct_tag
            plaintext = self.PLAINTEXT_TYPE(auth_and_decrypt(nonce_ct_tag=ciphertext_wrapper.ct_bytes, key=purp_key_bytes))
        except nacl.exceptions.CryptoError:
            raise

        next_key = self.__class__(self._derive_next_key(purp_key_bytes, RatchetState(purp_ratchet_state)),
                                  RatchetState(purp_ratchet_state + 1),
                                  self.store_keys)

        return plaintext, next_key

    @property
    def ratchet_state(self) -> RatchetState:
        """Get the ratchet state."""
        return self.__ratchet_state

    @property
    def ratchet_plaintext(self) -> MessageHeaderUserPT:
        """Get the ratchet plaintext for header encryption."""
        return MessageHeaderUserPT(self.__ratchet_state.serialize())


class RatchetKeyUser(RatchetKey[MessageAssemblyPacketUserPT, MessageAssemblyPacketUserCT]):
    """The forward secret ratchet key that encrypts/decrypts messages/files sent to contact."""
    PLAINTEXT_TYPE  = MessageAssemblyPacketUserPT
    CIPHERTEXT_TYPE = MessageAssemblyPacketUserCT


class RatchetKeyContact(RatchetKey[MessageAssemblyPacketContactPT, MessageAssemblyPacketContactCT]):
    """The forward secret ratchet key that decrypts messages/files from contact."""
    PLAINTEXT_TYPE  = MessageAssemblyPacketContactPT
    CIPHERTEXT_TYPE = MessageAssemblyPacketContactCT


class LocalRatchetKey(RatchetKey[CommandAssemblyPacketPT, CommandAssemblyPacketCT]):
    """The forward secret local key that encrypts/decrypts commands from Transmitter to Receiver Program."""
    PLAINTEXT_TYPE  = CommandAssemblyPacketPT
    CIPHERTEXT_TYPE = CommandAssemblyPacketCT
