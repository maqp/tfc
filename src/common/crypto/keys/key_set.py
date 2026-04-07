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

from typing import TYPE_CHECKING, Callable

from src.common.crypto.keys.ratchet_state import RatchetState
from src.common.crypto.keys.ratchet_key import LocalRatchetKey, RatchetKeyContact, RatchetKeyUser
from src.common.crypto.keys.symmetric_key import LocalHeaderKey

if TYPE_CHECKING:
    from src.common.crypto.keys.onion_service_keys import OnionServicePublicKey
    from src.common.crypto.keys.kek_hash import KEKHash
    from src.common.crypto.keys.symmetric_key import HeaderKeyUser, HeaderKeyContact, LocalMessageKey
    from src.common.crypto.keys.symmetric_key import MessageKeyContact, MessageKeyUser
    from src.common.crypto.pt_ct import CommandAssemblyPacketPT, LocalKeySetPT


class KeySet:
    """KeySet object contains frequently changing keys and hash ratchet counters.

        onion_pub_key: The public key that corresponds to the contact's v3
                       Tor Onion Service address. Used to uniquely identify
                       the KeySet object.

        tx_mk:         The forward secret message key for sent messages.

        rx_mk:         The forward secret message key for received messages.
                       Used only by the Receiver Program.

        tx_hk:         The static header key used to encrypt and sign the hash
                       ratchet counter provided along the encrypted
                       assembly packet.

        rx_hk:         The static header key used to authenticate and decrypt
                       the hash ratchet counter of received messages. Used
                       only by the Receiver Program.

        tx_harac:      The hash ratchet counter for sent messages.

        rx_harac:      The hash ratchet counter for received messages. Used
                       only by the Receiver Program.
    """

    def __init__(self,
                 onion_pub_key : 'OnionServicePublicKey',
                 tx_hk         : 'HeaderKeyUser',
                 tx_mk         : 'MessageKeyUser',
                 rx_hk         : 'HeaderKeyContact',
                 rx_mk         : 'MessageKeyContact',
                 tx_harac      : RatchetState,
                 rx_harac      : RatchetState,
                 store_keys    : Callable[..., None]
                 ) -> None:
        """Create new TxKeySet object."""
        self.onion_pub_key = onion_pub_key

        self.tx_hk = tx_hk
        self.tx_mk = tx_mk
        self.rx_hk = rx_hk
        self.rx_mk = rx_mk

        # Ratchet keys
        self.tx_rk = None if self.tx_mk.is_zero_key else RatchetKeyUser   (tx_mk.raw_bytes, tx_harac, store_keys)
        self.rx_rk = None if self.rx_mk.is_zero_key else RatchetKeyContact(rx_mk.raw_bytes, rx_harac, store_keys)

        self.store_keys = store_keys

    def serialize(self) -> bytes:
        """Serialize TxKeySet object for storage/transport."""
        tx_rk = self.tx_mk if self.tx_rk is None else self.tx_rk
        rx_rk = self.rx_mk if self.rx_rk is None else self.rx_rk

        tx_ratchet_state = RatchetState() if self.tx_rk is None else self.tx_rk.ratchet_state
        rx_ratchet_state = RatchetState() if self.rx_rk is None else self.rx_rk.ratchet_state

        return (self.onion_pub_key.serialize()
                + self.tx_hk.raw_bytes
                + tx_rk.raw_bytes
                + self.rx_hk.raw_bytes
                + rx_rk.raw_bytes
                + tx_ratchet_state.serialize()
                + rx_ratchet_state.serialize())

    def export_to_receiver_program(self) -> 'CommandAssemblyPacketPT':
        """Serialize KeySet into CommandAssemblyPacketPT object."""
        from src.common.crypto.pt_ct import CommandAssemblyPacketPT
        return CommandAssemblyPacketPT(self.serialize())

    def has_contact_key(self) -> bool:
        """Return true if contact's key is present.

        Mainly used for PSKs where PSK exchange won't
        necessarily happen when contact is added.
        """
        return not self.rx_hk.is_zero_key and not self.rx_mk.is_zero_key

    def add_contact_psk(self, rx_hk: 'HeaderKeyContact', rx_mk: 'MessageKeyContact') -> None:
        """Add contact's header and message pre-shared keys."""
        self.rx_hk = rx_hk
        self.rx_mk = rx_mk
        self.rx_rk = RatchetKeyContact(rx_mk.raw_bytes, RatchetState(), self.store_keys)


class LocalKeySet:
    """KeySet for local key used for TCB-synchronization."""

    def __init__(self,
                 header_key    : LocalHeaderKey,
                 message_key   : 'LocalMessageKey',
                 ratchet_state : RatchetState,
                 kek_hash      : 'KEKHash',
                 store_keys    : Callable[..., None]
                 ) -> None:
        """Create new LocalKeySet object."""
        self.header_key  = LocalHeaderKey(header_key.raw_bytes)
        self.ratchet_key = LocalRatchetKey(message_key.raw_bytes, ratchet_state, store_keys)
        self.__kek_hash  = kek_hash
        self.store_keys  = store_keys

    def serialize(self) -> bytes:
        """Serialize LocalKeySet object for storage."""
        return (  self.header_key .raw_bytes
                + self.ratchet_key.raw_bytes
                + self.ratchet_key.ratchet_plaintext.pt_bytes
                + self.__kek_hash.kek_bytes)

    def export_to_receiver_program(self) -> 'LocalKeySetPT':
        """Serialize LocalKeySet into LocalKeySetPT object for transport to Receiver Program."""
        from src.common.crypto.pt_ct import LocalKeySetPT
        return LocalKeySetPT(  self.header_key .raw_bytes
                             + self.ratchet_key.raw_bytes)

    @property
    def kek_hash(self) -> 'KEKHash':
        """Return kek hash.

        This is used to detect accidental export of full KEK to Networked Computer.
        """
        return self.__kek_hash
