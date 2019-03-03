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
"""

import os
import typing

from typing import Any, Callable, List

from src.common.crypto     import auth_and_decrypt, blake2b, csprng, encrypt_and_sign
from src.common.encoding   import int_to_bytes, onion_address_to_pub_key
from src.common.encoding   import bytes_to_int
from src.common.exceptions import CriticalError
from src.common.misc       import ensure_dir, separate_headers, split_byte_string
from src.common.statics    import *

if typing.TYPE_CHECKING:
    from src.common.db_masterkey import MasterKey
    from src.common.db_settings  import Settings


class KeySet(object):
    """\
    KeySet object contains frequently changing keys and hash ratchet
    counters of contacts:

    onion_pub_key: The public key that corresponds to the contact's v3
                   Tor Onion Service address. Used to uniquely identify
                   the KeySet object.

    tx_mk:         Forward secret message key for sent messages.

    rx_mk:         Forward secret message key for received messages.
                   Used only by the Receiver Program.

    tx_hk:         Static header key used to encrypt and sign the hash
                   ratchet counter provided along the encrypted
                   assembly packet.

    rx_hk:         Static header key used to authenticate and decrypt
                   the hash ratchet counter of received messages. Used
                   only by the Receiver Program.

    tx_harac:      The hash ratchet counter for sent messages.

    rx_harac:      The hash ratchet counter for received messages. Used
                   only by the Receiver Program.
    """

    def __init__(self,
                 onion_pub_key: bytes,
                 tx_mk:         bytes,
                 rx_mk:         bytes,
                 tx_hk:         bytes,
                 rx_hk:         bytes,
                 tx_harac:      int,
                 rx_harac:      int,
                 store_keys:    Callable
                 ) -> None:
        """Create a new KeySet object.

        The `self.store_keys` is a reference to the method of the parent
        object KeyList that stores the list of KeySet objects into an
        encrypted database.
        """
        self.onion_pub_key = onion_pub_key
        self.tx_mk         = tx_mk
        self.rx_mk         = rx_mk
        self.tx_hk         = tx_hk
        self.rx_hk         = rx_hk
        self.tx_harac      = tx_harac
        self.rx_harac      = rx_harac
        self.store_keys    = store_keys

    def serialize_k(self) -> bytes:
        """Return KeySet data as a constant length byte string.

        This function serializes the KeySet's data into a byte string
        that has the exact length of 32 + 4*32 + 2*8 = 176 bytes. The
        length is guaranteed regardless of the content of the
        attributes' values. The purpose of the constant length
        serialization is to hide any metadata about the KeySet database
        the ciphertext length of the key database would reveal.
        """
        return (self.onion_pub_key
                + self.tx_mk
                + self.rx_mk
                + self.tx_hk
                + self.rx_hk
                + int_to_bytes(self.tx_harac)
                + int_to_bytes(self.rx_harac))

    def rotate_tx_mk(self) -> None:
        """\
        Update Transmitter Program's tx-message key and tx-harac.

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
        self.tx_mk     = blake2b(self.tx_mk + int_to_bytes(self.tx_harac), digest_size=SYMMETRIC_KEY_LENGTH)
        self.tx_harac += 1
        self.store_keys()

    def update_mk(self,
                  direction: str,
                  key:       bytes,
                  offset:    int
                  ) -> None:
        """Update Receiver Program's tx/rx-message key and tx/rx-harac.

        This method provides per-message forward secrecy for received
        messages. Due to the possibility of dropped packets, the
        Receiver Program might have to jump over some key values and
        ratchet counter states. Therefore, the increase done by this
        function is not linear like in the case of `rotate_tx_mk`.
        """
        if direction == TX:
            self.tx_mk     = key
            self.tx_harac += offset
            self.store_keys()
        elif direction == RX:
            self.rx_mk     = key
            self.rx_harac += offset
            self.store_keys()
        else:
            raise CriticalError("Invalid key direction.")


class KeyList(object):
    """\
    KeyList object manages TFC's KeySet objects and the storage of the
    objects in an encrypted database.

    The main purpose of this object is to manage the `self.keysets`-list
    that contains TFC's keys. The database is stored on disk in
    encrypted form. Prior to encryption, the database is padded with
    dummy KeySets. The dummy KeySets hide the number of actual KeySets
    and thus the number of contacts, that would otherwise be revealed by
    the size of the encrypted database. As long as the user has less
    than 50 contacts, the database will effectively hide the actual
    number of contacts.

    The KeySet database is separated from contact database as traffic
    masking needs to update keys frequently with no risk of read/write
    queue blocking that occurs, e.g., when an updated nick of contact is
    being stored in the database.
    """

    def __init__(self, master_key: 'MasterKey', settings: 'Settings') -> None:
        """Create a new KeyList object."""
        self.master_key   = master_key
        self.settings     = settings
        self.keysets      = []  # type: List[KeySet]
        self.dummy_keyset = self.generate_dummy_keyset()
        self.dummy_id     = self.dummy_keyset.onion_pub_key
        self.file_name    = f'{DIR_USER_DATA}{settings.software_operation}_keys'

        ensure_dir(DIR_USER_DATA)
        if os.path.isfile(self.file_name):
            self._load_keys()
        else:
            self.store_keys()

    def store_keys(self) -> None:
        """Write the list of KeySet objects to an encrypted database.

        This function will first create a list of KeySets and dummy
        KeySets. It will then serialize every KeySet object on that list
        and join the constant length byte strings to form the plaintext
        that will be encrypted and stored in the database.

        By default, TFC has a maximum number of 50 contacts. In
        addition, the database stores the KeySet used to encrypt
        commands from Transmitter to Receiver Program). The plaintext
        length of 51 serialized KeySets is 51*176 = 8976 bytes. The
        ciphertext includes a 24-byte nonce and a 16-byte tag, so the
        size of the final database is 9016 bytes.
        """
        pt_bytes = b''.join([k.serialize_k() for k in self.keysets + self._dummy_keysets()])
        ct_bytes = encrypt_and_sign(pt_bytes, self.master_key.master_key)

        ensure_dir(DIR_USER_DATA)
        with open(self.file_name, 'wb+') as f:
            f.write(ct_bytes)

    def _load_keys(self) -> None:
        """Load KeySets from the encrypted database.

        This function first reads and decrypts the database content. It
        then splits the plaintext into a list of 176-byte blocks. Each
        block contains the serialized data of one KeySet. Next, the
        function will remove from the list all dummy KeySets (that start
        with the `dummy_id` byte string). The function will then
        populate the `self.keysets` list with KeySet objects, the data
        of which is sliced and decoded from the dummy-free blocks.
        """
        with open(self.file_name, 'rb') as f:
            ct_bytes = f.read()

        pt_bytes  = auth_and_decrypt(ct_bytes, self.master_key.master_key, database=self.file_name)
        blocks    = split_byte_string(pt_bytes, item_len=KEYSET_LENGTH)
        df_blocks = [b for b in blocks if not b.startswith(self.dummy_id)]

        for block in df_blocks:
            if len(block) != KEYSET_LENGTH:
                raise CriticalError("Invalid data in key database.")

            onion_pub_key, tx_mk, rx_mk, tx_hk, rx_hk, tx_harac_bytes, rx_harac_bytes \
                = separate_headers(block, [ONION_SERVICE_PUBLIC_KEY_LENGTH] + 4*[SYMMETRIC_KEY_LENGTH] + [HARAC_LENGTH])

            self.keysets.append(KeySet(onion_pub_key=onion_pub_key,
                                       tx_mk=tx_mk,
                                       rx_mk=rx_mk,
                                       tx_hk=tx_hk,
                                       rx_hk=rx_hk,
                                       tx_harac=bytes_to_int(tx_harac_bytes),
                                       rx_harac=bytes_to_int(rx_harac_bytes),
                                       store_keys=self.store_keys))

    @staticmethod
    def generate_dummy_keyset() -> 'KeySet':
        """Generate a dummy KeySet object.

        The dummy KeySet simplifies the code around the constant length
        serialization when the data is stored to, or read from the
        database.

        In case the dummy keyset would ever be loaded accidentally, it
        uses a set of random keys to prevent decryption by eavesdropper.
        """
        return KeySet(onion_pub_key=onion_address_to_pub_key(DUMMY_CONTACT),
                      tx_mk=csprng(),
                      rx_mk=csprng(),
                      tx_hk=csprng(),
                      rx_hk=csprng(),
                      tx_harac=INITIAL_HARAC,
                      rx_harac=INITIAL_HARAC,
                      store_keys=lambda: None)

    def _dummy_keysets(self) -> List[KeySet]:
        """\
        Generate a proper size list of dummy KeySets for database
        padding.

        The additional contact (+1) is the local key.
        """
        number_of_contacts_to_store = self.settings.max_number_of_contacts + 1
        number_of_dummies           = number_of_contacts_to_store - len(self.keysets)
        return [self.dummy_keyset] * number_of_dummies

    def add_keyset(self,
                   onion_pub_key: bytes,
                   tx_mk:         bytes,
                   rx_mk:         bytes,
                   tx_hk:         bytes,
                   rx_hk:         bytes) -> None:
        """\
        Add a new KeySet to `self.keysets` list and write changes to the
        database.
        """
        if self.has_keyset(onion_pub_key):
            self.remove_keyset(onion_pub_key)

        self.keysets.append(KeySet(onion_pub_key=onion_pub_key,
                                   tx_mk=tx_mk,
                                   rx_mk=rx_mk,
                                   tx_hk=tx_hk,
                                   rx_hk=rx_hk,
                                   tx_harac=INITIAL_HARAC,
                                   rx_harac=INITIAL_HARAC,
                                   store_keys=self.store_keys))
        self.store_keys()

    def remove_keyset(self, onion_pub_key: bytes) -> None:
        """\
        Remove KeySet from `self.keysets` based on Onion Service public key.

        If the KeySet was found and removed, write changes to the database.
        """
        for i, k in enumerate(self.keysets):
            if k.onion_pub_key == onion_pub_key:
                del self.keysets[i]
                self.store_keys()
                break

    def change_master_key(self, master_key: 'MasterKey') -> None:
        """Change the master key and encrypt the database with the new key."""
        self.master_key = master_key
        self.store_keys()

    def update_database(self, settings: 'Settings') -> None:
        """Update settings and database size."""
        self.settings = settings
        self.store_keys()

    def get_keyset(self, onion_pub_key: bytes) -> KeySet:
        """\
        Return KeySet object from `self.keysets`-list that matches the
        Onion Service public key used as the selector.
        """
        return next(k for k in self.keysets if k.onion_pub_key == onion_pub_key)

    def get_list_of_pub_keys(self) -> List[bytes]:
        """Return list of Onion Service public keys for KeySets."""
        return [k.onion_pub_key for k in self.keysets if k.onion_pub_key != LOCAL_PUBKEY]

    def has_keyset(self, onion_pub_key: bytes) -> bool:
        """Return True if KeySet with matching Onion Service public key exists, else False."""
        return any(onion_pub_key == k.onion_pub_key for k in self.keysets)

    def has_rx_mk(self, onion_pub_key: bytes) -> bool:
        """\
        Return True if KeySet with matching Onion Service public key has
        rx-message key, else False.

        When the PSK key exchange option is selected, the KeySet for
        newly created contact on Receiver Program is a null-byte string.
        This default value indicates the PSK of contact has not yet been
        imported.
        """
        return self.get_keyset(onion_pub_key).rx_mk != bytes(SYMMETRIC_KEY_LENGTH)

    def has_local_keyset(self) -> bool:
        """Return True if local KeySet object exists, else False."""
        return any(k.onion_pub_key == LOCAL_PUBKEY for k in self.keysets)

    def manage(self, command: str, *params: Any) -> None:
        """Manage KeyList based on a command.

        The command is delivered from `input_process` to `sender_loop`
        process via the `KEY_MANAGEMENT_QUEUE`.
        """
        if command == KDB_ADD_ENTRY_HEADER:
            self.add_keyset(*params)
        elif command == KDB_REMOVE_ENTRY_HEADER:
            self.remove_keyset(*params)
        elif command == KDB_CHANGE_MASTER_KEY_HEADER:
            self.change_master_key(*params)
        elif command == KDB_UPDATE_SIZE_HEADER:
            self.update_database(*params)
        else:
            raise CriticalError("Invalid KeyList management command.")
