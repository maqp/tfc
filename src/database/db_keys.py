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

import os
import time

from typing import Any, TypeGuard, TYPE_CHECKING

from src.common.crypto.keys.ratchet_state import RatchetState
from src.common.exceptions import CriticalError, SoftError
from src.common.crypto.keys.key_set import KeySet
from src.common.crypto.keys.onion_service_keys import OnionPublicKeyContact
from src.common.crypto.pt_ct import MessageAssemblyPacketUserPT
from src.common.crypto.keys.symmetric_key import MessageKeyUser, MessageKeyContact, HeaderKeyUser, HeaderKeyContact, MasterKeyRekeying
from src.common.statics import (KeyDBMgmt, DataDir, DummyID, CompoundFieldLength, CryptoVarLength, KeyLength, DBName, FieldLength)
from src.common.types_custom import BoolReplaceDB, IntRatchetOffset
from src.common.utils.encoding import bytes_to_int
from src.common.utils.io import ensure_dir
from src.common.utils.strings import split_byte_string, separate_headers
from src.common.utils.validators import validate_bytes
from src.database.database import TFCEncryptedDatabase

if TYPE_CHECKING:
    from src.common.entities.assembly_packet import MessageAssemblyPacket
    from src.common.crypto.pt_ct import (MessageAssemblyPacketContactCT, MessageAssemblyPacketContactPT,
                                         MessageAssemblyPacketUserCT, MessageHeaderContactCT, MessageHeaderUserCT)
    from src.common.types_compound import KeyDBUpdateMasterKeyTuple, KeyStoreMgmt
    from src.common.queues import TxQueue
    from src.database.db_masterkey import MasterKey
    from src.database.db_settings import Settings


class KeyStore:
    """\
    KeyStore object manages TFC's KeySet objects and the storage of the
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
        """Create a new KeyStore object."""
        self.__master_key = master_key
        self.__settings   = settings
        self.__dummy_data = self.__generate_dummy_data()

        self.__database = TFCEncryptedDatabase(DBName.KEY_STORE, master_key, settings.program_id)
        self.__key_sets : dict[OnionPublicKeyContact, KeySet] = {}

        ensure_dir(DataDir.USER_DATA)
        if os.path.isfile(self.__database.path_to_db):
            self.__load_keys()
        else:
            self.store_keys()


    # ┌───────────────────────────────────────────────────────────────────────────┐
    # │                           Cryptographic Services                          │
    # └───────────────────────────────────────────────────────────────────────────┘

    # ───────────────────────────── Encrypt and Sign ─────────────────────────────

    def encrypt_and_sign_message(self,
                                 assembly_packet : 'MessageAssemblyPacket',
                                 onion_pub_key   : 'OnionPublicKeyContact',
                                 ) -> tuple['MessageHeaderUserCT', 'MessageAssemblyPacketUserCT']:
        """Encrypt and sign message (text or file) to contact."""
        from src.common.entities.assembly_packet import MessageAssemblyPacket
        if not isinstance(assembly_packet, MessageAssemblyPacket):
            raise CriticalError('The plaintext was not MessageAssemblyPacket')
        if not isinstance(onion_pub_key, OnionPublicKeyContact):
            raise CriticalError('The public key was not OnionPublicKeyContact')

        key_set = self.__key_sets[onion_pub_key]

        if key_set.tx_hk is None: raise CriticalError('Missing header encryption key for outgoing packets')
        if key_set.tx_rk is None: raise CriticalError('Missing ratchet encryption key for outgoing packets')

        plaintext         = MessageAssemblyPacketUserPT(assembly_packet.raw_bytes)
        encrypted_message = key_set.tx_rk.encrypt_and_sign(plaintext)
        harac_in_bytes    = key_set.tx_rk.ratchet_plaintext
        key_set.tx_rk     = key_set.tx_rk.next_key()
        self.store_keys()

        encrypted_harac = key_set.tx_hk.encrypt_and_sign(harac_in_bytes)

        return encrypted_harac, encrypted_message


    # ───────────────────────── Authenticate and Decrypt ─────────────────────────

    # ┌────────────────┐
    # │ Header Packets │
    # └────────────────┘

    # Outgoing
    def auth_and_decrypt_sent_packet_header(self,
                                            onion_pub_key : 'OnionPublicKeyContact',
                                            nonce_ct_tag  : 'MessageHeaderUserCT',
                                            ) -> IntRatchetOffset:
        """Auth and decrypt header of packet to/from contact."""
        key_set = self.__key_sets[onion_pub_key]

        if key_set.tx_hk is None: raise CriticalError('Missing header decryption key for outgoing packets')
        if key_set.tx_rk is None: raise CriticalError('Missing ratchet key for outgoing packets')

        message_header_pt = key_set.tx_hk.auth_and_decrypt(nonce_ct_tag)

        try:
            purp_ratchet_state = bytes_to_int(message_header_pt.pt_bytes)
        except ValueError:
            raise SoftError(f'Failed to convert hash ratchet bytes to int.')

        return IntRatchetOffset(purp_ratchet_state - key_set.tx_rk.ratchet_state.value)

    # Incoming
    def auth_and_decrypt_received_packet_header(self,
                                                onion_pub_key : 'OnionPublicKeyContact',
                                                nonce_ct_tag  : 'MessageHeaderContactCT',
                                                ) -> IntRatchetOffset:
        """Auth and decrypt assembly packet received from contact."""
        key_set = self.__key_sets[onion_pub_key]

        if key_set.rx_hk is None: raise CriticalError('Missing header decryption key for incoming packets')
        if key_set.rx_rk is None: raise CriticalError('Missing ratchet key for incoming packets')

        message_header_pt = key_set.rx_hk.auth_and_decrypt(nonce_ct_tag)

        try:
            purp_ratchet_state = bytes_to_int(message_header_pt.pt_bytes)
        except ValueError:
            raise SoftError(f'Failed to convert hash ratchet bytes to int.')

        return IntRatchetOffset(purp_ratchet_state - key_set.rx_rk.ratchet_state.value)


    # ┌──────────────────┐
    # │ Assembly Packets │
    # └──────────────────┘

    # Outgoing
    def auth_and_decrypt_sent_assembly_packet(self,
                                              onion_pub_key : 'OnionPublicKeyContact',
                                              nonce_ct_tag  : 'MessageAssemblyPacketUserCT',
                                              offset        : IntRatchetOffset   = IntRatchetOffset(0)
                                              ) -> MessageAssemblyPacketUserPT:
        """Auth and decrypt assembly packet sent to contact."""
        key_set = self.__key_sets[onion_pub_key]

        if key_set.tx_rk is None: raise CriticalError('Missing payload decryption key for outgoing packets')

        plaintext, key_set.tx_rk = key_set.tx_rk.catch_up_and_decrypt(nonce_ct_tag, offset=offset)
        self.store_keys()
        return plaintext

    # Incoming
    def auth_and_decrypt_received_assembly_packet(self,
                                                  onion_pub_key : 'OnionPublicKeyContact',
                                                  nonce_ct_tag  : 'MessageAssemblyPacketContactCT',
                                                  offset        : IntRatchetOffset = IntRatchetOffset(0)
                                                  ) -> 'MessageAssemblyPacketContactPT':
        """Auth and decrypt assembly packet received from contact."""
        key_set = self.__key_sets[onion_pub_key]

        if key_set.rx_rk is None: raise CriticalError('Missing payload decryption key for incoming packets')

        plaintext, key_set.rx_rk = key_set.rx_rk.catch_up_and_decrypt(nonce_ct_tag, offset=offset)
        self.store_keys()
        return plaintext


    # ------------------------------------------------------------------------------------------------------------------

    def manage(self, queues: 'TxQueue', command: str, *params: Any) -> None:
        """Manage KeyList based on a command.

        The command is delivered from `input_process` to `sender_loop`
        process via the `KEY_MANAGEMENT_QUEUE`.
        """
        if   command == KeyDBMgmt.INSERT_ROW:        self.add_keyset(*params)
        elif command == KeyDBMgmt.DELETE_ROW:        self.remove_keyset(*params)
        elif command == KeyDBMgmt.WAIT_FOR_SYNC:     self.change_master_key(queues)
        elif command == KeyDBMgmt.UPDATE_MASTER_KEY: self.update_master_key(*params)
        elif command == KeyDBMgmt.UPDATE_ROW_COUNT:  self._update_database(*params)
        else: raise CriticalError(f"Invalid KeyList management command '{command}'.")


    # ┌───────────────────────────────────────────────────────────────────────────┐
    # │                                  Setters                                  │
    # └───────────────────────────────────────────────────────────────────────────┘

    def add_keyset(self,
                   onion_pub_key : 'OnionPublicKeyContact',
                   tx_hk         : HeaderKeyUser,
                   tx_mk         : MessageKeyUser,
                   rx_hk         : HeaderKeyContact,
                   rx_mk         : MessageKeyContact,
                   ) -> None:
        """\
        Add a new KeySet to `self.keysets` list and write changes to the
        database.
        """
        if self.has_keyset(onion_pub_key):
            self.remove_keyset(onion_pub_key)

        self.__key_sets[onion_pub_key] = KeySet(onion_pub_key = onion_pub_key,
                                                tx_mk         = tx_mk,
                                                rx_mk         = rx_mk,
                                                tx_hk         = tx_hk,
                                                rx_hk         = rx_hk,
                                                tx_harac      = RatchetState(),
                                                rx_harac      = RatchetState(),
                                                store_keys    = self.store_keys)
        self.store_keys()

    def add_contact_psk(self,
                        onion_pub_key : 'OnionPublicKeyContact',
                        rx_hk         : HeaderKeyContact,
                        rx_mk         : MessageKeyContact
                        ) -> None:
        """Add contact's PSK for receiving messages"""
        self.__key_sets[onion_pub_key].add_contact_psk(rx_hk, rx_mk)
        self.store_keys()


    # ┌───────────────────────────────────────────────────────────────────────────┐
    # │                                  Updaters                                 │
    # └───────────────────────────────────────────────────────────────────────────┘

    def _update_database(self, settings: 'Settings') -> None:
        """Update settings and database size."""
        self.__settings = settings
        self.store_keys()


    # ┌───────────────────────────────────────────────────────────────────────────┐
    # │                                  Deleters                                 │
    # └───────────────────────────────────────────────────────────────────────────┘

    def remove_keyset(self, onion_pub_key: 'OnionPublicKeyContact') -> None:
        """\
        Remove KeySet from `self.keysets` based on Onion Service public key.

        If the KeySet was found and removed, write changes to the database.
        """
        if self.has_keyset(onion_pub_key):
            del self.__key_sets[onion_pub_key]
            self.store_keys()


    # ┌───────────────────────────────────────────────────────────────────────────┐
    # │                                  Getters                                  │
    # └───────────────────────────────────────────────────────────────────────────┘

    def __get_keyset(self, onion_pub_key: 'OnionPublicKeyContact') -> KeySet:
        """\
        Return KeySet object from `self.keysets`-list that matches the
        Onion Service public key used as the selector.
        """
        return self.__key_sets[onion_pub_key]

    def get_list_of_pub_keys(self) -> list[OnionPublicKeyContact]:
        """Return list of Onion Service public keys for KeySets."""
        return list(self.__key_sets.keys())

    # ┌───────────────────────────────────────────────────────────────────────────┐
    # │                              Database Status                              │
    # └───────────────────────────────────────────────────────────────────────────┘

    def has_keyset(self, onion_pub_key: 'OnionPublicKeyContact') -> bool:
        """Return True if KeySet with matching Onion Service public key exists, else False."""
        return onion_pub_key in self.__key_sets

    def has_keyset_for_pub_key(self, pub_key: OnionPublicKeyContact) -> bool:
        """Return True if KeySet with matching Onion Service public key exists, else False."""
        return pub_key in self.__key_sets

    def has_rx_mk(self, onion_pub_key: 'OnionPublicKeyContact') -> bool:
        """\
        Return True if KeySet with matching Onion Service public key has
        rx-message key, else False.

        When the PSK key exchange option is selected, the KeySet for
        newly created contact on Receiver Program is a null-byte string.
        This default value indicates the PSK of contact has not yet been
        imported.
        """
        return self.__get_keyset(onion_pub_key).has_contact_key()


    # ┌───────────────────────────────────────────────────────────────────────────┐
    # │                              Database Padding                             │
    # └───────────────────────────────────────────────────────────────────────────┘

    @property
    def __dummy_pub_key(self) -> OnionPublicKeyContact:
        """Generate dummy public key."""
        return OnionPublicKeyContact.from_onion_address(DummyID.DUMMY_CONTACT, DO_NOT_VALIDATE=True)

    @property
    def __dummy_address(self) -> bytes:
        """Generate dummy address."""
        return self.__dummy_pub_key.serialize()

    def __generate_dummy_data(self) -> bytes:
        """Generate a dummy block of data to pad the key database.

        This code produces plaintext block that is exactly as long as normal serialized database row.
        The other vital part is the deterministic onion pub-key that can be used to recognize dummy
        data upon database loading.
        """
        return (KeySet(onion_pub_key = self.__dummy_pub_key,
                       tx_mk         = MessageKeyUser(),
                       rx_mk         = MessageKeyContact(),
                       tx_hk         = HeaderKeyUser(),
                       rx_hk         = HeaderKeyContact(),
                       tx_harac      = RatchetState(),
                       rx_harac      = RatchetState(),
                       store_keys    = lambda: None)
                .serialize())

    def __pad_key_database(self, pt_bytes: bytes) -> bytes:
        """\
        Add padding to the key database."""
        number_of_contacts_to_store = self.__settings.max_number_of_contacts
        number_of_dummies           = number_of_contacts_to_store - len(self.__key_sets)
        padding_data                = number_of_dummies * self.__dummy_data

        return pt_bytes + padding_data


    # ┌───────────────────────────────────────────────────────────────────────────┐
    # │                              Database Storage                             │
    # └───────────────────────────────────────────────────────────────────────────┘

    def __serialize(self) -> bytes:
        """Serialize data into the database."""
        pt_bytes = b''.join([k.serialize() for k in self.__key_sets.values()])
        pt_bytes = self.__pad_key_database(pt_bytes)
        return pt_bytes

    def store_keys(self, replace: BoolReplaceDB = BoolReplaceDB(True)) -> None:
        """Write the list of KeySet objects to an encrypted database.

        This function will first create a list of KeySets and dummy
        KeySets. It will then serialize every KeySet object on that list
        and join the constant length byte strings to form the plaintext
        that will be encrypted and stored in the database.

        By default, TFC has a maximum number of 300 contacts. The
        plaintext length of 300 serialized KeySets is 300*200 = 60,000
        bytes. The ciphertext includes a 24-byte nonce and a 16-byte
        tag, so the size of the final database is 60,040 bytes.
        """
        self.__database.store_database(self.__serialize(), replace)

    def __load_keys(self) -> None:
        """Load KeySets from the encrypted database.

        This function first reads and decrypts the database content. It
        then splits the plaintext into a list of 200-byte blocks. Each
        block contains the serialized data of one KeySet. Next, the
        function will remove from the list all dummy KeySets (that start
        with the `dummy_id` byte string). The function will then
        populate the `self.keysets` list with KeySet objects, the data
        of which is sliced and decoded from the dummy-free blocks.
        """
        pt_bytes    = self.__database.load_database()
        blocks      = split_byte_string(pt_bytes, item_len=CompoundFieldLength.KEYSET)
        df_blocks   = [b for b in blocks if not b.startswith(self.__dummy_address)]
        header_list = [FieldLength.ONION_ADDRESS.value,
                       KeyLength.SYMMETRIC_KEY.value,
                       KeyLength.SYMMETRIC_KEY.value,
                       KeyLength.SYMMETRIC_KEY.value,
                       KeyLength.SYMMETRIC_KEY.value,
                       CryptoVarLength.RATCHET_CTR.value]

        for block in df_blocks:
            validate_bytes(block, is_length=CompoundFieldLength.KEYSET.value)

            enc_onion_address, tx_hk, tx_mk, rx_hk, rx_mk, tx_harac_bytes, rx_harac_bytes \
                = separate_headers(block, header_list)

            onion_pub_key = OnionPublicKeyContact.from_onion_address_bytes(enc_onion_address)

            self.__key_sets[onion_pub_key] = KeySet(onion_pub_key = onion_pub_key,
                                                    tx_mk         = MessageKeyUser(tx_mk),
                                                    rx_mk         = MessageKeyContact(rx_mk),
                                                    tx_hk         = HeaderKeyUser(tx_hk),
                                                    rx_hk         = HeaderKeyContact(rx_hk),
                                                    tx_harac      = RatchetState.from_bytes(tx_harac_bytes),
                                                    rx_harac      = RatchetState.from_bytes(rx_harac_bytes),
                                                    store_keys    = self.store_keys)


    # ┌───────────────────────────────────────────────────────────────────────────┐
    # │                             Database Rekeying                             │
    # └───────────────────────────────────────────────────────────────────────────┘

    def rekey_to_temp_db(self, new_master_key: 'MasterKey') -> None:
        """Rekey the database to a temporary file."""
        self.__database.rekey_to_temp_db(new_master_key, self.__serialize())

    def migrate_to_rekeyed_db(self) -> None:
        """Migrate to the rekeyed database."""
        self.__database.migrate_to_rekeyed_db()

    def update_master_key(self, new_master_key: 'MasterKeyRekeying') -> None:
        """Replace the active master key used by the key database."""
        self.__master_key.replace_active_key(new_master_key.raw_bytes)
        self.__database.set_database_key(self.__master_key)

    def change_master_key(self, queues: 'TxQueue') -> None:
        """Change the master key and encrypt the database with the new key."""
        key_queue = queues.key_store_mgmt
        ack_queue = queues.key_mgmt_ack

        # Halt sender loop here until keys have been replaced by the
        # `input_loop` process, and new master key is delivered.
        ack_queue.put((KeyDBMgmt.RELEASE_WAIT,))
        while key_queue.qsize() == 0:
            time.sleep(0.001)
        queue_data = key_queue.get()
        if not is_master_key_update(queue_data):
            raise CriticalError(f"Invalid key management command '{queue_data[0]}'.")

        # Replace master key.
        self.update_master_key(queue_data[1])

        # Send new master key back to `input_loop` process to verify it was received.
        ack_queue.put((KeyDBMgmt.UPDATE_MASTER_KEY, queue_data[1]))


def is_master_key_update(queue_data: 'KeyStoreMgmt') -> TypeGuard['KeyDBUpdateMasterKeyTuple']:
    """Return True when the key-store command carries a replacement master key."""
    return len(queue_data) == 2 and queue_data[0] == KeyDBMgmt.UPDATE_MASTER_KEY
