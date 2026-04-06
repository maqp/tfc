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

from typing import Any, Optional as O, TypeGuard, TYPE_CHECKING

from src.common.entities.assembly_packet import CommandAssemblyPacket
from src.common.crypto.keys.ratchet_state import RatchetState
from src.common.exceptions import CriticalError, SoftError
from src.common.entities.confirm_code import ConfirmationCode
from src.common.crypto.keys.kek_hash import KEKHash
from src.common.crypto.keys.key_set import LocalKeySet
from src.common.crypto.pt_ct import CommandAssemblyPacketPT, CommandHeaderPT, LocalKeySetPT
from src.common.crypto.keys.symmetric_key import LocalHeaderKey, LocalKeyEncryptionKey, LocalMessageKey, MasterKeyRekeying
from src.common.statics import FieldLength, KeyDBMgmt, KeyLength, DBName, LocalKeyDBMgmt
from src.common.types_custom import BoolReplaceDB, IntRatchetOffsetLocalKey
from src.common.utils.encoding import bytes_to_int
from src.common.utils.strings import separate_headers
from src.database.database import TFCEncryptedDatabase

if TYPE_CHECKING:
    from src.common.crypto.pt_ct import CommandAssemblyPacketCT, CommandHeaderCT, LocalKeySetCT
    from src.common.types_compound import LocalKeyDBUpdateMasterKeyTuple, LocalKeyMgmt
    from src.database.db_masterkey import MasterKey
    from src.common.queues import TxQueue
    from src.database.db_settings import Settings


class LocalKeyDB:
    """\
    Local key database stores the local key used to synchronize
    sensitive data between Transmitter and Receiver Programs.
    """

    def __init__(self, master_key: 'MasterKey', settings: 'Settings') -> None:
        """Create a new LocalKeyDatabase object"""
        self.__master_key = master_key
        self.settings     = settings

        self.__local_key_set         : O[LocalKeySet]          = None
        self.__local_key_set_pending : O[LocalKeySet]          = None
        self.__kek_hash              : O[KEKHash]              = None
        self.__database              : TFCEncryptedDatabase    = TFCEncryptedDatabase(DBName.LOCAL_KEY, master_key, settings.program_id)
        self.__rekey_database        : O[TFCEncryptedDatabase] = None

        if os.path.isfile(self.__database.path_to_db):
            self.__load_keys()

    def __get_local_key_set(self) -> LocalKeySet:
        """Return the loaded local key set."""
        if self.__local_key_set is None:
            raise CriticalError('Local key database is empty.')
        return self.__local_key_set


    # ┌───────────────────────────────────────────────────────────────────────────┐
    # │                           Cryptographic Services                          │
    # └───────────────────────────────────────────────────────────────────────────┘

    def encrypt_and_sign_command(self,
                                 assembly_packet: CommandAssemblyPacket
                                 ) -> tuple['CommandHeaderCT', 'CommandAssemblyPacketCT']:
        """Encrypt and sign a command to account."""
        if not isinstance(assembly_packet, CommandAssemblyPacket):
            raise CriticalError('The plaintext was not CommandAssemblyPacket')
        if self.__local_key_set is None:
            raise CriticalError('Local key database is empty.')

        key_set             = self.__get_local_key_set()
        plaintext_command   = CommandAssemblyPacketPT(assembly_packet.raw_bytes)
        encrypted_command   = self.__local_key_set.ratchet_key.encrypt_and_sign(plaintext_command)
        ratchet_state_bytes = key_set.ratchet_key.ratchet_plaintext
        key_set.ratchet_key = key_set.ratchet_key.next_key()
        self.store_keys()

        encrypted_command_header = self.__local_key_set.header_key.encrypt_and_sign(CommandHeaderPT(ratchet_state_bytes.pt_bytes))

        return encrypted_command_header, encrypted_command

    def auth_and_decrypt_header(self, ciphertext: 'CommandHeaderCT') -> IntRatchetOffsetLocalKey:
        """Auth and decrypt header of packet to/from contact."""
        if self.__local_key_set is None:
            raise CriticalError('Local key database is empty.')

        key_set     = self.__get_local_key_set()
        harac_bytes = self.__local_key_set.header_key.auth_and_decrypt(ciphertext)

        try:
            purp_ratchet_state = bytes_to_int(harac_bytes.pt_bytes)
        except ValueError:
            raise SoftError(f'Failed to convert harac bytes to int.')

        return IntRatchetOffsetLocalKey(purp_ratchet_state - key_set.ratchet_key.ratchet_state.value)

    def auth_and_decrypt_packet(self,
                                ciphertext : 'CommandAssemblyPacketCT',
                                offset     : IntRatchetOffsetLocalKey = IntRatchetOffsetLocalKey(0)
                                ) -> CommandAssemblyPacket:
        """Auth and decrypt packet to/from contact."""
        key_set = self.__get_local_key_set()
        plaintext, key_set.ratchet_key = key_set.ratchet_key.catch_up_and_decrypt(ciphertext, offset=offset)
        self.store_keys()
        return CommandAssemblyPacket(plaintext.pt_bytes)

    def export_local_keyset_to_sender_process(self, queues: 'TxQueue') -> None:
        """Export the local keyset to sender process."""
        key_set = self.__get_local_key_set()
        queues.local_key_mgmt.put((LocalKeyDBMgmt.INSERT_ROW,
                                   key_set.header_key,
                                   LocalMessageKey(key_set.ratchet_key.raw_bytes),
                                   key_set.kek_hash))

    def manage(self,
               queues  : 'TxQueue',
               command : str,
               *params : Any
               ) -> None:
        """Manage KeyList based on a command.

        The command is delivered from `input_process` to `sender_loop`
        process via the `KEY_MANAGEMENT_QUEUE`.
        """
        if   command == LocalKeyDBMgmt.INSERT_ROW:        self.add_local_keyset(*params)
        elif command == LocalKeyDBMgmt.DELETE_ROW:        self.remove_keyset()
        elif command == LocalKeyDBMgmt.WAIT_FOR_SYNC:     self.change_master_key(queues)
        elif command == LocalKeyDBMgmt.UPDATE_MASTER_KEY: self.update_master_key(*params)
        else: raise CriticalError(f"Invalid KeyList management command '{command}'.")


    # ┌───────────────────────────────────────────────────────────────────────────┐
    # │                                  Setters                                  │
    # └───────────────────────────────────────────────────────────────────────────┘

    def new_local_key(self,
                      kek               : 'LocalKeyEncryptionKey',
                      confirmation_code : ConfirmationCode,
                      ) -> 'LocalKeySetCT':
        """Create new LocalKeySet. Return it encrypted with LocalKeyEncryptionKey."""
        if not isinstance(kek, LocalKeyEncryptionKey):
            raise CriticalError(f'Incorrect kek type. Expected KeyEncryptionKey, received {type(kek)}.')
        if not isinstance(confirmation_code, ConfirmationCode):
            raise CriticalError(f'Incorrect confirmation code type. Expected ConfirmationCode, received {type(confirmation_code)}.')

        self.__local_key_set_pending = LocalKeySet(header_key    = LocalHeaderKey(),
                                                   message_key   = LocalMessageKey(),
                                                   ratchet_state = RatchetState(),
                                                   kek_hash      = KEKHash.from_kek(kek),
                                                   store_keys    = self.store_keys)

        if self.__local_key_set_pending is None:
            raise CriticalError(f'The pending local key is missing.')

        exported_keyset_pt = self.__local_key_set_pending.export_to_receiver_program()

        return kek.encrypt_and_sign(LocalKeySetPT(exported_keyset_pt.pt_bytes + confirmation_code.raw_bytes))

    def mark_local_key_as_delivered(self) -> None:
        """Mark local key as delivered by moving from pending state."""
        self.__local_key_set         = self.__local_key_set_pending
        self.__local_key_set_pending = None

    def add_local_keyset(self,
                         tx_hk    : LocalHeaderKey,
                         tx_mk    : LocalMessageKey,
                         kek_hash : KEKHash
                         ) -> None:
        """\
        Add a new KeySet to `self.keysets` list
        and write changes to the database.
        """
        if self.has_keyset:
            self.remove_keyset()

        self.__local_key_set = LocalKeySet(tx_hk, tx_mk, RatchetState(), kek_hash, self.store_keys)

        self.store_keys()


    # ┌───────────────────────────────────────────────────────────────────────────┐
    # │                                  Deleters                                 │
    # └───────────────────────────────────────────────────────────────────────────┘

    def remove_keyset(self) -> None:
        """\
        Remove KeySet from `self.keysets` based on Onion Service public key.

        If the KeySet was found and removed, write changes to the database.
        """
        if self.has_keyset:
            self.__local_key_set = None
            if os.path.isfile(self.path_to_db):
                os.remove(self.path_to_db)

    # ┌───────────────────────────────────────────────────────────────────────────┐
    # │                                  Getters                                  │
    # └───────────────────────────────────────────────────────────────────────────┘

    @property
    def path_to_db(self) -> str:
        """Get the path to the database."""
        return self.__database.path_to_db

    @property
    def path_to_rekey_db(self) -> str:
        """Get the path to rekeying database."""
        return self.__database.path_to_rekey_db

    @property
    def kek_hash(self) -> KEKHash:
        """Get the key encryption key hash."""
        return self.__get_local_key_set().kek_hash


    # ┌───────────────────────────────────────────────────────────────────────────┐
    # │                              Database Status                              │
    # └───────────────────────────────────────────────────────────────────────────┘

    @property
    def has_keyset(self) -> bool:
        """Return True if local KeySet object exists, else False."""
        return self.__local_key_set is not None


    # ┌───────────────────────────────────────────────────────────────────────────┐
    # │                              Database Storage                             │
    # └───────────────────────────────────────────────────────────────────────────┘

    def store_keys(self, replace: BoolReplaceDB = BoolReplaceDB(True)) -> None:
        """Write the list of KeySet objects to an encrypted database.

        This function will first create a list of KeySets and dummy
        KeySets. It will then serialize every KeySet object on that list
        and join the constant length byte strings to form the plaintext
        that will be encrypted and stored in the database.

        By default, TFC has a maximum number of 300 contacts. In
        addition, the database stores the KeySet used to encrypt
        commands from Transmitter to Receiver Program. The plaintext
        length of 51 serialized KeySets is 301*176 = 52,976 bytes. The
        ciphertext includes a 24-byte nonce and a 16-byte tag, so the
        size of the final database is 53,016 bytes.
        """
        self.__database.store_database(self.__get_local_key_set().serialize(), replace)

    def __load_keys(self) -> None:
        """Load KeySets from the encrypted database.

        This function first reads and decrypts the database content. It
        then splits the plaintext into a list of 176-byte blocks. Each
        block contains the serialized data of one KeySet. Next, the
        function will remove from the list all dummy KeySets (that start
        with the `dummy_id` byte string). The function will then
        populate the `self.keysets` list with KeySet objects, the data
        of which is sliced and decoded from the dummy-free blocks.
        """
        pt_bytes = self.__database.load_database()

        header_list = [KeyLength.SYMMETRIC_KEY.value,
                       KeyLength.SYMMETRIC_KEY.value,
                       FieldLength.ENCODED_INTEGER.value,
                       FieldLength.KEK_HASH.value]

        if len(pt_bytes) != sum(header_list):
            raise CriticalError('Invalid local key database content.')

        tx_hk, tx_mk, tx_harac_bytes, kek_hash, _ = separate_headers(pt_bytes, header_list)

        self.__local_key_set = LocalKeySet(message_key   = LocalMessageKey(tx_mk),
                                           header_key    = LocalHeaderKey(tx_hk),
                                           ratchet_state = RatchetState.from_bytes(tx_harac_bytes),
                                           kek_hash      = KEKHash(kek_hash),
                                           store_keys    = self.store_keys)


    # ┌───────────────────────────────────────────────────────────────────────────┐
    # │                             Database Rekeying                             │
    # └───────────────────────────────────────────────────────────────────────────┘

    def rekey_to_temp_db(self, new_master_key: 'MasterKey', plaintext_data: bytes) -> None:
        """Rekey the database to a temporary file."""
        self.__database.rekey_to_temp_db(new_master_key, plaintext_data)

    def migrate_to_rekeyed_db(self) -> None:
        """Migrate to the rekeyed database."""
        self.__database.migrate_to_rekeyed_db()

    def update_master_key(self, new_master_key: 'MasterKeyRekeying') -> None:
        """Replace the active master key used by the local key database."""
        self.__master_key.replace_active_key(new_master_key.raw_bytes)
        self.__database.set_database_key(self.__master_key)

    @staticmethod
    def is_local_master_key_update(queue_data: 'LocalKeyMgmt') -> TypeGuard['LocalKeyDBUpdateMasterKeyTuple']:
        """Return True when the local-key command carries a replacement master key."""
        return len(queue_data) == 2 and queue_data[0] == LocalKeyDBMgmt.UPDATE_MASTER_KEY

    def change_master_key(self, queues: 'TxQueue') -> None:
        """Change the master key and encrypt the database with the new key."""
        key_queue = queues.local_key_mgmt
        ack_queue = queues.key_mgmt_ack

        # Halt sender loop here until keys have been replaced by the
        # `input_loop` process, and new master key is delivered.
        ack_queue.put((KeyDBMgmt.RELEASE_WAIT,))
        while key_queue.qsize() == 0:
            time.sleep(0.001)
        queue_data = key_queue.get()
        if not self.is_local_master_key_update(queue_data):
            raise CriticalError(f"Invalid key management command '{queue_data[0]}'.")

        # Replace master key.
        self.update_master_key(queue_data[1])

        # Send new master key back to `input_loop` process to verify it was received.
        ack_queue.put((KeyDBMgmt.UPDATE_MASTER_KEY, queue_data[1]))
