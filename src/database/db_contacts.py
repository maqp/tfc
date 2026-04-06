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

from typing import Iterator, Optional as O, TYPE_CHECKING

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from src.common.entities.contact import Contact
from src.common.entities.nick_name import Nick
from src.common.entities.window_uid import WindowUID
from src.common.types_custom import BoolFileReception, BoolLogMessages, BoolShowNotifications, BoolReplaceDB
from src.common.crypto.fingerprint import FingerprintUser, FingerprintContact
from src.common.utils.validators import validate_bytes
from src.database.database import TFCEncryptedDatabase
from src.common.utils.encoding import (bytes_to_bool, padded_bytes_to_str)
from src.common.utils.strings import split_byte_string, separate_headers
from src.common.statics import CompoundFieldLength, DummyID, FieldLength, KexStatus, CryptoVarLength, DBName
from src.common.crypto.keys.onion_service_keys import OnionPublicKeyContact

if TYPE_CHECKING:
    from src.database.db_masterkey import MasterKey
    from src.database.db_settings import Settings


class ContactList:
    """\
    ContactList object manages TFC's Contact objects and the storage of
    the objects in an encrypted database.

    The main purpose of this object is to manage the `self.contacts`
    list that contains TFC's contacts. The database is stored on disk
    in encrypted form. Prior to encryption, the database is padded with
    dummy contacts. The dummy contacts hide the number of actual
    contacts that would otherwise be revealed by the size of the
    encrypted database. As long as the user has less than 50 contacts,
    the database will effectively hide the actual number of contacts.
    The maximum number of contacts (and thus the size of the database)
    can be changed by editing the `max_number_of_contacts` setting. This
    can however, in theory, reveal to a physical attacker the user has
    more than 50 contacts.

    The ContactList object also provides handy methods with human-
    readable names for making queries to the database.
    """

    def __init__(self, master_key: 'MasterKey', settings: 'Settings') -> None:
        """Create a new ContactList object."""
        self.__settings   = settings
        self.__dummy_data = self.generate_dummy_contact().serialize()

        self.__database : TFCEncryptedDatabase                 = TFCEncryptedDatabase(DBName.CONTACTS, master_key, settings.program_id)
        self.__contacts : dict[OnionPublicKeyContact, Contact] = {}

        if os.path.isfile(self.__database.path_to_db):
            self._load_contacts()
        else:
            self.store_contacts()

    def __iter__(self) -> Iterator[Contact]:
        """Iterate over Contact objects in `self.contacts`."""
        yield from self.__contacts.values()

    def __len__(self) -> int:
        """Return the number of contacts in `self.contacts`.

        The Contact object that represents the local key is left out of
        the calculation.
        """
        return len(self.get_list_of_contacts())

    # ┌───────────────────────────────────────────────────────────────────────────┐
    # │                                  Setters                                  │
    # └───────────────────────────────────────────────────────────────────────────┘

    def add_contact(self,
                    onion_pub_key  : OnionPublicKeyContact,
                    nick           : Nick,
                    tx_fingerprint : FingerprintUser,
                    rx_fingerprint : FingerprintContact,
                    kex_status     : KexStatus,
                    log_messages   : BoolLogMessages,
                    file_reception : BoolFileReception,
                    notifications  : BoolShowNotifications
                    ) -> None:
        """\
        Add a new contact to `self.contacts` list and write changes to
        the database.

        Because TFC's hardware separation prevents automated DH-ratchet,
        the only way for the users to re-negotiate new keys is to start
        a new session by re-adding the contact. If the contact is
        re-added, TFC will need to remove the existing Contact object
        before adding the new one. In such case, TFC will update the
        nick, kex status, and fingerprints, but it will keep the old
        logging, file reception, and notification settings of the
        contact (as opposed to using the defaults determined by TFC's
        Settings object).
        """
        if self.has_onion_pub_key(onion_pub_key):
            current_contact = self.get_contact_by_pub_key(onion_pub_key)
            log_messages    = current_contact.log_messages
            file_reception  = current_contact.file_reception
            notifications   = current_contact.notifications
            self.remove_contact(onion_pub_key)

        self.__contacts[onion_pub_key] = Contact(onion_pub_key,
                                                 nick,
                                                 tx_fingerprint,
                                                 rx_fingerprint,
                                                 kex_status,
                                                 log_messages,
                                                 file_reception,
                                                 notifications)
        self.store_contacts()


    # ┌───────────────────────────────────────────────────────────────────────────┐
    # │                                  Deleters                                 │
    # └───────────────────────────────────────────────────────────────────────────┘

    def remove_contact(self, onion_pub_key: OnionPublicKeyContact) -> None:
        """Remove the contact that has a matching Onion Service public key.

        If the contact was found and removed, write changes to the database.
        """
        if onion_pub_key in self.__contacts:
            del self.__contacts[onion_pub_key]
            self.store_contacts()

    def remove_contact_by_address_or_nick(self, selector: str) -> None:
        """Remove the contact that has a matching nick or Onion Service address.

        If the contact was found and removed, write changes to the database.
        """
        for contact in self.__contacts.values():
            if self._selector_matches_contact(contact, selector):
                del self.__contacts[contact.onion_pub_key]
                self.store_contacts()
                break


    # ┌───────────────────────────────────────────────────────────────────────────┐
    # │                                  Getters                                  │
    # └───────────────────────────────────────────────────────────────────────────┘

    def get_contact_by_pub_key(self, public_key: OnionPublicKeyContact) -> Contact:
        """Return the Contact object for the specified Onion Service public key."""
        return self.__contacts[public_key]

    def get_contact_by_raw_pub_key(self, raw_pub_key: bytes) -> Contact:
        """Return the Contact object for the specified Onion Service public key."""
        return self.__contacts[OnionPublicKeyContact(Ed25519PublicKey.from_public_bytes(raw_pub_key))]

    def get_contact_by_address_or_nick(self, selector: str) -> Contact:
        """\
        Return the Contact object from `self.contacts` list that has the
        matching nick or Onion Service address.
        """
        for contact in self:
            if self._selector_matches_contact(contact, selector):
                return contact

        raise KeyError(selector)

    def get_nick(self, onion_pub_key: OnionPublicKeyContact) -> Nick:
        """Return nick of contact that has a matching Onion Service public key."""
        return self.get_contact_by_pub_key(onion_pub_key).nick

    def get_nick_by_pub_key(self, public_key: OnionPublicKeyContact) -> Nick:
        """Return nick of contact that has a matching Onion Service public key."""
        return self.get_contact_by_pub_key(public_key).nick

    def get_list_of_contacts(self) -> list[Contact]:
        """Return list of Contact objects in `self.contacts` list."""
        return [c for c in self if c.onion_address]

    def get_list_of_addresses(self) -> list[str]:
        """Return list of contacts' TFC accounts."""
        return [c.onion_address for c in self]

    def get_list_of_nicks(self, exclude_onion_pub_key: O[OnionPublicKeyContact] = None) -> list[Nick]:
        """Return list of contacts' nicks."""
        return [c.nick for c in self if exclude_onion_pub_key is None or c.onion_pub_key != exclude_onion_pub_key]

    def get_list_of_nick_strings(self) -> list[str]:
        """Get list of nick strings."""
        return [nick.value for nick in self.get_list_of_nicks()]

    def get_list_of_pub_keys(self) -> list[OnionPublicKeyContact]:
        """Return list of contacts' public keys."""
        return [c.onion_pub_key for c in self]

    def get_list_of_raw_pub_keys(self) -> list[bytes]:
        """Return list of raw public keys."""
        return [c.onion_pub_key.public_bytes_raw for c in self]

    def get_list_of_win_uids(self) -> list[WindowUID]:
        """Return list of contacts' win UIDs."""
        return [WindowUID.for_contact(c) for c in self.get_list_of_contacts()]

    def get_list_of_pending_pub_keys(self) -> list[OnionPublicKeyContact]:
        """Return list of public keys for contacts that haven't completed key exchange yet."""
        return [c.onion_pub_key for c in self if c.kex_status == KexStatus.KEX_STATUS_PENDING]

    def get_list_of_existing_pub_keys(self) -> list[OnionPublicKeyContact]:
        """Return list of public keys for contacts with whom key exchange has been completed."""
        return [c.onion_pub_key for c in self.get_list_of_contacts()
                if c.kex_status in [KexStatus.KEX_STATUS_UNVERIFIED, KexStatus.KEX_STATUS_VERIFIED,
                                    KexStatus.KEX_STATUS_HAS_RX_PSK, KexStatus.KEX_STATUS_NO_RX_PSK]]

    def get_list_of_group_eligible_pub_keys(self) -> list[OnionPublicKeyContact]:
        """Return public keys for contacts that are eligible to be added to groups."""
        return [c.onion_pub_key for c in self.get_list_of_contacts() if c.can_be_group_member]

    def get_contact_selectors(self) -> list[str]:
        """Return list of string-type UIDs that can be used to select a contact."""
        return self.get_list_of_addresses() + self.get_list_of_nick_strings()

    @staticmethod
    def _selector_matches_contact(contact: Contact, selector: str) -> bool:
        """Return True if selector matches the contact's address or nick."""
        return selector in [contact.onion_address, contact.nick.value]


    # ┌───────────────────────────────────────────────────────────────────────────┐
    # │                              Database Status                              │
    # └───────────────────────────────────────────────────────────────────────────┘

    @property
    def has_contacts(self) -> bool:
        """Return True if ContactList has any contacts, else False."""
        return any(self.get_list_of_contacts())

    def has_only_pending_contacts(self) -> bool:
        """Return True if ContactList only has pending contacts, else False."""
        return all(c.kex_status == KexStatus.KEX_STATUS_PENDING for c in self)

    def has_onion_pub_key(self, onion_pub_key: OnionPublicKeyContact | bytes) -> bool:
        """Return True if contact with public key exists, else False."""
        return onion_pub_key in self.__contacts

    def has_pub_key(self, public_key: OnionPublicKeyContact) -> bool:
        """Return True if contact with public key exists, else False."""
        return self.has_onion_pub_key(public_key)


    # ┌───────────────────────────────────────────────────────────────────────────┐
    # │                              Database Padding                             │
    # └───────────────────────────────────────────────────────────────────────────┘

    @property
    def _dummy_pub_key(self) -> OnionPublicKeyContact:
        """Generate dummy keyset account public key."""
        return OnionPublicKeyContact.from_onion_address(DummyID.DUMMY_CONTACT, DO_NOT_VALIDATE=True)

    def generate_dummy_contact(self) -> Contact:
        """Generate a dummy block of data to pad the contact database."""
        return Contact(onion_pub_key  = self._dummy_pub_key,
                       nick           = Nick(DummyID.DUMMY_NICK),
                       tx_fingerprint = FingerprintUser(bytes(CryptoVarLength.FINGERPRINT)),
                       rx_fingerprint = FingerprintContact(bytes(CryptoVarLength.FINGERPRINT)),
                       kex_status     = KexStatus.KEX_STATUS_NONE,
                       log_messages   = BoolLogMessages(False),
                       file_reception = BoolFileReception(False),
                       notifications  = BoolShowNotifications(False))

    def __pad_contact_database(self, pt_bytes: bytes) -> bytes:
        """\
        Pad the contact database.

        The number of dummy contacts and thus the amount of padding data
        depends on the number of actual contacts.

        The additional contact (+1) is the local contact used to
        represent the presence of the local key on Transmitter Program's
        `input_loop` process side that does not have access to the
        KeyList database that contains the local key.
        """
        number_of_contacts_to_store = self.__settings.max_number_of_contacts + 1
        number_of_dummies           = number_of_contacts_to_store - len(self.__contacts)
        padding_data                = number_of_dummies * self.__dummy_data

        return pt_bytes + padding_data


    # ┌───────────────────────────────────────────────────────────────────────────┐
    # │                              Database Storage                             │
    # └───────────────────────────────────────────────────────────────────────────┘

    def serialize(self) -> bytes:
        """Serialize data into the database."""
        pt_bytes = b''.join([c.serialize() for c in self])
        pt_bytes = self.__pad_contact_database(pt_bytes)
        return pt_bytes

    def store_contacts(self, replace: BoolReplaceDB = BoolReplaceDB(True)) -> None:
        """Write the list of contacts to an encrypted database.

        This function will first create a list of contacts and dummy
        contacts. It will then serialize every Contact object on that
        list and join the constant length byte strings to form the
        plaintext that will be encrypted and stored in the database.

        By default, TFC has a maximum number of 50 contacts. In
        addition, the database stores the contact that represents the
        local key (used to encrypt commands from Transmitter to Receiver
        Program). The plaintext length of 51 serialized contacts is
        51*1124 = 57364 bytes. The ciphertext includes a 24-byte nonce
        and a 16-byte tag, so the size of the final database is 57313
        bytes.
        """
        self.__database.store_database(self.serialize(), replace)

    def _load_contacts(self) -> None:
        """Load contacts from the encrypted database.

        This function first reads and decrypts the database content. It
        then splits the plaintext into a list of 1148-byte blocks: each
        block contains the serialized data of one contact. Next, the
        function will remove from the list all dummy contacts (that
        start with dummy contact's public key). The function will then
        populate the `self.contacts` list with Contact objects, the data
        of which is sliced and decoded from the dummy-free blocks.
        """
        pt_bytes    = self.__database.load_database()
        blocks      = split_byte_string(pt_bytes, item_len=CompoundFieldLength.CONTACT)
        df_blocks   = [b for b in blocks if not b == self.__dummy_data]
        header_list = [FieldLength.ONION_ADDRESS.value,
                       CryptoVarLength.FINGERPRINT.value,
                       CryptoVarLength.FINGERPRINT.value,
                       FieldLength.KEX_STATUS.value,
                       FieldLength.ENCODED_BOOLEAN.value,
                       FieldLength.ENCODED_BOOLEAN.value,
                       FieldLength.ENCODED_BOOLEAN.value]

        for block in df_blocks:
            validate_bytes(block, is_length=CompoundFieldLength.CONTACT)

            (enc_onion_address, tx_fingerprint, rx_fingerprint, kex_status_byte,
             log_messages_byte, file_reception_byte, notifications_byte, nick_bytes) \
                = separate_headers(block, header_list)

            onion_pub_key_contact = OnionPublicKeyContact.from_onion_address_bytes(enc_onion_address)

            self.__contacts[onion_pub_key_contact] = Contact(onion_pub_key  = onion_pub_key_contact,
                                                             tx_fingerprint = FingerprintUser      ( tx_fingerprint),
                                                             rx_fingerprint = FingerprintContact   ( rx_fingerprint),
                                                             kex_status     = KexStatus            ( kex_status_byte),
                                                             log_messages   = BoolLogMessages      ( bytes_to_bool       ( log_messages_byte   )),
                                                             file_reception = BoolFileReception    ( bytes_to_bool       ( file_reception_byte )),
                                                             notifications  = BoolShowNotifications( bytes_to_bool       ( notifications_byte  )),
                                                             nick           = Nick                 ( padded_bytes_to_str ( nick_bytes          )))


    # ┌───────────────────────────────────────────────────────────────────────────┐
    # │                             Database Rekeying                             │
    # └───────────────────────────────────────────────────────────────────────────┘

    def rekey_to_temp_db(self, new_master_key: 'MasterKey') -> None:
        """Rekey the database to temporary file."""
        self.__database.rekey_to_temp_db(new_master_key, data_to_write=self.serialize())

    def migrate_to_rekeyed_db(self) -> None:
        """Migrate to the rekeyed database."""
        self.__database.migrate_to_rekeyed_db()
