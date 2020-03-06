#!/usr/bin/env python3.7
# -*- coding: utf-8 -*-

"""
TFC - Onion-routed, endpoint secure messaging system
Copyright (C) 2013-2020  Markus Ottela

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

from typing import Iterable, Iterator, List, Optional, Sized

from src.common.database   import TFCDatabase
from src.common.encoding   import (bool_to_bytes, pub_key_to_onion_address, str_to_bytes, pub_key_to_short_address,
                                   bytes_to_bool, onion_address_to_pub_key, bytes_to_str)
from src.common.exceptions import CriticalError
from src.common.misc       import ensure_dir, get_terminal_width, separate_headers, split_byte_string
from src.common.output     import clear_screen
from src.common.statics    import (CONTACT_LENGTH, CONTACT_LIST_INDENT, DIR_USER_DATA, DUMMY_CONTACT, DUMMY_NICK, ECDHE,
                                   ENCODED_BOOLEAN_LENGTH, FINGERPRINT_LENGTH, KEX_STATUS_HAS_RX_PSK, KEX_STATUS_LENGTH,
                                   KEX_STATUS_NONE, KEX_STATUS_NO_RX_PSK, KEX_STATUS_PENDING, KEX_STATUS_UNVERIFIED,
                                   KEX_STATUS_VERIFIED, LOCAL_ID, ONION_SERVICE_PUBLIC_KEY_LENGTH, PSK)

if typing.TYPE_CHECKING:
    from src.common.db_masterkey import MasterKey
    from src.common.db_settings  import Settings
    from cryptography.hazmat.primitives.asymmetric.x448 import X448PrivateKey


class Contact(object):
    """\
    Contact object contains contact data not related to key management
    and hash ratchet state:

      onion_pub_key: The public key of the contact's v3 Tor Onion
                     Service. The Relay Program on user's Networked
                     Computer uses this public key to anonymously
                     discover the Onion Service and to authenticate the
                     end-to-end encryption used between Relay Computers.
                     Since Relay Program might run on an amnesic distro
                     like Tails, the Transmitter and Receiver Programs
                     handle long-term storage of the contact's Onion
                     Service public key. All `onion_pub_key` variables
                     across the codebase refer to the public key of a
                     contact (never that of the user).

               nick: As per Zooko's triangle and Stiegler's Petname
                     Systems, .onion names (i.e., TFC accounts) cannot
                     be global, secure and memorable at the same time*.
                     To deal with hard to remember accounts, in TFC
                     contacts (and groups) are managed mostly with
                     nicknames assigned by the user. The nickname must
                     be unique among both contacts and groups so that
                     single command `/msg <selection>` can select a
                     specific contact or group. Some nicknames are
                     reserved so that messages from contacts cannot be
                     confused with system messages of Receiver Program.
                     Nicknames also have a length limit of 254 chars.

    * https://trac.torproject.org/projects/tor/wiki/doc/HiddenServiceNames#Whyare.onionnamescreatedthatway

    TFC stores the 32-byte public key fingerprints of the ECDHE key
    exchange into the contact database. These values allow the user to
    verify at any time no MITM attack took place during the key
    exchange. When PSKs are used, a null-byte string is used as a
    placeholder value.

     tx_fingerprint: The user's fingerprint. This fingerprint is derived
                     from the user's public key which means it's
                     automatically authentic. During verification over
                     an authenticated channel, the user reads this value
                     to the contact out loud.

     rx_fingerprint: The purported fingerprint for the contact. This
                     fingerprint depends on the public key received from
                     the insecure network and therefore, it shouldn't be
                     trusted implicitly. During verification over an
                     authenticated channel, the contact reads their
                     `tx_fingerprint` to the user out loud, and the user
                     then compares it to this purported value.

         kex_status: This byte remembers the key exchange status of the
                     contact.

    TFC stores the contact-specific settings to the contact database:

       log_messages: This setting defines whether the Receiver Program
                     on Destination Computer writes the assembly packets
                     of a successfully received message into a log file.
                     When logging is enabled, Transmitter Program will
                     also log assembly packets of sent messages to its
                     log file.

     file_reception: This setting defines whether the Receiver Program
                     accepts files sent by the contact. The setting has
                     no effect on user's Transmitter Program.

      notifications: This setting defines whether, in situations where
                     some other window is active, the Receiver Program
                     displays a notification about the contact sending
                     a new message to their window. The setting has no
                     effect on user's Transmitter Program.

    tfc_private_key: This value is an ephemerally stored private key
                     for situations where the user interrupts the key
                     exchange. The purpose of the value is to prevent
                     the user from generating different ECDHE values
                     when re-selecting the contact to continue the key
                     exchange. Note that once a shared key is derived
                     from this private key (and contact's public key),
                     it is discarded. New private key will thus be
                     generated if the users decide to exchange new keys
                     with each other.
    """

    def __init__(self,
                 onion_pub_key:  bytes,
                 nick:           str,
                 tx_fingerprint: bytes,
                 rx_fingerprint: bytes,
                 kex_status:     bytes,
                 log_messages:   bool,
                 file_reception: bool,
                 notifications:  bool
                 ) -> None:
        """Create a new Contact object.

        `self.short_address` is the truncated version of the account
        used to identify TFC account in printed messages.
        """
        self.onion_pub_key   = onion_pub_key
        self.nick            = nick
        self.tx_fingerprint  = tx_fingerprint
        self.rx_fingerprint  = rx_fingerprint
        self.kex_status      = kex_status
        self.log_messages    = log_messages
        self.file_reception  = file_reception
        self.notifications   = notifications
        self.onion_address   = pub_key_to_onion_address(self.onion_pub_key)
        self.short_address   = pub_key_to_short_address(self.onion_pub_key)
        self.tfc_private_key = None  # type: Optional[X448PrivateKey]

    def serialize_c(self) -> bytes:
        """Return contact data as a constant length byte string.

        This function serializes the contact's data into a byte string
        that has the exact length of 3*32 + 4*1 + 1024 = 1124 bytes. The
        length is guaranteed regardless of the content or length of the
        attributes' values, including the contact's nickname. The
        purpose of the constant length serialization is to hide any
        metadata about the contact the ciphertext length of the contact
        database would reveal.
        """
        return (self.onion_pub_key
                + self.tx_fingerprint
                + self.rx_fingerprint
                + self.kex_status
                + bool_to_bytes(self.log_messages)
                + bool_to_bytes(self.file_reception)
                + bool_to_bytes(self.notifications)
                + str_to_bytes(self.nick))

    def uses_psk(self) -> bool:
        """\
        Return True if the user and the contact are using pre-shared
        keys (PSKs), else False.

        When the user sets up pre-shared keys with the contact, the key
        exchange status can only have two specific values (that remember
        whether the PSK of the contact has been imported). That fact can
        be used to determine whether the keys with contact were
        pre-shared.
        """
        return self.kex_status in [KEX_STATUS_NO_RX_PSK, KEX_STATUS_HAS_RX_PSK]


class ContactList(Iterable[Contact], Sized):
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
        self.settings      = settings
        self.contacts      = []  # type: List[Contact]
        self.dummy_contact = self.generate_dummy_contact()
        self.file_name     = f'{DIR_USER_DATA}{settings.software_operation}_contacts'
        self.database      = TFCDatabase(self.file_name, master_key)

        ensure_dir(DIR_USER_DATA)
        if os.path.isfile(self.file_name):
            self._load_contacts()
        else:
            self.store_contacts()

    def __iter__(self) -> Iterator[Contact]:
        """Iterate over Contact objects in `self.contacts`."""
        yield from self.contacts

    def __len__(self) -> int:
        """Return the number of contacts in `self.contacts`.

        The Contact object that represents the local key is left out of
        the calculation.
        """
        return len(self.get_list_of_contacts())

    def store_contacts(self, replace: bool = True) -> None:
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
        pt_bytes = b''.join([c.serialize_c() for c in self.contacts + self._dummy_contacts()])
        self.database.store_database(pt_bytes, replace)

    def _load_contacts(self) -> None:
        """Load contacts from the encrypted database.

        This function first reads and decrypts the database content. It
        then splits the plaintext into a list of 1124-byte blocks: each
        block contains the serialized data of one contact. Next, the
        function will remove from the list all dummy contacts (that
        start with dummy contact's public key). The function will then
        populate the `self.contacts` list with Contact objects, the data
        of which is sliced and decoded from the dummy-free blocks.
        """
        pt_bytes  = self.database.load_database()
        blocks    = split_byte_string(pt_bytes, item_len=CONTACT_LENGTH)
        df_blocks = [b for b in blocks if not b.startswith(self.dummy_contact.onion_pub_key)]

        for block in df_blocks:
            if len(block) != CONTACT_LENGTH:
                raise CriticalError("Invalid data in contact database.")

            (onion_pub_key, tx_fingerprint, rx_fingerprint, kex_status_byte,
             log_messages_byte, file_reception_byte, notifications_byte,
             nick_bytes) = separate_headers(block,
                                            [ONION_SERVICE_PUBLIC_KEY_LENGTH]
                                            + 2*[FINGERPRINT_LENGTH]
                                            + [KEX_STATUS_LENGTH]
                                            + 3*[ENCODED_BOOLEAN_LENGTH])

            self.contacts.append(Contact(onion_pub_key =onion_pub_key,
                                         tx_fingerprint=tx_fingerprint,
                                         rx_fingerprint=rx_fingerprint,
                                         kex_status    =kex_status_byte,
                                         log_messages  =bytes_to_bool(log_messages_byte),
                                         file_reception=bytes_to_bool(file_reception_byte),
                                         notifications =bytes_to_bool(notifications_byte),
                                         nick          =bytes_to_str(nick_bytes)))

    @staticmethod
    def generate_dummy_contact() -> Contact:
        """Generate a dummy Contact object.

        The dummy contact simplifies the code around the constant length
        serialization when the data is stored to, or read from the
        database.
        """
        return Contact(onion_pub_key =onion_address_to_pub_key(DUMMY_CONTACT),
                       nick          =DUMMY_NICK,
                       tx_fingerprint=bytes(FINGERPRINT_LENGTH),
                       rx_fingerprint=bytes(FINGERPRINT_LENGTH),
                       kex_status    =KEX_STATUS_NONE,
                       log_messages  =False,
                       file_reception=False,
                       notifications =False)

    def _dummy_contacts(self) -> List[Contact]:
        """\
        Generate a list of dummy contacts for database padding.

        The number of dummy contacts depends on the number of actual
        contacts.

        The additional contact (+1) is the local contact used to
        represent the presence of the local key on Transmitter Program's
        `input_loop` process side that does not have access to the
        KeyList database that contains the local key.
        """
        number_of_contacts_to_store = self.settings.max_number_of_contacts + 1
        number_of_dummies           = number_of_contacts_to_store - len(self.contacts)
        return [self.dummy_contact] * number_of_dummies

    def add_contact(self,
                    onion_pub_key:  bytes,
                    nick:           str,
                    tx_fingerprint: bytes,
                    rx_fingerprint: bytes,
                    kex_status:     bytes,
                    log_messages:   bool,
                    file_reception: bool,
                    notifications:  bool
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
        if self.has_pub_key(onion_pub_key):
            current_contact = self.get_contact_by_pub_key(onion_pub_key)
            log_messages    = current_contact.log_messages
            file_reception  = current_contact.file_reception
            notifications   = current_contact.notifications
            self.remove_contact_by_pub_key(onion_pub_key)

        self.contacts.append(Contact(onion_pub_key,
                                     nick,
                                     tx_fingerprint,
                                     rx_fingerprint,
                                     kex_status,
                                     log_messages,
                                     file_reception,
                                     notifications))
        self.store_contacts()

    def remove_contact_by_pub_key(self, onion_pub_key: bytes) -> None:
        """Remove the contact that has a matching Onion Service public key.

        If the contact was found and removed, write changes to the database.
        """
        for i, c in enumerate(self.contacts):
            if c.onion_pub_key == onion_pub_key:
                del self.contacts[i]
                self.store_contacts()
                break

    def remove_contact_by_address_or_nick(self, selector: str) -> None:
        """Remove the contact that has a matching nick or Onion Service address.

        If the contact was found and removed, write changes to the database.
        """
        for i, c in enumerate(self.contacts):
            if selector in [c.onion_address, c.nick]:
                del self.contacts[i]
                self.store_contacts()
                break

    def get_contact_by_pub_key(self, onion_pub_key: bytes) -> Contact:
        """\
        Return the Contact object from `self.contacts` list that has the
        matching Onion Service public key.
        """
        return next(c for c in self.contacts if onion_pub_key == c.onion_pub_key)

    def get_contact_by_address_or_nick(self, selector: str) -> Contact:
        """\
        Return the Contact object from `self.contacts` list that has the
        matching nick or Onion Service address.
        """
        return next(c for c in self.contacts if selector in [c.onion_address, c.nick])

    def get_nick_by_pub_key(self, onion_pub_key: bytes) -> str:
        """Return nick of contact that has a matching Onion Service public key."""
        return next(c.nick for c in self.contacts if onion_pub_key == c.onion_pub_key)

    def get_list_of_contacts(self) -> List[Contact]:
        """Return list of Contact objects in `self.contacts` list."""
        return [c for c in self.contacts if c.onion_address != LOCAL_ID]

    def get_list_of_addresses(self) -> List[str]:
        """Return list of contacts' TFC accounts."""
        return [c.onion_address for c in self.contacts if c.onion_address != LOCAL_ID]

    def get_list_of_nicks(self) -> List[str]:
        """Return list of contacts' nicks."""
        return [c.nick for c in self.contacts if c.onion_address != LOCAL_ID]

    def get_list_of_pub_keys(self) -> List[bytes]:
        """Return list of contacts' public keys."""
        return [c.onion_pub_key for c in self.contacts if c.onion_address != LOCAL_ID]

    def get_list_of_pending_pub_keys(self) -> List[bytes]:
        """Return list of public keys for contacts that haven't completed key exchange yet."""
        return [c.onion_pub_key for c in self.contacts if c.kex_status == KEX_STATUS_PENDING]

    def get_list_of_existing_pub_keys(self) -> List[bytes]:
        """Return list of public keys for contacts with whom key exchange has been completed."""
        return [c.onion_pub_key for c in self.get_list_of_contacts()
                if c.kex_status in [KEX_STATUS_UNVERIFIED, KEX_STATUS_VERIFIED,
                                    KEX_STATUS_HAS_RX_PSK, KEX_STATUS_NO_RX_PSK]]

    def contact_selectors(self) -> List[str]:
        """Return list of string-type UIDs that can be used to select a contact."""
        return self.get_list_of_addresses() + self.get_list_of_nicks()

    def has_contacts(self) -> bool:
        """Return True if ContactList has any contacts, else False."""
        return any(self.get_list_of_contacts())

    def has_only_pending_contacts(self) -> bool:
        """Return True if ContactList only has pending contacts, else False."""
        return all(c.kex_status == KEX_STATUS_PENDING for c in self.get_list_of_contacts())

    def has_pub_key(self, onion_pub_key: bytes) -> bool:
        """Return True if contact with public key exists, else False."""
        return onion_pub_key in self.get_list_of_pub_keys()

    def has_local_contact(self) -> bool:
        """Return True if the local key has been exchanged, else False."""
        return any(c.onion_address == LOCAL_ID for c in self.contacts)

    def print_contacts(self) -> None:
        """Print the list of contacts.

        Neatly printed contact list allows easy contact management:
        It allows the user to check active logging, file reception and
        notification settings, as well as what key exchange was used
        and what is the state of that key exchange. The contact list
        also shows and what the account displayed by the Relay Program
        corresponds to what nick etc.
        """
        # Initialize columns
        c1 = ['Contact']
        c2 = ['Account']
        c3 = ['Logging']
        c4 = ['Notify']
        c5 = ['Files ']
        c6 = ['Key Ex']

        # Key exchange status dictionary
        kex_dict = {KEX_STATUS_PENDING:    f"{ECDHE} (Pending)",
                    KEX_STATUS_UNVERIFIED: f"{ECDHE} (Unverified)",
                    KEX_STATUS_VERIFIED:   f"{ECDHE} (Verified)",
                    KEX_STATUS_NO_RX_PSK:  f"{PSK}  (No contact key)",
                    KEX_STATUS_HAS_RX_PSK: PSK}

        # Populate columns with contact data
        for c in self.get_list_of_contacts():
            c1.append(c.nick)
            c2.append(c.short_address)
            c3.append('Yes'    if c.log_messages   else 'No')
            c4.append('Yes'    if c.notifications  else 'No')
            c5.append('Accept' if c.file_reception else 'Reject')
            c6.append(kex_dict[c.kex_status])

        # Calculate column widths
        c1w, c2w, c3w, c4w, c5w, = [max(len(v) for v in column) + CONTACT_LIST_INDENT
                                    for column in [c1, c2, c3, c4, c5]]

        # Align columns by adding whitespace between fields of each line
        lines = [f'{f1:{c1w}}{f2:{c2w}}{f3:{c3w}}{f4:{c4w}}{f5:{c5w}}{f6}'
                 for f1, f2, f3, f4, f5, f6 in zip(c1, c2, c3, c4, c5, c6)]

        # Add a terminal-wide line between the column names and the data
        lines.insert(1, get_terminal_width() * '─')

        # Print the contact list
        clear_screen()
        print('\n' + '\n'.join(lines) + '\n\n')
