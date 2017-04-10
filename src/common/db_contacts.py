#!/usr/bin/env python3.6
# -*- coding: utf-8 -*-

"""
Copyright (C) 2013-2017  Markus Ottela

This file is part of TFC.

TFC is free software: you can redistribute it and/or modify it under the terms
of the GNU General Public License as published by the Free Software Foundation,
either version 3 of the License, or (at your option) any later version.

TFC is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with TFC. If not, see <http://www.gnu.org/licenses/>.
"""

import os
import typing

from typing import List

from src.common.crypto   import auth_and_decrypt, encrypt_and_sign
from src.common.encoding import bool_to_bytes, str_to_bytes
from src.common.encoding import bytes_to_bool, bytes_to_str
from src.common.misc     import clear_screen, ensure_dir, get_tty_w, split_byte_string
from src.common.statics  import *

if typing.TYPE_CHECKING:
    from src.common.db_masterkey import MasterKey
    from src.common.db_settings  import Settings


class Contact(object):
    """Contact object collects contact-data unrelated to key rotation."""

    def __init__(self,
                 rx_account:     str,
                 tx_account:     str,
                 nick:           str,
                 tx_fingerprint: bytes,
                 rx_fingerprint: bytes,
                 log_messages:   bool,
                 file_reception: bool,
                 notifications:  bool) -> None:
        """Create a new contact object."""
        self.rx_account     = rx_account
        self.tx_account     = tx_account
        self.nick           = nick

        self.tx_fingerprint = tx_fingerprint
        self.rx_fingerprint = rx_fingerprint

        self.log_messages   = log_messages
        self.file_reception = file_reception
        self.notifications  = notifications

    def dump_c(self) -> bytes:
        """Return contact data as constant length byte string."""
        return   str_to_bytes(self.rx_account) \
               + str_to_bytes(self.tx_account) \
               + str_to_bytes(self.nick) \
               + self.tx_fingerprint \
               + self.rx_fingerprint \
               + bool_to_bytes(self.log_messages) \
               + bool_to_bytes(self.file_reception) \
               + bool_to_bytes(self.notifications)


class ContactList(object):
    """ContactList object manages list of contact objects."""

    def __init__(self, master_key: 'MasterKey', settings: 'Settings') -> None:
        """Create a new contact list object."""
        self.master_key = master_key
        self.settings   = settings
        self.contacts   = []  # type: List[Contact]
        self.file_name  = f'{DIR_USER_DATA}/{settings.software_operation}_contacts'

        if os.path.isfile(self.file_name):
            self.load_contacts()
        else:
            self.store_contacts()

    def __iter__(self) -> 'ContactList':
        """Iterate over contacts."""
        for c in self.contacts:
            yield c

    def __len__(self) -> int:
        """Return number of contacts in contact list."""
        return len(self.contacts)

    def load_contacts(self) -> None:
        """Load contacts from encrypted database."""
        ensure_dir(f'{DIR_USER_DATA}/')
        with open(self.file_name, 'rb') as f:
            ct_bytes = f.read()

        pt_bytes = auth_and_decrypt(ct_bytes, self.master_key.master_key)
        entries  = split_byte_string(pt_bytes, item_len=3139)  # 3 * 1024 + 2 * 32 + 3 * 1
        dummy_id = 'dummy_contact'.encode('utf-32')
        contacts = [e for e in entries if not e.startswith(dummy_id)]

        for c in contacts:
            rx_account     = bytes_to_str(c[   0:1024])
            tx_account     = bytes_to_str(c[1024:2048])
            nick           = bytes_to_str(c[2048:3072])
            tx_fingerprint = c[3072:3104]
            rx_fingerprint = c[3104:3136]
            log_messages   = bytes_to_bool(c[3136:3137])
            file_reception = bytes_to_bool(c[3137:3138])
            notifications  = bytes_to_bool(c[3138:3139])

            self.contacts.append(Contact(rx_account, tx_account, nick,
                                         tx_fingerprint, rx_fingerprint,
                                         log_messages, file_reception, notifications))

    def store_contacts(self) -> None:
        """Write contacts to encrypted database."""
        dummy_contact_bytes = self.generate_dummy_contact()
        number_of_dummies   = self.settings.m_number_of_accnts - len(self.contacts)

        pt_bytes  = b''.join([c.dump_c() for c in self.contacts])
        pt_bytes += number_of_dummies * dummy_contact_bytes
        ct_bytes  = encrypt_and_sign(pt_bytes, self.master_key.master_key)

        ensure_dir(f'{DIR_USER_DATA}/')
        with open(self.file_name, 'wb+') as f:
            f.write(ct_bytes)

    @staticmethod
    def generate_dummy_contact() -> bytes:
        """Generate byte string for dummy contact."""
        rx_account     = str_to_bytes('dummy_contact')
        tx_account     = str_to_bytes('dummy_user')
        nick           = str_to_bytes('dummy_nick')
        tx_fingerprint = bytes(32)
        rx_fingerprint = bytes(32)
        logging_bytes  = bool_to_bytes(False)
        file_r_bytes   = bool_to_bytes(False)
        notify_bytes   = bool_to_bytes(False)

        return rx_account + tx_account + nick \
               + tx_fingerprint + rx_fingerprint \
               + logging_bytes + file_r_bytes + notify_bytes

    def get_contact(self, selector: str) -> Contact:
        """Load contact from list based on unique ID (account name or nick)."""
        return next(c for c in self.contacts if selector in [c.rx_account, c.nick])

    def contact_selectors(self) -> List[str]:
        """Return list of UIDs contacts can be selected with."""
        return self.get_list_of_accounts() + self.get_list_of_nicks()

    def get_list_of_accounts(self) -> List[str]:
        """Return list of accounts."""
        return [c.rx_account for c in self.contacts if c.rx_account != 'local']

    def get_list_of_nicks(self) -> List[str]:
        """Return list of nicks."""
        return [c.nick for c in self.contacts if c.nick != 'local']

    def get_list_of_users_accounts(self) -> List[str]:
        """Return list of user's accounts."""
        return list(set([c.tx_account for c in self.contacts if c.tx_account != 'local']))

    def remove_contact(self, selector: str) -> None:
        """Remove account based on account/nick, update database file."""
        for i, c in enumerate(self.contacts):
            if selector in [c.rx_account, c.nick]:
                del self.contacts[i]
                self.store_contacts()
                break

    def has_contacts(self) -> bool:
        """Return True if contact list has any contacts, else False."""
        return any(self.get_list_of_accounts())

    def has_contact(self, selector: str) -> bool:
        """Return True if contact with account/nick exists, else False."""
        return selector in self.contact_selectors()

    def has_local_contact(self) -> bool:
        """Return True if local key exists, else False."""
        return any(c.rx_account == 'local' for c in self.contacts)

    def add_contact(self,
                    rx_account:     str,
                    tx_account:     str,
                    nick:           str,
                    tx_fingerprint: bytes,
                    rx_fingerprint: bytes,
                    log_messages:   bool,
                    file_reception: bool,
                    notifications:  bool) -> None:
        """Add new contact to contact list, write changes to database."""
        if self.has_contact(rx_account):
            self.remove_contact(rx_account)

        contact = Contact(rx_account, tx_account, nick,
                          tx_fingerprint, rx_fingerprint,
                          log_messages, file_reception, notifications)

        self.contacts.append(contact)
        self.store_contacts()

    def print_contacts(self, spacing: bool = True) -> None:
        """Print list of contacts."""
        # Columns
        c1 = ['Contact']
        c2 = ['Logging']
        c3 = ['Notify']
        c4 = ['Files ']
        c5 = ['Key Ex']
        c6 = ['Account']

        for c in self.contacts:
            if c.rx_account == 'local':
                continue

            c1.append(c.nick)
            c2.append('Yes'    if c.log_messages                else 'No')
            c3.append('Yes'    if c.notifications               else 'No')
            c4.append('Accept' if c.file_reception              else 'Reject')
            c5.append('PSK'    if c.tx_fingerprint == bytes(32) else 'X25519')
            c6.append(c.rx_account)

        lst = []
        for nick, log_setting, notify_setting, file_reception_setting, key_exchange, account in zip(c1, c2, c3, c4, c5, c6):
            lst.append('{0:{6}} {1:{7}} {2:{8}} {3:{9}} {4:{10}} {5}'.format(
                nick, log_setting, notify_setting, file_reception_setting, key_exchange, account,
                len(max(c1, key=len)) + 4,
                len(max(c2, key=len)) + 4,
                len(max(c3, key=len)) + 4,
                len(max(c4, key=len)) + 4,
                len(max(c5, key=len)) + 4,
                len(max(c6, key=len)) + 4))

        if spacing:
            clear_screen()
            print('')

        lst.insert(1, get_tty_w() * '─')
        print('\n'.join(str(l) for l in lst))
        print('\n')
