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

import datetime
import os
import time

from src.common.crypto      import argon2_kdf, hash_chain
from src.common.db_contacts import Contact
from src.common.db_groups   import Group
from src.common.db_keys     import KeySet
from src.common.encoding    import int_to_bytes
from src.common.errors      import CriticalError
from src.common.input       import pwd_prompt
from src.common.misc        import ensure_dir
from src.common.statics     import *


def create_contact(nick='Alice',
                   user='user',
                   txfp=32 * b'\x01',
                   rxfp=32 * b'\x02',
                   l=True, f=True, n=True):
    """Create mock contact object."""
    account = 'local' if nick == 'local' else f'{nick.lower()}@jabber.org'
    user    = 'local' if nick == 'local' else f'{user.lower()}@jabber.org'
    return Contact(account, user, nick, txfp, rxfp, l, f, n)


class ContactList(object):
    """Mock object for unittesting."""

    def __init__(self, nicks=None, **kwargs):
        self.master_key = MasterKey()
        self.settings   = Settings()
        if nicks is None:
            self.contacts = []
        else:
            self.contacts = [create_contact(n) for n in nicks]
        for key, value in kwargs.items():
            setattr(self, key, value)

    def __iter__(self):
        for c in self.contacts:
            yield c

    def __len__(self):
        return len(self.contacts)

    def store_contacts(self):
        pass

    def get_contact(self, selector):
        return next(c for c in self.contacts if selector in [c.rx_account, c.nick])

    def contact_selectors(self):
        return self.get_list_of_accounts() + self.get_list_of_nicks()

    def get_list_of_accounts(self):
        return [c.rx_account for c in self.contacts if c.rx_account != 'local']

    def get_list_of_nicks(self):
        return [c.nick for c in self.contacts if c.nick != 'local']

    def get_list_of_users_accounts(self):
        return list(set([c.tx_account for c in self.contacts if c.tx_account != 'local']))

    def remove_contact(self, selector):
        for i, c in enumerate(self.contacts):
            if selector in [c.rx_account, c.nick]:
                del self.contacts[i]
                self.store_contacts()
                break

    def has_contacts(self):
        return any(self.get_list_of_accounts())

    def has_contact(self, selector):
        return selector in self.contact_selectors()

    def has_local_contact(self):
        return any(c.rx_account == 'local' for c in self.contacts)

    def add_contact(self, rx_account, tx_account, nick, tx_fingerprint, rx_fingerprint, log_messages, file_reception, notifications):
        if self.has_contact(rx_account):
            self.remove_contact(rx_account)
        contact = Contact(rx_account, tx_account, nick,
                          tx_fingerprint, rx_fingerprint,
                          log_messages, file_reception, notifications)
        self.contacts.append(contact)
        self.store_contacts()

    @staticmethod
    def print_contacts(spacing=False):
        print(spacing)


def create_group(name='testgroup', nick_list=None):
    """Create mock group object."""
    if nick_list is None:
        nick_list = ['Alice', 'Bob']
    settings = Settings()
    store_f  = lambda: None
    contacts = [create_contact(n) for n in nick_list]
    return Group(name, False, False, contacts, settings, store_f)


class GroupList(object):
    """Mock object for unittesting."""

    def __init__(self, groups = None, **kwargs):
        self.groups = []
        if groups is not None:
            for g in groups:
                self.groups.append(create_group(g))
        self.master_key   = MasterKey()
        self.contact_list = ContactList()
        self.settings     = Settings()
        for key, value in kwargs.items():
            setattr(self, key, value)

    def __iter__(self):
        for g in self.groups:
            yield g

    def __len__(self):
        return len(self.groups)

    def store_groups(self):
        pass

    def add_group(self, name, logging, notifications, members):
        if self.has_group(name):
            self.remove_group(name)
        self.groups.append(Group(name, logging, notifications, members, self.settings, self.store_groups))
        self.store_groups()

    def largest_group(self):
        largest = 0
        for g in self.groups:
            largest = max(len(g), largest)
        return largest

    def get_list_of_group_names(self):
        return [g.name for g in self.groups]

    def get_group(self, name):
        return next(g for g in self.groups if g.name == name)

    def has_group(self, name):
        return any([g.name == name for g in self.groups])

    def has_groups(self):
        return any(self.groups)

    def get_group_members(self, name):
        return self.get_group(name).members

    def remove_group(self, name):
        for i, g in enumerate(self.groups):
            if g.name == name:
                del self.groups[i]
                self.store_groups()
                break

    @staticmethod
    def print_groups():
        print('mock group printing')


def create_keyset(nick='Alice',
                  tx_key=32 * b'\x01',
                  tx_hek=32 * b'\x01',
                  rx_key=32 * b'\x01',
                  rx_hek=32 * b'\x01',
                  tx_harac=0,
                  rx_harac=0,
                  store_f=None):
    """Create mock keyset object."""
    if store_f is None:
        store_f = lambda: None
    account = 'local' if nick == 'local' else f'{nick.lower()}@jabber.org'
    return KeySet(account, tx_key, tx_hek, rx_key, rx_hek, tx_harac, rx_harac, store_f)


class KeyList(object):
    """Mock object for unittesting."""

    def __init__(self, nicks=None, **kwargs):
        self.master_key = MasterKey()
        self.settings   = Settings()
        if nicks is None:
            self.keysets = []
        else:
            self.keysets = [create_keyset(n) for n in nicks]
        for key, value in kwargs.items():
            setattr(self, key, value)

    def store_keys(self):
        pass

    def get_keyset(self, account):
        return next(k for k in self.keysets if account == k.rx_account)

    def has_local_key(self):
        return any(k.rx_account == 'local' for k in self.keysets)

    def has_keyset(self, account):
        return any(account == k.rx_account for k in self.keysets)

    def add_keyset(self, rx_account, tx_key, rx_key, tx_hek, rx_hek):
        if self.has_keyset(rx_account):
            self.remove_keyset(rx_account)
        self.keysets.append(KeySet(rx_account, tx_key, rx_key, tx_hek, rx_hek, 0, 0, self.store_keys))
        self.store_keys()

    def remove_keyset(self, name):
        for i, k in enumerate(self.keysets):
            if name == k.rx_account:
                del self.keysets[i]
                break

    def change_master_key(self, master_key):
        self.master_key = master_key

    def manage(self, command, *params):
        if   command == 'ADD': self.add_keyset(*params)
        elif command == 'REM': self.remove_keyset(*params)
        elif command == 'KEY': self.change_master_key(*params)
        else: raise CriticalError("Invalid KeyList management command.")


class MasterKey(object):
    """Mock object for unittesting."""

    def __init__(self, **kwargs):
        self.master_key = bytes(32)
        self.file_name  = f'{DIR_USER_DATA}/ut_login_data'
        for key, value in kwargs.items():
            setattr(self, key, value)

    @classmethod
    def get_password(cls, purpose="master password"):
        return pwd_prompt(f"Enter {purpose}: ", '┌', '┐')

    @classmethod
    def new_password(cls, purpose="master password"):
        password_1 = pwd_prompt(f"Enter a new {purpose}: ", '┌', '┐')
        password_2 = pwd_prompt(f"Confirm the {purpose}: ", '├', '┤')
        if password_1 == password_2:
            return password_1
        else:
            return cls.new_password(purpose)

    def new_master_key(self):
        password = MasterKey.new_password()
        salt     = os.urandom(32)
        rounds   = 1

        assert isinstance(salt, bytes)
        while True:
            time_start         = time.monotonic()
            master_key, memory = argon2_kdf(password, salt, rounds, local_testing=False)
            time_final         = time.monotonic() - time_start

            if time_final > 3.0:
                self.master_key = master_key
                master_key_hash = hash_chain(master_key)
                ensure_dir(f'{DIR_USER_DATA}/')
                with open(self.file_name, 'wb+') as f:
                    f.write(salt
                            + master_key_hash
                            + int_to_bytes(rounds)
                            + int_to_bytes(memory))
                break
            else:
                rounds *= 2


class Settings(object):
    """Mock object for unittesting."""

    def __init__(self, **kwargs):
        self.format_of_logfiles = '%Y-%m-%d %H:%M:%S'
        self.disable_gui_dialog = False
        self.m_members_in_group = 20
        self.m_number_of_groups = 20
        self.m_number_of_accnts = 20
        self.serial_iface_speed = 19200
        self.e_correction_ratio = 5
        self.log_msg_by_default = False
        self.store_file_default = False
        self.n_m_notify_privacy = False
        self.log_dummy_file_a_p = True

        # Transmitter settings
        self.txm_serial_adapter = True
        self.nh_bypass_messages = True
        self.confirm_sent_files = True
        self.double_space_exits = False
        self.trickle_connection = False
        self.trickle_stat_delay = 2.0
        self.trickle_rand_delay = 2.0
        self.long_packet_rand_d = False
        self.max_val_for_rand_d = 10.0

        # Receiver settings
        self.rxm_serial_adapter = True
        self.new_msg_notify_dur = 1.0

        self.master_key         = MasterKey()
        self.software_operation = 'ut'
        self.local_testing_mode = False
        self.data_diode_sockets = False

        self.session_ec_ratio  = self.e_correction_ratio
        self.session_if_speed  = self.serial_iface_speed
        self.session_trickle   = self.trickle_connection
        self.session_usb_iface = None

        # Override defaults with specified kwargs
        for key, value in kwargs.items():
            setattr(self, key, value)

    def store_settings(self):
        pass

    def change_setting(self, key, value, *_):
        attribute = self.__getattribute__(key)
        if isinstance(attribute, bool):
            value = value.lower().capitalize()
        value = value if isinstance(attribute, str) else eval(value)
        setattr(self, key, value)

    @staticmethod
    def print_settings():
        print("Mock setting printing")


class UserInput(object):
    """Mock object for unittesting."""

    def __init__(self, plaintext=None, **kwargs):
        self.plaintext = plaintext
        self.window    = None
        self.settings  = None
        self.w_type    = None
        self.type      = None
        for key, value in kwargs.items():
            setattr(self, key, value)


class Window(object):
    """Mock object for unittesting."""

    def __init__(self, **kwargs):
        self.contact_list    = ContactList()
        self.group_list      = GroupList()
        self.window_contacts = []
        self.group           = None
        self.contact         = None
        self.name            = None
        self.type            = None
        self.uid             = None
        self.imc_name        = None
        for key, value in kwargs.items():
            setattr(self, key, value)

    def __iter__(self):
        for c in self.window_contacts:
            yield c

    def __len__(self):
        return len(self.window_contacts)

    def deselect(self):
        pass

    def update_group_win_members(self, group_list):
        if self.type == 'group':
            if group_list.has_group(self.name):
                self.group           = group_list.get_group(self.name)
                self.window_contacts = self.group.members
                if self.window_contacts:
                    self.imc_name = self.window_contacts[0].rx_account
            else:
                self.deselect()

    def is_selected(self):
        return self.name is not None


class FileWindow(object):
    """Mock object for unittesting."""

    def __init__(self, uid, packet_list=None, **kwargs):
        self.uid             = uid
        self.unread_messages = 0
        self.is_active       = False
        if packet_list is None:
            self.packet_list = PacketList()
        else:
            self.packet_list = packet_list
        for key, value in kwargs.items():
            setattr(self, key, value)

    def redraw(self):
        pass


def create_window(nick='Alice'):
    account = 'local' if nick == 'local' else f'{nick.lower()}@jabber.org'
    return RxMWindow(uid=account)

class RxMWindow(object):
    """Mock object for unittesting."""

    def __init__(self, **kwargs):
        self.uid             = None
        self.contact_list    = None
        self.group_list      = None
        self.settings        = None
        self.type            = None
        self.name            = None
        self.is_active       = False
        self.group_timestamp = time.time() * 1000
        self.window_contacts = []
        self.message_log     = []
        self.unread_messages = 0
        self.previous_msg_ts = datetime.datetime.now()
        for key, value in kwargs.items():
            setattr(self, key, value)

    def __len__(self):
        return len(self.message_log)

    def __iter__(self):
        for m in self.message_log:
            yield m

    def remove_contacts(self, accounts):
        for account in accounts:
            for i, m in enumerate(self.window_contacts):
                if account == m.rx_account:
                    del self.window_contacts[i]

    def add_contacts(self, accounts):
        for a in accounts:
            if not self.has_contact(a) and self.contact_list.has_contact(a):
                self.window_contacts.append(self.contact_list.get_contact(a))

    def reset_window(self):
        self.message_log = []

    def clear_window(self):
        pass

    def has_contact(self, account):
        return any(c.rx_account == account for c in self.window_contacts)

    def print(self, msg_tuple):
        ts, message, account, origin = msg_tuple
        if self.previous_msg_ts.date() != ts.date():
            print(f"00:00 -!- Day changed.")
        self.previous_msg_ts = ts
        if self.is_active:
            print(message)
        else:
            self.unread_messages += 1

    def print_new(self,
                  timestamp,
                  message,
                  account='local',
                  origin=ORIGIN_USER_HEADER,
                  print_=True):
        msg_tuple = (timestamp, message, account, origin)
        self.message_log.append(msg_tuple)
        if print_:
            self.print(msg_tuple)

    def redraw(self):
        self.unread_messages = 0
        if self.message_log:
            self.previous_msg_ts = self.message_log[0][0]
        for msg_tuple in self.message_log:
            self.print(msg_tuple)


class WindowList(object):
    """Mock object for unittesting."""

    def __init__(self, nicks=None, **kwargs):
        self.contact_list = ContactList()
        self.group_list   = GroupList()
        self.packet_list  = PacketList()
        self.settings     = Settings()
        if nicks is None:
            self.windows = []
        else:
            self.windows = [create_window(n) for n in nicks]

        self.active_win = None
        for key, value in kwargs.items():
            setattr(self, key, value)

    def __len__(self):
        return len(self.windows)

    def __iter__(self):
        for w in self.windows:
            yield w

    def select_rx_window(self, name):
        if self.active_win is not None:
            self.active_win.is_active = False
        self.active_win           = self.get_window(name)
        self.active_win.is_active = True

    def has_window(self, name):
        return name in self.get_list_of_window_names()

    def get_list_of_window_names(self):
        return [w.uid for w in self.windows]

    def get_local_window(self):
        return self.get_window('local')

    def get_window(self, name):
        if not self.has_window(name):
            if name == FILE_R_WIN_ID_BYTES.decode():
                self.windows.append(FileWindow(name, self.packet_list))
            else:
                self.windows.append(RxMWindow(uid=name, contact_list=self.contact_list, group_list=self.group_list, settings=self.settings))

        return next(w for w in self.windows if w.uid == name)


class Gateway(object):

    def __init__(self, **kwargs):
        self.packets = []
        for key, value in kwargs.items():
            setattr(self, key, value)

    def write(self, output):
        self.packets.append(output)


class Packet(object):
    """Mock object for unittesting."""

    def __init__(self, **kwargs):
        self.account          = None
        self.contact          = None
        self.origin           = None
        self.type             = None
        self.settings         = None
        self.f_name           = None
        self.f_size           = None
        self.f_packets        = None
        self.f_eta            = None
        self.lt_active        = False
        self.is_complete      = False
        self.assembly_pt_list = []
        self.payload          = None  # Unittest mock return value
        for key, value in kwargs.items():
            setattr(self, key, value)

    def add_packet(self, packet):
        pass

    def assemble_message_packet(self):
        return self.payload

    def assemble_and_store_file(self):
        return self.payload

    def assemble_command_packet(self):
        return self.payload


class PacketList(object):
    """Mock object for unittesting."""

    def __init__(self, **kwargs):
        self.contact_list = ContactList()
        self.settings     = Settings()
        self.packet_l     = []
        for key, value in kwargs.items():
            setattr(self, key, value)

    def __iter__(self):
        for p in self.packet_l:
            yield p

    def __len__(self):
        return len(self.packet_l)

    def has_packet(self, account, origin, type_):
        return any(p for p in self.packet_l if (p.account == account
                                                and p.origin == origin
                                                and p.type == type_))

    def get_packet(self, account, origin, type_):
        if not self.has_packet(account, origin, type_):
            contact = self.contact_list.get_contact(account)
            self.packet_l.append(Packet(account=account, contact=contact, origin=origin, type=type_, settings=self.settings))
        return next(p for p in self.packet_l if (p.account == account
                                                 and p.origin == origin
                                                 and p.type == type_))
