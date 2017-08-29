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

import time

from datetime import datetime
from typing   import Iterable, Sized

from src.common.db_contacts  import Contact
from src.common.db_groups    import Group
from src.common.db_keys      import KeySet
from src.common.db_contacts  import ContactList as OrigContactList
from src.common.db_groups    import GroupList   as OrigGroupList
from src.common.db_keys      import KeyList     as OrigKeyList
from src.common.db_masterkey import MasterKey   as OrigMasterKey
from src.common.db_settings  import Settings    as OrigSettings
from src.common.statics      import *

from src.tx.windows import TxWindow as OrigTxWindow

from src.rx.packet  import PacketList as OrigPacketList
from src.rx.windows import RxWindow   as OrigRxWindow


def create_contact(nick          ='Alice',
                   user          ='user',
                   txfp          =FINGERPRINT_LEN * b'\x01',
                   rxfp          =FINGERPRINT_LEN * b'\x02',
                   log_messages  =True,
                   file_reception=True,
                   notifications =True):
    """Create mock contact object."""
    account = LOCAL_ID if nick == LOCAL_ID else f'{nick.lower()}@jabber.org'
    user    = LOCAL_ID if nick == LOCAL_ID else f'{user.lower()}@jabber.org'
    return Contact(account, user, nick,
                   txfp, rxfp,
                   log_messages, file_reception, notifications)


def create_group(name='testgroup', nick_list=None):
    """Create mock group object."""
    if nick_list is None:
        nick_list = ['Alice', 'Bob']
    settings = Settings()
    store_f  = lambda: None
    members  = [create_contact(n) for n in nick_list]
    return Group(name, False, False, members, settings, store_f)


def create_keyset(nick    ='Alice',
                  tx_key  =KEY_LENGTH * b'\x01',
                  tx_hek  =KEY_LENGTH * b'\x01',
                  rx_key  =KEY_LENGTH * b'\x01',
                  rx_hek  =KEY_LENGTH * b'\x01',
                  tx_harac=INITIAL_HARAC,
                  rx_harac=INITIAL_HARAC,
                  store_f =None):
    """Create mock keyset object."""
    account = LOCAL_ID if nick == LOCAL_ID else f'{nick.lower()}@jabber.org'
    store_f = lambda: None if store_f is None else store_f
    return KeySet(account, tx_key, tx_hek, rx_key, rx_hek, tx_harac, rx_harac, store_f)


def create_rx_window(nick='Alice'):
    account = LOCAL_ID if nick == LOCAL_ID else f'{nick.lower()}@jabber.org'
    return RxWindow(uid=account)


# Common
class ContactList(OrigContactList, Iterable, Sized):
    """Mock object for unittesting."""

    def __init__(self, nicks=None, **kwargs):
        self.master_key = MasterKey()
        self.settings   = Settings()
        self.contacts   = [] if nicks is None else [create_contact(n) for n in nicks]

        for key, value in kwargs.items():
            setattr(self, key, value)

    def store_contacts(self):
        pass

    def load_contacts(self):
        pass

    def print_contacts(self):
        pass


class Gateway(object):
    """Mock object for unittesting."""

    def __init__(self, **kwargs):
        self.packets = []
        for key, value in kwargs.items():
            setattr(self, key, value)

    def write(self, output):
        self.packets.append(output)


class GroupList(OrigGroupList, Iterable, Sized):
    """Mock object for unittesting."""

    def __init__(self, groups = None, **kwargs):
        self.master_key   = MasterKey()
        self.settings     = Settings()
        self.contact_list = ContactList()
        self.groups = [] if groups is None else [(create_group(g)) for g in groups]

        for key, value in kwargs.items():
            setattr(self, key, value)

    def store_groups(self):
        pass

    def load_groups(self):
        pass

    def print_groups(self):
        pass


class KeyList(OrigKeyList):
    """Mock object for unittesting."""

    def __init__(self, nicks=None, **kwargs):
        self.master_key = MasterKey()
        self.settings   = Settings()
        self.keysets    = [] if nicks is None else [create_keyset(n) for n in nicks]

        for key, value in kwargs.items():
            setattr(self, key, value)

    def store_keys(self):
        pass

    def load_keys(self):
        pass


class MasterKey(OrigMasterKey):
    """Mock object for unittesting."""

    def __init__(self, **kwargs):
        self.local_test = False
        self.master_key = bytes(KEY_LENGTH)
        self.file_name  = f'{DIR_USER_DATA}ut_login_data'

        for key, value in kwargs.items():
            setattr(self, key, value)


# TxM
class Settings(OrigSettings):
    """Mock object for unittesting."""

    def __init__(self, **kwargs):
        self.disable_gui_dialog            = False
        self.max_number_of_group_members   = 20
        self.max_number_of_groups          = 20
        self.max_number_of_contacts        = 20
        self.serial_baudrate               = 19200
        self.serial_error_correction       = 5
        self.log_messages_by_default       = False
        self.accept_files_by_default       = False
        self.show_notifications_by_default = True
        self.logfile_masking               = False

        # Transmitter settings
        self.txm_usb_serial_adapter       = True
        self.nh_bypass_messages           = True
        self.confirm_sent_files           = True
        self.double_space_exits           = False
        self.traffic_masking              = False
        self.traffic_masking_static_delay = 2.0
        self.traffic_masking_random_delay = 2.0
        self.multi_packet_random_delay    = False
        self.max_duration_of_random_delay = 10.0

        # Receiver settings
        self.rxm_usb_serial_adapter      = True
        self.new_message_notify_preview  = False
        self.new_message_notify_duration = 1.0

        self.master_key         = MasterKey()
        self.software_operation = 'ut'
        self.local_testing_mode = False
        self.data_diode_sockets = False

        self.session_serial_error_correction = self.serial_error_correction
        self.session_serial_baudrate         = self.serial_baudrate
        self.session_traffic_masking         = self.traffic_masking
        self.session_usb_serial_adapter      = None
        self.transmit_delay                  = 0.0
        self.receive_timeout                 = 0.0
        self.txm_inter_packet_delay          = 0.0
        self.rxm_receive_timeout             = 0.0

        # Override defaults with specified kwargs
        for key, value in kwargs.items():
            setattr(self, key, value)

    def store_settings(self):
        pass

    def load_settings(self):
        pass

    @staticmethod
    def validate_key_value_pair(key, value, contact_list, group_list):
        pass

    def print_settings(self):
        pass


class TxWindow(OrigTxWindow):
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


class UserInput(object):
    """Mock object for unittesting."""

    def __init__(self, plaintext=None, **kwargs):
        self.plaintext = plaintext
        self.type      = None
        for key, value in kwargs.items():
            setattr(self, key, value)


# RxM
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


class PacketList(OrigPacketList):
    """Mock object for unittesting."""

    def __init__(self, **kwargs):
        self.settings     = Settings()
        self.contact_list = ContactList()
        self.packets      = []

        for key, value in kwargs.items():
            setattr(self, key, value)


class RxWindow(OrigRxWindow):
    """Mock object for unittesting."""

    def __init__(self, **kwargs):
        self.uid          = None
        self.contact_list = ContactList()
        self.group_list   = GroupList()
        self.settings     = Settings()
        self.packet_list  = PacketList()

        self.is_active       = False
        self.group_timestamp = time.time() * 1000

        self.window_contacts = []
        self.message_log     = []
        self.handle_dict     = dict()
        self.previous_msg_ts = datetime.now()
        self.unread_messages = 0

        self.type            = None
        self.type_print      = None
        self.name            = None

        for key, value in kwargs.items():
            setattr(self, key, value)


class WindowList(object):
    """Mock object for unittesting."""

    def __init__(self, nicks=None, **kwargs):
        self.contact_list = ContactList()
        self.group_list   = GroupList()
        self.packet_list  = PacketList()
        self.settings     = Settings()
        self.windows      = [] if nicks is None else [create_rx_window(n) for n in nicks]

        self.active_win = None
        for key, value in kwargs.items():
            setattr(self, key, value)

    def __len__(self):
        return len(self.windows)

    def __iter__(self):
        yield from self.windows

    def group_windows(self):
        return [w for w in self.windows if w.type == WIN_TYPE_GROUP]

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
        return self.get_window(LOCAL_ID)

    def remove_window(self, uid: str) -> None:
        for i, w in enumerate(self.windows):
            if uid == w.uid:
                del self.windows[i]
                break

    def get_window(self, uid):
        if not self.has_window(uid):
            self.windows.append(RxWindow(uid=uid,
                                         contact_list=self.contact_list,
                                         group_list  =self.group_list,
                                         settings    =self.settings,
                                         packet_list =self.packet_list))

        return next(w for w in self.windows if w.uid == uid)
