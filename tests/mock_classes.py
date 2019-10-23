#!/usr/bin/env python3.7
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

import getpass
import time

from datetime import datetime
from typing   import Generator, Iterable, List, Sized

import nacl.signing

from src.common.db_contacts  import Contact
from src.common.db_groups    import Group
from src.common.db_keys      import KeySet
from src.common.db_contacts  import ContactList     as OrigContactList
from src.common.db_groups    import GroupList       as OrigGroupList
from src.common.db_onion     import OnionService    as OrigOnionService
from src.common.db_keys      import KeyList         as OrigKeyList
from src.common.db_masterkey import MasterKey       as OrigMasterKey
from src.common.gateway      import Gateway         as OrigGateway
from src.common.gateway      import GatewaySettings as OrigGatewaySettings
from src.common.db_settings  import Settings        as OrigSettings
from src.common.encoding     import pub_key_to_onion_address, pub_key_to_short_address
from src.common.misc         import calculate_race_condition_delay
from src.common.reed_solomon import RSCodec
from src.common.statics      import (DIR_USER_DATA, FINGERPRINT_LENGTH, INITIAL_HARAC, KEX_STATUS_VERIFIED, LOCAL_ID,
                                     LOCAL_NICK, LOCAL_PUBKEY, ONION_SERVICE_PRIVATE_KEY_LENGTH, SYMMETRIC_KEY_LENGTH,
                                     TX, WIN_TYPE_GROUP, WIN_UID_LOCAL)

from src.transmitter.windows import TxWindow as OrigTxWindow

from src.receiver.packet  import PacketList as OrigPacketList
from src.receiver.windows import RxWindow   as OrigRxWindow

from tests.utils import nick_to_pub_key, group_name_to_group_id


def create_contact(nick,
                   tx_fingerprint=FINGERPRINT_LENGTH * b'\x01',
                   rx_fingerprint=FINGERPRINT_LENGTH * b'\x02',
                   kex_status    =KEX_STATUS_VERIFIED,
                   log_messages  =True,
                   file_reception=True,
                   notifications =True):
    """Create a mock contact object."""
    if nick == LOCAL_ID:
        pub_key = LOCAL_PUBKEY
        nick    = LOCAL_NICK
    else:
        pub_key = nick_to_pub_key(nick)

    return Contact(pub_key, nick,
                   tx_fingerprint, rx_fingerprint, kex_status,
                   log_messages, file_reception, notifications)


def create_group(name, nick_list=None):
    """Create a mock group object."""
    if nick_list is None:
        nick_list = ['Alice', 'Bob']
    settings = Settings()
    members  = [create_contact(n) for n in nick_list]
    return Group(name, group_name_to_group_id(name), False, False, members, settings, lambda: None)


def create_keyset(nick,
                  tx_key=SYMMETRIC_KEY_LENGTH * b'\x01',
                  tx_hek=SYMMETRIC_KEY_LENGTH * b'\x01',
                  rx_key=SYMMETRIC_KEY_LENGTH * b'\x01',
                  rx_hek=SYMMETRIC_KEY_LENGTH * b'\x01',
                  tx_harac=INITIAL_HARAC,
                  rx_harac=INITIAL_HARAC,
                  store_f=None):
    """Create a mock keyset object."""
    pub_key = LOCAL_PUBKEY if nick == LOCAL_ID else nick_to_pub_key(nick)
    return KeySet(pub_key, tx_key, tx_hek, rx_key, rx_hek, tx_harac, rx_harac,
                  store_keys=lambda: None if store_f is None else store_f)


def create_rx_window(nick='Alice'):
    """Create a mock Rx-window object."""
    pub_key = LOCAL_PUBKEY if nick == LOCAL_ID else nick_to_pub_key(nick)
    return RxWindow(uid=pub_key)


# Common
class ContactList(OrigContactList, Iterable, Sized):
    """Mock the object for unit testing."""

    def __init__(self, nicks=None, **kwargs):
        self.master_key = MasterKey()
        self.settings   = Settings()
        self.contacts   = [] if nicks is None else [create_contact(n) for n in nicks]

        for key, value in kwargs.items():
            setattr(self, key, value)

    def __iter__(self) -> Generator:
        yield from self.contacts

    def store_contacts(self):
        """Mock method."""
        pass

    def load_contacts(self):
        """Mock method."""
        pass

    def print_contacts(self):
        """Mock method."""
        pass


class Gateway(OrigGateway):
    """Mock the object for unit testing."""

    def __init__(self, **kwargs):
        self.packets  = []
        self.settings = GatewaySettings(**kwargs)
        self.rs       = RSCodec(2 * self.settings.serial_error_correction)

    def write(self, output):
        """Mock method."""
        self.packets.append(output)


class GroupList(OrigGroupList, Iterable, Sized):
    """Mock the object for unit testing."""

    def __init__(self, groups=None, **kwargs):
        self.master_key   = MasterKey()
        self.settings     = Settings()
        self.contact_list = ContactList()
        self.groups = [] if groups is None else [(create_group(g)) for g in groups]  # type: List[Group]
        self.store_groups_called = False

        for key, value in kwargs.items():
            setattr(self, key, value)

    def __iter__(self) -> Generator:
        """Mock method."""
        yield from self.groups

    def __len__(self) -> int:
        """Mock method."""
        return len(self.groups)

    def store_groups(self):
        """Mock method."""
        self.store_groups_called = True

    def load_groups(self):
        """Mock method."""
        pass

    def print_groups(self):
        """Mock method."""
        pass


class KeyList(OrigKeyList):
    """Mock the object for unit testing."""

    def __init__(self, nicks=None, **kwargs):
        self.master_key = MasterKey()
        self.settings   = Settings()
        self.keysets    = [] if nicks is None else [create_keyset(n) for n in nicks]

        self.store_keys_called = False

        for key, value in kwargs.items():
            setattr(self, key, value)

    def store_keys(self):
        """Mock method."""
        self.store_keys_called = True

    def load_keys(self):
        """Mock method."""
        pass


class MasterKey(OrigMasterKey):
    """Mock the object for unit testing."""

    def __init__(self, **kwargs):
        """Create new MasterKey mock object."""
        self.local_test = False
        self.master_key = bytes(SYMMETRIC_KEY_LENGTH)
        self.file_name  = f'{DIR_USER_DATA}{TX}_login_data'

        for key, value in kwargs.items():
            setattr(self, key, value)

    def load_master_key(self) -> bytes:
        """Create mock master key bytes."""
        if getpass.getpass() == 'test_password':
            return self.master_key
        else:
            return SYMMETRIC_KEY_LENGTH * b'f'


class OnionService(OrigOnionService):
    """Mock the object for unit testing."""

    def __init__(self, **kwargs):
        """Create new OnionService mock object."""
        self.onion_private_key  = ONION_SERVICE_PRIVATE_KEY_LENGTH*b'a'
        self.conf_code          = b'a'
        self.public_key         = bytes(nacl.signing.SigningKey(seed=self.onion_private_key).verify_key)
        self.user_onion_address = pub_key_to_onion_address(self.public_key)
        self.user_short_address = pub_key_to_short_address(self.public_key)
        self.is_delivered       = False

        for key, value in kwargs.items():
            setattr(self, key, value)


# Transmitter Program
class Settings(OrigSettings):
    """Mock the object for unit testing."""

    def __init__(self, **kwargs):
        """Create new Settings mock object."""
        self.disable_gui_dialog            = False
        self.max_number_of_group_members   = 50
        self.max_number_of_groups          = 50
        self.max_number_of_contacts        = 50
        self.log_messages_by_default       = False
        self.accept_files_by_default       = False
        self.show_notifications_by_default = True
        self.log_file_masking              = False
        self.ask_password_for_log_access   = True

        # Transmitter settings
        self.nc_bypass_messages = False
        self.confirm_sent_files = True
        self.double_space_exits = False
        self.traffic_masking    = False
        self.tm_static_delay    = 2.0
        self.tm_random_delay    = 2.0

        # Relay settings
        self.allow_contact_requests = True

        # Receiver settings
        self.new_message_notify_preview  = False
        self.new_message_notify_duration = 1.0
        self.max_decompress_size         = 100_000_000

        self.master_key         = MasterKey()
        self.software_operation = TX
        self.local_testing_mode = False

        self.all_keys = list(vars(self).keys())
        self.key_list = self.all_keys[:self.all_keys.index('master_key')]
        self.defaults = {k: self.__dict__[k] for k in self.key_list}

        # Override defaults with specified kwargs
        for key, value in kwargs.items():
            setattr(self, key, value)

    def store_settings(self):
        """Mock method."""
        pass

    def load_settings(self):
        """Mock method."""
        pass

    @staticmethod
    def validate_key_value_pair(key, value, contact_list, group_list):
        """Mock method."""
        pass


# Transmitter Program
class GatewaySettings(OrigGatewaySettings):
    """Mock the object for unit testing."""

    def __init__(self, **kwargs):
        """Create new GatewaySettings mock object."""
        self.serial_baudrate           = 19200
        self.serial_error_correction   = 5
        self.use_serial_usb_adapter    = True
        self.built_in_serial_interface = 'ttyS0'

        self.software_operation = TX
        self.local_testing_mode = False
        self.data_diode_sockets = False

        self.all_keys = list(vars(self).keys())
        self.key_list = self.all_keys[:self.all_keys.index('software_operation')]
        self.defaults = {k: self.__dict__[k] for k in self.key_list}

        self.session_serial_error_correction = self.serial_error_correction
        self.session_serial_baudrate         = self.serial_baudrate
        self.session_usb_serial_adapter      = self.use_serial_usb_adapter

        self.tx_inter_packet_delay = 0.0
        self.rx_receive_timeout    = 0.0

        self.race_condition_delay = calculate_race_condition_delay(self.session_serial_error_correction,
                                                                   self.serial_baudrate)

        # Override defaults with specified kwargs
        for key, value in kwargs.items():
            setattr(self, key, value)

    def store_settings(self):
        """Mock method."""
        pass

    def load_settings(self):
        """Mock method."""
        pass


class TxWindow(OrigTxWindow):
    """Mock the object for unit testing."""

    def __init__(self, **kwargs):
        """Create new TxWindow mock object."""
        self.contact_list    = ContactList()
        self.group_list      = GroupList()
        self.window_contacts = []
        self.group           = None
        self.contact         = None
        self.name            = None
        self.type            = None
        self.uid             = None
        self.group_id        = None
        self.imc_name        = None
        for key, value in kwargs.items():
            setattr(self, key, value)


class UserInput(object):
    """Mock the object for unit testing."""

    def __init__(self, plaintext=None, **kwargs):
        """Create new UserInput mock object."""
        self.plaintext = plaintext
        self.type      = None
        for key, value in kwargs.items():
            setattr(self, key, value)


# Receiver Program
class Packet(object):
    """Mock the object for unit testing."""

    def __init__(self, **kwargs):
        """Create new Pack mock object."""
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
        """Mock method."""
        pass

    def assemble_message_packet(self):
        """Mock method."""
        return self.payload

    def assemble_and_store_file(self):
        """Mock method."""
        return self.payload

    def assemble_command_packet(self):
        """Mock method."""
        return self.payload


class PacketList(OrigPacketList):
    """Mock the object for unit testing."""

    def __init__(self, **kwargs):
        self.settings     = Settings()
        self.contact_list = ContactList()
        self.packets      = []

        for key, value in kwargs.items():
            setattr(self, key, value)


class RxWindow(OrigRxWindow):
    """Mock the object for unit testing."""

    def __init__(self, **kwargs):
        self.uid          = None
        self.contact_list = ContactList()
        self.group_list   = GroupList()
        self.settings     = Settings()
        self.packet_list  = PacketList()

        self.is_active       = False
        self.group_timestamp = time.time() * 1000
        self.group           = None

        self.window_contacts = []
        self.message_log     = []
        self.handle_dict     = dict()
        self.previous_msg_ts = datetime.now()
        self.unread_messages = 0

        self.type       = None
        self.type_print = None
        self.name       = None

        for key, value in kwargs.items():
            setattr(self, key, value)


class WindowList(object):
    """Mock the object for unit testing."""

    def __init__(self, nicks=None, **kwargs):
        """Create new WindowList mock object."""
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
        """Mock method."""
        return [w for w in self.windows if w.type == WIN_TYPE_GROUP]

    def set_active_rx_window(self, name):
        """Mock method."""
        if self.active_win is not None:
            self.active_win.is_active = False
        self.active_win           = self.get_window(name)
        self.active_win.is_active = True

    def has_window(self, name):
        """Mock method."""
        return name in self.get_list_of_window_names()

    def get_list_of_window_names(self):
        """Mock method."""
        return [w.uid for w in self.windows]

    def get_local_window(self):
        """Mock method."""
        return self.get_window(WIN_UID_LOCAL)

    def remove_window(self, uid: str) -> None:
        """Mock method."""
        for i, w in enumerate(self.windows):
            if uid == w.uid:
                del self.windows[i]
                break

    def get_window(self, uid):
        """Mock method."""
        if not self.has_window(uid):
            self.windows.append(RxWindow(uid=uid,
                                         contact_list=self.contact_list,
                                         group_list  =self.group_list,
                                         settings    =self.settings,
                                         packet_list =self.packet_list))

        return next(w for w in self.windows if w.uid == uid)
