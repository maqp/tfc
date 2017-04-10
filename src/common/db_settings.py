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
import serial
import struct
import textwrap
import typing

from typing import Union

from src.common.crypto   import auth_and_decrypt, encrypt_and_sign
from src.common.encoding import bool_to_bytes, double_to_bytes, int_to_bytes, str_to_bytes
from src.common.encoding import bytes_to_bool, bytes_to_double, bytes_to_int, bytes_to_str
from src.common.errors   import CriticalError, FunctionReturn
from src.common.misc     import clear_screen, ensure_dir, get_tty_w, round_up
from src.common.input    import yes
from src.common.output   import c_print
from src.common.statics  import *

if typing.TYPE_CHECKING:
    from src.common.db_contacts  import ContactList
    from src.common.db_groups    import GroupList
    from src.common.db_masterkey import MasterKey


class Settings(object):
    """Settings object stores all user adjustable settings under an encrypted database."""

    def __init__(self,
                 master_key: 'MasterKey',
                 operation:  str,
                 local_test: bool,
                 dd_sockets: bool) -> None:
        """Create a new settings object.

        The settings below are altered from within the program itself.
        Changes made to settings are stored inside an encrypted database.

        :param master_key: Settings database encryption key
        :param operation:  Operation mode of the program (tx or rx)
        :param local_test: Setting value passed from command line argument
        :param dd_sockets: Setting value passed from command line argument
        """
        #           WARNING
        # THESE ARE DEFAULT VALUES FOR
        # SETTINGS. DO NOT EDIT THEM.
        # USE THE '/set' COMMAND INSTEAD.

        # Common settings
        self.format_of_logfiles = '%Y-%m-%d %H:%M:%S'  # Timestamp format of logged messages
        self.disable_gui_dialog = False                # True replaces Tkinter dialogs with CLI prompts
        self.m_members_in_group = 20                   # Max members in group (Rx.py must have same value)
        self.m_number_of_groups = 20                   # Max number of groups (Rx.py must have same value)
        self.m_number_of_accnts = 20                   # Max number of accounts (Rx.py must have same val)
        self.serial_iface_speed = 19200                # The speed of serial interface in bauds per sec
        self.e_correction_ratio = 5                    # N/o byte errors serial datagrams can recover from
        self.log_msg_by_default = False                # Default logging setting for new contacts
        self.store_file_default = False                # True accepts files from new contacts by default
        self.n_m_notify_privacy = False                # Default privacy notification setting for new contacts
        self.log_dummy_file_a_p = True                 # False disables storage of placeholder data for files

        # Transmitter settings
        self.txm_serial_adapter = True                 # False searches for integrated serial interface
        self.nh_bypass_messages = True                 # False removes interrupting NH bypass messages
        self.confirm_sent_files = True                 # False sends files without asking for confirmation
        self.double_space_exits = False                # True exits with doubles space, False clears screen
        self.trickle_connection = False                # True enables trickle connection to hide metadata
        self.trickle_stat_delay = 2.0                  # Static delay between trickle packets
        self.trickle_rand_delay = 2.0                  # Max random delay for timing obfuscation
        self.long_packet_rand_d = False                # True adds spam guard evading delay
        self.max_val_for_rand_d = 10.0                 # Spam guard evasion max delay

        # Receiver settings
        self.rxm_serial_adapter = True                 # False searches for integrated serial interface
        self.new_msg_notify_dur = 1.0                  # Number of seconds new msg notification appears

        self.master_key         = master_key
        self.software_operation = operation
        self.local_testing_mode = local_test
        self.data_diode_sockets = dd_sockets

        self.file_name          = f'{DIR_USER_DATA}/{operation}_settings'
        index_of_last_attr      = list(self.__dict__.keys()).index('new_msg_notify_dur') + 1  # Include last index in slice
        self.key_list           = list(self.__dict__.keys())[0:index_of_last_attr]
        self.defaults           = {k: self.__dict__[k] for k in list(self.__dict__.keys())[:index_of_last_attr]}

        if os.path.isfile(self.file_name):
            self.load_settings()
            # TxM is unable to send serial interface type changing command
            # if RxM looks for the type of adapter user doesn't have available.
            if operation == 'rx':
                self.setup()
                self.store_settings()
        else:
            self.setup()
            self.store_settings()

        # Following settings change only when program is restarted on TxM/RxM/NH
        self.session_ec_ratio  = self.e_correction_ratio
        self.session_if_speed  = self.serial_iface_speed
        self.session_trickle   = self.trickle_connection
        self.session_usb_iface = self.rxm_serial_adapter if operation == 'rx' else self.txm_serial_adapter

    def load_settings(self) -> None:
        """Load settings from encrypted database."""
        ensure_dir(f'{DIR_USER_DATA}/')
        with open(self.file_name, 'rb') as f:
            ct_bytes = f.read()

        pt_bytes = auth_and_decrypt(ct_bytes, self.master_key.master_key)

        # Update settings based on plaintext byte string content
        for i, key in enumerate(self.key_list):

            attribute = self.__getattribute__(key)

            if isinstance(attribute, bool):
                value    = bytes_to_bool(pt_bytes[0])  # type: Union[bool, int, float, str]
                pt_bytes = pt_bytes[1:]

            elif isinstance(attribute, int):
                value    = bytes_to_int(pt_bytes[:8])
                pt_bytes = pt_bytes[8:]

            elif isinstance(attribute, float):
                value    = bytes_to_double(pt_bytes[:8])
                pt_bytes = pt_bytes[8:]

            elif isinstance(attribute, str):
                value    = bytes_to_str(pt_bytes[:1024])
                pt_bytes = pt_bytes[1024:]  # 255 * 4 = 1020. The four additional bytes is the UTF-32 BOM.

            else:
                raise CriticalError("Invalid data type in settings default values.")

            setattr(self, key, value)

    def store_settings(self) -> None:
        """Store settings to encrypted database."""
        attribute_list = [self.__getattribute__(k) for k in self.key_list]

        # Convert attributes into constant length byte string
        pt_bytes = b''
        for a in attribute_list:
            if   isinstance(a, bool):  pt_bytes += bool_to_bytes(a)
            elif isinstance(a, int):   pt_bytes += int_to_bytes(a)
            elif isinstance(a, float): pt_bytes += double_to_bytes(a)
            elif isinstance(a, str):   pt_bytes += str_to_bytes(a)
            else:                      raise CriticalError("Invalid attribute type in settings.")

        ct_bytes = encrypt_and_sign(pt_bytes, self.master_key.master_key)

        ensure_dir(f'{DIR_USER_DATA}/')
        with open(self.file_name, 'wb+') as f:
            f.write(ct_bytes)

    def change_setting(self,
                       key:          str,
                       value:        str,
                       contact_list: 'ContactList',
                       group_list:   'GroupList') -> None:
        """Parse, update and store new setting value."""
        attribute = self.__getattribute__(key)

        if isinstance(attribute, bool):
            value_ = value
            value  = value.lower().capitalize()
            if value not in ['True', 'False']:
                raise FunctionReturn(f"Invalid value {value_}.")

        elif isinstance(attribute, int):
            if not value.isdigit() or eval(value) < 0 or eval(value) > 7378697629483820640:
                raise FunctionReturn(f"Invalid value {value}.")

        elif isinstance(attribute, float):
            if not isinstance(eval(value), float) or eval(value) < 0.0:
                raise FunctionReturn(f"Invalid value {value}.")
            try:
                double_to_bytes(eval(value))
            except struct.error:
                raise FunctionReturn(f"Invalid value {value}.")

        elif isinstance(attribute, str):
            if len(value) > 255:
                raise FunctionReturn(f"Setting must be shorter than 256 chars.")

        else:
            raise CriticalError("Invalid attribute type in settings.")

        self.validate_key_value_pair(key, value, contact_list, group_list)

        value = value if isinstance(attribute, str) else eval(value)
        setattr(self, key, value)
        self.store_settings()

    @staticmethod
    def validate_key_value_pair(key:          str,
                                value:        str,
                                contact_list: 'ContactList',
                                group_list:   'GroupList') -> None:
        """Check values of some settings in closer detail."""
        if key in ['m_members_in_group', 'm_number_of_groups', 'm_number_of_accnts']:
            if eval(value) % 10 != 0:
                raise FunctionReturn("Database padding settings must be divisible by 10.")

        if key == 'm_members_in_group':
            min_size = round_up(group_list.largest_group())
            if eval(value) < min_size:
                raise FunctionReturn(f"Can't set max number of members lower than {min_size}.")

        if key == 'm_number_of_groups':
            min_size = round_up(len(group_list))
            if eval(value) < min_size:
                raise FunctionReturn(f"Can't set max number of groups lower than {min_size}.")

        if key == 'm_number_of_accnts':
            min_size = round_up(len(contact_list))
            if eval(value) < min_size:
                raise FunctionReturn(f"Can't set max number of contacts lower than {min_size}.")

        if key == 'serial_iface_speed':
            if eval(value) not in serial.Serial().BAUDRATES:
                raise FunctionReturn("Specified baud rate is not supported.")
            c_print("Baud rate will change on restart.", head=1, tail=1)

        if key == 'e_correction_ratio':
            if not value.isdigit() or eval(value) < 1:
                raise FunctionReturn("Invalid value for error correction ratio.")
            c_print("Error correction ratio will change on restart.", head=1, tail=1)

        if key in ['rxm_serial_adapter', 'txm_serial_adapter']:
            c_print("Interface will change on restart.", head=1, tail=1)

        if key in ['trickle_connection', 'trickle_stat_delay', 'trickle_rand_delay']:
            c_print("Trickle setting will change on restart.", head=1, tail=1)

    def setup(self) -> None:
        """Prompt user to enter initial settings."""
        clear_screen()
        if not self.local_testing_mode:
            if self.software_operation == 'tx':
                self.txm_serial_adapter = yes("Does TxM use USB-to-serial/TTL adapter?", head=1, tail=1)
            else:
                self.rxm_serial_adapter = yes("Does RxM use USB-to-serial/TTL adapter?", head=1, tail=1)

    def print_settings(self) -> None:
        """Print list of settings, their current and default values and setting descriptions."""

        # Common
        desc_d = {
         "format_of_logfiles": "Timestamp format of logged messages",
         "disable_gui_dialog": "True replaces Tkinter dialogs with CLI prompts",

         "m_members_in_group": "Max members in group (Must be same on TxM/RxM)",
         "m_number_of_groups": "Max number of groups (Must be same on TxM/RxM)",
         "m_number_of_accnts": "Max number of accounts (Must be same on TxM/RxM)",

         "serial_iface_speed": "The speed of serial interface in bauds per sec",
         "e_correction_ratio": "N/o byte errors serial datagrams can recover from",

         "log_msg_by_default": "Default logging setting for new contacts",
         "store_file_default": "True accepts files from new contacts by default",
         "n_m_notify_privacy": "Default message notification setting for new contacts",
         "log_dummy_file_a_p": "False disables storage of placeholder data for files",

         # TxM
         "txm_serial_adapter": "False uses system's integrated serial interface",
         "nh_bypass_messages": "False removes NH bypass interrupt messages",
         "confirm_sent_files": "False sends files without asking for confirmation",
         "double_space_exits": "True exits with doubles space, else clears screen",

         "trickle_connection": "True enables trickle connection to hide metadata",
         "trickle_stat_delay": "Static delay between trickle packets",
         "trickle_rand_delay": "Max random delay for timing obfuscation",

         "long_packet_rand_d": "True adds spam guard evading delay",
         "max_val_for_rand_d": "Maximum time for random spam guard evasion delay",

         # RxM
         "rxm_serial_adapter": "False uses system's integrated serial interface",
         "new_msg_notify_dur": "Number of seconds new msg notification appears"}

        clear_screen()
        tty_w = get_tty_w()

        print("Setting name        Current value      Default value      Description")
        print(tty_w * '-')

        for key in self.defaults:
            def_value     = str(self.defaults[key]).ljust(len('%Y-%m-%d %H:%M:%S'))
            description   = desc_d[key]
            wrapper       = textwrap.TextWrapper(width=max(1, (tty_w - 59)))
            desc_lines    = wrapper.fill(description).split('\n')
            current_value = str(self.__getattribute__(key)).ljust(17)

            print(f"{key}  {current_value}  {def_value}  {desc_lines[0]}")

            # Print wrapped description lines with indent
            if len(desc_lines) > 1:
                for line in desc_lines[1:]:
                    print(58 * ' ' + line)
                print('')

        print('\n')
