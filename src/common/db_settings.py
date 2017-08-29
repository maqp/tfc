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
import textwrap
import typing

from typing import Union

from src.common.crypto     import auth_and_decrypt, encrypt_and_sign
from src.common.encoding   import bool_to_bytes, double_to_bytes, int_to_bytes
from src.common.encoding   import bytes_to_bool, bytes_to_double, bytes_to_int
from src.common.exceptions import CriticalError, FunctionReturn
from src.common.misc       import calculate_race_condition_delay, calculate_serial_delays
from src.common.misc       import ensure_dir, get_terminal_width, round_up
from src.common.input      import yes
from src.common.output     import c_print, clear_screen
from src.common.statics    import *

if typing.TYPE_CHECKING:
    from src.common.db_contacts  import ContactList
    from src.common.db_groups    import GroupList
    from src.common.db_masterkey import MasterKey


class Settings(object):
    """\
    Settings object stores all user adjustable
    settings under an encrypted database.
    """

    def __init__(self,
                 master_key: 'MasterKey',
                 operation:  str,
                 local_test: bool,
                 dd_sockets: bool) -> None:
        """Create a new Settings object.

        The settings below are altered from within the program itself.
        Changes made to the default settings are stored in encrypted
        settings database.

        :param master_key: MasterKey object
        :param operation:  Operation mode of the program (tx or rx)
        :param local_test: Setting value passed from command-line argument
        :param dd_sockets: Setting value passed from command-line argument
        """
        # Common settings
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
        self.txm_usb_serial_adapter        = True
        self.nh_bypass_messages            = True
        self.confirm_sent_files            = True
        self.double_space_exits            = False
        self.traffic_masking               = False
        self.traffic_masking_static_delay  = 2.0
        self.traffic_masking_random_delay  = 2.0
        self.multi_packet_random_delay     = False
        self.max_duration_of_random_delay  = 10.0

        # Receiver settings
        self.rxm_usb_serial_adapter        = True
        self.new_message_notify_preview    = False
        self.new_message_notify_duration   = 1.0

        self.master_key         = master_key
        self.software_operation = operation
        self.local_testing_mode = local_test
        self.data_diode_sockets = dd_sockets

        self.file_name = f'{DIR_USER_DATA}{operation}_settings'

        self.key_list = list(vars(self).keys())
        self.key_list = self.key_list[:self.key_list.index('master_key')]
        self.defaults = {k: self.__dict__[k] for k in self.key_list}

        ensure_dir(DIR_USER_DATA)
        if os.path.isfile(self.file_name):
            self.load_settings()
            if operation == RX:
                # TxM is unable to send serial interface type changing command if
                # RxM looks for the type of adapter user doesn't have available.
                # Therefore setup() is run every time the Receiver program starts.
                self.setup()
        else:
            self.setup()
        self.store_settings()

        # Following settings change only when program is restarted
        self.session_serial_error_correction = self.serial_error_correction
        self.session_serial_baudrate         = self.serial_baudrate
        self.session_traffic_masking         = self.traffic_masking
        self.session_usb_serial_adapter      = self.rxm_usb_serial_adapter if operation == RX else self.txm_usb_serial_adapter
        self.race_condition_delay            = calculate_race_condition_delay(self, txm=True)

        self.rxm_receive_timeout, self.txm_inter_packet_delay = calculate_serial_delays(self.session_serial_baudrate)

    def store_settings(self) -> None:
        """Store settings to encrypted database."""
        attribute_list = [self.__getattribute__(k) for k in self.key_list]

        pt_bytes = b''
        for a in attribute_list:
            if isinstance(a, bool):
                pt_bytes += bool_to_bytes(a)
            elif isinstance(a, int):
                pt_bytes += int_to_bytes(a)
            elif isinstance(a, float):
                pt_bytes += double_to_bytes(a)
            else:
                raise CriticalError("Invalid attribute type in settings.")

        ct_bytes = encrypt_and_sign(pt_bytes, self.master_key.master_key)

        ensure_dir(DIR_USER_DATA)
        with open(self.file_name, 'wb+') as f:
            f.write(ct_bytes)

    def load_settings(self) -> None:
        """Load settings from encrypted database."""
        with open(self.file_name, 'rb') as f:
            ct_bytes = f.read()

        pt_bytes = auth_and_decrypt(ct_bytes, self.master_key.master_key)

        # Update settings based on plaintext byte string content
        for key in self.key_list:

            attribute = self.__getattribute__(key)

            if isinstance(attribute, bool):
                value    = bytes_to_bool(pt_bytes[0])  # type: Union[bool, int, float]
                pt_bytes = pt_bytes[BOOLEAN_SETTING_LEN:]

            elif isinstance(attribute, int):
                value    = bytes_to_int(pt_bytes[:INTEGER_SETTING_LEN])
                pt_bytes = pt_bytes[INTEGER_SETTING_LEN:]

            elif isinstance(attribute, float):
                value    = bytes_to_double(pt_bytes[:FLOAT_SETTING_LEN])
                pt_bytes = pt_bytes[FLOAT_SETTING_LEN:]

            else:
                raise CriticalError("Invalid data type in settings default values.")

            setattr(self, key, value)

    def change_setting(self,
                       key:          str,
                       value_str:    str,
                       contact_list: 'ContactList',
                       group_list:   'GroupList') -> None:
        """Parse, update and store new setting value."""
        attribute = self.__getattribute__(key)

        try:
            if isinstance(attribute, bool):
                value_ = value_str.lower()
                if value_ not in ['true', 'false']:
                    raise ValueError
                value = (value_ == 'true')  # type: Union[bool, int, float]

            elif isinstance(attribute, int):
                value = int(value_str)
                if value < 0 or value > 2**64-1:
                    raise ValueError

            elif isinstance(attribute, float):
                value = float(value_str)
                if value < 0.0:
                    raise ValueError
            else:
                raise CriticalError("Invalid attribute type in settings.")

        except ValueError:
            raise FunctionReturn(f"Error: Invalid value '{value_str}'")

        self.validate_key_value_pair(key, value, contact_list, group_list)

        setattr(self, key, value)
        self.store_settings()

    @staticmethod
    def validate_key_value_pair(key:          str,
                                value:        Union[int, float, bool],
                                contact_list: 'ContactList',
                                group_list:   'GroupList') -> None:
        """\
        Perform further evaluation on settings
        the values of which have restrictions.
        """
        if key in ['max_number_of_group_members', 'max_number_of_groups', 'max_number_of_contacts']:
            if value % 10 != 0 or value == 0:
                raise FunctionReturn("Error: Database padding settings must be divisible by 10.")

        if key == 'max_number_of_group_members':
            min_size = round_up(group_list.largest_group())
            if value < min_size:
                raise FunctionReturn(f"Error: Can't set max number of members lower than {min_size}.")

        if key == 'max_number_of_groups':
            min_size = round_up(len(group_list))
            if value < min_size:
                raise FunctionReturn(f"Error: Can't set max number of groups lower than {min_size}.")

        if key == 'max_number_of_contacts':
            min_size = round_up(len(contact_list))
            if value < min_size:
                raise FunctionReturn(f"Error: Can't set max number of contacts lower than {min_size}.")

        if key == 'serial_baudrate':
            if value not in serial.Serial().BAUDRATES:
                raise FunctionReturn("Error: Specified baud rate is not supported.")
            c_print("Baud rate will change on restart.", head=1, tail=1)

        if key == 'serial_error_correction':
            if value < 1:
                raise FunctionReturn("Error: Invalid value for error correction ratio.")
            c_print("Error correction ratio will change on restart.", head=1, tail=1)

        if key == 'new_message_notify_duration' and value < 0.05:
            raise FunctionReturn("Error: Too small value for message notify duration.")

        if key in ['rxm_usb_serial_adapter', 'txm_usb_serial_adapter']:
            c_print("Interface will change on restart.", head=1, tail=1)

        if key in ['traffic_masking', 'traffic_masking_static_delay', 'traffic_masking_random_delay']:
            c_print("Traffic masking setting will change on restart.", head=1, tail=1)

    def setup(self) -> None:
        """Prompt user to enter initial settings."""
        clear_screen()
        if not self.local_testing_mode:
            if self.software_operation == TX:
                self.txm_usb_serial_adapter = yes("Does TxM use USB-to-serial/TTL adapter?", head=1, tail=1)
            else:
                self.rxm_usb_serial_adapter = yes("Does RxM use USB-to-serial/TTL adapter?", head=1, tail=1)

    def print_settings(self) -> None:
        """\
        Print list of settings, their current and
        default values, and setting descriptions.
        """
        desc_d = {
            # Common settings
            "disable_gui_dialog":            "True replaces Tkinter dialogs with CLI prompts",
            "max_number_of_group_members":   "Max members in group (TxM/RxM must have the same value)",
            "max_number_of_groups":          "Max number of groups (TxM/RxM must have the same value)",
            "max_number_of_contacts":        "Max number of contacts (TxM/RxM must have the same value)",
            "serial_baudrate":               "The speed of serial interface in bauds per second",
            "serial_error_correction":       "Number of byte errors serial datagrams can recover from",
            "log_messages_by_default":       "Default logging setting for new contacts/groups",
            "accept_files_by_default":       "Default file reception setting for new contacts",
            "show_notifications_by_default": "Default message notification setting for new contacts/groups",
            "logfile_masking":               "True hides real size of logfile during traffic masking",

            # Transmitter settings
            "txm_usb_serial_adapter":        "False uses system's integrated serial interface",
            "nh_bypass_messages":            "False removes NH bypass interrupt messages",
            "confirm_sent_files":            "False sends files without asking for confirmation",
            "double_space_exits":            "True exits, False clears screen with double space command",
            "traffic_masking":               "True enables traffic masking to hide metadata",
            "traffic_masking_static_delay":  "Static delay between traffic masking packets",
            "traffic_masking_random_delay":  "Max random delay for traffic masking timing obfuscation",
            "multi_packet_random_delay":     "True adds IM server spam guard evading delay",
            "max_duration_of_random_delay":  "Maximum time for random spam guard evasion delay",

            # Receiver settings
            "rxm_usb_serial_adapter":        "False uses system's integrated serial interface",
            "new_message_notify_preview":    "When True, shows preview of received message",
            "new_message_notify_duration":   "Number of seconds new message notification appears"}

        # Columns
        c1 = ['Setting name']
        c2 = ['Current value']
        c3 = ['Default value']
        c4 = ['Description']

        terminal_width   = get_terminal_width()
        desc_line_indent = 64

        if terminal_width < desc_line_indent + 1:
            raise FunctionReturn("Error: Screen width is too small.")

        for key in self.defaults:
            c1.append(key)
            c2.append(str(self.__getattribute__(key)))
            c3.append(str(self.defaults[key]))

            description = desc_d[key]
            wrapper     = textwrap.TextWrapper(width=max(1, (terminal_width - desc_line_indent)))
            desc_lines  = wrapper.fill(description).split('\n')
            desc_string = desc_lines[0]

            for l in desc_lines[1:]:
                desc_string += '\n' + desc_line_indent * ' ' + l

            if len(desc_lines) > 1:
                desc_string += '\n'

            c4.append(desc_string)

        lst = []
        for name, current, default, description in zip(c1, c2, c3, c4):
            lst.append('{0:{1}} {2:{3}} {4:{5}} {6}'.format(
                name,    max(len(v) for v in c1) + SETTINGS_INDENT,
                current, max(len(v) for v in c2) + SETTINGS_INDENT,
                default, max(len(v) for v in c3) + SETTINGS_INDENT,
                description))

        lst.insert(1, get_terminal_width() * '─')
        clear_screen()
        print('\n' + '\n'.join(lst) + '\n')
