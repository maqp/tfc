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
import textwrap
import typing

from typing import Union

from src.common.database   import TFCDatabase
from src.common.encoding   import (bool_to_bytes, double_to_bytes, int_to_bytes,
                                   bytes_to_bool, bytes_to_double, bytes_to_int)
from src.common.exceptions import CriticalError, SoftError
from src.common.input      import yes
from src.common.misc       import ensure_dir, get_terminal_width, round_up
from src.common.output     import clear_screen, m_print
from src.common.statics    import (DIR_USER_DATA, ENCODED_BOOLEAN_LENGTH, ENCODED_FLOAT_LENGTH, ENCODED_INTEGER_LENGTH,
                                   MAX_INT, SETTINGS_INDENT, TRAFFIC_MASKING_MIN_RANDOM_DELAY,
                                   TRAFFIC_MASKING_MIN_STATIC_DELAY, TX)

if typing.TYPE_CHECKING:
    from src.common.db_contacts  import ContactList
    from src.common.db_groups    import GroupList
    from src.common.db_masterkey import MasterKey
    SettingType = Union[int, float, bool]


class Settings(object):
    """\
    Settings object stores user adjustable settings (excluding those
    related to serial interface) under an encrypted database.
    """

    def __init__(self,
                 master_key: 'MasterKey',  # MasterKey object
                 operation:  str,          # Operation mode of the program (Tx or Rx)
                 local_test: bool,         # Local testing setting from command-line argument
                 qubes:      bool = False  # Qubes setting from command-line argument
                 ) -> None:
        """Create a new Settings object.

        The settings below are defaults, and are only to be altered from
        within the program itself. Changes made to the default settings
        are stored in the encrypted settings database, from which they
        are loaded when the program starts.
        """
        # Common settings
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

        # Relay Settings
        self.allow_contact_requests = True

        # Receiver settings
        self.new_message_notify_preview  = False
        self.new_message_notify_duration = 1.0
        self.max_decompress_size         = 100_000_000

        self.master_key         = master_key
        self.software_operation = operation
        self.local_testing_mode = local_test
        self.qubes              = qubes

        self.file_name = f'{DIR_USER_DATA}{operation}_settings'
        self.database  = TFCDatabase(self.file_name, master_key)

        self.all_keys = list(vars(self).keys())
        self.key_list = self.all_keys[:self.all_keys.index('master_key')]
        self.defaults = {k: self.__dict__[k] for k in self.key_list}

        ensure_dir(DIR_USER_DATA)
        if os.path.isfile(self.file_name):
            self.load_settings()
        else:
            self.store_settings()

    def store_settings(self, replace: bool = True) -> None:
        """Store settings to an encrypted database.

        The plaintext in the encrypted database is a constant
        length bytestring regardless of stored setting values.
        """
        attribute_list = [self.__getattribute__(k) for k in self.key_list]

        bytes_lst = []
        for a in attribute_list:
            if isinstance(a, bool):
                bytes_lst.append(bool_to_bytes(a))
            elif isinstance(a, int):
                bytes_lst.append(int_to_bytes(a))
            elif isinstance(a, float):
                bytes_lst.append(double_to_bytes(a))
            else:
                raise CriticalError("Invalid attribute type in settings.")

        pt_bytes = b''.join(bytes_lst)
        self.database.store_database(pt_bytes, replace)

    def load_settings(self) -> None:
        """Load settings from the encrypted database."""
        pt_bytes = self.database.load_database()

        # Update settings based on plaintext byte string content
        for key in self.key_list:

            attribute = self.__getattribute__(key)

            if isinstance(attribute, bool):
                value    = bytes_to_bool(pt_bytes[0])  # type: Union[bool, int, float]
                pt_bytes = pt_bytes[ENCODED_BOOLEAN_LENGTH:]

            elif isinstance(attribute, int):
                value    = bytes_to_int(pt_bytes[:ENCODED_INTEGER_LENGTH])
                pt_bytes = pt_bytes[ENCODED_INTEGER_LENGTH:]

            elif isinstance(attribute, float):
                value    = bytes_to_double(pt_bytes[:ENCODED_FLOAT_LENGTH])
                pt_bytes = pt_bytes[ENCODED_FLOAT_LENGTH:]

            else:
                raise CriticalError("Invalid data type in settings default values.")

            setattr(self, key, value)

    def change_setting(self,
                       key:          str,  # Name of the setting
                       value_str:    str,  # Value of the setting
                       contact_list: 'ContactList',
                       group_list:   'GroupList'
                       ) -> None:
        """Parse, update and store new setting value."""
        attribute = self.__getattribute__(key)

        try:
            if isinstance(attribute, bool):
                value = dict(true=True, false=False)[value_str.lower()]  # type: Union[bool, int, float]

            elif isinstance(attribute, int):
                value = int(value_str)
                if value < 0 or value > MAX_INT:
                    raise ValueError

            elif isinstance(attribute, float):
                value = float(value_str)
                if value < 0.0:
                    raise ValueError

            else:
                raise CriticalError("Invalid attribute type in settings.")

        except (KeyError, ValueError):
            raise SoftError(f"Error: Invalid setting value '{value_str}'.", head_clear=True)

        self.validate_key_value_pair(key, value, contact_list, group_list)

        setattr(self, key, value)
        self.store_settings()

    @staticmethod
    def validate_key_value_pair(key:          str,            # Name of the setting
                                value:        'SettingType',  # Value of the setting
                                contact_list: 'ContactList',  # ContactList object
                                group_list:   'GroupList',    # GroupList object
                                ) -> None:
        """Evaluate values for settings that have further restrictions."""
        Settings.validate_database_limit(key, value)
        Settings.validate_max_number_of_group_members(key, value, group_list)
        Settings.validate_max_number_of_groups(key, value, group_list)
        Settings.validate_max_number_of_contacts(key, value, contact_list)
        Settings.validate_new_message_notify_duration(key, value)
        Settings.validate_traffic_masking_delay(key, value, contact_list)

    @staticmethod
    def validate_database_limit(key: str, value: 'SettingType') -> None:
        """Validate setting values for database entry limits."""
        if key in ["max_number_of_group_members", "max_number_of_groups", "max_number_of_contacts"]:
            if value % 10 != 0 or value == 0:
                raise SoftError("Error: Database padding settings must be divisible by 10.", head_clear=True)

    @staticmethod
    def validate_max_number_of_group_members(key:        str,
                                             value:      'SettingType',
                                             group_list: 'GroupList'
                                             ) -> None:
        """Validate setting value for maximum number of group members."""
        if key == "max_number_of_group_members":
            min_size = round_up(group_list.largest_group())
            if value < min_size:
                raise SoftError(f"Error: Can't set the max number of members lower than {min_size}.", head_clear=True)

    @staticmethod
    def validate_max_number_of_groups(key:        str,
                                      value:      'SettingType',
                                      group_list: 'GroupList'
                                      ) -> None:
        """Validate setting value for maximum number of groups."""
        if key == "max_number_of_groups":
            min_size = round_up(len(group_list))
            if value < min_size:
                raise SoftError(f"Error: Can't set the max number of groups lower than {min_size}.", head_clear=True)

    @staticmethod
    def validate_max_number_of_contacts(key:          str,
                                        value:        'SettingType',
                                        contact_list: 'ContactList'
                                        ) -> None:
        """Validate setting value for maximum number of contacts."""
        if key == "max_number_of_contacts":
            min_size = round_up(len(contact_list))
            if value < min_size:
                raise SoftError(f"Error: Can't set the max number of contacts lower than {min_size}.", head_clear=True)

    @staticmethod
    def validate_new_message_notify_duration(key: str, value: 'SettingType') -> None:
        """Validate setting value for duration of new message notification."""
        if key == "new_message_notify_duration" and value < 0.05:
            raise SoftError("Error: Too small value for message notify duration.", head_clear=True)

    @staticmethod
    def validate_traffic_masking_delay(key:          str,
                                       value:        'SettingType',
                                       contact_list: 'ContactList'
                                       ) -> None:
        """Validate setting value for traffic masking delays."""
        if key in ["tm_static_delay", "tm_random_delay"]:

            for key_, name, min_setting in [("tm_static_delay", "static", TRAFFIC_MASKING_MIN_STATIC_DELAY),
                                            ("tm_random_delay", "random", TRAFFIC_MASKING_MIN_RANDOM_DELAY)]:
                if key == key_ and value < min_setting:
                    raise SoftError(f"Error: Can't set {name} delay lower than {min_setting}.", head_clear=True)

            if contact_list.settings.software_operation == TX:
                m_print(["WARNING!", "Changing traffic masking delay can make your endpoint and traffic look unique!"],
                        bold=True, head=1, tail=1)

                if not yes("Proceed anyway?"):
                    raise SoftError("Aborted traffic masking setting change.", head_clear=True)

            m_print("Traffic masking setting will change on restart.", head=1, tail=1)

    def print_settings(self) -> None:
        """\
        Print list of settings, their current and
        default values, and setting descriptions.
        """
        desc_d = {
            # Common settings
            "disable_gui_dialog":            "True replaces GUI dialogs with CLI prompts",
            "max_number_of_group_members":   "Maximum number of members in a group",
            "max_number_of_groups":          "Maximum number of groups",
            "max_number_of_contacts":        "Maximum number of contacts",
            "log_messages_by_default":       "Default logging setting for new contacts/groups",
            "accept_files_by_default":       "Default file reception setting for new contacts",
            "show_notifications_by_default": "Default message notification setting for new contacts/groups",
            "log_file_masking":              "True hides real size of log file during traffic masking",
            "ask_password_for_log_access":   "False disables password prompt when viewing/exporting logs",

            # Transmitter settings
            "nc_bypass_messages":            "False removes Networked Computer bypass interrupt messages",
            "confirm_sent_files":            "False sends files without asking for confirmation",
            "double_space_exits":            "True exits, False clears screen with double space command",
            "traffic_masking":               "True enables traffic masking to hide metadata",
            "tm_static_delay":               "The static delay between traffic masking packets",
            "tm_random_delay":               "Max random delay for traffic masking timing obfuscation",

            # Relay settings
            "allow_contact_requests":        "When False, does not show TFC contact requests",

            # Receiver settings
            "new_message_notify_preview":    "When True, shows a preview of the received message",
            "new_message_notify_duration":   "Number of seconds new message notification appears",
            "max_decompress_size":           "Max size Receiver accepts when decompressing file"}

        # Columns
        c1 = ['Setting name']
        c2 = ['Current value']
        c3 = ['Default value']
        c4 = ['Description']

        terminal_width     = get_terminal_width()
        description_indent = 64

        if terminal_width < description_indent + 1:
            raise SoftError("Error: Screen width is too small.", head_clear=True)

        # Populate columns with setting data
        for key in self.defaults:
            c1.append(key)
            c2.append(str(self.__getattribute__(key)))
            c3.append(str(self.defaults[key]))

            description = desc_d[key]
            wrapper     = textwrap.TextWrapper(width=max(1, (terminal_width - description_indent)))
            desc_lines  = wrapper.fill(description).split('\n')
            desc_string = desc_lines[0]

            for line in desc_lines[1:]:
                desc_string += '\n' + description_indent * ' ' + line

            if len(desc_lines) > 1:
                desc_string += '\n'

            c4.append(desc_string)

        # Calculate column widths
        c1w, c2w, c3w = [max(len(v) for v in column) + SETTINGS_INDENT for column in [c1, c2, c3]]

        # Align columns by adding whitespace between fields of each line
        lines = [f'{f1:{c1w}} {f2:{c2w}} {f3:{c3w}} {f4}' for f1, f2, f3, f4 in zip(c1, c2, c3, c4)]

        # Add a terminal-wide line between the column names and the data
        lines.insert(1, get_terminal_width() * '─')

        # Print the settings
        clear_screen()
        print('\n' + '\n'.join(lines))
