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
import math

from typing import TYPE_CHECKING

from src.common.types_compound import BoolSettingLimits, BoolSettingValue, FloatSettingLimits, FloatSettingValue, \
    IntSettingLimits, IntSettingValue, TFCSettingValue
from src.common.types_custom import BoolFileReception, BoolLogMessages, BoolShowNotifications, BoolDisableGuiDialog, \
    IntMaxNumberOfGroupMembers, IntMaxNumberOfGroups, IntMaxNumberOfContacts, BoolLogFileMasking, \
    BoolAskPasswordForLogAccess, BoolNcBypassMessages, BoolConfirmTMFiles, BoolDoubleSpaceExits, BoolTrafficMasking, \
    BoolRequireResends, FloatTMStaticDelay, FloatTMRandomDelay, IntAutoreplayTimes, BoolAutoreplayLoop, \
    BoolAllowContactRequests, BoolNewMessageNotifyPreview, FloatNewMessageNotifyDuration, IntMaxDecompressSizeMB, \
    BoolReplaceDB
from src.database.database import TFCEncryptedDatabase
from src.common.utils.encoding import (bool_to_bytes, double_to_bytes, int_to_bytes,
                                       bytes_to_bool, bytes_to_double, bytes_to_int)
from src.common.utils.conversion import round_up
from src.common.exceptions import CriticalError, SoftError
from src.ui.common.input.get_yes import get_yes
from src.ui.common.output.print_message import print_message
from src.common.statics import (DBName,
                                FieldLength,
                                ProgramID,
                                SettingLimitsBool,
                                SettingLimitsFloat,
                                SettingLimitsInt,
                                TFCSettingKey)

if TYPE_CHECKING:
    from src.common.launch_args import LaunchArgumentsTCB
    from src.database.db_contacts import ContactList
    from src.database.db_groups import GroupList
    from src.database.db_masterkey import MasterKey


class Settings:
    """\
    Settings object stores user adjustable settings (excluding those
    related to serial interface) under an encrypted database.
    """

    SETTING_KEYS = (
        TFCSettingKey.DISABLE_GUI_DIALOG.value,
        TFCSettingKey.MAX_NUMBER_OF_GROUP_MEMBERS.value,
        TFCSettingKey.MAX_NUMBER_OF_GROUPS.value,
        TFCSettingKey.MAX_NUMBER_OF_CONTACTS.value,
        TFCSettingKey.LOG_MESSAGES_BY_DEFAULT.value,
        TFCSettingKey.ACCEPT_FILES_BY_DEFAULT.value,
        TFCSettingKey.SHOW_NOTIFICATIONS_BY_DEFAULT.value,
        TFCSettingKey.LOG_FILE_MASKING.value,
        TFCSettingKey.ASK_PASSWORD_FOR_LOG_ACCESS.value,
        TFCSettingKey.NC_BYPASS_MESSAGES.value,
        TFCSettingKey.CONFIRM_TM_FILES.value,
        TFCSettingKey.DOUBLE_SPACE_EXITS.value,
        TFCSettingKey.TRAFFIC_MASKING.value,
        TFCSettingKey.TM_STATIC_DELAY.value,
        TFCSettingKey.TM_RANDOM_DELAY.value,
        TFCSettingKey.REQUIRE_RESENDS.value,
        TFCSettingKey.AUTOREPLAY_TIMES.value,
        TFCSettingKey.AUTOREPLAY_LOOP.value,
        TFCSettingKey.ALLOW_CONTACT_REQUESTS.value,
        TFCSettingKey.NEW_MESSAGE_NOTIFY_PREVIEW.value,
        TFCSettingKey.NEW_MESSAGE_NOTIFY_DURATION.value,
        TFCSettingKey.MAX_DECOMPRESS_SIZE_MB.value,
    )

    BOOL_SETTING_KEYS: frozenset[TFCSettingKey] = frozenset({
        TFCSettingKey.DISABLE_GUI_DIALOG,
        TFCSettingKey.LOG_MESSAGES_BY_DEFAULT,
        TFCSettingKey.ACCEPT_FILES_BY_DEFAULT,
        TFCSettingKey.SHOW_NOTIFICATIONS_BY_DEFAULT,
        TFCSettingKey.LOG_FILE_MASKING,
        TFCSettingKey.ASK_PASSWORD_FOR_LOG_ACCESS,
        TFCSettingKey.NC_BYPASS_MESSAGES,
        TFCSettingKey.CONFIRM_TM_FILES,
        TFCSettingKey.DOUBLE_SPACE_EXITS,
        TFCSettingKey.TRAFFIC_MASKING,
        TFCSettingKey.REQUIRE_RESENDS,
        TFCSettingKey.AUTOREPLAY_LOOP,
        TFCSettingKey.ALLOW_CONTACT_REQUESTS,
        TFCSettingKey.NEW_MESSAGE_NOTIFY_PREVIEW,
    })

    INT_SETTING_KEYS: frozenset[TFCSettingKey] = frozenset({
        TFCSettingKey.MAX_NUMBER_OF_GROUP_MEMBERS,
        TFCSettingKey.MAX_NUMBER_OF_GROUPS,
        TFCSettingKey.MAX_NUMBER_OF_CONTACTS,
        TFCSettingKey.AUTOREPLAY_TIMES,
        TFCSettingKey.MAX_DECOMPRESS_SIZE_MB,
    })

    FLOAT_SETTING_KEYS: frozenset[TFCSettingKey] = frozenset({
        TFCSettingKey.TM_STATIC_DELAY,
        TFCSettingKey.TM_RANDOM_DELAY,
        TFCSettingKey.NEW_MESSAGE_NOTIFY_DURATION,
    })

    def __init__(self,
                 master_key       : 'MasterKey',
                 launch_arguments : 'LaunchArgumentsTCB'
                 ) -> None:
        """Create a new Settings object.

        The settings below are defaults, and are only to be altered from
        within the program itself. Changes made to the default settings
        are stored in the encrypted settings database, from which they
        are loaded when the program starts.
        """
        # ┌──────────────────┐
        # │ Default Settings │
        # └──────────────────┘

        # Shared settings
        self.disable_gui_dialog            = BoolDisableGuiDialog          (False)
        self.max_number_of_group_members   = IntMaxNumberOfGroupMembers    (300)
        self.max_number_of_groups          = IntMaxNumberOfGroups          (300)
        self.max_number_of_contacts        = IntMaxNumberOfContacts        (300)
        self.log_messages_by_default       = BoolLogMessages               (False)
        self.accept_files_by_default       = BoolFileReception             (False)
        self.show_notifications_by_default = BoolShowNotifications         (True)
        self.log_file_masking              = BoolLogFileMasking            (False)
        self.ask_password_for_log_access   = BoolAskPasswordForLogAccess   (True)

        # Transmitter settings
        self.nc_bypass_messages            = BoolNcBypassMessages          (False)
        self.confirm_tm_files              = BoolConfirmTMFiles            (True)
        self.double_space_exits            = BoolDoubleSpaceExits          (False)
        self.traffic_masking               = BoolTrafficMasking            (False)
        self.tm_static_delay               = FloatTMStaticDelay            (2.0)
        self.tm_random_delay               = FloatTMRandomDelay            (2.0)
        self.require_resends               = BoolRequireResends            (False)
        self.autoreplay_times              = IntAutoreplayTimes            (1)
        self.autoreplay_loop               = BoolAutoreplayLoop            (False)

        # Relay Settings
        self.allow_contact_requests        = BoolAllowContactRequests      (True)

        # Receiver settings
        self.new_message_notify_preview    = BoolNewMessageNotifyPreview   (False)
        self.new_message_notify_duration   = FloatNewMessageNotifyDuration (1.0)
        self.max_decompress_size_mb        = IntMaxDecompressSizeMB        (100)

        # ┌──────────────┐
        # │ Runtime Data │
        # └──────────────┘
        self.master_key         = master_key
        self.program_id         = launch_arguments.program_id
        self.program_name       = launch_arguments.program_name
        self.local_testing_mode = launch_arguments.local_test
        self.qubes              = launch_arguments.qubes

        self.__database = TFCEncryptedDatabase(DBName.SETTINGS, master_key, self.program_id)

        self.key_list = list(self.SETTING_KEYS)
        self.defaults = {key: self.get_setting_value(key) for key in self.key_list}

        if os.path.isfile(self.__database.path_to_db):
            self.load_settings()
        else:
            self.store_settings()

    @property
    def db_prefix(self) -> str:
        """Return the db prefix."""
        return self.program_id

    @staticmethod
    def normalize_setting_key(key: str | TFCSettingKey) -> TFCSettingKey:
        """Return a normalized settings enum value."""
        return key if isinstance(key, TFCSettingKey) else TFCSettingKey(key)

    def get_setting_value(self, key: str | TFCSettingKey) -> TFCSettingValue:
        """Return the current value of a setting."""
        match self.normalize_setting_key(key):
            case TFCSettingKey.DISABLE_GUI_DIALOG:            return self.disable_gui_dialog
            case TFCSettingKey.MAX_NUMBER_OF_GROUP_MEMBERS:   return self.max_number_of_group_members
            case TFCSettingKey.MAX_NUMBER_OF_GROUPS:          return self.max_number_of_groups
            case TFCSettingKey.MAX_NUMBER_OF_CONTACTS:        return self.max_number_of_contacts
            case TFCSettingKey.LOG_MESSAGES_BY_DEFAULT:       return self.log_messages_by_default
            case TFCSettingKey.ACCEPT_FILES_BY_DEFAULT:       return self.accept_files_by_default
            case TFCSettingKey.SHOW_NOTIFICATIONS_BY_DEFAULT: return self.show_notifications_by_default
            case TFCSettingKey.LOG_FILE_MASKING:              return self.log_file_masking
            case TFCSettingKey.ASK_PASSWORD_FOR_LOG_ACCESS:   return self.ask_password_for_log_access
            case TFCSettingKey.NC_BYPASS_MESSAGES:            return self.nc_bypass_messages
            case TFCSettingKey.CONFIRM_TM_FILES:              return self.confirm_tm_files
            case TFCSettingKey.DOUBLE_SPACE_EXITS:            return self.double_space_exits
            case TFCSettingKey.TRAFFIC_MASKING:               return self.traffic_masking
            case TFCSettingKey.TM_STATIC_DELAY:               return self.tm_static_delay
            case TFCSettingKey.TM_RANDOM_DELAY:               return self.tm_random_delay
            case TFCSettingKey.REQUIRE_RESENDS:               return self.require_resends
            case TFCSettingKey.AUTOREPLAY_TIMES:              return self.autoreplay_times
            case TFCSettingKey.AUTOREPLAY_LOOP:               return self.autoreplay_loop
            case TFCSettingKey.ALLOW_CONTACT_REQUESTS:        return self.allow_contact_requests
            case TFCSettingKey.NEW_MESSAGE_NOTIFY_PREVIEW:    return self.new_message_notify_preview
            case TFCSettingKey.NEW_MESSAGE_NOTIFY_DURATION:   return self.new_message_notify_duration
            case TFCSettingKey.MAX_DECOMPRESS_SIZE_MB:        return self.max_decompress_size_mb
        raise RuntimeError(f'Unknown setting key {key}')

    def set_setting_value(self, key: str | TFCSettingKey, value: TFCSettingValue) -> None:
        """Set a setting value using its explicit typed storage."""
        normalized_key = self.normalize_setting_key(key)

        if normalized_key in self.BOOL_SETTING_KEYS:
            self.set_bool_setting_value(normalized_key, self.to_bool_setting_value(normalized_key, bool(value)))
            return

        if normalized_key in self.INT_SETTING_KEYS:
            self.set_int_setting_value(normalized_key, self.to_int_setting_value(normalized_key, int(value)))
            return

        if normalized_key in self.FLOAT_SETTING_KEYS:
            self.set_float_setting_value(normalized_key, self.to_float_setting_value(normalized_key, float(value)))
            return

        raise RuntimeError(f'Unknown setting key {key}')

    def set_bool_setting_value(self, key: TFCSettingKey, value: BoolSettingValue) -> None:
        """Store a boolean setting value."""
        match key:
            case TFCSettingKey.DISABLE_GUI_DIALOG:            self.disable_gui_dialog            = BoolDisableGuiDialog       (bool(value))
            case TFCSettingKey.LOG_MESSAGES_BY_DEFAULT:       self.log_messages_by_default       = BoolLogMessages            (bool(value))
            case TFCSettingKey.ACCEPT_FILES_BY_DEFAULT:       self.accept_files_by_default       = BoolFileReception          (bool(value))
            case TFCSettingKey.SHOW_NOTIFICATIONS_BY_DEFAULT: self.show_notifications_by_default = BoolShowNotifications      (bool(value))
            case TFCSettingKey.LOG_FILE_MASKING:              self.log_file_masking              = BoolLogFileMasking         (bool(value))
            case TFCSettingKey.ASK_PASSWORD_FOR_LOG_ACCESS:   self.ask_password_for_log_access   = BoolAskPasswordForLogAccess(bool(value))
            case TFCSettingKey.NC_BYPASS_MESSAGES:            self.nc_bypass_messages            = BoolNcBypassMessages       (bool(value))
            case TFCSettingKey.CONFIRM_TM_FILES:              self.confirm_tm_files              = BoolConfirmTMFiles         (bool(value))
            case TFCSettingKey.DOUBLE_SPACE_EXITS:            self.double_space_exits            = BoolDoubleSpaceExits       (bool(value))
            case TFCSettingKey.TRAFFIC_MASKING:               self.traffic_masking               = BoolTrafficMasking         (bool(value))
            case TFCSettingKey.REQUIRE_RESENDS:               self.require_resends               = BoolRequireResends         (bool(value))
            case TFCSettingKey.AUTOREPLAY_LOOP:               self.autoreplay_loop               = BoolAutoreplayLoop         (bool(value))
            case TFCSettingKey.ALLOW_CONTACT_REQUESTS:        self.allow_contact_requests        = BoolAllowContactRequests   (bool(value))
            case TFCSettingKey.NEW_MESSAGE_NOTIFY_PREVIEW:    self.new_message_notify_preview    = BoolNewMessageNotifyPreview(bool(value))
            case _:                                           raise RuntimeError(f'Unknown bool setting key {key}')

    def set_int_setting_value(self, key: TFCSettingKey, value: IntSettingValue) -> None:
        """Store an integer setting value."""
        match key:
            case TFCSettingKey.MAX_NUMBER_OF_GROUP_MEMBERS: self.max_number_of_group_members = IntMaxNumberOfGroupMembers(int(value))
            case TFCSettingKey.MAX_NUMBER_OF_GROUPS:        self.max_number_of_groups        = IntMaxNumberOfGroups      (int(value))
            case TFCSettingKey.MAX_NUMBER_OF_CONTACTS:      self.max_number_of_contacts      = IntMaxNumberOfContacts    (int(value))
            case TFCSettingKey.AUTOREPLAY_TIMES:            self.autoreplay_times            = IntAutoreplayTimes        (int(value))
            case TFCSettingKey.MAX_DECOMPRESS_SIZE_MB:      self.max_decompress_size_mb      = IntMaxDecompressSizeMB    (int(value))
            case _:                                         raise RuntimeError(f'Unknown int setting key {key}')

    def set_float_setting_value(self, key: TFCSettingKey, value: FloatSettingValue) -> None:
        """Store a float setting value."""
        match key:
            case TFCSettingKey.TM_STATIC_DELAY:             self.tm_static_delay             = FloatTMStaticDelay           (float(value))
            case TFCSettingKey.TM_RANDOM_DELAY:             self.tm_random_delay             = FloatTMRandomDelay           (float(value))
            case TFCSettingKey.NEW_MESSAGE_NOTIFY_DURATION: self.new_message_notify_duration = FloatNewMessageNotifyDuration(float(value))
            case _:                                         raise RuntimeError(f'Unknown float setting key {key}')

    @staticmethod
    def parse_bool_value(value_str: str) -> bool:
        """Parse a boolean setting value."""
        try:
            return dict(true=True, false=False)[value_str.lower()]
        except KeyError as exc:
            raise SoftError(f"Error: Invalid setting value '{value_str}'.", clear_before=True) from exc

    @staticmethod
    def parse_int_value(value_str: str) -> int:
        """Parse an integer setting value."""
        try:
            return int(value_str)
        except ValueError as exc:
            raise SoftError(f"Error: Invalid setting value '{value_str}'.", clear_before=True) from exc

    @staticmethod
    def parse_float_value(value_str: str) -> float:
        """Parse a finite float setting value."""
        try:
            value = float(value_str)
        except ValueError as exc:
            raise SoftError(f"Error: Invalid setting value '{value_str}'.", clear_before=True) from exc

        if not math.isfinite(value):
            raise SoftError(f"Error: Invalid setting value '{value_str}'.", clear_before=True)

        return value

    @staticmethod
    def to_bool_setting_value(key: TFCSettingKey, value: bool) -> BoolSettingValue:
        """Convert a raw boolean to the setting-specific type."""
        match key:
            case TFCSettingKey.DISABLE_GUI_DIALOG:            return BoolDisableGuiDialog       (value)
            case TFCSettingKey.LOG_MESSAGES_BY_DEFAULT:       return BoolLogMessages            (value)
            case TFCSettingKey.ACCEPT_FILES_BY_DEFAULT:       return BoolFileReception          (value)
            case TFCSettingKey.SHOW_NOTIFICATIONS_BY_DEFAULT: return BoolShowNotifications      (value)
            case TFCSettingKey.LOG_FILE_MASKING:              return BoolLogFileMasking         (value)
            case TFCSettingKey.ASK_PASSWORD_FOR_LOG_ACCESS:   return BoolAskPasswordForLogAccess(value)
            case TFCSettingKey.NC_BYPASS_MESSAGES:            return BoolNcBypassMessages       (value)
            case TFCSettingKey.CONFIRM_TM_FILES:              return BoolConfirmTMFiles         (value)
            case TFCSettingKey.DOUBLE_SPACE_EXITS:            return BoolDoubleSpaceExits       (value)
            case TFCSettingKey.TRAFFIC_MASKING:               return BoolTrafficMasking         (value)
            case TFCSettingKey.REQUIRE_RESENDS:               return BoolRequireResends         (value)
            case TFCSettingKey.AUTOREPLAY_LOOP:               return BoolAutoreplayLoop         (value)
            case TFCSettingKey.ALLOW_CONTACT_REQUESTS:        return BoolAllowContactRequests   (value)
            case TFCSettingKey.NEW_MESSAGE_NOTIFY_PREVIEW:    return BoolNewMessageNotifyPreview(value)
            case _:                                           raise RuntimeError(f'Unknown bool setting key {key}')

    @staticmethod
    def to_int_setting_value(key: TFCSettingKey, value: int) -> IntSettingValue:
        """Convert a raw integer to the setting-specific type."""
        match key:
            case TFCSettingKey.MAX_NUMBER_OF_GROUP_MEMBERS: return IntMaxNumberOfGroupMembers(value)
            case TFCSettingKey.MAX_NUMBER_OF_GROUPS:        return IntMaxNumberOfGroups      (value)
            case TFCSettingKey.MAX_NUMBER_OF_CONTACTS:      return IntMaxNumberOfContacts    (value)
            case TFCSettingKey.AUTOREPLAY_TIMES:            return IntAutoreplayTimes        (value)
            case TFCSettingKey.MAX_DECOMPRESS_SIZE_MB:      return IntMaxDecompressSizeMB    (value)
            case _:                                         raise RuntimeError(f'Unknown int setting key {key}')

    @staticmethod
    def to_float_setting_value(key: TFCSettingKey, value: float) -> FloatSettingValue:
        """Convert a raw float to the setting-specific type."""
        match key:
            case TFCSettingKey.TM_STATIC_DELAY:             return FloatTMStaticDelay           (value)
            case TFCSettingKey.TM_RANDOM_DELAY:             return FloatTMRandomDelay           (value)
            case TFCSettingKey.NEW_MESSAGE_NOTIFY_DURATION: return FloatNewMessageNotifyDuration(value)
            case _:                                         raise RuntimeError(f'Unknown float setting key {key}')

    @staticmethod
    def get_bool_setting_limits() -> BoolSettingLimits:
        """Return the shared boolean setting bounds."""
        return SettingLimitsBool.MIN, SettingLimitsBool.MAX

    @staticmethod
    def get_int_setting_limits(key: TFCSettingKey) -> IntSettingLimits:
        """Return integer bounds for the specified setting."""
        match key:
            case TFCSettingKey.MAX_NUMBER_OF_GROUP_MEMBERS:
                return (SettingLimitsInt.MAX_NUMBER_OF_GROUP_MEMBERS_MIN,
                        SettingLimitsInt.MAX_NUMBER_OF_GROUP_MEMBERS_MAX)
            case TFCSettingKey.MAX_NUMBER_OF_GROUPS:
                return (SettingLimitsInt.MAX_NUMBER_OF_GROUPS_MIN,
                        SettingLimitsInt.MAX_NUMBER_OF_GROUPS_MAX)
            case TFCSettingKey.MAX_NUMBER_OF_CONTACTS:
                return (SettingLimitsInt.MAX_NUMBER_OF_CONTACTS_MIN,
                        SettingLimitsInt.MAX_NUMBER_OF_CONTACTS_MAX)
            case TFCSettingKey.AUTOREPLAY_TIMES:
                return (SettingLimitsInt.AUTOREPLAY_TIMES_MIN,
                        SettingLimitsInt.AUTOREPLAY_TIMES_MAX)
            case TFCSettingKey.MAX_DECOMPRESS_SIZE_MB:
                return (SettingLimitsInt.MAX_DECOMPRESS_SIZE_MB_MIN,
                        SettingLimitsInt.MAX_DECOMPRESS_SIZE_MB_MAX)
            case _:
                raise RuntimeError(f'Unknown int setting key {key}')

    @staticmethod
    def get_float_setting_limits(key: TFCSettingKey) -> FloatSettingLimits:
        """Return float bounds for the specified setting."""
        match key:
            case TFCSettingKey.TM_STATIC_DELAY:
                return (SettingLimitsFloat.TM_STATIC_DELAY_MIN,
                        SettingLimitsFloat.TM_STATIC_DELAY_MAX)
            case TFCSettingKey.TM_RANDOM_DELAY:
                return (SettingLimitsFloat.TM_RANDOM_DELAY_MIN,
                        SettingLimitsFloat.TM_RANDOM_DELAY_MAX)
            case TFCSettingKey.NEW_MESSAGE_NOTIFY_DURATION:
                return (SettingLimitsFloat.NEW_MESSAGE_NOTIFY_DURATION_MIN,
                        SettingLimitsFloat.NEW_MESSAGE_NOTIFY_DURATION_MAX)
            case _:
                raise RuntimeError(f'Unknown float setting key {key}')

    def _serialize_settings(self) -> bytes:
        """Serialize settings to constant-length plaintext."""
        attribute_list = [self.get_setting_value(key) for key in self.key_list]

        bytes_lst = []
        for a in attribute_list:
            if   isinstance(a, bool):  bytes_lst.append(bool_to_bytes  (a))
            elif isinstance(a, int):   bytes_lst.append(int_to_bytes   (a))
            elif isinstance(a, float): bytes_lst.append(double_to_bytes(a))
            else: raise CriticalError('Invalid attribute type in settings.')

        return b''.join(bytes_lst)

    def serialize(self) -> bytes:
        """Serialize settings for database storage."""
        return self._serialize_settings()

    def store_settings(self, replace: BoolReplaceDB = BoolReplaceDB(True)) -> None:
        """Store settings to an encrypted database.

        The plaintext in the encrypted database is a constant
        length bytestring regardless of stored setting values.
        """
        self.__database.store_database(self._serialize_settings(), replace)

    def invalid_setting(self,
                        key   : TFCSettingKey,
                        value : TFCSettingValue
                        ) -> None:
        """Reset an invalid persisted setting to its default value."""
        default_value = self.defaults[key.value]

        print_message([f"Error: Invalid value '{value}' for setting '{key.value}' in settings database.",
                       f'The value has been set to default ({default_value}).'],
                      padding_top    = 1,
                      padding_bottom = 1)
        self.set_setting_value(key, default_value)

    def load_settings(self) -> None:
        """Load settings from the encrypted database."""
        pt_bytes   = self.__database.load_database()
        rewrite_db = False

        # Update settings based on plaintext byte string content
        for key in self.key_list:
            normalized_key = self.normalize_setting_key(key)

            if normalized_key in self.BOOL_SETTING_KEYS:
                bool_value = self.to_bool_setting_value(normalized_key, bytes_to_bool(pt_bytes[0]))
                pt_bytes   = pt_bytes[FieldLength.ENCODED_BOOLEAN:]
                try:
                    self.validate_bool_setting_value(bool_value)
                except SoftError:
                    self.invalid_setting(normalized_key, bool_value)
                    rewrite_db = True
                else:
                    self.set_bool_setting_value(normalized_key, bool_value)

            elif normalized_key in self.INT_SETTING_KEYS:
                int_value = self.to_int_setting_value(normalized_key, bytes_to_int(pt_bytes[:FieldLength.ENCODED_INTEGER]))
                pt_bytes  = pt_bytes[FieldLength.ENCODED_INTEGER:]
                try:
                    self.validate_loaded_int_setting_value(normalized_key, int_value)
                except SoftError:
                    self.invalid_setting(normalized_key, int_value)
                    rewrite_db = True
                else:
                    self.set_int_setting_value(normalized_key, int_value)

            elif normalized_key in self.FLOAT_SETTING_KEYS:
                float_value = self.to_float_setting_value(normalized_key, bytes_to_double(pt_bytes[:FieldLength.ENCODED_FLOAT]))
                pt_bytes    = pt_bytes[FieldLength.ENCODED_FLOAT:]
                try:
                    self.validate_float_setting_value(normalized_key, float_value)
                except SoftError:
                    self.invalid_setting(normalized_key, float_value)
                    rewrite_db = True
                else:
                    self.set_float_setting_value(normalized_key, float_value)

            else:
                raise CriticalError('Invalid data type in settings default values.')

        if rewrite_db:
            self.store_settings()

    def change_setting(self,
                       key          : str,  # Name of the setting
                       value_str    : str,  # Value of the setting
                       contact_list : 'ContactList',
                       group_list   : 'GroupList'
                       ) -> None:
        """Parse, update and store new setting value."""
        normalized_key = self.normalize_setting_key(key)

        if normalized_key in self.BOOL_SETTING_KEYS:
            bool_value = self.to_bool_setting_value(normalized_key, self.parse_bool_value(value_str))
            self.validate_bool_setting_value(bool_value)
            self.set_bool_setting_value(normalized_key, bool_value)

        elif normalized_key in self.INT_SETTING_KEYS:
            int_value = self.to_int_setting_value(normalized_key, self.parse_int_value(value_str))
            self.validate_int_setting_value(normalized_key, int_value, contact_list, group_list)
            self.set_int_setting_value(normalized_key, int_value)

        elif normalized_key in self.FLOAT_SETTING_KEYS:
            float_value = self.to_float_setting_value(normalized_key, self.parse_float_value(value_str))
            self.validate_float_setting_value(normalized_key, float_value)
            self.validate_traffic_masking_delay_change(normalized_key)
            self.set_float_setting_value(normalized_key, float_value)

        else:
            raise CriticalError('Invalid attribute type in settings.')

        self.store_settings()

    @staticmethod
    def validate_bool_setting_value(value: BoolSettingValue) -> None:
        """Validate a parsed boolean setting value."""
        minimum, maximum = Settings.get_bool_setting_limits()
        if bool(value) not in (minimum.value, maximum.value):
            raise SoftError('Error: Invalid boolean setting value.', clear_before=True)

    @staticmethod
    def validate_int_setting_limit(key: TFCSettingKey, value: IntSettingValue) -> None:
        """Validate an integer setting against its configured bounds."""
        minimum, maximum = Settings.get_int_setting_limits(key)
        numeric_value    = int(value)
        if numeric_value < minimum.value or numeric_value > maximum.value:
            raise SoftError((f"Error: Value for setting '{key.value}' must be between "
                             f'{minimum.value} and {maximum.value}.'), clear_before=True)

    @staticmethod
    def validate_float_setting_value(key: TFCSettingKey, value: FloatSettingValue) -> None:
        """Validate a float setting against its configured bounds."""
        numeric_value = float(value)
        if not math.isfinite(numeric_value):
            raise SoftError(f"Error: Invalid value for setting '{key.value}'.", clear_before=True)

        minimum, maximum = Settings.get_float_setting_limits(key)
        if numeric_value < minimum.value or numeric_value > maximum.value:
            raise SoftError((f"Error: Value for setting '{key.value}' must be between "
                             f'{minimum.value} and {maximum.value}.'), clear_before=True)

    @staticmethod
    def validate_int_setting_value(key          : TFCSettingKey,
                                   value        : IntSettingValue,
                                   contact_list : 'ContactList',
                                   group_list   : 'GroupList'
                                   ) -> None:
        """Evaluate integer settings that have further restrictions."""
        Settings.validate_int_setting_limit(           key, value)
        Settings.validate_database_limit(              key, value)
        Settings.validate_max_number_of_group_members( key, value, group_list)
        Settings.validate_max_number_of_groups(        key, value, group_list)
        Settings.validate_max_number_of_contacts(      key, value, contact_list)

    @staticmethod
    def validate_loaded_int_setting_value(key   : TFCSettingKey,
                                          value : IntSettingValue
                                          ) -> None:
        """Validate integer settings loaded from persistent storage."""
        Settings.validate_int_setting_limit(key, value)
        Settings.validate_database_limit(key, value)

    @staticmethod
    def validate_database_limit(key: TFCSettingKey, value: IntSettingValue) -> None:
        """Validate setting values for database entry limits."""
        if key in {TFCSettingKey.MAX_NUMBER_OF_GROUP_MEMBERS,
                   TFCSettingKey.MAX_NUMBER_OF_GROUPS,
                   TFCSettingKey.MAX_NUMBER_OF_CONTACTS}:
            if int(value) % 10 != 0:
                raise SoftError('Error: Database padding settings must be divisible by 10.', clear_before=True)

    @staticmethod
    def validate_max_number_of_group_members(key        : TFCSettingKey,
                                             value      : IntSettingValue,
                                             group_list : 'GroupList'
                                             ) -> None:
        """Validate setting value for maximum number of group members."""
        if key == TFCSettingKey.MAX_NUMBER_OF_GROUP_MEMBERS:
            min_size = round_up(group_list.size_of_largest_group())
            if int(value) < min_size:
                raise SoftError(f"Error: Can't set the max number of members lower than {min_size}.", clear_before=True)

    @staticmethod
    def validate_max_number_of_groups(key        : TFCSettingKey,
                                      value      : IntSettingValue,
                                      group_list : 'GroupList'
                                      ) -> None:
        """Validate setting value for maximum number of groups."""
        if key == TFCSettingKey.MAX_NUMBER_OF_GROUPS:
            min_size = round_up(len(group_list))
            if int(value) < min_size:
                raise SoftError(f"Error: Can't set the max number of groups lower than {min_size}.", clear_before=True)

    @staticmethod
    def validate_max_number_of_contacts(key          : TFCSettingKey,
                                        value        : IntSettingValue,
                                        contact_list : 'ContactList'
                                        ) -> None:
        """Validate setting value for maximum number of contacts."""
        if key == TFCSettingKey.MAX_NUMBER_OF_CONTACTS:
            min_size = round_up(len(contact_list))
            if int(value) < min_size:
                raise SoftError(f"Error: Can't set the max number of contacts lower than {min_size}.", clear_before=True)

    def validate_traffic_masking_delay_change(self, key: TFCSettingKey) -> None:
        """Warn about traffic masking delay changes."""
        if key not in {TFCSettingKey.TM_STATIC_DELAY, TFCSettingKey.TM_RANDOM_DELAY}:
            return

        if self.program_id == ProgramID.TX:
            print_message(['WARNING!', 'Changing traffic masking delay can make your endpoint and traffic look unique!'],
                          bold=True, padding_top=1, padding_bottom=1)

            if not get_yes('Proceed anyway?'):
                raise SoftError('Aborted traffic masking setting change.', clear_before=True)

        print_message('Traffic masking setting will change on restart.', padding_top=1, padding_bottom=1)

    def rekey_to_temp_db(self, new_master_key: 'MasterKey') -> None:
        """Rekey the database to a temporary file."""
        self.__database.rekey_to_temp_db(new_master_key, self.serialize())

    def migrate_to_rekeyed_db(self) -> None:
        """Migrate to the rekeyed database."""
        self.__database.migrate_to_rekeyed_db()
