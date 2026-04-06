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

import json
import os

from typing import Any

import serial

from src.common.exceptions import SoftError, CriticalError
from src.common.launch_args import LaunchArgumentsTCB, LaunchArgumentsRelay
from src.common.reed_solomon import RSCodec
from src.common.statics import (CompoundFieldLength, DataDir, ProgramID, ProgramName, SettingLimitsBool,
                                SettingLimitsInt, SerialLiterals, TFCSettingKey)
from src.common.types_compound import (BoolSettingLimits, BoolSettingValue, GatewaySettingValue, IntSettingLimits,
                                       IntSettingValue, StrSettingValueDB)
from src.common.types_custom import (IntSerialBaudrate, IntSerialErrorCorrection, BoolUseSerialUSBAdapter,
                                     StrBuiltInSerialInterface, FloatTxInterPacketDelay, FloatRxReceiveTimeout)
from src.common.utils.io import ensure_dir
from src.ui.common.input.get_yes import get_yes
from src.ui.common.output.print_message import print_message


class GatewaySettings:
    """\
    Gateway settings store settings for serial interface in an
    unencrypted JSON database.

    The reason these settings are in plaintext is it protects the system
    from an inconsistent serial setting state: Would the user change one
    or more settings of their serial interfaces, and would the setting
    adjusting packet to Receiver Program drop, Relay Program could in
    some situations no longer communicate with the Receiver Program.

    Serial interface settings are not sensitive enough to justify the
    inconveniences that would result from encrypting the setting values.
    """

    SETTING_KEYS = (
        'serial_baudrate',
        'serial_error_correction',
        'use_serial_usb_adapter',
        'built_in_serial_interface',
    )

    BOOL_SETTING_KEYS : frozenset[str] = frozenset({'use_serial_usb_adapter'})
    INT_SETTING_KEYS  : frozenset[str] = frozenset({'serial_baudrate', 'serial_error_correction'})
    STR_SETTING_KEYS  : frozenset[str] = frozenset({'built_in_serial_interface'})

    def __init__(self, launch_arguments: 'LaunchArgumentsTCB|LaunchArgumentsRelay') -> None:
        """Create a new Settings object.

        The settings below are altered from within the program itself.
        Changes made to the default settings are stored in the JSON
        file under $HOME/tfc/user_data from where, if needed, they can
        be manually altered by the user.
        """
        self.serial_baudrate           = IntSerialBaudrate        (19200)
        self.serial_error_correction   = IntSerialErrorCorrection (5)
        self.use_serial_usb_adapter    = BoolUseSerialUSBAdapter  (True)
        self.built_in_serial_interface = StrBuiltInSerialInterface('ttyS0')

        self.program_id         = launch_arguments.program_id
        self.local_testing_mode = launch_arguments.local_test
        self.data_diode_sockets = launch_arguments.data_diode_sockets
        self.qubes              = launch_arguments.qubes

        self.key_list = list(self.SETTING_KEYS)
        self.defaults = {key: self.get_setting_value(key) for key in self.key_list}

        self.file_name = f'{DataDir.USER_DATA}/{self.program_id}_serial_settings.json'

        ensure_dir(DataDir.USER_DATA.value)
        if os.path.isfile(self.file_name):
            self.load_settings()
        else:
            self.setup()
            self.store_settings()

        self.session_serial_baudrate         = self.serial_baudrate
        self.session_serial_error_correction = self.serial_error_correction
        self.session_usb_serial_adapter      = self.use_serial_usb_adapter

        self.tx_inter_packet_delay, self.rx_receive_timeout = self.calculate_serial_delays(self.session_serial_baudrate)

        self.race_condition_delay = self.calculate_race_condition_delay(self.session_serial_error_correction,
                                                                        self.serial_baudrate)

    @classmethod
    def calculate_serial_delays(cls, baud_rate: IntSerialBaudrate) -> tuple[FloatTxInterPacketDelay,
                                                                            FloatRxReceiveTimeout]:
        """Calculate the inter-packet delay and receive timeout.

        Although this calculation mainly depends on the baud rate, a
        minimal value will be set for rx_receive_timeout. This is to
        ensure high baud rates do not cause issues by having shorter
        delays than what the `time.sleep()` resolution allows.
        """
        bytes_per_sec = baud_rate / SerialLiterals.BAUDS_PER_BYTE.value
        byte_travel_t = 1 / bytes_per_sec

        rx_receive_timeout    = FloatRxReceiveTimeout(max(2 * byte_travel_t, SerialLiterals.SERIAL_RX_MIN_TIMEOUT.value))
        tx_inter_packet_delay = FloatTxInterPacketDelay(2 * rx_receive_timeout)

        return tx_inter_packet_delay, rx_receive_timeout

    def setup(self) -> None:
        """Prompt the user to enter initial serial interface setting.

        Ensure that the serial interface is available before proceeding.
        """
        if not self.local_testing_mode and not self.qubes:
            name = {ProgramID.TX : ProgramName.TRANSMITTER.value,
                    ProgramID.NC : ProgramName.RELAY.value,
                    ProgramID.RX : ProgramName.RECEIVER.value
                    }[self.program_id]

            self.use_serial_usb_adapter = BoolUseSerialUSBAdapter(get_yes(f'Use USB-to-serial/TTL adapter for {name} Computer?', head=1, tail=1))

            if self.use_serial_usb_adapter:
                for f in sorted(os.listdir('/dev/')):
                    if f.startswith('ttyUSB'):
                        return None
                print_message('Error: USB-to-serial/TTL adapter not found.')
                self.setup()
            else:
                if self.built_in_serial_interface not in sorted(os.listdir('/dev/')):
                    print_message(f'Error: Serial interface /dev/{self.built_in_serial_interface} not found.')
                    self.setup()
        return None

    @staticmethod
    def normalize_tfc_setting_key(key: str) -> TFCSettingKey:
        """Normalize a gateway key that is shared with TFC settings."""
        return TFCSettingKey(key)

    def get_setting_value(self, key: str) -> GatewaySettingValue:
        """Return the current value of a serial setting."""
        if key == 'serial_baudrate':           return self.serial_baudrate
        if key == 'serial_error_correction':   return self.serial_error_correction
        if key == 'use_serial_usb_adapter':    return self.use_serial_usb_adapter
        if key == 'built_in_serial_interface': return self.built_in_serial_interface
        raise KeyError(key)

    def set_setting_value(self, key: str, value: GatewaySettingValue) -> None:
        """Set a serial setting through explicit attribute access."""
        if key in self.BOOL_SETTING_KEYS:
            self.set_bool_setting_value(key, self.to_bool_setting_value(key, bool(value)))
            return

        if key in self.INT_SETTING_KEYS:
            self.set_int_setting_value(key, self.to_int_setting_value(key, int(value)))
            return

        if key in self.STR_SETTING_KEYS:
            self.set_str_setting_value(key, StrBuiltInSerialInterface(str(value)))
            return

        raise KeyError(key)

    def set_bool_setting_value(self, key: str, value: BoolSettingValue) -> None:
        """Store a boolean gateway setting value."""
        if key == 'use_serial_usb_adapter':
            self.use_serial_usb_adapter = BoolUseSerialUSBAdapter(bool(value))
            return
        raise KeyError(key)

    def set_int_setting_value(self, key: str, value: IntSettingValue) -> None:
        """Store an integer gateway setting value."""
        if key == 'serial_baudrate':
            self.serial_baudrate = IntSerialBaudrate(int(value))
            return
        if key == 'serial_error_correction':
            self.serial_error_correction = IntSerialErrorCorrection(int(value))
            return
        raise KeyError(key)

    def set_str_setting_value(self, key: str, value: StrSettingValueDB) -> None:
        """Store a string gateway setting value."""
        if key == 'built_in_serial_interface':
            self.built_in_serial_interface = StrBuiltInSerialInterface(str(value))
            return
        raise KeyError(key)

    @staticmethod
    def parse_bool_value(value_str: str) -> bool:
        """Parse a boolean gateway setting value."""
        try:
            return dict(true=True, false=False)[value_str.lower()]
        except KeyError as exc:
            raise SoftError(f"Error: Invalid setting value '{value_str}'.", clear_delay=1, clear_after=True) from exc

    @staticmethod
    def parse_int_value(value_str: str) -> int:
        """Parse an integer gateway setting value."""
        try:
            return int(value_str)
        except ValueError as exc:
            raise SoftError(f"Error: Invalid setting value '{value_str}'.", clear_delay=1, clear_after=True) from exc

    @staticmethod
    def to_bool_setting_value(key: str, value: bool) -> BoolSettingValue:
        """Convert a raw boolean to the gateway setting-specific type."""
        if key == 'use_serial_usb_adapter':
            return BoolUseSerialUSBAdapter(value)
        raise KeyError(key)

    def to_int_setting_value(self, key: str, value: int) -> IntSettingValue:
        """Convert a raw integer to the gateway setting-specific type."""
        normalized_key = self.normalize_tfc_setting_key(key)
        if normalized_key == TFCSettingKey.SERIAL_BAUDRATE:         return IntSerialBaudrate(value)
        if normalized_key == TFCSettingKey.SERIAL_ERROR_CORRECTION: return IntSerialErrorCorrection(value)
        raise KeyError(key)

    @staticmethod
    def get_bool_setting_limits() -> BoolSettingLimits:
        """Return the shared boolean setting bounds."""
        return SettingLimitsBool.MIN, SettingLimitsBool.MAX

    def get_int_setting_limits(self, key: str) -> IntSettingLimits:
        """Return integer bounds for the specified gateway setting."""
        normalized_key = self.normalize_tfc_setting_key(key)
        if normalized_key == TFCSettingKey.SERIAL_BAUDRATE:         return SettingLimitsInt.SERIAL_BAUDRATE_MIN,         SettingLimitsInt.SERIAL_BAUDRATE_MAX
        if normalized_key == TFCSettingKey.SERIAL_ERROR_CORRECTION: return SettingLimitsInt.SERIAL_ERROR_CORRECTION_MIN, SettingLimitsInt.SERIAL_ERROR_CORRECTION_MAX
        raise KeyError(key)

    def to_dict(self) -> dict[str, bool | int | str]:
        """Return the persisted serial settings as a plain dictionary."""
        return {key: self.get_setting_value(key) for key in self.key_list}

    def store_settings(self) -> None:
        """Store serial settings in JSON format."""
        serialized = json.dumps(self.to_dict(), indent=4)

        with open(self.file_name, 'w+') as f:
            f.write(serialized)
            f.flush()
            os.fsync(f.fileno())

    def invalid_setting(self,
                        key       : str,
                        json_dict : dict[str, bool|int|str]
                        ) -> None:
        """Notify about setting an invalid value to default value."""
        print_message([f"Error: Invalid value '{json_dict[key]}' for setting '{key}' in '{self.file_name}'.",
                 f'The value has been set to default ({self.defaults[key]}).'], padding_top=1, padding_bottom=1)
        self.set_setting_value(key, self.defaults[key])

    def load_settings(self) -> None:
        """Load and validate JSON settings for serial interface."""
        with open(self.file_name) as f:
            try:
                json_dict = json.load(f)
            except json.decoder.JSONDecodeError:
                os.remove(self.file_name)
                self.store_settings()
                print(f"\nError: Invalid JSON format in '{self.file_name}'."
                       '\nSerial interface settings have been set to default values.\n')
                return None

        # Check for missing setting
        self.check_missing_settings(json_dict)

        # Store after loading to add missing, to replace invalid settings,
        # and to remove settings that do not belong in the JSON file.
        self.store_settings()
        return None

    def check_missing_settings(self, json_dict: Any) -> None:
        """Check for missing JSON fields and invalid values."""
        for key in self.key_list:
            try:
                self.check_key_in_key_store(key, json_dict)
                if   key == 'serial_baudrate':           self.validate_serial_baudrate         (key, json_dict)
                elif key == 'serial_error_correction':   self.validate_serial_error_correction (key, json_dict)
                elif key == 'use_serial_usb_adapter':    self.validate_serial_usb_adapter_value(key, json_dict)
                elif key == 'built_in_serial_interface': self.validate_serial_interface_value  (key, json_dict)
            except SoftError:
                continue

            self.set_setting_value(key, json_dict[key])

    def check_key_in_key_store(self, key: str, json_dict: Any) -> None:
        """Check if the setting's key value is in the setting dictionary."""
        if key not in json_dict:
            print_message([f"Error: Missing setting '{key}' in '{self.file_name}'.",
                     f'The value has been set to default ({self.defaults[key]}).'], padding_top=1, padding_bottom=1)
            self.set_setting_value(key, self.defaults[key])
            raise SoftError('Missing key', output=False)

    def validate_serial_usb_adapter_value(self, key: str, json_dict: Any) -> None:
        """Validate the serial usb adapter setting value."""
        if not isinstance(json_dict[key], bool):
            self.invalid_setting(key, json_dict)
            raise SoftError('Invalid value', output=False)
        self.validate_bool_setting_value(BoolUseSerialUSBAdapter(json_dict[key]))

    def validate_serial_baudrate(self, key: str, json_dict: Any) -> None:
        """Validate the serial baudrate setting value."""
        if not isinstance(json_dict[key], int) or isinstance(json_dict[key], bool):
            self.invalid_setting(key, json_dict)
            raise SoftError('Invalid value', output=False)

        try:
            self.validate_serial_baudrate_value(IntSerialBaudrate(json_dict[key]))
        except SoftError:
            self.invalid_setting(key, json_dict)
            raise SoftError('Invalid value', output=False)

    def validate_serial_error_correction(self, key: str, json_dict: Any) -> None:
        """Validate the serial error correction setting value."""
        if not isinstance(json_dict[key], int) or isinstance(json_dict[key], bool):
            self.invalid_setting(key, json_dict)
            raise SoftError('Invalid value', output=False)

        try:
            self.validate_serial_error_correction_value(IntSerialErrorCorrection(json_dict[key]))
        except SoftError:
            self.invalid_setting(key, json_dict)
            raise SoftError('Invalid value', output=False)

    def validate_serial_interface_value(self, key: str, json_dict: Any) -> None:
        """Validate the serial interface setting value."""
        if not isinstance(json_dict[key], str):
            self.invalid_setting(key, json_dict)
            raise SoftError('Invalid value', output=False)

        if not any(json_dict[key] == f for f in os.listdir('/sys/class/tty')):
            self.invalid_setting(key, json_dict)
            raise SoftError('Invalid value', output=False)

    def change_setting(self, key: str, value_str: str) -> None:
        """Parse, update and store new setting value."""
        if key in self.BOOL_SETTING_KEYS:
            bool_value = self.to_bool_setting_value(key, self.parse_bool_value(value_str))
            self.validate_bool_setting_value(bool_value)
            self.set_bool_setting_value(key, bool_value)

        elif key in self.INT_SETTING_KEYS:
            int_value = self.to_int_setting_value(key, self.parse_int_value(value_str))
            self.validate_int_setting_value(key, int_value)
            self.set_int_setting_value(key, int_value)

        else:
            raise CriticalError('Invalid attribute type in settings.')

        self.store_settings()

    @staticmethod
    def validate_bool_setting_value(value: BoolSettingValue) -> None:
        """Validate a boolean gateway setting."""
        minimum, maximum = GatewaySettings.get_bool_setting_limits()
        if bool(value) not in (minimum.value, maximum.value):
            raise SoftError('Error: Invalid boolean setting value.', clear_delay=1, clear_after=True)

    def validate_int_setting_limit(self, key: str, value: IntSettingValue) -> None:
        """Validate an integer gateway setting against configured bounds."""
        minimum, maximum = self.get_int_setting_limits(key)
        numeric_value    = int(value)
        if numeric_value < minimum.value or numeric_value > maximum.value:
            raise SoftError((f"Error: Value for setting '{key}' must be between "
                             f'{minimum.value} and {maximum.value}.'), clear_delay=1, clear_after=True)

    def validate_serial_baudrate_value(self, value: IntSerialBaudrate) -> None:
        """Validate the serial baudrate setting value."""
        self.validate_int_setting_limit(TFCSettingKey.SERIAL_BAUDRATE.value, value)
        if int(value) not in serial.Serial().BAUDRATES:
            raise SoftError('Error: The specified baud rate is not supported.', clear_delay=1, clear_after=True)

    def validate_serial_error_correction_value(self, value: IntSerialErrorCorrection) -> None:
        """Validate the serial error correction setting value."""
        self.validate_int_setting_limit(TFCSettingKey.SERIAL_ERROR_CORRECTION.value, value)

    def validate_int_setting_value(self, key: str, value: IntSettingValue) -> None:
        """Validate integer gateway settings and show restart notices."""
        if key == TFCSettingKey.SERIAL_BAUDRATE.value:
            self.validate_serial_baudrate_value(IntSerialBaudrate(int(value)))
            print_message('Baud rate will change on restart.', padding_top=1, padding_bottom=1)
            return

        if key == TFCSettingKey.SERIAL_ERROR_CORRECTION.value:
            self.validate_serial_error_correction_value(IntSerialErrorCorrection(int(value)))
            print_message('Error correction ratio will change on restart.', padding_top=1, padding_bottom=1)
            return

        raise KeyError(key)

    @staticmethod
    def calculate_race_condition_delay(serial_error_correction : IntSerialErrorCorrection,
                                       serial_baudrate         : IntSerialBaudrate
                                       ) -> float:
        """\
        Calculate the delay required to prevent Relay Program race condition.

        When Transmitter Program outputs a command to exit or wipe data,
        Relay program will also receive a copy of the command. If the Relay
        Program acts on the command too early, the Receiver Program will not
        receive the exit/wipe command at all.

        This function calculates the delay Transmitter Program should wait
        before outputting command to the Relay Program, to ensure the
        Receiver Program has received its encrypted command.
        """
        rs                = RSCodec(2 * serial_error_correction)
        packet_length     = CompoundFieldLength.PACKET.value
        enc_packet_length = len(rs.encode(os.urandom(packet_length)))
        enc_cmd_length    = len(rs.encode(os.urandom(CompoundFieldLength.COMMAND_DATAGRAM.value)))
        max_bytes         = enc_packet_length + (2 * enc_cmd_length)

        return (max_bytes * SerialLiterals.BAUDS_PER_BYTE.value) / serial_baudrate
