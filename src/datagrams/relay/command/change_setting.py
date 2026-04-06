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

from datetime import datetime
from typing import Optional as O, TYPE_CHECKING

from src.common.statics import DatagramHeader, RelayCommand, SettingKey
from src.common.utils.validators import validate_bytes
from src.datagrams.datagram import DatagramRelayCommand

if TYPE_CHECKING:
    from src.common.statics import TFCSettingKey
    from src.common.types_custom import StrSettingValue


class DatagramRelayChangeSetting(DatagramRelayCommand):

    def __init__(self,
                 setting_key   : O['TFCSettingKey'],
                 setting_value : 'StrSettingValue | bytes'
                 ) -> None:
        """Create new RelayChangeSettingDatagram object."""
        self.__setting_key   = setting_key
        self.__setting_value = setting_value.encode() if isinstance(setting_value, str) else setting_value

    @property
    def setting_value(self) -> bytes:
        """Return the serialized setting value."""
        return self.__setting_value

    def to_txp_rep_bytes(self) -> bytes:
        """Serializes the datagram for transport from Transmitter Program to Relay Program."""
        if self.__setting_key is None:
            raise ValueError('Setting key is required for serialization.')

        relay_settings = {SettingKey.serial_error_correction : RelayCommand.SET_ERROR_CORRECTION,
                          SettingKey.serial_baudrate         : RelayCommand.SET_BAUDRATE,
                          SettingKey.allow_contact_requests  : RelayCommand.MANAGE_CONTACT_REQUESTS,
                          SettingKey.require_resends         : RelayCommand.SET_REQUIRE_RESENDS,
                          SettingKey.autoreplay_times        : RelayCommand.SET_AUTOREPLAY_TIMES,
                          SettingKey.autoreplay_loop         : RelayCommand.SET_AUTOREPLAY_LOOP}  # type: dict[str, bytes]

        setting_key_header_bytes = relay_settings[self.__setting_key]

        return DatagramHeader.RELAY_COMMAND.value + setting_key_header_bytes + self.__setting_value

    @classmethod
    def from_txp_rep_bytes(cls, timestamp: datetime, datagram_bytes: bytes) -> 'DatagramRelayChangeSetting':
        """Deserializes the datagram from `Transmitter Program to Relay Program` bytes."""
        validate_bytes(datagram_bytes, min_length=1)
        return DatagramRelayChangeSetting(None, datagram_bytes)
