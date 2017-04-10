#!/usr/bin/env python3.5
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

import os.path
import struct

from typing import Union

from src.common.misc    import ensure_dir
from src.common.statics import *
from src.nh.misc        import yes


def bool_to_bytes(boolean: bool) -> bytes:
    """Convert boolean value to 1-byte byte string."""
    return bytes([boolean])


def int_to_bytes(integer: int) -> bytes:
    """Convert integer to 8-byte byte string."""
    return struct.pack('!Q', integer)


def bytes_to_bool(byte_string: Union[bytes, int]) -> bool:
    """Convert 1-byte byte string to boolean value."""
    if isinstance(byte_string, bytes):
        byte_string = byte_string[0]
    return bool(byte_string)


def bytes_to_int(byte_string: bytes) -> int:
    """Convert 8-byte byte string to integer."""
    return struct.unpack('!Q', byte_string)[0]


class Settings(object):
    """Settings object stores NH side persistent settings

    NH-side settings are not encrypted because NH is assumed to be in
    control of the adversary. Encryption would require password and
    because some users might use same password for NH and TxM/RxM,
    sensitive passwords might leak to remote attacker who might later
    physically compromise the endpoint.
    """

    def __init__(self, local_testing: bool, dd_sockets: bool, operation='nh') -> None:

        # Settings from launcher / CLI arguments
        self.local_testing_mode = local_testing
        self.data_diode_sockets = dd_sockets

        self.t_fmt = "%m-%d / %H:%M:%S"  # Timestamp format of displayed messages
        self.disable_gui_dialog = False  # When True, only uses CLI prompts for RxM file imports
        self.relay_to_im_client = True   # False stops sending messages to IM client
        self.serial_usb_adapter = True   # Number of USB-to-serial adapters used (0, 1 or 2)
        self.serial_iface_speed = 19200  # The speed of serial interface in bauds per sec
        self.e_correction_ratio = 5      # N/o byte errors serial datagrams can recover from

        self.software_operation = operation
        self.file_name          = '{}/{}_settings'.format(DIR_USER_DATA, operation)

        if os.path.isfile(self.file_name):
            self.load_settings()
        else:
            self.setup()
            self.store_settings()
        self.session_ec_ratio = self.e_correction_ratio
        self.session_if_speed = self.serial_iface_speed

    def load_settings(self) -> None:
        """Load persistent settings from file."""
        ensure_dir('{}/'.format(DIR_USER_DATA))
        settings = open(self.file_name, 'rb').read()
        self.serial_iface_speed = bytes_to_int(settings[0:8])
        self.e_correction_ratio = bytes_to_int(settings[8:16])
        self.serial_usb_adapter = bytes_to_bool(settings[16:17])
        self.disable_gui_dialog = bytes_to_bool(settings[17:18])

    def store_settings(self) -> None:
        """Store persistent settings to file."""
        setting_data  = int_to_bytes(self.serial_iface_speed)
        setting_data += int_to_bytes(self.e_correction_ratio)
        setting_data += bool_to_bytes(self.serial_usb_adapter)
        setting_data += bool_to_bytes(self.disable_gui_dialog)
        ensure_dir('{}/'.format(DIR_USER_DATA))
        open(self.file_name, 'wb+').write(setting_data)

    def setup(self) -> None:
        """Prompt user to enter initial settings."""
        if not self.local_testing_mode:
            self.serial_usb_adapter = yes("Does NH use USB-to-serial/TTL adapter?", tail=1)
