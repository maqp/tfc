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

from src.common.encoding import bool_to_bytes, int_to_bytes
from src.common.encoding import bytes_to_bool, bytes_to_int
from src.common.input    import yes
from src.common.misc     import calculate_race_condition_delay, calculate_serial_delays, ensure_dir
from src.common.statics  import *


class Settings(object):
    """Settings object stores NH side persistent settings.

    NH-side settings are not encrypted because NH is assumed to be in
    control of the adversary. Encryption would require password and
    because some users might use same password for NH and TxM/RxM,
    sensitive passwords might leak to remote attacker who might later
    physically compromise the endpoint.
    """

    def __init__(self, local_testing: bool, dd_sockets: bool, operation=NH) -> None:
        # Fixed settings
        self.relay_to_im_client      = True   # False stops forwarding messages to IM client

        # Controllable settings
        self.serial_usb_adapter      = True   # False uses system's integrated serial interface
        self.disable_gui_dialog      = False  # True replaces Tkinter dialogs with CLI prompts
        self.serial_baudrate         = 19200  # The speed of serial interface in bauds per second
        self.serial_error_correction = 5      # Number of byte errors serial datagrams can recover from

        self.software_operation = operation
        self.file_name          = '{}{}_settings'.format(DIR_USER_DATA, operation)

        # Settings from launcher / CLI arguments
        self.local_testing_mode = local_testing
        self.data_diode_sockets = dd_sockets

        ensure_dir(DIR_USER_DATA)
        if os.path.isfile(self.file_name):
            self.load_settings()
        else:
            self.setup()
            self.store_settings()

        # Following settings change only when program is restarted
        self.session_serial_error_correction = self.serial_error_correction
        self.session_serial_baudrate         = self.serial_baudrate
        self.race_condition_delay            = calculate_race_condition_delay(self)

        self.receive_timeout, self.transmit_delay = calculate_serial_delays(self.session_serial_baudrate)

    def store_settings(self) -> None:
        """Store persistent settings to file."""
        setting_data  = int_to_bytes(self.serial_baudrate)
        setting_data += int_to_bytes(self.serial_error_correction)
        setting_data += bool_to_bytes(self.serial_usb_adapter)
        setting_data += bool_to_bytes(self.disable_gui_dialog)

        ensure_dir(DIR_USER_DATA)
        with open(self.file_name, 'wb+') as f:
            f.write(setting_data)

    def load_settings(self) -> None:
        """Load persistent settings from file."""
        with open(self.file_name, 'rb') as f:
            settings = f.read()

        self.serial_baudrate         = bytes_to_int(settings[0:8])
        self.serial_error_correction = bytes_to_int(settings[8:16])
        self.serial_usb_adapter      = bytes_to_bool(settings[16:17])
        self.disable_gui_dialog      = bytes_to_bool(settings[17:18])

    def setup(self) -> None:
        """Prompt user to enter initial settings."""
        if not self.local_testing_mode:
            self.serial_usb_adapter = yes("Does NH use USB-to-serial/TTL adapter?", tail=1)
