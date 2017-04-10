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

import os
import serial
import sys
import time
import typing

from src.common.errors  import FunctionReturn
from src.common.path    import ask_path_gui
from src.common.statics import *
from src.nh.misc        import c_print, clear_screen

if typing.TYPE_CHECKING:
    from multiprocessing import Queue
    from src.nh.settings import Settings


def nh_command(settings: 'Settings',
               q_to_nh:  'Queue',
               q_to_rxm: 'Queue',
               q_im_cmd: 'Queue',
               file_no:  int  # stdin input file descriptor
               ) -> None:
    """Process NH side commands."""

    sys.stdin = os.fdopen(file_no)

    while True:
        try:
            if q_to_nh.empty():
                time.sleep(0.001)
                continue
            command = q_to_nh.get()
            header  = command[:2]

            if header in [UNENCRYPTED_SCREEN_CLEAR, UNENCRYPTED_SCREEN_RESET]:
                # Handle race condition with RxM command notification
                time.sleep(0.1)
                if settings.local_testing_mode and settings.data_diode_sockets:
                    time.sleep(0.7)

            if header == UNENCRYPTED_SCREEN_CLEAR:
                q_im_cmd.put(command)
                clear_screen()

            if header == UNENCRYPTED_SCREEN_RESET:
                q_im_cmd.put(command)
                os.system('reset')

            if header == UNENCRYPTED_EXIT_COMMAND:
                exit()

            if header == UNENCRYPTED_EC_RATIO:
                value = eval(command[2:])

                if not isinstance(value, int) or value < 1:
                    c_print("Error: Received Invalid EC ratio value from TxM.")
                    continue

                settings.e_correction_ratio = value
                settings.store_settings()
                c_print("Error correction ratio will change on restart.", head=1, tail=1)

            if header == UNENCRYPTED_BAUDRATE:
                value = eval(command[2:])

                if not isinstance(value, int) or value not in serial.Serial.BAUDRATES:
                    c_print("Error: Received invalid baud rate value from TxM.")
                    continue

                settings.serial_iface_speed = value
                settings.store_settings()
                c_print("Baud rate will change on restart.", head=1, tail=1)

            if header == UNENCRYPTED_IMPORT_COMMAND:
                f_path = ask_path_gui("Select file to import...", settings, get_file=True)
                with open(f_path, 'rb') as f:
                    f_data = f.read()
                q_to_rxm.put(IMPORTED_FILE_CT_HEADER + f_data)

            if header == UNENCRYPTED_GUI_DIALOG:
                value = eval(command[2:])

                settings.disable_gui_dialog = value
                settings.store_settings()

                c_print("Changed setting disable_gui_dialog to {}.".format(value), head=1, tail=1)

        except (KeyboardInterrupt, EOFError, FunctionReturn):
            pass
