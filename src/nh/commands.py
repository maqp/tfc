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

from typing import Any, Dict

from src.common.exceptions import FunctionReturn
from src.common.misc       import ignored
from src.common.output     import c_print, clear_screen
from src.common.path       import ask_path_gui
from src.common.statics    import *

if typing.TYPE_CHECKING:
    from multiprocessing import Queue
    from src.nh.settings import Settings


def nh_command(queues:   Dict[bytes, 'Queue'],
               settings: 'Settings',
               stdin_fd: int,
               unittest: bool = False) -> None:
    """Loop that processes NH side commands."""
    sys.stdin      = os.fdopen(stdin_fd)
    queue_from_txm = queues[TXM_TO_NH_QUEUE]

    while True:
        with ignored(EOFError, FunctionReturn, KeyboardInterrupt):
            while queue_from_txm.qsize() == 0:
                time.sleep(0.01)

            command = queue_from_txm.get()
            process_command(settings, command, queues)

            if unittest:
                break


def process_command(settings: 'Settings', command: bytes, queues: Dict[bytes, 'Queue']) -> None:
    """Process received command."""
    #             Keyword                      Function to run   (                  Parameters                  )
    #             -----------------------------------------------------------------------------------------------
    function_d = {UNENCRYPTED_SCREEN_CLEAR:   (clear_windows,     settings, command, queues[NH_TO_IM_QUEUE]     ),
                  UNENCRYPTED_SCREEN_RESET:   (reset_windows,     settings, command, queues[NH_TO_IM_QUEUE]     ),
                  UNENCRYPTED_EXIT_COMMAND:   (exit_tfc,          settings,          queues[EXIT_QUEUE]         ),
                  UNENCRYPTED_WIPE_COMMAND:   (wipe, settings,                       queues[EXIT_QUEUE]         ),
                  UNENCRYPTED_IMPORT_COMMAND: (rxm_import,        settings,          queues[RXM_OUTGOING_QUEUE] ),
                  UNENCRYPTED_EC_RATIO:       (change_ec_ratio,   settings, command                             ),
                  UNENCRYPTED_BAUDRATE:       (change_baudrate,   settings, command                             ),
                  UNENCRYPTED_GUI_DIALOG:     (change_gui_dialog, settings, command                             )}  # type: Dict[bytes, Any]

    header = command[:2]

    if header not in function_d:
        raise FunctionReturn("Error: Received an invalid command.")

    from_dict  = function_d[header]
    func       = from_dict[0]
    parameters = from_dict[1:]
    func(*parameters)


def race_condition_delay(settings: 'Settings') -> None:
    """Handle race condition with RxM command notification."""
    if settings.local_testing_mode:
        time.sleep(0.1)
        if settings.data_diode_sockets:
            time.sleep(1)

def clear_windows(settings: 'Settings', command: bytes, queue_to_im: 'Queue') -> None:
    """Clear NH screen and IM client window."""
    race_condition_delay(settings)
    queue_to_im.put(command)
    clear_screen()


def reset_windows(settings: 'Settings', command: bytes, queue_to_im: 'Queue') -> None:
    """Reset NH screen and clear IM client window."""
    race_condition_delay(settings)
    queue_to_im.put(command)
    os.system('reset')


def exit_tfc(settings: 'Settings', queue_exit: 'Queue') -> None:
    """Exit TFC."""
    race_condition_delay(settings)
    queue_exit.put(EXIT)


def rxm_import(settings: 'Settings', queue_to_rxm: 'Queue') -> None:
    """Import encrypted file to RxM."""
    f_path = ask_path_gui("Select file to import...", settings, get_file=True)
    with open(f_path, 'rb') as f:
        f_data = f.read()
    queue_to_rxm.put(IMPORTED_FILE_HEADER + f_data)


def change_ec_ratio(settings: 'Settings', command: bytes) -> None:
    """Change Reed-Solomon erasure code correction ratio setting on NH."""
    try:
        value = int(command[2:])
        if value < 1 or value > 2 ** 64 - 1:
            raise ValueError
    except ValueError:
        raise FunctionReturn("Error: Received invalid EC ratio value from TxM.")

    settings.serial_error_correction = value
    settings.store_settings()
    c_print("Error correction ratio will change on restart.", head=1, tail=1)


def change_baudrate(settings: 'Settings', command: bytes) -> None:
    """Change serial interface baud rate setting on NH."""
    try:
        value = int(command[2:])
        if value not in serial.Serial.BAUDRATES:
            raise ValueError
    except ValueError:
        raise FunctionReturn("Error: Received invalid baud rate value from TxM.")

    settings.serial_baudrate = value
    settings.store_settings()
    c_print("Baud rate will change on restart.", head=1, tail=1)


def change_gui_dialog(settings: 'Settings', command: bytes) -> None:
    """Change file selection (GUI/CLI prompt) setting on NH."""
    try:
        value_bytes = command[2:].lower()
        if value_bytes not in [b'true', b'false']:
            raise ValueError
        value = (value_bytes == b'true')
    except ValueError:
        raise FunctionReturn("Error: Received invalid GUI dialog setting value from TxM.")

    settings.disable_gui_dialog = value
    settings.store_settings()

    c_print("Changed setting disable_gui_dialog to {}.".format(value), head=1, tail=1)


def wipe(settings: 'Settings', queue_exit: 'Queue') -> None:
    """Reset terminal, wipe all user data from NH and power off system.

    No effective RAM overwriting tool currently exists, so as long as TxM/RxM
    use FDE and DDR3 memory, recovery of user data becomes impossible very fast:

        https://www1.cs.fau.de/filepool/projects/coldboot/fares_coldboot.pdf
    """
    os.system('reset')
    race_condition_delay(settings)
    queue_exit.put(WIPE)
