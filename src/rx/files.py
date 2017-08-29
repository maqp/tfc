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

import base64
import binascii
import os.path
import typing
import zlib

import nacl.exceptions

from src.common.crypto     import auth_and_decrypt
from src.common.encoding   import bytes_to_str
from src.common.exceptions import FunctionReturn
from src.common.input      import get_b58_key
from src.common.misc       import ensure_dir
from src.common.output     import box_print, c_print, phase, print_on_previous_line
from src.common.statics    import *

if typing.TYPE_CHECKING:
    from datetime               import datetime
    from src.common.db_settings import Settings
    from src.rx.windows         import WindowList


def store_unique(f_data: bytes, f_dir: str, f_name: str) -> str:
    """Store file under unique filename.

    Add trailing counter .# to duplicate files.
    """
    ensure_dir(f_dir)

    if os.path.isfile(f_dir + f_name):
        ctr = 1
        while os.path.isfile(f_dir + f_name + f'.{ctr}'):
            ctr += 1
        f_name += f'.{ctr}'

    with open(f_dir + f_name, 'wb+') as f:
        f.write(f_data)

    return f_name


def process_received_file(payload: bytes, nick: str) -> None:
    """Process received file assembly packets."""
    try:
        f_name_b, f_data = payload.split(US_BYTE)
    except ValueError:
        raise FunctionReturn("Error: Received file had invalid structure.")

    try:
        f_name = f_name_b.decode()
    except UnicodeError:
        raise FunctionReturn("Error: Received file name had invalid encoding.")

    if not f_name.isprintable() or not f_name:
        raise FunctionReturn("Error: Received file had an invalid name.")

    try:
        f_data = base64.b85decode(f_data)
    except (binascii.Error, ValueError):
        raise FunctionReturn("Error: Received file had invalid encoding.")

    file_ct  = f_data[:-KEY_LENGTH]
    file_key = f_data[-KEY_LENGTH:]
    if len(file_key) != KEY_LENGTH:
        raise FunctionReturn("Error: Received file had an invalid key.")

    try:
        file_pt = auth_and_decrypt(file_ct, file_key, soft_e=True)
    except nacl.exceptions.CryptoError:
        raise FunctionReturn("Error: Decryption of file data failed.")

    try:
        file_dc = zlib.decompress(file_pt)
    except zlib.error:
        raise FunctionReturn("Error: Decompression of file data failed.")

    file_dir   = f'{DIR_RX_FILES}{nick}/'
    final_name = store_unique(file_dc, file_dir, f_name)
    box_print(f"Stored file from {nick} as '{final_name}'")


def process_imported_file(ts:          'datetime',
                          packet:      bytes,
                          window_list: 'WindowList',
                          settings:    'Settings'):
    """Decrypt and store imported file."""
    while True:
        try:
            print('')
            key = get_b58_key(B58_FILE_KEY, settings)
        except KeyboardInterrupt:
            raise FunctionReturn("File import aborted.", head=2)

        try:
            phase("Decrypting file", head=1)
            file_pt = auth_and_decrypt(packet[1:], key, soft_e=True)
            phase(DONE)
            break
        except (nacl.exceptions.CryptoError, nacl.exceptions.ValueError):
            phase('ERROR', done=True)
            c_print("Invalid decryption key. Try again.")
            print_on_previous_line(reps=7, delay=1.5)
        except KeyboardInterrupt:
            phase('ABORT', done=True)
            raise FunctionReturn("File import aborted.")

    try:
        phase("Decompressing file")
        file_dc = zlib.decompress(file_pt)
        phase(DONE)
    except zlib.error:
        phase('ERROR', done=True)
        raise FunctionReturn("Error: Decompression of file data failed.")

    try:
        f_name = bytes_to_str(file_dc[:PADDED_UTF32_STR_LEN])
    except UnicodeError:
        raise FunctionReturn("Error: Received file name had invalid encoding.")

    if not f_name.isprintable() or not f_name:
        raise FunctionReturn("Error: Received file had an invalid name.")

    f_data     = file_dc[PADDED_UTF32_STR_LEN:]
    final_name = store_unique(f_data, DIR_IMPORTED, f_name)

    message = f"Stored imported file as '{final_name}'"
    box_print(message, head=1)

    local_win = window_list.get_local_window()
    local_win.add_new(ts, message)
