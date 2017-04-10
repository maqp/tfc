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

from src.common.crypto   import auth_and_decrypt
from src.common.encoding import bytes_to_str
from src.common.errors   import FunctionReturn
from src.common.input    import get_b58_key
from src.common.misc     import ensure_dir
from src.common.output   import box_print, c_print, phase, print_on_previous_line
from src.common.statics  import *

if typing.TYPE_CHECKING:
    from datetime       import datetime
    from src.rx.windows import WindowList


def store_unique(file_data: bytes, f_dir: str, f_name: str) -> str:
    """Store file under unique filename.

    Add trailing counter .# to duplicate files.
    """
    ensure_dir(f'{f_dir}/')

    if os.path.isfile(f'{f_dir}/{f_name}'):
        f_name += '.1'
    while os.path.isfile(f'{f_dir}/{f_name}'):
        *name_parts, ctr = f_name.split('.')
        f_name  = '.'.join(name_parts)
        f_name += ('.' + str(int(ctr) + 1))

    with open('{}/{}'.format(f_dir, f_name), 'wb+') as f:
        f.write(file_data)
    return f_name


def process_imported_file(ts:          'datetime',
                          packet:      bytes,
                          window_list: 'WindowList'):
    """Decrypt and store imported file."""
    while True:
        try:
            print('')
            key = get_b58_key('imported_file')
            phase("Decrypting file", head=1)
            file_pt = auth_and_decrypt(packet[1:], key, soft_e=True)
            phase("Done")
            break
        except nacl.exceptions.CryptoError:
            c_print("Invalid decryption key. Try again.", head=2)
            print_on_previous_line(reps=6, delay=1.5)
        except KeyboardInterrupt:
            raise FunctionReturn("File import aborted.")

    try:
        phase("Decompressing file")
        file_dc = zlib.decompress(file_pt)
        phase("Done")
    except zlib.error:
        raise FunctionReturn("Decompression of file data failed.")

    try:
        f_name  = bytes_to_str(file_dc[:1024])
    except UnicodeError:
        raise FunctionReturn("Received file had an invalid name.")

    if not f_name.isprintable():
        raise FunctionReturn("Received file had an invalid name.")

    f_data     = file_dc[1024:]
    final_name = store_unique(f_data, DIR_IMPORTED, f_name)

    message = "Stored imported file to {}/{}".format(DIR_IMPORTED, final_name)
    box_print(message, head=1)

    local_win = window_list.get_local_window()
    local_win.print_new(ts, message, print_=False)


def process_received_file(payload: bytes, nick: str) -> None:
    """Process received file assembly packets"""
    try:
        f_name, _, _, f_data = payload.split(US_BYTE)
    except ValueError:
        raise FunctionReturn("Received file had invalid structure.")

    try:
        f_name_d = f_name.decode()
    except UnicodeError:
        raise FunctionReturn("Received file had an invalid name.")

    if not f_name_d.isprintable():
        raise FunctionReturn("Received file had an invalid name.")

    try:
        f_data = base64.b85decode(f_data)
    except (binascii.Error, ValueError):
        raise FunctionReturn("Received file had invalid encoding.")

    file_ct  = f_data[:-32]
    file_key = f_data[-32:]
    if len(file_key) != 32:
        raise FunctionReturn("Received file had an invalid key.")

    try:
        file_pt = auth_and_decrypt(file_ct, file_key, soft_e=True)
    except nacl.exceptions.CryptoError:
        raise FunctionReturn("Decryption of file data failed.")

    try:
        file_dc = zlib.decompress(file_pt)
    except zlib.error:
        raise FunctionReturn("Decompression of file data failed.")

    if len(file_dc) == 0:
        raise FunctionReturn("Received file did not contain data.")

    f_dir      = f'{DIR_RX_FILES}/{nick}'
    final_name = store_unique(file_dc, f_dir, f_name_d)
    box_print(["Stored file from {} as {}.".format(nick, final_name)])
