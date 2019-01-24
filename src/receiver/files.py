#!/usr/bin/env python3.6
# -*- coding: utf-8 -*-

"""
TFC - Onion-routed, endpoint secure messaging system
Copyright (C) 2013-2019  Markus Ottela

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

import os.path
import typing
import zlib

from typing import Dict, Tuple

import nacl.exceptions

from src.common.crypto     import auth_and_decrypt, blake2b
from src.common.encoding   import bytes_to_str
from src.common.exceptions import FunctionReturn
from src.common.misc       import decompress, ensure_dir, separate_headers, separate_trailer
from src.common.output     import phase, print_on_previous_line
from src.common.statics    import *

if typing.TYPE_CHECKING:
    from datetime               import datetime
    from src.common.db_contacts import ContactList
    from src.common.db_settings import Settings
    from src.receiver.windows   import WindowList


def store_unique(file_data: bytes,  # File data to store
                 file_dir:  str,    # Directory to store file
                 file_name: str     # Preferred name for the file.
                 ) -> str:
    """Store file under a unique filename.

    If file exists, add trailing counter .# with value as large as
    needed to ensure existing file is not overwritten.
    """
    ensure_dir(file_dir)

    if os.path.isfile(file_dir + file_name):
        ctr = 1
        while os.path.isfile(file_dir + file_name + f'.{ctr}'):
            ctr += 1
        file_name += f'.{ctr}'

    with open(file_dir + file_name, 'wb+') as f:
        f.write(file_data)

    return file_name


def process_assembled_file(ts:            'datetime',    # Timestamp last received packet
                           payload:       bytes,         # File name and content
                           onion_pub_key: bytes,         # Onion Service pubkey of sender
                           nick:          str,           # Nickname of sender
                           settings:      'Settings',    # Settings object
                           window_list:   'WindowList',  # WindowList object
                           ) -> None:
    """Process received file assembly packets."""
    try:
        file_name_b, file_data = payload.split(US_BYTE, 1)
    except ValueError:
        raise FunctionReturn("Error: Received file had an invalid structure.")

    try:
        file_name = file_name_b.decode()
    except UnicodeError:
        raise FunctionReturn("Error: Received file name had invalid encoding.")

    if not file_name.isprintable() or not file_name or '/' in file_name:
        raise FunctionReturn("Error: Received file had an invalid name.")

    file_ct, file_key = separate_trailer(file_data, SYMMETRIC_KEY_LENGTH)

    if len(file_key) != SYMMETRIC_KEY_LENGTH:
        raise FunctionReturn("Error: Received file had an invalid key.")

    try:
        file_pt = auth_and_decrypt(file_ct, file_key)
    except nacl.exceptions.CryptoError:
        raise FunctionReturn("Error: Decryption of file data failed.")

    try:
        file_dc = decompress(file_pt, settings.max_decompress_size)
    except zlib.error:
        raise FunctionReturn("Error: Decompression of file data failed.")

    file_dir   = f'{DIR_RECV_FILES}{nick}/'
    final_name = store_unique(file_dc, file_dir, file_name)

    message = f"Stored file from {nick} as '{final_name}'."
    if settings.traffic_masking and window_list.active_win is not None:
        window = window_list.active_win
    else:
        window = window_list.get_window(onion_pub_key)
    window.add_new(ts, message, onion_pub_key, output=True, event_msg=True)


def new_file(ts:           'datetime',
             packet:       bytes,                                  # Sender of file and file ciphertext
             file_keys:    Dict[bytes, bytes],                     # Dictionary for file decryption keys
             file_buf:     Dict[bytes, Tuple['datetime', bytes]],  # Dictionary for cached file ciphertexts
             contact_list: 'ContactList',                          # ContactList object
             window_list:  'WindowList',                           # WindowList object
             settings:     'Settings'                              # Settings object
             ) -> None:
    """Validate received file and process or cache it."""
    onion_pub_key, _, file_ct = separate_headers(packet, [ONION_SERVICE_PUBLIC_KEY_LENGTH, ORIGIN_HEADER_LENGTH])

    if not contact_list.has_pub_key(onion_pub_key):
        raise FunctionReturn("File from an unknown account.", output=False)

    nick = contact_list.get_contact_by_pub_key(onion_pub_key).nick
    if not contact_list.get_contact_by_pub_key(onion_pub_key).file_reception:
        raise FunctionReturn(f"Alert! Discarded file from {nick} as file reception for them is disabled.", bold=True)

    k = onion_pub_key + blake2b(file_ct)  # Dictionary key

    if k in file_keys:
        decryption_key = file_keys[k]
        process_file(ts, onion_pub_key, file_ct, decryption_key, contact_list, window_list, settings)
        file_keys.pop(k)
    else:
        file_buf[k] = (ts, file_ct)


def process_file(ts:            'datetime',     # Timestamp of received_packet
                 onion_pub_key: bytes,          # Onion Service pubkey of sender
                 file_ct:       bytes,          # File ciphertext
                 file_key:      bytes,          # File decryption key
                 contact_list:  'ContactList',  # ContactList object
                 window_list:   'WindowList',   # WindowList object
                 settings:      'Settings'      # Settings object
                 ) -> None:
    """Store file received from a contact."""
    nick = contact_list.get_contact_by_pub_key(onion_pub_key).nick

    phase("Processing received file", head=1)
    try:
        file_pt = auth_and_decrypt(file_ct, file_key)
    except nacl.exceptions.CryptoError:
        raise FunctionReturn(f"Error: Decryption key for file from {nick} was invalid.")

    try:
        file_dc = decompress(file_pt, settings.max_decompress_size)
    except zlib.error:
        raise FunctionReturn(f"Error: Failed to decompress file from {nick}.")
    phase(DONE)
    print_on_previous_line(reps=2)

    try:
        file_name = bytes_to_str(file_dc[:PADDED_UTF32_STR_LENGTH])
    except UnicodeError:
        raise FunctionReturn(f"Error: Name of file from {nick} had invalid encoding.")

    if not file_name.isprintable() or not file_name or '/' in file_name:
        raise FunctionReturn(f"Error: Name of file from {nick} was invalid.")

    f_data = file_dc[PADDED_UTF32_STR_LENGTH:]

    file_dir   = f'{DIR_RECV_FILES}{nick}/'
    final_name = store_unique(f_data, file_dir, file_name)
    message    = f"Stored file from {nick} as '{final_name}'."

    if settings.traffic_masking and window_list.active_win is not None:
        window = window_list.active_win
    else:
        window = window_list.get_window(onion_pub_key)

    window.add_new(ts, message, onion_pub_key, output=True, event_msg=True)
