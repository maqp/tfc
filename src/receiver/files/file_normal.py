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

import zlib

from datetime import datetime
from typing import TYPE_CHECKING

import nacl.exceptions

from src.common.entities.window_uid import WindowUID

from src.common.exceptions import SoftError
from src.common.crypto.keys.onion_service_keys import OnionPublicKeyContact
from src.common.crypto.keys.symmetric_key import MulticastFileKey
from src.common.statics import  FieldLength, StatusMsg, DataDir, Origin
from src.common.types_compound import FileBufferDict
from src.ui.common.output.vt100_utils import clear_previous_lines
from src.ui.common.output.phase import phase
from src.common.utils.encoding import decompress, padded_bytes_to_str
from src.common.utils.io import store_unique
from src.datagrams.receiver.file_multicast import DatagramFileMulticast

if TYPE_CHECKING:
    from src.database.db_contacts import ContactList
    from src.database.db_settings import Settings
    from src.ui.receiver.window_rx import WindowList
    from src.common.crypto.pt_ct import MulticastFileCT


def cache_or_store_file(datagram     : 'DatagramFileMulticast',
                        file_keys    : dict[bytes, 'MulticastFileKey'],
                        file_buf     : 'FileBufferDict',
                        contact_list : 'ContactList',
                        window_list  : 'WindowList',
                        settings     : 'Settings'
                        ) -> None:
    """Validate received file and process or cache it."""
    onion_pub_key = datagram.pub_key_contact
    file_ct       = datagram.file_ct
    ts            = datagram.ts

    if not contact_list.has_onion_pub_key(onion_pub_key):
        raise SoftError('File from an unknown account.', output=False)

    contact = contact_list.get_contact_by_pub_key(onion_pub_key)

    if not contact.file_reception:
        raise SoftError(f'Alert! Discarded file from {contact.nick} as file reception for them is disabled.', bold=True)

    dict_key = onion_pub_key.serialize() + file_ct.ct_hash

    if dict_key in file_keys:
        file_key = file_keys[dict_key]
        store_file(ts, onion_pub_key, file_ct, file_key, contact_list, window_list, settings)
        file_keys.pop(dict_key)
    else:
        file_buf[onion_pub_key] = (ts, file_ct)


def store_file(ts            : 'datetime',
               onion_pub_key : 'OnionPublicKeyContact',
               file_ct       : 'MulticastFileCT',
               file_key      : 'MulticastFileKey',
               contact_list  : 'ContactList',
               window_list   : 'WindowList',
               settings      : 'Settings'
               ) -> None:
    """Store file received from a contact."""
    contact = contact_list.get_contact_by_pub_key(onion_pub_key)
    nick    = contact.nick

    phase('Processing received file', padding_top=1)
    try:
        file_pt = file_key.auth_and_decrypt(file_ct)
    except nacl.exceptions.CryptoError:
        raise SoftError(f'Error: Decryption key for file from {nick} was invalid.')

    try:
        file_dc = decompress(file_pt.pt_bytes, max_size_mb=settings.max_decompress_size_mb)
    except zlib.error:
        raise SoftError(f'Error: Failed to decompress file from {nick}.')
    phase(StatusMsg.DONE)
    clear_previous_lines(no_lines=2)

    try:
        file_name = padded_bytes_to_str(file_dc[:FieldLength.PADDED_UTF32_STR])
    except UnicodeError:
        raise SoftError(f'Error: Name of file from {nick} had an invalid encoding.')

    if not file_name.isprintable() or not file_name or '/' in file_name:
        raise SoftError(f'Error: Name of file from {nick} was invalid.')

    final_name = store_unique(file_dir = f'{DataDir.RECEIVED_FILES}/{nick.sender_dir_name}',
                              file_name = file_name,
                              file_data = file_dc[FieldLength.PADDED_UTF32_STR:])

    message = f"Stored file from {nick} as '{final_name}'."

    if settings.traffic_masking and window_list.active_win is not None:
        window = window_list.active_win
    else:
        window = window_list.get_or_create_window(WindowUID.for_contact(contact))

    window.add_new_message(ts, contact, Origin.CONTACT, message, output=True, event_msg=True)
