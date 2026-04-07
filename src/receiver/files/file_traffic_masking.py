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

from typing import TYPE_CHECKING

import nacl.exceptions

from src.common.entities.window_uid import WindowUID
from src.common.exceptions import SoftError, ValidationError
from src.common.crypto.pt_ct import FileInnerCT
from src.common.crypto.keys.symmetric_key import LongFileKey
from src.common.statics import Separator, KeyLength, DataDir, Origin, CompoundFieldLength
from src.common.types_custom import BytesAssembledFile
from src.common.utils.encoding import decompress
from src.common.utils.io import store_unique
from src.common.utils.strings import separate_trailer
from src.common.utils.validators import validate_bytes

if TYPE_CHECKING:
    from datetime import datetime

    from src.common.entities.contact import Contact
    from src.common.entities.nick_name import Nick
    from src.database.db_settings import Settings
    from src.ui.receiver.window_rx import WindowList


def process_assembled_file(ts          : 'datetime',
                           payload     : BytesAssembledFile,
                           contact     : 'Contact',
                           nick        : 'Nick',
                           settings    : 'Settings',
                           window_list : 'WindowList',
                           ) -> None:
    """Process received file assembly packets."""
    # Validate file name
    try:
        file_name_b, file_data = payload.split(Separator.US_BYTE, 1)
    except ValueError:
        raise SoftError('Error: Received file had an invalid structure.')

    try:
        file_name = file_name_b.decode()
    except UnicodeError:
        raise SoftError('Error: Received file name had an invalid encoding.')

    if not file_name.isprintable() or not file_name or '/' in file_name:
        raise SoftError('Error: Received file had an invalid name.')

    # Decrypt inner CT
    file_inner_ct_bytes, inner_key_bytes = separate_trailer(file_data, KeyLength.SYMMETRIC_KEY)

    validate_bytes(file_inner_ct_bytes, min_length=CompoundFieldLength.ATTACHMENT_CT_MIN)
    file_ct = FileInnerCT(file_inner_ct_bytes)

    try:
        file_key = LongFileKey(inner_key_bytes)
    except ValidationError:
        raise SoftError('Error: Received file had an invalid key.')

    try:
        file_pt = file_key.auth_and_decrypt(file_ct)
    except nacl.exceptions.CryptoError:
        raise SoftError('Error: Decryption of file data failed.')

    # Decompress
    file_data = decompress(file_pt.pt_bytes, settings.max_decompress_size_mb)

    # Store
    final_name = store_unique(file_dir  = f'{DataDir.RECEIVED_FILES}/{nick.sender_dir_name}',
                              file_name = file_name,
                              file_data = file_data)

    # Report
    message = f"Stored file from {nick.value} into '{final_name}'."
    if settings.traffic_masking and window_list.active_win is not None:
        window = window_list.active_win
    else:
        window = window_list.get_or_create_window(WindowUID.for_contact(contact))
    window.add_new_message(ts, contact, Origin.CONTACT, message, output=True, event_msg=True)
