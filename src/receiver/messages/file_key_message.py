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

import base64

from typing import TYPE_CHECKING

from src.common.exceptions import SoftError
from src.common.crypto.keys.symmetric_key import MulticastFileKey
from src.common.statics import Origin, CryptoVarLength, KeyLength
from src.common.types_compound import FileKeyDict
from src.common.types_custom import BytesAssembledMessage
from src.common.utils.strings import separate_header

if TYPE_CHECKING:
    from src.common.entities.contact import Contact
    from src.common.entities.nick_name import Nick
    from src.database.db_contacts import ContactList


def process_file_key_message(assembled    : BytesAssembledMessage,
                             contact      : 'Contact',
                             origin       : Origin,
                             contact_list : 'ContactList',
                             file_keys    : 'FileKeyDict'
                             ) -> 'Nick':
    """Process received file key delivery message."""
    if origin == Origin.USER:
        raise SoftError('File key message from the user.', output=False)

    try:
        decoded = base64.b85decode(assembled)
    except ValueError:
        raise SoftError('Error: Received an invalid file key message.')

    ct_hash, file_key_bytes = separate_header(decoded, CryptoVarLength.BLAKE2_DIGEST)

    if len(ct_hash) != CryptoVarLength.BLAKE2_DIGEST or len(file_key_bytes) != KeyLength.SYMMETRIC_KEY:
        raise SoftError('Error: Received an invalid file key message.')

    file_keys[contact.onion_pub_key.serialize() + ct_hash] = MulticastFileKey(file_key_bytes)
    nick = contact_list.get_nick(contact.onion_pub_key)

    return nick
