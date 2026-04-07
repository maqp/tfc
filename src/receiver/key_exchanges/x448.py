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

import struct

from datetime import datetime
from typing import TYPE_CHECKING

from src.common.entities.nick_name import Nick
from src.common.exceptions import SoftError, ValidationError
from src.common.crypto.keys.onion_service_keys import OnionPublicKeyContact
from src.common.crypto.fingerprint import FingerprintUser, FingerprintContact
from src.common.crypto.keys.symmetric_key import HeaderKeyUser, MessageKeyUser, HeaderKeyContact, MessageKeyContact
from src.common.statics import KeyLength, KexStatus, FieldLength
from src.ui.common.output.print_message import print_message
from src.common.utils.encoding import padded_bytes_to_str
from src.common.utils.strings import separate_headers

if TYPE_CHECKING:
    from src.common.entities.serialized_command import SerializedCommand
    from src.database.db_contacts import ContactList
    from src.database.db_keys import KeyStore
    from src.database.db_settings import Settings
    from src.ui.receiver.window_rx import WindowList


def key_ex_x448(ser_cmd      : 'SerializedCommand',
                ts           : datetime,
                window_list  : 'WindowList',
                contact_list : 'ContactList',
                settings     : 'Settings',
                key_store    : 'KeyStore',
                ) -> None:
    """Add contact and symmetric keys derived from X448 shared key."""
    # ┌──────────────┐
    # │ Parse fields │
    # └──────────────┘
    header_lengths = [FieldLength.ONION_ADDRESS.value,
                      KeyLength.SYMMETRIC_KEY.value,
                      KeyLength.SYMMETRIC_KEY.value,
                      KeyLength.SYMMETRIC_KEY.value,
                      KeyLength.SYMMETRIC_KEY.value]

    (enc_onion_address,
     tx_hk_bytes,
     tx_mk_bytes,
     rx_hk_bytes,
     rx_mk_bytes,
     nick_bytes) = separate_headers(ser_cmd.command_bytes, header_lengths)

    # ┌─────────────────┐
    # │ Validate fields │
    # └─────────────────┘
    try:
        onion_pub_key = OnionPublicKeyContact.from_onion_address_bytes(enc_onion_address)
    except ValidationError:
        raise SoftError('Error: Received invalid contact onion address')

    try:
        tx_hk = HeaderKeyUser(tx_hk_bytes)
        tx_mk = MessageKeyUser(tx_mk_bytes)
        rx_hk = HeaderKeyContact(rx_hk_bytes)
        rx_mk = MessageKeyContact(rx_mk_bytes)
    except ValidationError:
        raise SoftError('Error: Received invalid contact keyset')

    try:
        nick = Nick(padded_bytes_to_str(nick_bytes))
    except (struct.error, UnicodeError):
        raise SoftError('Error: Received invalid contact nick data')

    # ┌──────────────────┐
    # │ Add contact/keys │
    # └──────────────────┘
    contact_list.add_contact(onion_pub_key,
                             nick,
                             FingerprintUser   .generate_zero_fp(),
                             FingerprintContact.generate_zero_fp(),
                             KexStatus.KEX_STATUS_NONE,
                             settings.log_messages_by_default,
                             settings.accept_files_by_default,
                             settings.show_notifications_by_default)

    key_store.add_keyset(onion_pub_key,
                         tx_hk,
                         tx_mk,
                         rx_hk,
                         rx_mk)

    # ---

    message     = f'Successfully added {nick}.'
    sys_msg_win = window_list.sys_msg_win
    sys_msg_win.add_new_system_message(ts, message)
    print_message([message, f'Confirmation code (to Transmitter): {onion_pub_key.c_code.hr_code}'], box=True)
