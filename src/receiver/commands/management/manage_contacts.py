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

from datetime import datetime
from typing import TYPE_CHECKING

from src.common.entities.nick_name import Nick
from src.common.entities.window_uid import WindowUID
from src.common.exceptions import SoftError
from src.common.crypto.keys.onion_service_keys import OnionPublicKeyContact
from src.common.statics import FieldLength, WindowType
from src.ui.common.output.print_message import print_message
from src.common.utils.strings import separate_header
from src.database.db_logs import MessageLog

if TYPE_CHECKING:
    from src.common.entities.serialized_command import SerializedCommand
    from src.database.db_contacts import ContactList
    from src.database.db_groups import GroupList
    from src.database.db_keys import KeyStore
    from src.database.db_masterkey import MasterKey
    from src.database.db_settings import Settings
    from src.ui.receiver.window_rx import WindowList


def delete_contact(ser_cmd      : 'SerializedCommand',
                   ts           : datetime,
                   window_list  : 'WindowList',
                   contact_list : 'ContactList',
                   group_list   : 'GroupList',
                   settings     : 'Settings',
                   key_store    : 'KeyStore',
                   master_key   : 'MasterKey',
                   ) -> None:
    """Delete contact from Receiver Program."""
    onion_pub_key = OnionPublicKeyContact.from_onion_address_bytes(ser_cmd.command_bytes)

    key_store.remove_keyset(onion_pub_key)
    window_list.remove_window(WindowUID(onion_pub_key.public_bytes_raw))

    try:
        contact = contact_list.get_contact_by_pub_key(onion_pub_key)
    except KeyError:
        raise SoftError(f"Receiver has no account '{onion_pub_key.short_address}' to remove.")

    nick     = contact.nick
    in_group = any([g.remove_members([onion_pub_key]) for g in group_list])

    contact_list.remove_contact(onion_pub_key)

    message = f"Removed {nick} ({onion_pub_key.short_address}) from contacts{' and groups' if in_group else ''}."
    print_message(message, bold=True, padding_top=1, padding_bottom=1)

    sys_msg_win = window_list.sys_msg_win
    sys_msg_win.add_new_system_message(ts, message)

    MessageLog(master_key, settings).remove_logs(contact_list, group_list, onion_pub_key.public_bytes_raw)


def change_nick(ser_cmd      : 'SerializedCommand',
                ts           : datetime,
                window_list  : 'WindowList',
                contact_list : 'ContactList'
                ) -> None:
    """Change nickname of contact."""
    enc_onion_addr, nick_bytes = separate_header(ser_cmd.command_bytes, header_length=FieldLength.ONION_ADDRESS)
    onion_pub_key = OnionPublicKeyContact.from_onion_address_bytes(enc_onion_addr)

    nick = Nick(nick_bytes.decode())

    try:
        contact = contact_list.get_contact_by_pub_key(onion_pub_key)
    except KeyError:
        raise SoftError(f"Error: Receiver has no contact '{onion_pub_key.short_address}' to rename.")

    contact.nick = nick
    contact_list.store_contacts()

    window = window_list.get_or_create_window(WindowUID(onion_pub_key.public_bytes_raw))
    if window.window_type == WindowType.CONTACT:
        window.redraw()

    sys_msg_win = window_list.sys_msg_win
    sys_msg_win.add_new_system_message(ts, f"Changed account '{onion_pub_key.short_address}' nick to '{nick}'.", output=True)
