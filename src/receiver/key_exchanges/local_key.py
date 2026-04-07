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

import readline

from datetime import datetime
from typing import TYPE_CHECKING

import nacl.exceptions

from src.common.entities.local_key_buffer import LocalKeyBuffer
from src.common.exceptions import SoftError
from src.common.entities.confirm_code import ConfirmationCode
from src.common.crypto.keys.kek_hash import KEKHash

from src.common.crypto.keys.symmetric_key import LocalKeyEncryptionKey, LocalMessageKey, LocalHeaderKey
from src.common.statics import B58KeyType, FieldLength, KeyLength
from src.common.utils.security import clear_clipboard
from src.ui.common.input.get_b58_key import get_b58_key
from src.ui.common.output.print_message import print_message
from src.ui.common.output.vt100_utils import reset_terminal
from src.common.utils.strings import separate_headers
from src.common.utils.validators import validate_bytes

if TYPE_CHECKING:
    from src.common.crypto.pt_ct import LocalKeySetPT
    from src.database.db_contacts import ContactList
    from src.database.db_local_key import LocalKeyDB
    from src.database.db_settings import Settings
    from src.ui.receiver.window_rx import WindowList
    from src.datagrams.receiver.local_key import DatagramReceiverLocalKey
    from src.common.queues import RxQueue


def protect_kek() -> None:
    """Prevent leak of KeyEncryptionKey via terminal history / clipboard."""
    readline.clear_history()
    reset_terminal()
    clear_clipboard()


def handle_local_key_buffer(kek    : 'LocalKeyEncryptionKey',
                            queues : 'RxQueue'
                            ) -> tuple['datetime', 'LocalKeySetPT']:
    """Check if the KEK was for a packet further ahead in the queue."""
    buffer = LocalKeyBuffer()
    queue  = queues.datagram_local_keys

    while queue.qsize() > 0:
        datagram = queue.get()

        if datagram.ts is None:
            continue

        local_key_ct_bytes = datagram.local_key_ct

        if not buffer.has_key(datagram.ts):
            buffer.insert(datagram.ts, local_key_ct_bytes)

    for ts, local_key_ct in buffer.items():
        try:
            plaintext = kek.auth_and_decrypt(local_key_ct)

            # If we reach this point, decryption was successful.
            del buffer[ts]

            # Put packets not yet decrypted back into queue.
            for ts_, local_key_ct_ in buffer.get_packets_after(ts):
                queue.put(DatagramReceiverLocalKey(local_key_ct_, ts_))

            return ts, plaintext

        except nacl.exceptions.CryptoError:
            # Try decrypting newer local key packet next
            continue

    # Finished the buffer without finding local key CT
    # for the KEK. Maybe the KEK is from another session.
    raise SoftError('Error: Incorrect LocalKeyEncryptionKey.', clear_delay=1)


def decrypt_local_key(local_key_db    : 'LocalKeyDB',
                      datagram        : 'DatagramReceiverLocalKey',
                      kek_hashes      : list['KEKHash'],
                      datagram_hashes : list[bytes],
                      settings        : 'Settings',
                      queues          : 'RxQueue'
                      ) -> tuple['datetime', ConfirmationCode]:
    """Decrypt local key packet."""
    while True:
        kek      = LocalKeyEncryptionKey(get_b58_key(B58KeyType.B58_LOCAL_KEY, settings))
        kek_hash = KEKHash.from_kek(kek)

        # Check if the key was an old one.
        if kek_hash in kek_hashes:
            print_message('Error: Entered an old local key decryption key.', clear_delay=1)
            continue

        try:
            local_key_data = kek.auth_and_decrypt(datagram.local_key_ct)
            ts = datagram.ts
        except nacl.exceptions.CryptoError:
            ts, local_key_data = handle_local_key_buffer(kek, queues)

        protect_kek()

        # Cache hashes needed to recognize reissued local key packets and key decryption keys.
        kek_hashes.append(kek_hash)
        datagram_hashes.append(datagram.datagram_hash)

        tx_hk_bytes, tx_mk_bytes, c_code_bytes = separate_headers(local_key_data.pt_bytes, 2 * [KeyLength.SYMMETRIC_KEY.value])

        validate_bytes(c_code_bytes, is_length=FieldLength.CONFIRM_CODE.value)

        local_key_db.add_local_keyset(LocalHeaderKey(tx_hk_bytes),
                                      LocalMessageKey(tx_mk_bytes),
                                      KEKHash(bytes(KeyLength.SYMMETRIC_KEY)))

        return ts, ConfirmationCode(c_code_bytes)

    raise RuntimeError('Broke out of loop')


def process_local_key(datagram      : 'DatagramReceiverLocalKey',
                      window_list   : 'WindowList',
                      local_key_db  : 'LocalKeyDB',
                      settings      : 'Settings',
                      kek_hashes    : list[KEKHash],
                      packet_hashes : list[bytes],
                      queues        : 'RxQueue'
                      ) -> None:
    """Decrypt local key packet and add local contact/keyset."""
    first_local_key = not local_key_db.has_keyset

    try:
        if datagram.datagram_hash in packet_hashes:
            raise SoftError('Error: Received old local key packet.', output=False)

        print_message('Local key setup', bold=True, clear_before=True, padding_top=1, padding_bottom=1)

        ts, c_code = decrypt_local_key(local_key_db, datagram, kek_hashes, packet_hashes, settings, queues)

        print_message([f'Local key successfully installed.',
                 f'Confirmation code (to Transmitter): {c_code.hr_code}'],
                      box=True, padding_top=1)

        sys_msg_win = window_list.sys_msg_win

        if first_local_key:
            window_list.active_win = sys_msg_win

        raise SoftError('Added new local key.', window=sys_msg_win, ts=ts, output=False)

    except (EOFError, KeyboardInterrupt):
        message = 'Local key setup aborted.'
        print_message(message, bold=True, clear_after=True, clear_delay=1, padding_top=2)

        if window_list.active_win is not None and not first_local_key:
            window_list.active_win.redraw()

        raise SoftError(message, output=False)


def local_key_rdy(ts           : 'datetime',
                  window_list  : 'WindowList',
                  contact_list : 'ContactList'
                  ) -> None:
    """Clear local key bootstrap process from the screen."""
    message = 'Successfully completed the local key setup.'

    sys_msg_win = window_list.sys_msg_win
    sys_msg_win.add_new_system_message(ts, message)

    print_message(message, bold=True, clear_after=True, clear_delay=1)

    active_win = window_list.active_win

    if contact_list.has_contacts:
        if active_win is not None and active_win.is_chat_window:
            active_win.redraw()
    else:
        print_message('Waiting for new contacts', bold=True, padding_top=1, padding_bottom=1)
