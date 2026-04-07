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

import os
import struct
import subprocess

from datetime import datetime
from typing import TYPE_CHECKING

import nacl.exceptions

from src.common.entities.nick_name import Nick
from src.common.exceptions import SoftError, ValidationError
from src.common.crypto.argon2_salt import Argon2Salt
from src.common.crypto.algorithms.argon2 import argon2_kdf
from src.common.crypto.keys.onion_service_keys import OnionPublicKeyContact
from src.common.crypto.fingerprint import FingerprintUser, FingerprintContact
from src.common.crypto.pt_ct import PSKCT
from src.common.crypto.keys.symmetric_key import (HeaderKeyUser, MessageKeyUser, HeaderKeyContact, MessageKeyContact,
                                                  PSKEncryptionKey)
from src.common.statics import KeyLength, KexStatus, FieldLength, CompoundFieldLength, Argon2Literals
from src.common.types_custom import IntArgon2TimeCost, IntArgon2MemoryCost, IntArgon2Parallelism
from src.ui.common.input.get_yes import get_yes
from src.ui.common.input.path.get_path import get_path
from src.common.utils.encoding import padded_bytes_to_str, bytes_to_int
from src.common.utils.strings import separate_headers, separate_header
from src.common.utils.validators import validate_bytes
from src.database.db_masterkey import MasterKey
from src.ui.common.output.print_message import print_message
from src.ui.common.output.vt100_utils import clear_previous_lines
from src.ui.common.output.phase import phase

if TYPE_CHECKING:
    from src.common.entities.serialized_command import SerializedCommand
    from src.common.crypto.pt_ct import PSKPT
    from src.database.db_contacts import ContactList
    from src.database.db_keys import KeyStore
    from src.database.db_settings import Settings
    from src.ui.receiver.window_rx import WindowList


def key_ex_psk_tx(ser_cmd      : 'SerializedCommand',
                  ts           : datetime,
                  window_list  : 'WindowList',
                  contact_list : 'ContactList',
                  settings     : 'Settings',
                  key_store    : 'KeyStore'
                  ) -> None:
    """Add contact and Tx-PSKs."""
    # ┌──────────────┐
    # │ Parse fields │
    # └──────────────┘
    headers_lengths = [FieldLength.ONION_ADDRESS.value,
                       KeyLength.SYMMETRIC_KEY.value,
                       KeyLength.SYMMETRIC_KEY.value,
                       KeyLength.SYMMETRIC_KEY.value,
                       KeyLength.SYMMETRIC_KEY.value]

    # We ignore the recipient's keys as they're zero anyway.
    (enc_onion_address,
     tx_hk_bytes,
     tx_mk_bytes,
     _,
     _,
     nick_bytes) = separate_headers(ser_cmd.command_bytes, headers_lengths)

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
    except ValidationError:
        raise SoftError('Error: Received invalid outgoing keys keys')

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
                             KexStatus.KEX_STATUS_NO_RX_PSK,
                             settings.log_messages_by_default,
                             settings.accept_files_by_default,
                             settings.show_notifications_by_default)

    # The Rx-side keys are set as null-byte strings to indicate they have not
    # been added yet. The zero-keys do not allow existential forgeries as
    # `decrypt_assembly_packet` does not allow the use of zero-keys for decryption.
    key_store.add_keyset(onion_pub_key = onion_pub_key,
                         tx_hk         = tx_hk,
                         tx_mk         = tx_mk,
                         rx_hk         = HeaderKeyContact .generate_zero_key(),
                         rx_mk         = MessageKeyContact.generate_zero_key())

    # ---

    message     = f'Added Tx-side PSK for {nick} ({onion_pub_key.short_address}).'
    sys_msg_win = window_list.sys_msg_win
    sys_msg_win.add_new_system_message(ts, message)
    print_message([message, f'Confirmation code (to Transmitter): {onion_pub_key.c_code.hr_code}'], box=True)


def key_ex_psk_rx(ser_cmd      : 'SerializedCommand',
                  ts           : datetime,
                  window_list  : 'WindowList',
                  contact_list : 'ContactList',
                  settings     : 'Settings',
                  key_store    : 'KeyStore',
                  ) -> None:
    """Import Rx-PSK of contact."""
    # ┌──────────────┐
    # │ Parse fields │
    # └──────────────┘
    enc_onion_address = ser_cmd.command_bytes

    # ┌─────────────────┐
    # │ Validate fields │
    # └─────────────────┘
    try:
        onion_pub_key = OnionPublicKeyContact.from_onion_address_bytes(enc_onion_address)
    except ValidationError:
        raise SoftError('Error: Received invalid contact onion address')

    if not contact_list.has_onion_pub_key(onion_pub_key):
        raise SoftError(f"Error: Unknown account '{onion_pub_key.short_address}'.", clear_before=True)

    contact = contact_list.get_contact_by_pub_key(onion_pub_key)

    # ┌─────────────────────────┐
    # │ Import and validate PSK │
    # └─────────────────────────┘

    path_to_psk_file = get_path(f'Select PSK for {contact.nick} ({onion_pub_key.short_address})', settings, get_file=True)

    try:
        with open(path_to_psk_file, 'rb') as f:
            psk_data = f.read()
    except PermissionError:
        raise SoftError('Error: No read permission to read the PSK file.')

    try:
        validate_bytes(psk_data, is_length=CompoundFieldLength.PSK_FILE_SIZE)
    except ValidationError:
        raise SoftError('Error: The PSK data in the file was invalid.', clear_before=True)

    header_lengths = [KeyLength.ARGON2_SALT.value,
                      FieldLength.ENCODED_INTEGER.value,
                      FieldLength.ENCODED_INTEGER.value,
                      FieldLength.ENCODED_INTEGER.value]

    salt_bytes, time_cost_bytes, memory_cost_bytes, parallelism_bytes, ct_tag = separate_headers(psk_data, header_lengths)

    time_cost   = IntArgon2TimeCost   ( bytes_to_int(time_cost_bytes  ) )
    memory_cost = IntArgon2MemoryCost ( bytes_to_int(memory_cost_bytes) )
    parallelism = IntArgon2Parallelism( bytes_to_int(parallelism_bytes) )

    # The worst that could happen is Receiver Program crashes Destination VM from resource overuse.
    # The user gets to choose whether to proceed with the custom parameters provided by the sender.
    if (   time_cost   > Argon2Literals.ARGON2_PSK_TIME_COST
        or memory_cost > Argon2Literals.ARGON2_PSK_MEMORY_COST
        or parallelism > Argon2Literals.ARGON2_PSK_PARALLELISM):
        if not get_yes(f'Decrypt PSK with bundled values (Time cost: {time_cost}, Memory cost: {memory_cost}, Parallelism: {parallelism})?'):
            raise SoftError('PSK decryption aborted.', clear_before=True)

    psk_pt = decrypt_rx_psk(Argon2Salt(salt_bytes), PSKCT(ct_tag), time_cost, memory_cost, parallelism)

    rx_hk_bytes, rx_mk_bytes = separate_header(psk_pt.pt_bytes, header_length=KeyLength.SYMMETRIC_KEY)

    try:
        rx_hk = HeaderKeyContact(rx_hk_bytes)
        rx_mk = MessageKeyContact(rx_mk_bytes)
    except ValidationError:
        raise SoftError('Error: Received invalid keys from contact.', clear_before=True)

    # ┌─────────┐
    # │ Add PSK │
    # └─────────┘
    key_store.add_contact_psk(onion_pub_key, rx_hk, rx_mk)
    contact.kex_status = KexStatus.KEX_STATUS_HAS_RX_PSK
    contact_list.store_contacts()

    # ┌────────────────────────┐
    # │ Destroy PSK ciphertext │
    # └────────────────────────┘
    subprocess.Popen(['shred', '-n', '3', '-z', '-u', path_to_psk_file]).wait()
    if os.path.isfile(path_to_psk_file):
        print_message(f'Warning! Overwriting of PSK ({path_to_psk_file}) failed. Press <Enter> to continue.',
                      manual_proceed=True, box=True)

    message = f'Added PSK for messages from {contact.nick} ({onion_pub_key.short_address}).'

    sys_msg_win = window_list.sys_msg_win
    sys_msg_win.add_new_system_message(ts, message)

    print_message([message, '', 'Warning!',
             'Physically destroy the keyfile transmission media ',
             'to ensure it does not steal data from this computer!', '',
             f'Confirmation code (to Transmitter): {onion_pub_key.c_code.hr_code}'], box=True, padding_top=1, padding_bottom=1)


def decrypt_rx_psk(salt        : Argon2Salt,
                   psk_ct      : PSKCT,
                   time_cost   : IntArgon2TimeCost,
                   memory_cost : IntArgon2MemoryCost,
                   parallelism : IntArgon2Parallelism
                   ) -> 'PSKPT':
    """Get PSK password from user and decrypt Rx-PSK."""
    while True:
        try:
            password = MasterKey.get_password('PSK password')
            with phase('Deriving the key decryption key', padding_top=2) as set_done_message:
                kek = PSKEncryptionKey(argon2_kdf(password, salt, time_cost, memory_cost, parallelism))
                try:
                    psk_pt = kek.auth_and_decrypt(psk_ct)
                except nacl.exceptions.CryptoError:
                    clear_previous_lines(no_lines=1)
                    set_done_message('Invalid password')
                    clear_previous_lines(no_lines=5, delay=1)
                    continue

                clear_previous_lines(no_lines=5, delay=1)
                return psk_pt

        except (EOFError, KeyboardInterrupt):
            raise SoftError('PSK import aborted.', padding_top=2, clear_delay=1, clear_after=True)

    raise RuntimeError('Broke out of loop')
