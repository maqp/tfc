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

import os.path
import pipes
import subprocess
import typing

from typing import Dict

import nacl.exceptions

from src.common.crypto       import argon2_kdf, auth_and_decrypt, csprng
from src.common.db_masterkey import MasterKey
from src.common.encoding     import b58encode
from src.common.exceptions   import FunctionReturn
from src.common.input        import get_b58_key
from src.common.misc         import split_string
from src.common.output       import box_print, c_print, clear_screen, phase, print_key, print_on_previous_line
from src.common.path         import ask_path_gui
from src.common.statics      import *

if typing.TYPE_CHECKING:
    from datetime               import datetime
    from src.common.db_contacts import ContactList
    from src.common.db_keys     import KeyList
    from src.common.db_settings import Settings
    from src.rx.windows         import WindowList


# Local key

def process_local_key(ts:           'datetime',
                      packet:       bytes,
                      window_list:  'WindowList',
                      contact_list: 'ContactList',
                      key_list:     'KeyList',
                      settings:     'Settings') -> None:
    """Decrypt local key packet and add local contact/keyset."""
    bootstrap = not key_list.has_local_key()

    try:
        while True:
            clear_screen()
            box_print("Received encrypted local key", tail=1)
            kdk = get_b58_key(B58_LOCAL_KEY, settings)

            try:
                pt = auth_and_decrypt(packet[1:], key=kdk, soft_e=True)
                break
            except nacl.exceptions.CryptoError:
                if bootstrap:
                    raise FunctionReturn("Error: Incorrect key decryption key.", delay=1.5)
                c_print("Incorrect key decryption key.", head=1)
                clear_screen(delay=1.5)

        key       = pt[0:32]
        hek       = pt[32:64]
        conf_code = pt[64:65]

        # Add local contact to contact list database
        contact_list.add_contact(LOCAL_ID, LOCAL_ID, LOCAL_ID,
                                 bytes(FINGERPRINT_LEN), bytes(FINGERPRINT_LEN),
                                 False, False, True)

        # Add local keyset to keyset database
        key_list.add_keyset(rx_account=LOCAL_ID,
                            tx_key=key,
                            rx_key=csprng(),
                            tx_hek=hek,
                            rx_hek=csprng())

        box_print(f"Confirmation code for TxM: {conf_code.hex()}", head=1)

        local_win = window_list.get_local_window()
        local_win.add_new(ts, "Added new local key.")

        if bootstrap:
            window_list.active_win = local_win

    except KeyboardInterrupt:
        raise FunctionReturn("Local key setup aborted.", delay=1, head=3, tail_clear=True)


def local_key_installed(ts:           'datetime',
                        window_list:  'WindowList',
                        contact_list: 'ContactList') -> None:
    """Clear local key bootstrap process from screen."""
    message   = "Successfully completed local key exchange."
    local_win = window_list.get_window(LOCAL_ID)
    local_win.add_new(ts, message)

    box_print(message)
    clear_screen(delay=1)

    if not contact_list.has_contacts():
        c_print("Waiting for new contacts", head=1, tail=1)


# X25519

def process_public_key(ts:          'datetime',
                       packet:      bytes,
                       window_list: 'WindowList',
                       settings:    'Settings',
                       pubkey_buf:  Dict[str, bytes]) -> None:
    """Display contact's public key and add it to buffer."""
    pub_key = packet[1:33]
    origin  = packet[33:34]

    try:
        account = packet[34:].decode()
    except UnicodeError:
        raise FunctionReturn("Error! Account for received public key had invalid encoding.")

    if origin not in [ORIGIN_CONTACT_HEADER, ORIGIN_USER_HEADER]:
        raise FunctionReturn("Error! Received public key had an invalid origin header.")

    if origin == ORIGIN_CONTACT_HEADER:
        pubkey_buf[account] = pub_key
        print_key(f"Received public key from {account}:", pub_key, settings)

        local_win   = window_list.get_local_window()
        pub_key_b58 = ' '.join(split_string(b58encode(pub_key), item_len=(51 if settings.local_testing_mode else 3)))
        local_win.add_new(ts, f"Received public key from {account}: {pub_key_b58}")

    elif origin == ORIGIN_USER_HEADER and account in pubkey_buf:
        clear_screen()
        print_key(f"Public key for {account}:", pubkey_buf[account], settings)


def add_x25519_keys(packet:       bytes,
                    ts:           'datetime',
                    window_list:  'WindowList',
                    contact_list: 'ContactList',
                    key_list:     'KeyList',
                    settings:     'Settings',
                    pubkey_buf:   Dict[str, bytes]) -> None:
    """Add contact and their X25519 keys."""
    tx_key = packet[0:32]
    tx_hek = packet[32:64]
    rx_key = packet[64:96]
    rx_hek = packet[96:128]

    account, nick = [f.decode() for f in packet[128:].split(US_BYTE)]

    contact_list.add_contact(account, DUMMY_USER, nick,
                             bytes(FINGERPRINT_LEN),
                             bytes(FINGERPRINT_LEN),
                             settings.log_messages_by_default,
                             settings.accept_files_by_default,
                             settings.show_notifications_by_default)

    key_list.add_keyset(account, tx_key, rx_key, tx_hek, rx_hek)

    pubkey_buf.pop(account, None)

    message   = f"Added X25519 keys for {nick} ({account})."
    local_win = window_list.get_window(LOCAL_ID)
    local_win.add_new(ts, message)

    box_print(message)
    clear_screen(delay=1)


# PSK

def add_psk_tx_keys(cmd_data:     bytes,
                    ts:           'datetime',
                    window_list:  'WindowList',
                    contact_list: 'ContactList',
                    key_list:     'KeyList',
                    settings:     'Settings',
                    pubkey_buf:   Dict[str, bytes]) -> None:
    """Add contact and Tx-PSKs."""
    tx_key = cmd_data[0:32]
    tx_hek = cmd_data[32:64]

    account, nick = [f.decode() for f in cmd_data[64:].split(US_BYTE)]

    contact_list.add_contact(account, DUMMY_USER, nick,
                             bytes(FINGERPRINT_LEN), bytes(FINGERPRINT_LEN),
                             settings.log_messages_by_default,
                             settings.accept_files_by_default,
                             settings.show_notifications_by_default)

    # The Rx-side keys are set as null-byte strings to indicate they have not
    # been added yet. This does not allow existential forgeries as
    # decrypt_assembly_packet does not allow use of zero-keys for decryption.
    key_list.add_keyset(account,
                        tx_key=tx_key,
                        rx_key=bytes(KEY_LENGTH),
                        tx_hek=tx_hek,
                        rx_hek=bytes(KEY_LENGTH))

    pubkey_buf.pop(account, None)

    message   = f"Added Tx-PSK for {nick} ({account})."
    local_win = window_list.get_window(LOCAL_ID)
    local_win.add_new(ts, message)

    box_print(message)
    clear_screen(delay=1)


def import_psk_rx_keys(cmd_data:     bytes,
                       ts:           'datetime',
                       window_list:  'WindowList',
                       contact_list: 'ContactList',
                       key_list:     'KeyList',
                       settings:     'Settings') -> None:
    """Import Rx-PSK of contact."""
    account = cmd_data.decode()

    if not contact_list.has_contact(account):
        raise FunctionReturn(f"Error: Unknown account '{account}'")

    contact  = contact_list.get_contact(account)
    psk_file = ask_path_gui(f"Select PSK for {contact.nick}", settings, get_file=True)

    with open(psk_file, 'rb') as f:
        psk_data = f.read()

    if len(psk_data) != PSK_FILE_SIZE:
        raise FunctionReturn("Error: Invalid PSK data in file.")

    salt   = psk_data[:ARGON2_SALT_LEN]
    ct_tag = psk_data[ARGON2_SALT_LEN:]

    while True:
        try:
            password = MasterKey.get_password("PSK password")
            phase("Deriving key decryption key", head=2)
            kdk, _  = argon2_kdf(password, salt, parallelism=1)
            psk_pt  = auth_and_decrypt(ct_tag, key=kdk, soft_e=True)
            phase(DONE)
            break

        except nacl.exceptions.CryptoError:
            print_on_previous_line()
            c_print("Invalid password. Try again.", head=1)
            print_on_previous_line(reps=5, delay=1.5)
        except KeyboardInterrupt:
            raise FunctionReturn("PSK import aborted.", head=2)

    rx_key = psk_pt[0:32]
    rx_hek = psk_pt[32:64]

    if any(k == bytes(KEY_LENGTH) for k in [rx_key, rx_hek]):
        raise FunctionReturn("Error: Received invalid keys from contact.")

    keyset        = key_list.get_keyset(account)
    keyset.rx_key = rx_key
    keyset.rx_hek = rx_hek
    key_list.store_keys()

    # Pipes protects against shell injection. Source of command's parameter
    # is user's own RxM and therefore trusted, but it's still good practice.
    subprocess.Popen(f"shred -n 3 -z -u {pipes.quote(psk_file)}", shell=True).wait()
    if os.path.isfile(psk_file):
        box_print(f"Warning! Overwriting of PSK ({psk_file}) failed. Press <Enter> to continue.", manual_proceed=True)

    local_win = window_list.get_local_window()
    message   = f"Added Rx-PSK for {contact.nick} ({account})."
    local_win.add_new(ts, message)

    box_print([message, '', "Warning!",
               "Physically destroy the keyfile transmission ",
               "media to ensure that no data escapes RxM!"], head=1, tail=1)
