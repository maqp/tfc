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
import time
import typing

from typing import Dict

import nacl.exceptions

from src.common.crypto       import argon2_kdf, auth_and_decrypt
from src.common.db_masterkey import MasterKey
from src.common.encoding     import b58encode
from src.common.errors       import FunctionReturn
from src.common.input        import get_b58_key
from src.common.misc         import clear_screen, split_string
from src.common.output       import box_print, c_print, phase, print_on_previous_line
from src.common.path         import ask_path_gui
from src.common.statics      import *

if typing.TYPE_CHECKING:
    from datetime               import datetime
    from src.common.db_contacts import ContactList
    from src.common.db_keys     import KeyList
    from src.common.db_settings import Settings
    from src.rx.windows         import WindowList


###############################################################################
#                                  LOCAL KEY                                  #
###############################################################################

def process_local_key(packet:       bytes,
                      contact_list: 'ContactList',
                      key_list:     'KeyList') -> None:
    """Decrypt local key packet, add local contact/keyset."""
    try:
        clear_screen()
        box_print(["Received encrypted local key"], tail=1)

        kdk = get_b58_key('localkey')

        try:
            pt = auth_and_decrypt(packet[1:], key=kdk, soft_e=True)
        except nacl.exceptions.CryptoError:
            raise FunctionReturn("Invalid key decryption key.", delay=1.5)

        key       = pt[0:32]
        hek       = pt[32:64]
        conf_code = pt[64:65]

        # Add local contact to contact list database
        contact_list.add_contact('local', 'local', 'local',
                                 bytes(32), bytes(32),
                                 False, False, True)

        # Add local contact to keyset database
        key_list.add_keyset('local', key, bytes(32), hek, bytes(32))
        box_print([f"Confirmation code for TxM: {conf_code.hex()}"], head=1)

    except KeyboardInterrupt:
        raise FunctionReturn("Local key setup aborted.", delay=1)


def local_key_installed(ts:           'datetime',
                        window_list:  'WindowList',
                        contact_list: 'ContactList') -> None:
    """Clear local key bootstrap process from screen."""
    local_win = window_list.get_window('local')
    local_win.print_new(ts, "Created a new local key.", print_=False)

    box_print(["Successfully added a new local key."])
    clear_screen(delay=1)

    if not contact_list.has_contacts():
        clear_screen()
        c_print("Waiting for new contacts", head=1, tail=1)


###############################################################################
#                                    X25519                                   #
###############################################################################

def process_public_key(ts:          'datetime',
                       packet:      bytes,
                       window_list: 'WindowList',
                       settings:    'Settings',
                       pubkey_buf:  Dict[str, str]) -> None:
    """Display public from contact."""
    pub_key = packet[1:33]
    origin  = packet[33:34]
    account = packet[34:].decode()

    if origin == ORIGIN_CONTACT_HEADER:
        pub_key_enc = b58encode(pub_key)
        ssl         = {48: 8, 49: 7, 50: 5}.get(len(pub_key_enc), 5)
        pub_key_enc = pub_key_enc if settings.local_testing_mode else ' '.join(split_string(pub_key_enc, item_len=ssl))

        pubkey_buf[account] = pub_key_enc

        box_print([f"Received public key from {account}", '', pubkey_buf[account]], head=1, tail=1)

        local_win = window_list.get_local_window()
        local_win.print_new(ts, f"Received public key from {account}: {pub_key_enc}", print_=False)

    if origin == ORIGIN_USER_HEADER and account in pubkey_buf:
        clear_screen()
        box_print([f"Public key for {account}", '', pubkey_buf[account]], head=1, tail=1)


def ecdhe_command(cmd_data:     bytes,
                  ts:           'datetime',
                  window_list:  'WindowList',
                  contact_list: 'ContactList',
                  key_list:     'KeyList',
                  settings:     'Settings',
                  pubkey_buf:   Dict[str, str]) -> None:
    """Add contact and it's X25519 keys."""
    tx_key = cmd_data[0:32]
    tx_hek = cmd_data[32:64]
    rx_key = cmd_data[64:96]
    rx_hek = cmd_data[96:128]

    account, nick = [f.decode() for f in cmd_data[128:].split(US_BYTE)]

    contact_list.add_contact(account, 'user_placeholder', nick,
                             bytes(32), bytes(32),
                             settings.log_msg_by_default,
                             settings.store_file_default,
                             settings.n_m_notify_privacy)

    key_list.add_keyset(account, tx_key, rx_key, tx_hek, rx_hek)

    pubkey_buf.pop(account, None)

    local_win = window_list.get_window('local')
    local_win.print_new(ts, f"Added X25519 keys for {nick} ({account}).", print_=False)

    box_print([f"Successfully added {nick}."])
    clear_screen(delay=1)


###############################################################################
#                                     PSK                                     #
###############################################################################

def psk_command(cmd_data:     bytes,
                ts:           'datetime',
                window_list:  'WindowList',
                contact_list: 'ContactList',
                key_list:     'KeyList',
                settings:     'Settings',
                pubkey_buf:   Dict[str, str]) -> None:
    """Add contact and tx-PSKs."""
    tx_key = cmd_data[0:32]
    tx_hek = cmd_data[32:64]

    account, nick = [f.decode() for f in cmd_data[64:].split(US_BYTE)]

    contact_list.add_contact(account, 'user_placeholder', nick,
                             bytes(32), bytes(32),
                             settings.log_msg_by_default,
                             settings.store_file_default,
                             settings.n_m_notify_privacy)

    # The Rx-side keys are set as null-byte strings to indicate they have not been added yet.
    key_list.add_keyset(account, tx_key, bytes(32), tx_hek, bytes(32))

    pubkey_buf.pop(account, None)

    local_win = window_list.get_window('local')
    local_win.print_new(ts, f"Added Tx-PSK for {nick} ({account}).", print_=False)

    box_print([f"Successfully added {nick}."])
    clear_screen(delay=1)


def psk_import(cmd_data:     bytes,
               ts:           'datetime',
               window_list:  'WindowList',
               contact_list: 'ContactList',
               key_list:     'KeyList',
               settings:     'Settings') -> None:
    """Import rx-PSK of contact."""
    account = cmd_data.decode()

    if not contact_list.has_contact(account):
        raise FunctionReturn(f"Unknown account {account}.")

    contact  = contact_list.get_contact(account)
    pskf     = ask_path_gui(f"Select PSK for {contact.nick}", settings, get_file=True)

    with open(pskf, 'rb') as f:
        psk_data = f.read()

    if len(psk_data) != 136:  # Nonce (24) + Salt (32) + rx-key (32) + rx-hek (32) + tag (16)
        raise FunctionReturn("Invalid PSK data in file.")

    salt   = psk_data[:32]
    ct_tag = psk_data[32:]

    while True:
        try:
            password = MasterKey.get_password("PSK password")
            phase("Deriving key decryption key", head=2)
            kdk, _ = argon2_kdf(password, salt, rounds=16, memory=128000, parallelism=1)
            psk_pt = auth_and_decrypt(ct_tag, key=kdk, soft_e=True)
            phase("Done")
            break

        except nacl.exceptions.CryptoError:
            print_on_previous_line()
            c_print("Invalid password. Try again.", head=1)
            print_on_previous_line(reps=5, delay=1.5)
        except KeyboardInterrupt:
            raise FunctionReturn("PSK import aborted.")

    rx_key = psk_pt[0:32]
    rx_hek = psk_pt[32:64]

    if rx_key == bytes(32) or rx_hek == bytes(32):
        raise FunctionReturn("Keys from contact are not valid.")

    keyset        = key_list.get_keyset(account)
    keyset.rx_key = rx_key
    keyset.rx_hek = rx_hek
    key_list.store_keys()

    # Pipes protects against shell injection. Source of command
    # is trusted (user's own TxM) but it's still good practice.
    subprocess.Popen("shred -n 3 -z -u {}".format(pipes.quote(pskf)), shell=True).wait()
    if os.path.isfile(pskf):
        box_print(f"Warning! Overwriting of PSK ({pskf}) failed.")
        time.sleep(3)

    local_win = window_list.get_local_window()
    local_win.print_new(ts, f"Added Rx-PSK for {contact.nick} ({account})", print_=False)

    box_print([f"Added Rx-PSK for {contact.nick}.", '', "Warning!",
               "Physically destroy the keyfile transmission ",
               "media to ensure that no data escapes RxM!"], head=1, tail=1)
