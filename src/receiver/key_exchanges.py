#!/usr/bin/env python3.7
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
import pipes
import readline
import struct
import subprocess
import tkinter
import typing

from typing import List, Tuple

import nacl.exceptions

from src.common.crypto       import argon2_kdf, auth_and_decrypt, blake2b, csprng
from src.common.db_masterkey import MasterKey
from src.common.encoding     import b58encode, bytes_to_str, pub_key_to_short_address
from src.common.exceptions   import FunctionReturn
from src.common.input        import get_b58_key
from src.common.misc         import separate_header, separate_headers
from src.common.output       import m_print, phase, print_on_previous_line
from src.common.path         import ask_path_gui
from src.common.statics      import (ARGON2_PSK_MEMORY_COST, ARGON2_PSK_PARALLELISM, ARGON2_PSK_TIME_COST,
                                     ARGON2_SALT_LENGTH, B58_LOCAL_KEY, CONFIRM_CODE_LENGTH, DONE, FINGERPRINT_LENGTH,
                                     KEX_STATUS_HAS_RX_PSK, KEX_STATUS_LOCAL_KEY, KEX_STATUS_NONE, KEX_STATUS_NO_RX_PSK,
                                     LOCAL_NICK, LOCAL_PUBKEY, ONION_SERVICE_PUBLIC_KEY_LENGTH, PSK_FILE_SIZE, RESET,
                                     SYMMETRIC_KEY_LENGTH, WIN_TYPE_CONTACT, WIN_TYPE_GROUP)

if typing.TYPE_CHECKING:
    from datetime               import datetime
    from multiprocessing        import Queue
    from src.common.db_contacts import ContactList
    from src.common.db_keys     import KeyList
    from src.common.db_settings import Settings
    from src.receiver.windows   import WindowList


# Local key

def process_local_key(ts:            'datetime',
                      packet:        bytes,
                      window_list:   'WindowList',
                      contact_list:  'ContactList',
                      key_list:      'KeyList',
                      settings:      'Settings',
                      kdk_hashes:     List[bytes],
                      packet_hashes:  List[bytes],
                      l_queue:        'Queue[Tuple[datetime, bytes]]'
                      ) -> None:
    """Decrypt local key packet and add local contact/keyset."""
    bootstrap = not key_list.has_local_keyset()
    plaintext = None

    try:
        packet_hash = blake2b(packet)

        # Check if the packet is an old one
        if packet_hash in packet_hashes:
            raise FunctionReturn("Error: Received old local key packet.", output=False)

        while True:
            m_print("Local key setup", bold=True, head_clear=True, head=1, tail=1)
            kdk      = get_b58_key(B58_LOCAL_KEY, settings)
            kdk_hash = blake2b(kdk)

            try:
                plaintext = auth_and_decrypt(packet, kdk)
                break
            except nacl.exceptions.CryptoError:
                # Check if key was an old one
                if kdk_hash in kdk_hashes:
                    m_print("Error: Entered an old local key decryption key.", delay=1)
                    continue

                # Check if the kdk was for a packet further ahead in the queue
                buffer = []  # type: List[Tuple[datetime, bytes]]
                while l_queue.qsize() > 0:
                    tup = l_queue.get()  # type: Tuple[datetime, bytes]
                    if tup not in buffer:
                        buffer.append(tup)

                for i, tup in enumerate(buffer):
                    try:
                        plaintext = auth_and_decrypt(tup[1], kdk)

                        # If we reach this point, decryption was successful.
                        for unexamined in buffer[i+1:]:
                            l_queue.put(unexamined)
                        buffer = []
                        ts     = tup[0]
                        break

                    except nacl.exceptions.CryptoError:
                        continue
                else:
                    # Finished the buffer without finding local key CT
                    # for the kdk. Maybe the kdk is from another session.
                    raise FunctionReturn("Error: Incorrect key decryption key.", delay=1)

            break

        # This catches PyCharm's weird claim that plaintext might be referenced before assignment
        if plaintext is None:  # pragma: no cover
            raise FunctionReturn("Error: Could not decrypt local key.")

        # Add local contact to contact list database
        contact_list.add_contact(LOCAL_PUBKEY,
                                 LOCAL_NICK,
                                 KEX_STATUS_LOCAL_KEY,
                                 bytes(FINGERPRINT_LENGTH),
                                 bytes(FINGERPRINT_LENGTH),
                                 False, False, True)

        tx_mk, tx_hk, c_code = separate_headers(plaintext, 2 * [SYMMETRIC_KEY_LENGTH])

        # Add local keyset to keyset database
        key_list.add_keyset(onion_pub_key=LOCAL_PUBKEY,
                            tx_mk=tx_mk,
                            rx_mk=csprng(),
                            tx_hk=tx_hk,
                            rx_hk=csprng())

        # Cache hashes needed to recognize reissued local key packets and key decryption keys.
        packet_hashes.append(packet_hash)
        kdk_hashes.append(kdk_hash)

        # Prevent leak of KDK via terminal history / clipboard
        readline.clear_history()
        os.system(RESET)
        root = tkinter.Tk()
        root.withdraw()
        try:
            if root.clipboard_get() == b58encode(kdk):  # type: ignore
                root.clipboard_clear()                  # type: ignore
        except tkinter.TclError:
            pass
        root.destroy()

        m_print(["Local key successfully installed.",
                f"Confirmation code (to Transmitter): {c_code.hex()}"], box=True, head=1)

        local_win = window_list.get_local_window()
        local_win.add_new(ts, "Added new local key.")

        if bootstrap:
            window_list.active_win = local_win

    except (EOFError, KeyboardInterrupt):
        m_print("Local key setup aborted.", bold=True, tail_clear=True, delay=1, head=2)

        if window_list.active_win is not None and not bootstrap:
            window_list.active_win.redraw()

        raise FunctionReturn("Local key setup aborted.", output=False)


def local_key_rdy(ts:           'datetime',
                  window_list:  'WindowList',
                  contact_list: 'ContactList') -> None:
    """Clear local key bootstrap process from the screen."""
    message   = "Successfully completed the local key setup."
    local_win = window_list.get_local_window()
    local_win.add_new(ts, message)

    m_print(message, bold=True, tail_clear=True, delay=1)

    if contact_list.has_contacts():
        if window_list.active_win is not None and window_list.active_win.type in [WIN_TYPE_CONTACT, WIN_TYPE_GROUP]:
            window_list.active_win.redraw()
    else:
        m_print("Waiting for new contacts", bold=True, head=1, tail=1)


# ECDHE

def key_ex_ecdhe(packet:       bytes,
                 ts:           'datetime',
                 window_list:  'WindowList',
                 contact_list: 'ContactList',
                 key_list:     'KeyList',
                 settings:     'Settings'
                 ) -> None:
    """Add contact and symmetric keys derived from X448 shared key."""

    onion_pub_key, tx_mk, rx_mk, tx_hk, rx_hk, nick_bytes \
        = separate_headers(packet, [ONION_SERVICE_PUBLIC_KEY_LENGTH] + 4*[SYMMETRIC_KEY_LENGTH])

    try:
        nick = bytes_to_str(nick_bytes)
    except (struct.error, UnicodeError):
        raise FunctionReturn("Error: Received invalid contact data")

    contact_list.add_contact(onion_pub_key, nick,
                             bytes(FINGERPRINT_LENGTH),
                             bytes(FINGERPRINT_LENGTH),
                             KEX_STATUS_NONE,
                             settings.log_messages_by_default,
                             settings.accept_files_by_default,
                             settings.show_notifications_by_default)

    key_list.add_keyset(onion_pub_key, tx_mk, rx_mk, tx_hk, rx_hk)

    message   = f"Successfully added {nick}."
    local_win = window_list.get_local_window()
    local_win.add_new(ts, message)

    c_code = blake2b(onion_pub_key, digest_size=CONFIRM_CODE_LENGTH)
    m_print([message, f"Confirmation code (to Transmitter): {c_code.hex()}"], box=True)


# PSK

def key_ex_psk_tx(packet:       bytes,
                  ts:           'datetime',
                  window_list:  'WindowList',
                  contact_list: 'ContactList',
                  key_list:     'KeyList',
                  settings:     'Settings'
                  ) -> None:
    """Add contact and Tx-PSKs."""

    onion_pub_key, tx_mk, _, tx_hk, _, nick_bytes \
        = separate_headers(packet, [ONION_SERVICE_PUBLIC_KEY_LENGTH] + 4*[SYMMETRIC_KEY_LENGTH])

    try:
        nick = bytes_to_str(nick_bytes)
    except (struct.error, UnicodeError):
        raise FunctionReturn("Error: Received invalid contact data")

    contact_list.add_contact(onion_pub_key, nick,
                             bytes(FINGERPRINT_LENGTH),
                             bytes(FINGERPRINT_LENGTH),
                             KEX_STATUS_NO_RX_PSK,
                             settings.log_messages_by_default,
                             settings.accept_files_by_default,
                             settings.show_notifications_by_default)

    # The Rx-side keys are set as null-byte strings to indicate they have not
    # been added yet. The zero-keys do not allow existential forgeries as
    # `decrypt_assembly_packet`does not allow the use of zero-keys for decryption.
    key_list.add_keyset(onion_pub_key=onion_pub_key,
                        tx_mk=tx_mk,
                        rx_mk=bytes(SYMMETRIC_KEY_LENGTH),
                        tx_hk=tx_hk,
                        rx_hk=bytes(SYMMETRIC_KEY_LENGTH))

    c_code    = blake2b(onion_pub_key, digest_size=CONFIRM_CODE_LENGTH)
    message   = f"Added Tx-side PSK for {nick} ({pub_key_to_short_address(onion_pub_key)})."
    local_win = window_list.get_local_window()
    local_win.add_new(ts, message)

    m_print([message, f"Confirmation code (to Transmitter): {c_code.hex()}"], box=True)


def key_ex_psk_rx(packet:       bytes,
                  ts:           'datetime',
                  window_list:  'WindowList',
                  contact_list: 'ContactList',
                  key_list:     'KeyList',
                  settings:     'Settings'
                  ) -> None:
    """Import Rx-PSK of contact."""
    c_code, onion_pub_key = separate_header(packet, CONFIRM_CODE_LENGTH)
    short_addr            = pub_key_to_short_address(onion_pub_key)

    if not contact_list.has_pub_key(onion_pub_key):
        raise FunctionReturn(f"Error: Unknown account '{short_addr}'.", head_clear=True)

    contact  = contact_list.get_contact_by_pub_key(onion_pub_key)
    psk_file = ask_path_gui(f"Select PSK for {contact.nick} ({short_addr})", settings, get_file=True)

    try:
        with open(psk_file, 'rb') as f:
            psk_data = f.read()
    except PermissionError:
        raise FunctionReturn("Error: No read permission for the PSK file.")

    if len(psk_data) != PSK_FILE_SIZE:
        raise FunctionReturn("Error: The PSK data in the file was invalid.", head_clear=True)

    salt, ct_tag = separate_header(psk_data, ARGON2_SALT_LENGTH)

    while True:
        try:
            password = MasterKey.get_password("PSK password")
            phase("Deriving the key decryption key", head=2)
            kdk = argon2_kdf(password, salt, ARGON2_PSK_TIME_COST, ARGON2_PSK_MEMORY_COST, ARGON2_PSK_PARALLELISM)
            psk = auth_and_decrypt(ct_tag, kdk)
            phase(DONE)
            break

        except nacl.exceptions.CryptoError:
            print_on_previous_line()
            m_print("Invalid password. Try again.", head=1)
            print_on_previous_line(reps=5, delay=1)
        except (EOFError, KeyboardInterrupt):
            raise FunctionReturn("PSK import aborted.", head=2, delay=1, tail_clear=True)

    rx_mk, rx_hk = separate_header(psk, SYMMETRIC_KEY_LENGTH)

    if any(k == bytes(SYMMETRIC_KEY_LENGTH) for k in [rx_mk, rx_hk]):
        raise FunctionReturn("Error: Received invalid keys from contact.", head_clear=True)

    keyset       = key_list.get_keyset(onion_pub_key)
    keyset.rx_mk = rx_mk
    keyset.rx_hk = rx_hk
    key_list.store_keys()

    contact.kex_status = KEX_STATUS_HAS_RX_PSK
    contact_list.store_contacts()

    # Pipes protects against shell injection. Source of command's parameter is
    # the program itself, and therefore trusted, but it's still good practice.
    subprocess.Popen(f"shred -n 3 -z -u {pipes.quote(psk_file)}", shell=True).wait()
    if os.path.isfile(psk_file):
        m_print(f"Warning! Overwriting of PSK ({psk_file}) failed. Press <Enter> to continue.",
                manual_proceed=True, box=True)

    message   = f"Added Rx-side PSK for {contact.nick} ({short_addr})."
    local_win = window_list.get_local_window()
    local_win.add_new(ts, message)

    m_print([message, '', "Warning!",
             "Physically destroy the keyfile transmission media ",
             "to ensure it does not steal data from this computer!", '',
             f"Confirmation code (to Transmitter): {c_code.hex()}"], box=True, head=1, tail=1)
