#!/usr/bin/env python3.7
# -*- coding: utf-8 -*-

"""
TFC - Onion-routed, endpoint secure messaging system
Copyright (C) 2013-2020  Markus Ottela

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

from datetime import datetime
from typing   import List, Tuple

import nacl.exceptions

from src.common.crypto       import argon2_kdf, auth_and_decrypt, blake2b, csprng
from src.common.db_masterkey import MasterKey
from src.common.encoding     import b58encode, bytes_to_str, pub_key_to_short_address
from src.common.exceptions   import SoftError
from src.common.input        import get_b58_key
from src.common.misc         import reset_terminal, separate_header, separate_headers
from src.common.output       import m_print, phase, print_on_previous_line
from src.common.path         import ask_path_gui
from src.common.statics      import (ARGON2_PSK_MEMORY_COST, ARGON2_PSK_PARALLELISM, ARGON2_PSK_TIME_COST,
                                     ARGON2_SALT_LENGTH, B58_LOCAL_KEY, CONFIRM_CODE_LENGTH, DONE, FINGERPRINT_LENGTH,
                                     KEX_STATUS_HAS_RX_PSK, KEX_STATUS_LOCAL_KEY, KEX_STATUS_NONE, KEX_STATUS_NO_RX_PSK,
                                     LOCAL_NICK, LOCAL_PUBKEY, ONION_SERVICE_PUBLIC_KEY_LENGTH, PSK_FILE_SIZE,
                                     SYMMETRIC_KEY_LENGTH, WIN_TYPE_CONTACT, WIN_TYPE_GROUP)

if typing.TYPE_CHECKING:
    from multiprocessing        import Queue
    from src.common.db_contacts import ContactList
    from src.common.db_keys     import KeyList
    from src.common.db_settings import Settings
    from src.receiver.windows   import WindowList

    local_key_queue = Queue[Tuple[datetime, bytes]]


# Local key

def protect_kdk(kdk: bytes) -> None:
    """Prevent leak of KDK via terminal history / clipboard."""
    readline.clear_history()
    reset_terminal()
    root = tkinter.Tk()
    root.withdraw()

    try:
        if root.clipboard_get() == b58encode(kdk):  # type: ignore
            root.clipboard_clear()  # type: ignore
    except tkinter.TclError:
        pass

    root.destroy()


def process_local_key_buffer(kdk:     bytes,
                             l_queue: 'local_key_queue'
                             ) -> Tuple[datetime, bytes]:
    """Check if the KDK was for a packet further ahead in the queue."""
    buffer = []  # type: List[Tuple[datetime, bytes]]
    while l_queue.qsize() > 0:
        tup = l_queue.get()  # type: Tuple[datetime, bytes]
        if tup not in buffer:
            buffer.append(tup)

    for i, tup in enumerate(buffer):
        try:
            plaintext = auth_and_decrypt(tup[1], kdk)

            # If we reach this point, decryption was successful.
            for unexamined in buffer[i + 1:]:
                l_queue.put(unexamined)
            buffer = []
            ts     = tup[0]

            return ts, plaintext

        except nacl.exceptions.CryptoError:
            continue

    # Finished the buffer without finding local key CT
    # for the kdk. Maybe the kdk is from another session.
    raise SoftError("Error: Incorrect key decryption key.", delay=1)


def decrypt_local_key(ts:            'datetime',
                      packet:        bytes,
                      kdk_hashes:    List[bytes],
                      packet_hashes: List[bytes],
                      settings:      'Settings',
                      l_queue:       'local_key_queue'
                      ) -> Tuple['datetime', bytes]:
    """Decrypt local key packet."""
    while True:
        kdk      = get_b58_key(B58_LOCAL_KEY, settings)
        kdk_hash = blake2b(kdk)

        # Check if the key was an old one.
        if kdk_hash in kdk_hashes:
            m_print("Error: Entered an old local key decryption key.", delay=1)
            continue

        try:
            plaintext = auth_and_decrypt(packet, kdk)
        except nacl.exceptions.CryptoError:
            ts, plaintext = process_local_key_buffer(kdk, l_queue)

        protect_kdk(kdk)

        # Cache hashes needed to recognize reissued local key packets and key decryption keys.
        kdk_hashes.append(kdk_hash)
        packet_hashes.append(blake2b(packet))

        return ts, plaintext


def process_local_key(ts:            'datetime',
                      packet:        bytes,
                      window_list:   'WindowList',
                      contact_list:  'ContactList',
                      key_list:      'KeyList',
                      settings:      'Settings',
                      kdk_hashes:    List[bytes],
                      packet_hashes: List[bytes],
                      l_queue:       'Queue[Tuple[datetime, bytes]]'
                      ) -> None:
    """Decrypt local key packet and add local contact/keyset."""
    first_local_key = not key_list.has_local_keyset()

    try:
        if blake2b(packet) in packet_hashes:
            raise SoftError("Error: Received old local key packet.", output=False)

        m_print("Local key setup", bold=True, head_clear=True, head=1, tail=1)

        ts, plaintext = decrypt_local_key(ts, packet, kdk_hashes, packet_hashes, settings, l_queue)

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

        m_print(["Local key successfully installed.", f"Confirmation code (to Transmitter): {c_code.hex()}"],
                box=True, head=1)

        cmd_win = window_list.get_command_window()

        if first_local_key:
            window_list.active_win = cmd_win

        raise SoftError("Added new local key.", window=cmd_win, ts=ts, output=False)

    except (EOFError, KeyboardInterrupt):
        m_print("Local key setup aborted.", bold=True, tail_clear=True, delay=1, head=2)

        if window_list.active_win is not None and not first_local_key:
            window_list.active_win.redraw()

        raise SoftError("Local key setup aborted.", output=False)


def local_key_rdy(ts:           'datetime',
                  window_list:  'WindowList',
                  contact_list: 'ContactList'
                  ) -> None:
    """Clear local key bootstrap process from the screen."""
    message = "Successfully completed the local key setup."
    cmd_win = window_list.get_command_window()
    cmd_win.add_new(ts, message)

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
        raise SoftError("Error: Received invalid contact data")

    contact_list.add_contact(onion_pub_key, nick,
                             bytes(FINGERPRINT_LENGTH),
                             bytes(FINGERPRINT_LENGTH),
                             KEX_STATUS_NONE,
                             settings.log_messages_by_default,
                             settings.accept_files_by_default,
                             settings.show_notifications_by_default)

    key_list.add_keyset(onion_pub_key, tx_mk, rx_mk, tx_hk, rx_hk)

    message = f"Successfully added {nick}."
    cmd_win = window_list.get_command_window()
    cmd_win.add_new(ts, message)

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
        raise SoftError("Error: Received invalid contact data")

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

    c_code  = blake2b(onion_pub_key, digest_size=CONFIRM_CODE_LENGTH)
    message = f"Added Tx-side PSK for {nick} ({pub_key_to_short_address(onion_pub_key)})."
    cmd_win = window_list.get_command_window()
    cmd_win.add_new(ts, message)

    m_print([message, f"Confirmation code (to Transmitter): {c_code.hex()}"], box=True)


def decrypt_rx_psk(ct_tag: bytes, salt: bytes) -> bytes:
    """Get PSK password from user and decrypt Rx-PSK."""
    while True:
        try:
            password = MasterKey.get_password("PSK password")
            phase("Deriving the key decryption key", head=2)
            kdk = argon2_kdf(password, salt, ARGON2_PSK_TIME_COST, ARGON2_PSK_MEMORY_COST, ARGON2_PSK_PARALLELISM)
            psk = auth_and_decrypt(ct_tag, kdk)
            phase(DONE)
            return psk

        except nacl.exceptions.CryptoError:
            print_on_previous_line()
            m_print("Invalid password. Try again.", head=1)
            print_on_previous_line(reps=5, delay=1)
        except (EOFError, KeyboardInterrupt):
            raise SoftError("PSK import aborted.", head=2, delay=1, tail_clear=True)


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
        raise SoftError(f"Error: Unknown account '{short_addr}'.", head_clear=True)

    contact  = contact_list.get_contact_by_pub_key(onion_pub_key)
    psk_file = ask_path_gui(f"Select PSK for {contact.nick} ({short_addr})", settings, get_file=True)

    try:
        with open(psk_file, 'rb') as f:
            psk_data = f.read()
    except PermissionError:
        raise SoftError("Error: No read permission for the PSK file.")

    if len(psk_data) != PSK_FILE_SIZE:
        raise SoftError("Error: The PSK data in the file was invalid.", head_clear=True)

    salt, ct_tag = separate_header(psk_data, ARGON2_SALT_LENGTH)
    psk          = decrypt_rx_psk(ct_tag, salt)
    rx_mk, rx_hk = separate_header(psk, SYMMETRIC_KEY_LENGTH)

    if any(k == bytes(SYMMETRIC_KEY_LENGTH) for k in [rx_mk, rx_hk]):
        raise SoftError("Error: Received invalid keys from contact.", head_clear=True)

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

    message = f"Added Rx-side PSK for {contact.nick} ({short_addr})."
    cmd_win = window_list.get_command_window()
    cmd_win.add_new(ts, message)

    m_print([message, '', "Warning!",
             "Physically destroy the keyfile transmission media ",
             "to ensure it does not steal data from this computer!", '',
             f"Confirmation code (to Transmitter): {c_code.hex()}"], box=True, head=1, tail=1)
