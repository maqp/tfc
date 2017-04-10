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

import os
import typing

from typing import Dict

import nacl.encoding
import nacl.public

from src.common.crypto       import argon2_kdf, encrypt_and_sign, hash_chain, keygen
from src.common.db_masterkey import MasterKey
from src.common.encoding     import b58encode
from src.common.errors       import FunctionReturn
from src.common.input        import get_b58_key, nh_bypass_msg, yes
from src.common.misc         import clear_screen, get_tty_w, split_string
from src.common.output       import box_print, c_print, message_printer, phase, print_fingerprints, print_on_previous_line
from src.common.path         import ask_path_gui
from src.common.statics      import *
from src.tx.packet           import queue_command, transmit

if typing.TYPE_CHECKING:
    from multiprocessing        import Queue
    from src.common.db_contacts import ContactList
    from src.common.db_settings import Settings
    from src.common.gateway     import Gateway
    from src.tx.windows         import Window


###############################################################################
#                                  LOCAL KEY                                  #
###############################################################################

def ask_confirmation_code() -> str:
    """Ask user to input confirmation code from RxM to verify local key has been installed."""
    title = "Enter confirmation code (from RxM): "

    upper_line = ('┌' + (len(title) + 8) * '─' + '┐')
    title_line = ('│' +      title  + 8  * ' ' + '│')
    lower_line = ('└' + (len(title) + 8) * '─' + '┘')

    ttyw = get_tty_w()

    upper_line = upper_line.center(ttyw)
    title_line = title_line.center(ttyw)
    lower_line = lower_line.center(ttyw)

    print(upper_line)
    print(title_line)
    print(lower_line)
    print(3 * CURSOR_UP_ONE_LINE)

    indent = title_line.find('│')
    return input(indent * ' ' + f'│ {title}')


def print_kdk(kdk_bytes: bytes, settings: 'Settings') -> None:
    """Print symmetric key decryption key.

    If local testing is not enabled, this function will add spacing between
    key decryption key to help user keep track of key typing progress. The
    length of the Base58 encoded key varies between 48..50 characters, thus
    spacing is adjusted to get even length for each substring.

    :param kdk_bytes: Key decryption key
    :param settings:  Settings object
    :return:          None
    """
    kdk_enc = b58encode(kdk_bytes)
    ssl     = {48: 8, 49: 7, 50: 5}.get(len(kdk_enc), 5)
    kdk     = kdk_enc if settings.local_testing_mode else ' '.join(split_string(kdk_enc, item_len=ssl))

    box_print(["Local key decryption key (to RxM)", kdk])


def new_local_key(contact_list: 'ContactList',
                  settings:     'Settings',
                  queues:       Dict[bytes, 'Queue'],
                  gateway:      'Gateway') -> None:
    """Run local key agreement protocol.

    Local key encrypts commands and data sent from TxM to RxM. The key is
    delivered to RxM in packet encrypted with an ephemeral symmetric key.
    The checksummed Base58 format decryption key is typed on RxM manually.
    """
    try:
        if contact_list.has_local_contact and settings.session_trickle:
            raise FunctionReturn("Command disabled during trickle connection.")

        clear_screen()
        c_print("Local key setup", head=1, tail=1)

        conf_code = os.urandom(1)
        key       = keygen()
        hek       = keygen()
        kek       = keygen()
        packet    = LOCAL_KEY_PACKET_HEADER + encrypt_and_sign(key + hek + conf_code, key=kek)

        nh_bypass_msg('start', settings)
        transmit(packet, settings, gateway)

        while True:
            print_kdk(kek, settings)
            purp_code = ask_confirmation_code()
            if purp_code == conf_code.hex():
                print('')
                break
            elif purp_code == 'resend':
                phase("Resending local key", head=2)
                transmit(packet, settings, gateway)
                phase('Done')
                print_on_previous_line(reps=9)
            else:
                box_print(["Incorrect confirmation code. If RxM did not receive",
                           "encrypted local key, resend it by typing 'resend'."], head=1)
                print_on_previous_line(reps=11, delay=2)

        nh_bypass_msg('finish', settings)

        # Add local contact to contact list database
        contact_list.add_contact('local', 'local', 'local',
                                 bytes(32), bytes(32),
                                 False, False, False)

        # Add local contact to keyset database
        queues[KEY_MANAGEMENT_QUEUE].put(('ADD', 'local', key, bytes(32), hek, bytes(32)))

        # Notify RxM that confirmation code was successfully entered.
        queue_command(LOCAL_KEY_INSTALLED_HEADER, settings, queues[COMMAND_PACKET_QUEUE])

        box_print(["Successfully added a new local key."])
        clear_screen(delay=1)

    except KeyboardInterrupt:
        raise FunctionReturn("Local key setup aborted.", delay=1)


###############################################################################
#                                    X25519                                   #
###############################################################################

def verify_fingerprints(tx_fp: bytes, rx_fp: bytes) -> bool:
    """Verify fingerprints over off-band channel to detect MITM attacks between NHs.

    :param tx_fp: User's fingerprint
    :param rx_fp: Contact's fingerprint
    :return:      True if fingerprints match, else False
    """
    clear_screen()

    message_printer("To verify the public key was not swapped during delivery, "
                    "call your contact over end-to-end encrypted line, preferably "
                    "Signal by Open Whisper Systems. Verify call's Short "
                    "Authentication String and then compare fingerprints below.", head=1, tail=1)

    print_fingerprints(tx_fp, "         Your fingerprint (you read)         ")
    print_fingerprints(rx_fp, "Purported fingerprint for contact (they read)")

    return yes("Is the contact's fingerprint correct?")


def start_key_exchange(account:      str,
                       user:         str,
                       nick:         str,
                       contact_list: 'ContactList',
                       settings:     'Settings',
                       queues:       Dict[bytes, 'Queue'],
                       gateway:      'Gateway') -> None:
    """Start X25519 key exchange with recipient.

    Variable naming:

        tx     = user's key                 rx  = contact's key
        sk     = private (secret) key       pk  = public key
        key    = message key                hek = header key
        dh_ssk = DH shared secret

    :param account:      The contact's account name (e.g. alice@jabber.org)
    :param user:         The user's account name (e.g. bob@jabber.org)
    :param nick:         Contact's nickname
    :param contact_list: Contact list object
    :param settings:     Settings object
    :param queues:       Dictionary of multiprocessing queues
    :param gateway:      Gateway object
    :return:             None
    """
    try:
        tx_sk = nacl.public.PrivateKey.generate()
        tx_pk = bytes(tx_sk.public_key)

        transmit(PUBLIC_KEY_PACKET_HEADER
                 + tx_pk
                 + user.encode()
                 + US_BYTE
                 + account.encode(),
                 settings, gateway)

        rx_pk  = nacl.public.PublicKey(get_b58_key('pubkey'))
        dh_box = nacl.public.Box(tx_sk, rx_pk)
        dh_ssk = dh_box.shared_key()
        rx_pk  = bytes(rx_pk)

        # Domain separate each key with key-type specific byte-string and
        # with public keys that both clients know which way to place.
        tx_key = hash_chain(dh_ssk + rx_pk + b'message_key')
        rx_key = hash_chain(dh_ssk + tx_pk + b'message_key')

        tx_hek = hash_chain(dh_ssk + rx_pk + b'header_key')
        rx_hek = hash_chain(dh_ssk + tx_pk + b'header_key')

        # Domain separate fingerprints of public keys by using the shared
        # secret as salt. This way entities who might monitor fingerprint
        # verification channel are unable to correlate spoken values with
        # public keys that transit through a compromised IM server. This
        # protects against deanonymization of IM accounts in cases where
        # clients connect to the compromised server via Tor.
        tx_fp  = hash_chain(dh_ssk + tx_pk + b'fingerprint')
        rx_fp  = hash_chain(dh_ssk + rx_pk + b'fingerprint')

        if not verify_fingerprints(tx_fp, rx_fp):
            box_print(["Possible man-in-the-middle attack detected.",
                       "Aborting key exchange for your safety."], tail=1)
            raise FunctionReturn("Fingerprint mismatch", output=False, delay=2.5)

        packet = KEY_EX_ECDHE_HEADER \
                 + tx_key + tx_hek \
                 + rx_key + rx_hek \
                 + account.encode() + US_BYTE + nick.encode()

        queue_command(packet, settings, queues[COMMAND_PACKET_QUEUE])

        contact_list.add_contact(account, user, nick,
                                 tx_fp, rx_fp,
                                 settings.log_msg_by_default,
                                 settings.store_file_default,
                                 settings.n_m_notify_privacy)

        # Null-bytes below are fillers for Rx-keys not used by TxM.
        queues[KEY_MANAGEMENT_QUEUE].put(('ADD', account, tx_key, bytes(32), tx_hek, bytes(32)))

        box_print([f"Successfully added {nick}."])
        clear_screen(delay=1)

    except KeyboardInterrupt:
        raise FunctionReturn("Key exchange aborted.", delay=1)


###############################################################################
#                                     PSK                                     #
###############################################################################

def new_psk(account:      str,
            user:         str,
            nick:         str,
            contact_list: 'ContactList',
            settings:     'Settings',
            queues:       Dict[bytes, 'Queue']) -> None:
    """Generate new pre-shared key for manual key delivery.

    :param account:      The contact's account name (e.g. alice@jabber.org)
    :param user:         The user's account name (e.g. bob@jabber.org)
    :param nick:         Nick of contact
    :param contact_list: Contact list object
    :param settings:     Settings object
    :param queues:       Dictionary of multiprocessing queues
    :return:             None
    """
    try:
        tx_key   = keygen()
        tx_hek   = keygen()
        salt     = keygen()
        password = MasterKey.new_password("password for PSK")

        phase("Deriving key encryption key", head=2)
        kek, _ = argon2_kdf(password, salt, rounds=16, memory=128000, parallelism=1)
        phase('Done')

        ct_tag  = encrypt_and_sign(tx_key + tx_hek, key=kek)
        store_d = ask_path_gui(f"Select removable media for {nick}", settings)
        f_name  = f"{store_d}/{user}.psk - Give to {account}"

        try:
            with open(f_name, 'wb+') as f:
                f.write(salt + ct_tag)
        except PermissionError:
            raise FunctionReturn("Error: Did not have permission to write to directory.")

        packet = KEY_EX_PSK_TX_HEADER \
                 + tx_key \
                 + tx_hek \
                 + account.encode() + US_BYTE +  nick.encode()

        queue_command(packet, settings, queues[COMMAND_PACKET_QUEUE])

        contact_list.add_contact(account, user, nick,
                                 bytes(32), bytes(32),
                                 settings.log_msg_by_default,
                                 settings.store_file_default,
                                 settings.n_m_notify_privacy)

        queues[KEY_MANAGEMENT_QUEUE].put(('ADD', account, tx_key, bytes(32), tx_hek, bytes(32)))

        box_print([f"Successfully added {nick}."], head=1)
        clear_screen(delay=1)

    except KeyboardInterrupt:
        raise FunctionReturn("PSK generation aborted.")


def rxm_load_psk(window:       'Window',
                 contact_list: 'ContactList',
                 settings:     'Settings',
                 c_queue:      'Queue') -> None:
    """Load PSK for selected contact on RxM."""
    if settings.session_trickle:
        raise FunctionReturn("Command disabled during trickle connection.")

    if window.type == 'group':
        raise FunctionReturn("Group is selected.")

    if contact_list.get_contact(window.uid).tx_fingerprint != bytes(32):
        raise FunctionReturn("Current key was exchanged with X25519.")

    packet = KEY_EX_PSK_RX_HEADER + window.uid.encode()
    queue_command(packet, settings, c_queue)
