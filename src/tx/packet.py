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

import random
import time
import typing
import zlib

from typing import Dict

from src.common.crypto       import byte_padding, encrypt_and_sign, hash_chain
from src.common.encoding     import int_to_bytes
from src.common.errors       import CriticalError
from src.common.misc         import split_byte_string
from src.common.output       import c_print
from src.common.reed_solomon import RSCodec
from src.common.statics      import *

if typing.TYPE_CHECKING:
    from multiprocessing        import Queue
    from src.common.db_keys     import KeyList
    from src.common.db_settings import Settings
    from src.common.gateway     import Gateway
    from src.tx.user_input      import UserInput
    from src.tx.windows         import Window


def queue_command(payload:  bytes,
                  settings: 'Settings',
                  c_queue:  'Queue') -> None:
    """Split command into assembly packets and queue them.

    :param payload:  Command's plaintext string.
    :param settings: Settings object
    :param c_queue:  Multiprocessing queue for commands
    :return:         None
    """
    payload = zlib.compress(payload, level=9)

    if len(payload) < 255:
        padded      = byte_padding(payload)
        packet_list = [C_S_HEADER + padded]
    else:
        payload += hash_chain(payload)
        padded   = byte_padding(payload)
        p_list   = split_byte_string(padded, item_len=255)

        packet_list = ([C_L_HEADER + p_list[0]] +
                       [C_A_HEADER + p for p in p_list[1:-1]] +
                       [C_E_HEADER + p_list[-1]])

    if settings.session_trickle:
        for p in packet_list:
            c_queue.put(p)
    else:
        for p in packet_list:
            c_queue.put((p, settings))


def send_packet(packet: bytes,
                key_list:   'KeyList',
                settings:   'Settings',
                gateway:    'Gateway',
                l_queue:    'Queue',
                rx_account: str  = None,
                tx_account: str  = None,
                logging:    bool = None) -> None:
    """Encrypt and send assembly packet.

    Load keys from key database, encrypt assembly packet, add
    headers, send and optionally log the assembly packet.

    :param packet:     Padded plaintext assembly packet
    :param key_list:   Key list object
    :param settings:   Settings object
    :param gateway:    Gateway object
    :param l_queue:    Multiprocessing queue for logged messages
    :param rx_account: Recipient account
    :param tx_account: Sender's account associated with recipient's account
    :param logging:    When True, log the assembly packet
    :return:           None
    """
    if len(packet) != 256:
        raise CriticalError("Invalid assembly packet PT length.")

    if rx_account is None:
        keyset  = key_list.get_keyset('local')
        header  = COMMAND_PACKET_HEADER
        trailer = b''
    else:
        keyset  = key_list.get_keyset(rx_account)
        header  = MESSAGE_PACKET_HEADER
        trailer = tx_account.encode() + US_BYTE + rx_account.encode()

    harac_in_bytes    = int_to_bytes(keyset.tx_harac)
    encrypted_harac   = encrypt_and_sign(harac_in_bytes, keyset.tx_hek)
    encrypted_message = encrypt_and_sign(packet, keyset.tx_key)
    encrypted_packet  = header + encrypted_harac + encrypted_message + trailer
    transmit(encrypted_packet, settings, gateway)

    keyset.rotate_tx_key()

    if logging and rx_account is not None:
        l_queue.put((packet, rx_account, settings, key_list.master_key))


def transmit(packet: bytes, settings: 'Settings', gateway: 'Gateway') -> None:
    """Add Reed-Solomon erasure code and output packet via gateway."""
    rs     = RSCodec(2 * settings.session_ec_ratio)
    packet = rs.encode(packet)
    gateway.write(packet)

    if not settings.session_trickle:
        if settings.long_packet_rand_d:
            random_delay = random.SystemRandom().uniform(0, settings.max_val_for_rand_d)
            time.sleep(random_delay)


def cancel_packet(user_input: 'UserInput',
                  window:     'Window',
                  settings:   'Settings',
                  queues:     Dict[bytes, 'Queue']) -> None:
    """Cancel sent message/file to contact/group."""
    command   = user_input.plaintext
    queue     = dict(cm=queues[MESSAGE_PACKET_QUEUE], cf=queues[FILE_PACKET_QUEUE])[command]
    cancel_pt = dict(cm=M_C_HEADER,                   cf=F_C_HEADER )[command] + bytes(255)
    p_type    = dict(cm='messages',                   cf='files'    )[command]
    cancel    = False

    if settings.session_trickle:
        if not queue.empty():
            cancel = True
            while not queue.empty():
                queue.get()
            log_m_dictionary = dict((c.rx_account, c.log_messages) for c in window)
            queue.put((cancel_pt, log_m_dictionary))

        message = f"Cancelled queues {p_type}." if cancel else f"No {p_type} to cancel."
        c_print(message, head=1, tail=1)

    else:
        p_buffer = []

        while not queue.empty():
            packet, settings, rx_account, tx_account, logging, win = queue.get()

            # Put messages unrelated to active window into buffer
            if win != window.uid:
                p_buffer.append((packet, settings, rx_account, tx_account, logging, win))
            else:
                cancel = True

        # Put cancel packets for each window contact to queue first
        if cancel:
            for c in window:
                print('put cancel packet to queue')
                queue.put((cancel_pt, settings, c.rx_account, c.tx_account, c.log_messages, window.uid))

        # Put buffered tuples back to queue
        for p in p_buffer:
            queue.put(p)

        if cancel:
            message = f"Cancelled queued {p_type} to {window.type} {window.name}."
        else:
            message = f"No {p_type} queued for {window.type} {window.name}"

        c_print(message, head=1, tail=1)
