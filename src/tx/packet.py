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
import random
import time
import typing
import zlib

from typing import Dict, List, Union

from src.common.crypto       import byte_padding, csprng, encrypt_and_sign, hash_chain
from src.common.encoding     import int_to_bytes
from src.common.exceptions   import CriticalError, FunctionReturn
from src.common.input        import yes
from src.common.misc         import split_byte_string
from src.common.output       import c_print
from src.common.path         import ask_path_gui
from src.common.reed_solomon import RSCodec
from src.common.statics      import *

from src.tx.files import File

if typing.TYPE_CHECKING:
    from multiprocessing        import Queue
    from src.common.db_keys     import KeyList
    from src.common.db_settings import Settings
    from src.common.gateway     import Gateway
    from src.tx.user_input      import UserInput
    from src.tx.windows         import MockWindow, TxWindow


def queue_message(user_input: 'UserInput',
                  window:     Union['MockWindow', 'TxWindow'],
                  settings:   'Settings',
                  m_queue:    'Queue',
                  header:     bytes = b'',
                  log_as_ph:  bool  = False) -> None:
    """Prepend header, split to assembly packets and queue them."""
    if not header:
        if window.type == WIN_TYPE_GROUP:
            group_msg_id = os.urandom(GROUP_MSG_ID_LEN)
            header       = GROUP_MESSAGE_HEADER + group_msg_id + window.name.encode() + US_BYTE
        else:
            header = PRIVATE_MESSAGE_HEADER

    payload     = header + user_input.plaintext.encode()
    packet_list = split_to_assembly_packets(payload, MESSAGE)

    queue_packets(packet_list, MESSAGE, settings, m_queue, window, log_as_ph)


def queue_file(window:   'TxWindow',
               settings: 'Settings',
               f_queue:  'Queue',
               gateway:  'Gateway') -> None:
    """Ask file path and load file data."""
    path = ask_path_gui("Select file to send...", settings, get_file=True)
    file = File(path, window, settings, gateway)

    packet_list = split_to_assembly_packets(file.plaintext, FILE)

    if settings.confirm_sent_files:
        try:
            if not yes(f"Send {file.name.decode()} ({file.size_print}) to {window.type_print} {window.name} "
                       f"({len(packet_list)} packets, time: {file.time_print})?"):
                raise FunctionReturn("File selection aborted.")
        except KeyboardInterrupt:
            raise FunctionReturn("File selection aborted.", head=3)

    queue_packets(packet_list, FILE, settings, f_queue, window, log_as_ph=True)


def queue_command(command:  bytes,
                  settings: 'Settings',
                  c_queue:  'Queue',
                  window:   'TxWindow' = None) -> None:
    """Split command to assembly packets and queue them for sender_loop()."""
    packet_list = split_to_assembly_packets(command, COMMAND)

    queue_packets(packet_list, COMMAND, settings, c_queue, window)


def queue_to_nh(packet:   bytes,
                settings: 'Settings',
                nh_queue: 'Queue',
                delay:    bool = False) -> None:
    """Queue unencrypted command/exported file to NH."""
    nh_queue.put((packet, delay, settings))


def split_to_assembly_packets(payload: bytes, p_type: str) -> List[bytes]:
    """Split payload to assembly packets.

    Messages and commands are compressed to reduce transmission time.
    Files have been compressed at earlier phase, before B85 encoding.

    If the compressed message can not be sent over one packet, it is
    split into multiple assembly packets with headers. Long messages
    are encrypted with inner layer of XSalsa20-Poly1305 to provide
    sender based control over partially transmitted data. Regardless
    of packet size, files always have an inner layer of encryption,
    and it is added in earlier phase. Commands do not need
    sender-based control, so they are only delivered with hash that
    makes integrity check easy.

    First assembly packet in file transmission is prepended with 8-byte
    packet counter that tells sender and receiver how many packets the
    file transmission requires.
    """
    s_header = {MESSAGE: M_S_HEADER, FILE: F_S_HEADER, COMMAND: C_S_HEADER}[p_type]
    l_header = {MESSAGE: M_L_HEADER, FILE: F_L_HEADER, COMMAND: C_L_HEADER}[p_type]
    a_header = {MESSAGE: M_A_HEADER, FILE: F_A_HEADER, COMMAND: C_A_HEADER}[p_type]
    e_header = {MESSAGE: M_E_HEADER, FILE: F_E_HEADER, COMMAND: C_E_HEADER}[p_type]

    if p_type in [MESSAGE, COMMAND]:
        payload = zlib.compress(payload, level=COMPRESSION_LEVEL)

    if len(payload) < PADDING_LEN:
        padded      = byte_padding(payload)
        packet_list = [s_header + padded]

    else:
        if p_type == MESSAGE:
            msg_key = csprng()
            payload = encrypt_and_sign(payload, msg_key)
            payload += msg_key

        elif p_type == FILE:
            payload = bytes(FILE_PACKET_CTR_LEN) + payload

        elif p_type == COMMAND:
            payload += hash_chain(payload)

        padded = byte_padding(payload)
        p_list = split_byte_string(padded, item_len=PADDING_LEN)

        if p_type == FILE:
            p_list[0] = int_to_bytes(len(p_list)) + p_list[0][FILE_PACKET_CTR_LEN:]

        packet_list = ([l_header + p_list[0]] +
                       [a_header + p for p in p_list[1:-1]] +
                       [e_header + p_list[-1]])

    return packet_list


def queue_packets(packet_list: List[bytes],
                  p_type:      str,
                  settings:    'Settings',
                  queue:       'Queue',
                  window:      Union['MockWindow', 'TxWindow'] = None,
                  log_as_ph:   bool = False) -> None:
    """Queue assembly packets for sender_loop()."""
    if p_type in [MESSAGE, FILE] and window is not None:

        if settings.session_traffic_masking:
            for p in packet_list:
                queue.put((p, window.log_messages, log_as_ph))
        else:
            for c in window:
                for p in packet_list:
                    queue.put((p, settings, c.rx_account, c.tx_account, window.log_messages, log_as_ph, window.uid))

    elif p_type == COMMAND:
        if settings.session_traffic_masking:
            for p in packet_list:
                if window is None:
                    log_setting = None
                else:
                    log_setting = window.log_messages
                queue.put((p, log_setting))
        else:
            for p in packet_list:
                queue.put((p, settings))


def send_packet(key_list:   'KeyList',
                gateway:    'Gateway',
                log_queue:  'Queue',
                packet:     bytes,
                settings:   'Settings',
                rx_account: str  = None,
                tx_account: str  = None,
                logging:    bool = None,
                log_as_ph:  bool = None) -> None:
    """Encrypt and send assembly packet.

    :param packet:     Padded plaintext assembly packet
    :param key_list:   Key list object
    :param settings:   Settings object
    :param gateway:    Gateway object
    :param log_queue:  Multiprocessing queue for logged messages
    :param rx_account: Recipient account
    :param tx_account: Sender's account associated with recipient's account
    :param logging:    When True, log the assembly packet
    :param log_as_ph:  When True, log assembly packet as placeholder data
    :return:           None
    """
    if len(packet) != ASSEMBLY_PACKET_LEN:
        raise CriticalError("Invalid assembly packet PT length.")

    if rx_account is None:
        keyset  = key_list.get_keyset(LOCAL_ID)
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

    log_queue.put((logging, log_as_ph, packet, rx_account, settings, key_list.master_key))


def transmit(packet:   bytes,
             settings: 'Settings',
             gateway:  'Gateway',
             delay:    bool = True) -> None:
    """Add Reed-Solomon erasure code and output packet via gateway.

    Note that random.SystemRandom() uses Kernel CSPRNG (/dev/urandom),
    not Python's weak RNG based on Mersenne Twister:
        https://docs.python.org/2/library/random.html#random.SystemRandom
    """
    rs     = RSCodec(2 * settings.session_serial_error_correction)
    packet = rs.encode(packet)
    gateway.write(packet)

    if settings.local_testing_mode:
        time.sleep(LOCAL_TESTING_PACKET_DELAY)

    if not settings.session_traffic_masking:
        if settings.multi_packet_random_delay and delay:
            random_delay = random.SystemRandom().uniform(0, settings.max_duration_of_random_delay)
            time.sleep(random_delay)


def cancel_packet(user_input: 'UserInput',
                  window:     'TxWindow',
                  settings:   'Settings',
                  queues:     Dict[bytes, 'Queue']) -> None:
    """Cancel sent message/file to contact/group."""

    queue, header, p_type = dict(cm=(queues[MESSAGE_PACKET_QUEUE], M_C_HEADER, 'messages'),
                                 cf=(queues[FILE_PACKET_QUEUE],    F_C_HEADER, 'files'   ))[user_input.plaintext]

    cancel_pt = header + bytes(PADDING_LEN)

    cancel = False
    if settings.session_traffic_masking:
        if queue.qsize() != 0:
            cancel = True
            while queue.qsize() != 0:
                queue.get()
            log_m_dictionary = dict((c.rx_account, c.log_messages) for c in window)
            queue.put((cancel_pt, log_m_dictionary, True))

        message = f"Cancelled queues {p_type}." if cancel else f"No {p_type} to cancel."
        c_print(message, head=1, tail=1)

    else:
        p_buffer = []
        while queue.qsize() != 0:
            q_data  = queue.get()
            win_uid = q_data[6]

            # Put messages unrelated to active window into buffer
            if win_uid != window.uid:
                p_buffer.append(q_data)
            else:
                cancel = True

        # Put cancel packets for each window contact to queue first
        if cancel:
            for c in window:
                queue.put((cancel_pt, settings, c.rx_account, c.tx_account, c.log_messages, window.uid))

        # Put buffered tuples back to queue
        for p in p_buffer:
            queue.put(p)

        if cancel:
            message = f"Cancelled queued {p_type} to {window.type_print} {window.name}."
        else:
            message = f"No {p_type} queued for {window.type_print} {window.name}."

        c_print(message, head=1, tail=1)
