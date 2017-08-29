#!/usr/bin/env python3.5
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
import time
import typing

from datetime import datetime
from typing   import Dict

from src.common.misc         import ignored
from src.common.output       import box_print
from src.common.reed_solomon import ReedSolomonError, RSCodec
from src.common.statics      import *

if typing.TYPE_CHECKING:
    from multiprocessing import Queue
    from src.nh.gateway  import Gateway
    from src.nh.settings import Settings


def txm_incoming(queues:   Dict[bytes, 'Queue'],
                 settings: 'Settings',
                 unittest: bool = False) -> None:
    """Loop that places messages received from TxM to appropriate queues."""
    rs = RSCodec(2 * settings.session_serial_error_correction)

    q_to_tip = queues[TXM_INCOMING_QUEUE]
    m_to_rxm = queues[RXM_OUTGOING_QUEUE]
    c_to_rxm = queues[TXM_TO_RXM_QUEUE]
    q_to_im  = queues[TXM_TO_IM_QUEUE]
    q_to_nh  = queues[TXM_TO_NH_QUEUE]

    while True:
        with ignored(EOFError, KeyboardInterrupt):
            while q_to_tip.qsize() == 0:
                time.sleep(0.01)

            packet = q_to_tip.get()

            try:
                packet = bytes(rs.decode(packet))
            except ReedSolomonError:
                box_print("Warning! Failed to correct errors in received packet.", head=1, tail=1)
                continue

            ts     = datetime.now().strftime("%m-%d / %H:%M:%S")
            header = packet[:1]

            if header == UNENCRYPTED_PACKET_HEADER:
                q_to_nh.put(packet[1:])

            elif header in [LOCAL_KEY_PACKET_HEADER, COMMAND_PACKET_HEADER]:
                p_type = 'local key' if header == LOCAL_KEY_PACKET_HEADER else 'command'
                print("{} - {} TxM > RxM".format(ts, p_type))
                c_to_rxm.put(packet)

            elif header in [MESSAGE_PACKET_HEADER, PUBLIC_KEY_PACKET_HEADER]:
                payload_len, p_type = {PUBLIC_KEY_PACKET_HEADER: (KEY_LENGTH,     'pub key'),
                                       MESSAGE_PACKET_HEADER:    (MESSAGE_LENGTH, 'message')}[header]
                payload             = packet[1:1 + payload_len]
                trailer             = packet[1 + payload_len:]
                user, contact       = trailer.split(US_BYTE)

                print("{} - {} TxM > {} > {}".format(ts, p_type, user.decode(), contact.decode()))
                q_to_im.put((header, payload, user, contact))
                m_to_rxm.put(header + payload + ORIGIN_USER_HEADER + contact)

            elif header == EXPORTED_FILE_HEADER:
                payload = packet[1:]

                file_name = os.urandom(8).hex()
                while os.path.isfile(file_name):
                    file_name = os.urandom(8).hex()

                with open(file_name, 'wb+') as f:
                    f.write(payload)
                print("{} - Exported file from TxM as {}".format(ts, file_name))

            if unittest:
                break


def rxm_outgoing(queues:   Dict[bytes, 'Queue'],
                 settings: 'Settings',
                 gateway:  'Gateway',
                 unittest: bool = False) -> None:
    """Loop that outputs packets from queues to RxM.

    Commands (and local keys) from TxM to RxM have higher priority
    than messages and public keys from contacts. This prevents
    contact from doing DoS on RxM by filling queue with packets.
    """
    rs      = RSCodec(2 * settings.session_serial_error_correction)
    c_queue = queues[TXM_TO_RXM_QUEUE]
    m_queue = queues[RXM_OUTGOING_QUEUE]

    while True:
        try:
            time.sleep(0.01)

            while c_queue.qsize() != 0:
                packet = rs.encode(bytearray(c_queue.get()))
                gateway.write(packet)

            if m_queue.qsize() != 0:
                packet = rs.encode(bytearray(m_queue.get()))
                gateway.write(packet)

            if unittest:
                break
        except (EOFError, KeyboardInterrupt):
            pass
