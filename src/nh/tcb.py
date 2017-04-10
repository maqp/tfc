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

import datetime
import os
import time
import typing

from src.nh.misc             import box_print
from src.common.reed_solomon import ReedSolomonError, RSCodec
from src.common.statics      import *

if typing.TYPE_CHECKING:
    from multiprocessing import Queue
    from src.nh.gateway  import Gateway
    from src.nh.settings import Settings


def txm_incoming(settings: 'Settings',
                 q_to_tip: 'Queue',
                 q_to_rxm: 'Queue',
                 q_to_im:  'Queue',
                 q_to_nh:  'Queue') -> None:
    """Load messages from TxM and forward them to appropriate process via queue."""
    rs = RSCodec(2 * settings.session_ec_ratio)

    while True:
        try:
            if q_to_tip.empty():
                time.sleep(0.001)
            packet = q_to_tip.get()

            try:
                packet = bytes(rs.decode(packet))
            except ReedSolomonError:
                box_print(["Warning! Failed to correct errors in received packet."], head=1, tail=1)
                continue

            ts     = datetime.datetime.now().strftime(settings.t_fmt)
            header = packet[:1]

            if header == UNENCRYPTED_PACKET_HEADER:
                q_to_nh.put(packet[1:])

            elif header in [LOCAL_KEY_PACKET_HEADER, COMMAND_PACKET_HEADER]:
                p_type = 'local key' if header == LOCAL_KEY_PACKET_HEADER else 'command'
                print("{} - {} TxM > RxM".format(ts, p_type))
                q_to_rxm.put(packet)

            elif header in [MESSAGE_PACKET_HEADER, PUBLIC_KEY_PACKET_HEADER]:
                payload_len, p_type = (32, 'pub key') if header == PUBLIC_KEY_PACKET_HEADER else (344, 'message')
                payload             = packet[1:1 + payload_len]
                trailer             = packet[1 + payload_len:]
                user, contact       = trailer.split(US_BYTE)

                print("{} - {} TxM > {} > {}".format(ts, p_type, user.decode(), contact.decode()))
                q_to_im.put((header, payload, user, contact))
                q_to_rxm.put(header + payload + ORIGIN_USER_HEADER + contact)

            elif header == EXPORTED_FILE_CT_HEADER:
                payload   = packet[1:]
                file_name = os.urandom(16).hex()
                with open(file_name, 'wb+') as f:
                    f.write(payload)
                print("{} - Exported file from TxM as {}".format(ts, file_name))

        except (EOFError, KeyboardInterrupt):
            pass


def rxm_outgoing(settings: 'Settings',
                 q_to_rxm: 'Queue',
                 gateway:  'Gateway') -> None:
    """Output packets from RxM-queue to RxM."""
    rs = RSCodec(2 * settings.session_ec_ratio)
    while True:
        try:
            if q_to_rxm.empty():
                time.sleep(0.001)
                continue
            from_q = q_to_rxm.get()
            packet = rs.encode(bytearray(from_q))
            gateway.write(packet)
        except (EOFError, KeyboardInterrupt):
            pass
