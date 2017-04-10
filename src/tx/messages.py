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

import time
import typing
import zlib

from typing import Union

from src.common.crypto   import byte_padding, encrypt_and_sign, keygen
from src.common.encoding import double_to_bytes
from src.common.misc     import split_byte_string
from src.common.statics  import *

if typing.TYPE_CHECKING:
    from multiprocessing        import Queue
    from src.common.db_settings import Settings
    from src.tx.user_input      import UserInput
    from src.tx.windows         import Window
    from src.tx.commands_g      import MockWindow


class Message(object):
    """The message object is an automatically generated message.

    It has same the attributes as messages created from UserInput object.
    """
    def __init__(self, plaintext: str) -> None:
        self.plaintext = plaintext
        self.type      = 'message'


def queue_message(user_input: Union['UserInput', 'Message'],
                  window:     Union['MockWindow', 'Window'],
                  settings:   'Settings',
                  m_queue:    'Queue',
                  header:     bytes = b'') -> None:
    """Convert message into set of assembly packets and queue them.

    :param user_input: UserInput object
    :param window:     Window object
    :param settings:   Settings object
    :param m_queue:    Multiprocessing message queue
    :param header:     Overrides message header with group management header
    :return:           None
    """
    if not header:
        if window.type == 'group':
            timestamp = double_to_bytes(time.time() * 1000)
            header    = GROUP_MESSAGE_HEADER + timestamp + window.name.encode() + US_BYTE
        else:
            header = PRIVATE_MESSAGE_HEADER

    plaintext = user_input.plaintext.encode()
    payload   = header + plaintext
    payload   = zlib.compress(payload, level=9)

    if len(payload) < 255:
        padded      = byte_padding(payload)
        packet_list = [M_S_HEADER + padded]
    else:
        msg_key  = keygen()
        payload  = encrypt_and_sign(payload, msg_key)
        payload += msg_key
        padded   = byte_padding(payload)
        p_list   = split_byte_string(padded, item_len=255)

        packet_list = ([M_L_HEADER + p_list[0]] +
                       [M_A_HEADER + p for p in p_list[1:-1]] +
                       [M_E_HEADER + p_list[-1]])

    if settings.session_trickle:
        log_m_dictionary = dict((c.rx_account, c.log_messages) for c in window)
        for p in packet_list:
            m_queue.put((p, log_m_dictionary))

    else:
        for c in window:
            log_setting = window.group.log_messages if window.type == 'group' else c.log_messages
            for p in packet_list:
                m_queue.put((p, settings, c.rx_account, c.tx_account, log_setting, window.uid))
