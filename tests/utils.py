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

import base64
import binascii
import io
import os
import unittest
import zlib

from contextlib import contextmanager, redirect_stdout

from src.common.crypto     import encrypt_and_sign, hash_chain
from src.common.encoding   import int_to_bytes
from src.common.exceptions import FunctionReturn
from src.common.statics    import *

from src.tx.packet import split_to_assembly_packets


class TFCTestCase(unittest.TestCase):

    def assertFR(self, msg, func, *args, **kwargs):
        """Check that FunctionReturn error is raised and specific message is displayed."""
        e_raised = False
        try:
            func(*args, **kwargs)
        except FunctionReturn as inst:
            e_raised = True
            self.assertEqual(inst.message, msg)

        self.assertTrue(e_raised)

    def assertPrints(self, msg, func, *args, **kwargs):
        """Check that specific message is printed by function."""
        f = io.StringIO()
        with redirect_stdout(f):
            self.assertIsNone(func(*args, **kwargs))
        self.assertEqual(f.getvalue(), msg)


@contextmanager
def ignored(*exceptions):
    """Ignore exception."""
    try:
        yield
    except exceptions:
        pass


def cleanup():
    """Remove unittest related files."""
    for f in os.listdir(DIR_USER_DATA):
        if f.startswith('ut'):
            with ignored(FileNotFoundError):
                os.remove(f'{DIR_USER_DATA}{f}')


def assembly_packet_creator(p_type:       str,
                            payload:      bytes = b'',
                            origin:       bytes = b'',
                            header:       bytes = b'',
                            group_name:   str   = None,
                            encrypt:      bool  = False,
                            break_g_name: bool  = False,
                            origin_acco:  bytes = b'alice@jabber.org'):
    """Create assembly packet list and optionally encrypt it."""
    if p_type == MESSAGE:
        if not header:
            if group_name is not None:
                group_msg_id = GROUP_MSG_ID_LEN * b'a'
                group_name   = binascii.unhexlify('a466c02c221cb135') if break_g_name else group_name.encode()
                header       = GROUP_MESSAGE_HEADER + group_msg_id + group_name + US_BYTE
            else:
                header = PRIVATE_MESSAGE_HEADER
        payload = header + payload

    if p_type == FILE:
        if not payload:
            compressed = zlib.compress(os.urandom(10000), level=COMPRESSION_LEVEL)
            file_key   = os.urandom(KEY_LENGTH)
            encrypted  = encrypt_and_sign(compressed, key=file_key) + file_key
            encoded    = base64.b85encode(encrypted)
            payload    = int_to_bytes(1) + int_to_bytes(2) + b'testfile.txt' + US_BYTE + encoded

    packet_list = split_to_assembly_packets(payload, p_type)

    if not encrypt:
        return packet_list

    if encrypt:
        harac = 1
        m_key = KEY_LENGTH * b'\x01'
        m_hek = KEY_LENGTH * b'\x01'
        assembly_ct_list = []
        for p in packet_list:
            harac_in_bytes    = int_to_bytes(harac)
            encrypted_harac   = encrypt_and_sign(harac_in_bytes, m_hek)
            encrypted_message = encrypt_and_sign(p,              m_key)
            encrypted_packet  = MESSAGE_PACKET_HEADER + encrypted_harac + encrypted_message + origin + origin_acco
            assembly_ct_list.append(encrypted_packet)
            m_key  = hash_chain(m_key)
            harac += 1

        return assembly_ct_list
