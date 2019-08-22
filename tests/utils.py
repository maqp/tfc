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

import hashlib
import io
import os
import shutil
import unittest
import zlib

from contextlib      import contextmanager, redirect_stdout
from multiprocessing import Queue
from typing          import Any, Callable, Dict, List, Union

from src.common.crypto     import blake2b, byte_padding, csprng, encrypt_and_sign
from src.common.encoding   import int_to_bytes, pub_key_to_onion_address
from src.common.misc       import split_byte_string
from src.common.exceptions import FunctionReturn
from src.common.statics    import *


UNDECODABLE_UNICODE = bytes.fromhex('3f264d4189d7a091')
VALID_ECDHE_PUB_KEY = '4EcuqaDddsdsucgBX2PY2qR8hReAaeSN2ohJB9w5Cvq6BQjDaPPgzSvW932aHiosT42SKJGu2PpS1Za3Xrao'
VALID_LOCAL_KEY_KDK = '5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ'


def nick_to_pub_key(nick: str) -> bytes:
    """Produce deterministic public key from nick."""
    return hashlib.sha256(nick.encode()).digest()


def nick_to_onion_address(nick: str) -> str:
    """Produce deterministic v3 Onion Service address from nick."""
    return pub_key_to_onion_address(nick_to_pub_key(nick))


def nick_to_short_address(nick: str) -> str:
    """Produce deterministic short address from nick."""
    return nick_to_onion_address(nick)[:TRUNC_ADDRESS_LENGTH]


def group_name_to_group_id(name: str) -> bytes:
    """Produce deterministic group ID from group name."""
    return hashlib.sha256(name.encode()).digest()[:GROUP_ID_LENGTH]


class TFCTestCase(unittest.TestCase):

    def assert_fr(self, msg, func, *args, **kwargs):
        """\
        Check that FunctionReturn error is raised
        and that a specific message is displayed.
        """
        e_raised = False
        try:
            func(*args, **kwargs)
        except FunctionReturn as inst:
            e_raised = True
            self.assertEqual(msg, inst.message)

        self.assertTrue(e_raised)

    def assert_prints(self, msg, func, *args, **kwargs):
        """Check that specific message is printed by function."""
        f = io.StringIO()
        with redirect_stdout(f):
            self.assertIsNone(func(*args, **kwargs))
        self.assertEqual(f.getvalue(), msg)


@contextmanager
def ignored(*exceptions):
    """Ignore an exception."""
    try:
        yield
    except exceptions:
        pass


def cd_unit_test():
    """Create a directory for the unit test and change to it.

    Separate working directory for unit test protects existing user data
    and allows running tests in parallel.
    """
    name = f"unit_test_{(os.urandom(16)).hex()}/"
    try:
        os.mkdir(name)
    except FileExistsError:
        pass
    os.chdir(name)
    return name


def cleanup(name):
    """Remove unit test related directory."""
    os.chdir('..')
    shutil.rmtree(f'{name}/')


def func_that_raises(exception: Any) -> Callable:
    """Return function that when called, raises the specified exception."""
    return lambda *args, **kwargs: (_ for _ in ()).throw(exception)


def tamper_file(file_name: str, tamper_size: int) -> None:
    """Change `tamper_size` bytes in file `file_name`."""

    with open(file_name, 'rb') as f:
        data = f.read()

    while True:
        tampered_bytes = os.urandom(tamper_size)
        if tampered_bytes != data[:tamper_size]:
            break
    new_data = tampered_bytes + data[tamper_size:]

    with open(file_name, 'wb') as f:
        f.write(new_data)


def tear_queue(queue: 'Queue'):
    """Empty and close multiprocessing queue."""
    while queue.qsize() != 0:
        queue.get()
    queue.close()


def tear_queues(queues: Dict[bytes, 'Queue']):
    """Empty and close multiprocessing queues."""
    for q in queues:
        tear_queue(queues[q])


def tamper_last_byte(byte_string: bytes) -> bytes:
    """Increase the ord value of last byte by 1 mod 255."""
    return byte_string[:-1] + chr((ord(byte_string[-1:]) + 1) % 256).encode()


def assembly_packet_creator(
                            # --- Payload creation ---

                            # Common settings
                            packet_type:        str,                        # Packet type (MESSAGE, FILE, or COMMAND, do not use tampered values)
                            payload:            Union[bytes, str] = None,   # Payload message content (Plaintext message (str), file data (bytes), or command (bytes))
                            inner_key:          bytes = None,               # Key for inner encryption layer
                            tamper_ciphertext:  bool  = False,              # When True, tampers with the inner layer of encryption to make it undecryptable

                            # Message packet parameters
                            message_header:     bytes = None,               # Message header (PRIVATE_MESSAGE_HEADER, GROUP_MESSAGE_HEADER, FILE_KEY_HEADER, or tamper byte)
                            tamper_plaintext:   bool  = False,              # When true, replaces plaintext with undecodable bytestring.
                            group_id:           bytes = None,               # When specified, creates message for group (4 byte random string)
                            group_msg_id:       bytes = None,               # The group message id (16 byte random string)
                            whisper_header:     bytes = b'\x00',            # Define whisper-header (b'\x00' for False, b'\x01' for True, others for tampering)

                            # File packet parameters
                            create_zip_bomb:    bool  = False,              # When True, creates large enough ciphertext to trigger zip bomb protection
                            tamper_compression: bool  = False,              # When True, tampers with compression to make decompression impossible
                            packet_time:        bytes = None,               # Allows overriding the 8-byte packet time header
                            packet_size:        bytes = None,               # Allows overriding the 8-byte packet size header
                            file_name:          bytes = None,               # Name of the file (allows e.g. injection of invalid file names)
                            omit_header_delim:  bool  = False,              # When True, omits the file_name<>file_data delimiter.

                            # --- Assembly packet splitting ---
                            s_header_override:  bytes = None,               # Allows overriding the `short packet` assembly packet header
                            l_header_override:  bytes = None,               # Allows overriding the `start of long packet` assembly packet header
                            a_header_override:  bytes = None,               # Allows overriding the `appended long packet` assembly packet header
                            e_header_override:  bytes = None,               # Allows overriding the `last packet of long packet` assembly packet header
                            tamper_cmd_hash:    bool  = False,              # When True, tampers with the command hash to make it undecryptable
                            no_padding:         bool  = False,              # When True, does not add padding to assembly packet.
                            split_length:       int   = PADDING_LENGTH,     # Allows configuring the length to which assembly packets are split

                            # --- Packet encryption ---
                            encrypt_packet:  bool     = False,              # When True, encrypts packet into set of datagrams starting with default key (32*b'\x01')
                            message_number:  int      = 0,                  # Determines the message key and harac for message
                            harac:           int      = INITIAL_HARAC,      # Allows choosing the hash ratchet counter for packet encryption
                            message_key:     bytes    = None,               # Allows choosing the message key to encrypt message with
                            header_key:      bytes    = None,               # Allows choosing the header key for hash ratchet encryption
                            tamper_harac:    bool     = False,              # When True, tampers with the MAC of encrypted harac
                            tamper_message:  bool     = False,              # When True, tampers with the MAC of encrypted messagae
                            onion_pub_key:   bytes    = b'',                # Defines the contact public key to use with datagram creation
                            origin_header:   bytes    = b'',                # Allows editing the origin header
                            ) -> List[bytes]:
    """Create assembly packet list and optionally encrypt it to create datagram list."""

    # ------------------------------------------------------------------------------------------------------------------
    # |                                                 Create payload                                                 |
    # ------------------------------------------------------------------------------------------------------------------

    if packet_type == MESSAGE:

        assert isinstance(payload, str)

        if message_header is None:
            if group_id is not None:
                group_msg_id_bytes = bytes(GROUP_MSG_ID_LENGTH) if group_msg_id is None else group_msg_id
                header = GROUP_MESSAGE_HEADER + group_id + group_msg_id_bytes
            else:
                header = PRIVATE_MESSAGE_HEADER
        else:
            header = message_header

        payload_bytes = UNDECODABLE_UNICODE if tamper_plaintext else payload.encode()

        payload = whisper_header + header + payload_bytes

    # ---

    elif packet_type == FILE:  # Create packets for traffic masking file transmission

        file_data_size  = 100_000_001 if create_zip_bomb else 10_000
        payload_bytes   = os.urandom(file_data_size) if payload is None else payload

        compressed      = zlib.compress(payload_bytes, level=COMPRESSION_LEVEL)
        compressed      = compressed if not tamper_compression else compressed[::-1]
        file_key_bytes  = os.urandom(SYMMETRIC_KEY_LENGTH) if inner_key is None else inner_key

        ciphertext      = encrypt_and_sign(compressed, key=file_key_bytes)
        ciphertext      = ciphertext if not tamper_ciphertext else ciphertext[::-1]
        ct_with_key     = ciphertext + file_key_bytes

        time_bytes      = int_to_bytes(2)              if packet_time is None   else packet_time
        size_bytes      = int_to_bytes(file_data_size) if packet_size is None   else packet_size
        file_name_bytes = b'test_file.txt'             if file_name   is None   else file_name
        delimiter       = US_BYTE                      if not omit_header_delim else b''

        payload   = time_bytes + size_bytes + file_name_bytes + delimiter + ct_with_key

    elif packet_type == COMMAND:
        payload = payload

    else:
        raise ValueError(f"Invalid packet type '{packet_type}'.")

    # ------------------------------------------------------------------------------------------------------------------
    # |                                       Split payload to assembly packets                                        |
    # ------------------------------------------------------------------------------------------------------------------

    s_header = {MESSAGE: M_S_HEADER, FILE: F_S_HEADER, COMMAND: C_S_HEADER}[packet_type]
    l_header = {MESSAGE: M_L_HEADER, FILE: F_L_HEADER, COMMAND: C_L_HEADER}[packet_type]
    a_header = {MESSAGE: M_A_HEADER, FILE: F_A_HEADER, COMMAND: C_A_HEADER}[packet_type]
    e_header = {MESSAGE: M_E_HEADER, FILE: F_E_HEADER, COMMAND: C_E_HEADER}[packet_type]

    s_header = s_header if s_header_override is None else s_header_override
    l_header = l_header if l_header_override is None else l_header_override
    a_header = a_header if a_header_override is None else a_header_override
    e_header = e_header if e_header_override is None else e_header_override

    if packet_type in [MESSAGE, COMMAND]:
        compressed = zlib.compress(payload, level=COMPRESSION_LEVEL)
        payload    = compressed if not tamper_compression else compressed[::-1]

    if len(payload) < PADDING_LENGTH:
        padded      = byte_padding(payload)
        packet_list = [s_header + padded]

    else:
        if packet_type == MESSAGE:
            msg_key  = csprng() if inner_key is None else inner_key
            payload  = encrypt_and_sign(payload, msg_key)
            payload  = payload if not tamper_ciphertext else payload[::-1]
            payload += msg_key

        elif packet_type == FILE:
            payload = bytes(FILE_PACKET_CTR_LENGTH) + payload

        elif packet_type == COMMAND:
            command_hash  = blake2b(payload)
            command_hash  = command_hash if not tamper_cmd_hash else command_hash[::-1]
            payload      += command_hash

        padded = payload if no_padding else byte_padding(payload)
        p_list = split_byte_string(padded, item_len=split_length)

        if packet_type == FILE:
            p_list[0] = int_to_bytes(len(p_list)) + p_list[0][FILE_PACKET_CTR_LENGTH:]

        packet_list = ([l_header + p_list[0]] +
                       [a_header + p for p in p_list[1:-1]] +
                       [e_header + p_list[-1]])

    if not encrypt_packet:
        return packet_list

    # ------------------------------------------------------------------------------------------------------------------
    # |                                  Encrypt assembly packets to create datagrams                                  |
    # ------------------------------------------------------------------------------------------------------------------

    message_key = SYMMETRIC_KEY_LENGTH * b'\x01' if message_key is None else message_key
    header_key  = SYMMETRIC_KEY_LENGTH * b'\x01' if header_key  is None else header_key

    for _ in range(message_number):
        message_key = blake2b(message_key + int_to_bytes(harac), digest_size=SYMMETRIC_KEY_LENGTH)
        harac      += 1

    assembly_ct_list = []

    for packet in packet_list:
        harac_in_bytes    = int_to_bytes(harac)
        encrypted_harac   = encrypt_and_sign(harac_in_bytes, header_key)
        encrypted_message = encrypt_and_sign(packet,         message_key)

        encrypted_harac   = encrypted_harac   if not tamper_harac   else tamper_last_byte(encrypted_harac)
        encrypted_message = encrypted_message if not tamper_message else tamper_last_byte(encrypted_message)

        encrypted_packet = onion_pub_key + origin_header + encrypted_harac + encrypted_message

        assembly_ct_list.append(encrypted_packet)

        message_key = blake2b(message_key + int_to_bytes(harac), digest_size=SYMMETRIC_KEY_LENGTH)
        harac += 1

    return assembly_ct_list


def gen_queue_dict() -> Dict[bytes, Queue]:
    """Create dictionary that has all the queues used by TFC processes."""
    transmitter_queues = [MESSAGE_PACKET_QUEUE,
                          COMMAND_PACKET_QUEUE,
                          TM_MESSAGE_PACKET_QUEUE,
                          TM_FILE_PACKET_QUEUE,
                          TM_COMMAND_PACKET_QUEUE,
                          TM_NOISE_PACKET_QUEUE,
                          TM_NOISE_COMMAND_QUEUE,
                          RELAY_PACKET_QUEUE,
                          LOG_PACKET_QUEUE,
                          LOG_SETTING_QUEUE,
                          TRAFFIC_MASKING_QUEUE,
                          LOGFILE_MASKING_QUEUE,
                          KEY_MANAGEMENT_QUEUE,
                          SENDER_MODE_QUEUE,
                          WINDOW_SELECT_QUEUE,
                          EXIT_QUEUE]

    receiver_queues = [GATEWAY_QUEUE,
                       LOCAL_KEY_DATAGRAM_HEADER,
                       MESSAGE_DATAGRAM_HEADER,
                       FILE_DATAGRAM_HEADER,
                       COMMAND_DATAGRAM_HEADER,
                       EXIT_QUEUE]

    relay_queues = [GATEWAY_QUEUE,
                    DST_MESSAGE_QUEUE,
                    M_TO_FLASK_QUEUE,
                    F_TO_FLASK_QUEUE,
                    SRC_TO_RELAY_QUEUE,
                    DST_COMMAND_QUEUE,
                    CONTACT_MGMT_QUEUE,
                    C_REQ_STATE_QUEUE,
                    URL_TOKEN_QUEUE,
                    GROUP_MSG_QUEUE,
                    CONTACT_REQ_QUEUE,
                    C_REQ_MGMT_QUEUE,
                    GROUP_MGMT_QUEUE,
                    ONION_CLOSE_QUEUE,
                    ONION_KEY_QUEUE,
                    TOR_DATA_QUEUE,
                    EXIT_QUEUE]

    unit_test_queue = [UNIT_TEST_QUEUE]

    queue_list = set(transmitter_queues + receiver_queues + relay_queues + unit_test_queue)
    queue_dict = dict()

    for q in queue_list:
        queue_dict[q] = Queue()

    return queue_dict
