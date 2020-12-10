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

import hashlib
import os
import time
import typing

from typing import Any, Dict, List, Tuple, Union

from src.common.crypto     import encrypt_and_sign
from src.common.encoding   import (b85encode, bytes_to_int, int_to_bytes,
                                   pub_key_to_short_address)
from src.common.exceptions import SoftError
from src.common.misc       import ensure_dir, ignored, separate_header, split_byte_string
from src.common.output     import rp_print
from src.common.statics    import (BLAKE2_DIGEST_LENGTH, COMMAND_DATAGRAM_HEADER, DATAGRAM_HEADER_LENGTH, DST_COMMAND_QUEUE,
                                   DST_MESSAGE_QUEUE, ENCODED_INTEGER_LENGTH, FILE_DATAGRAM_HEADER,
                                   GATEWAY_QUEUE, GROUP_ID_LENGTH, GROUP_MSG_EXIT_GROUP_HEADER, GROUP_MSG_INVITE_HEADER,
                                   GROUP_MSG_JOIN_HEADER, GROUP_MSG_MEMBER_ADD_HEADER, GROUP_MSG_MEMBER_REM_HEADER,
                                   LOCAL_KEY_DATAGRAM_HEADER, MESSAGE_DATAGRAM_HEADER, ONION_SERVICE_PUBLIC_KEY_LENGTH,
                                   ORIGIN_USER_HEADER, PUBLIC_KEY_DATAGRAM_HEADER, RELAY_BUFFER_OUTGOING_F_DIR,
                                   RELAY_BUFFER_OUTGOING_FILE, RELAY_BUFFER_OUTGOING_M_DIR,
                                   RELAY_BUFFER_OUTGOING_MESSAGE, SRC_TO_RELAY_QUEUE, TX_BUF_KEY_QUEUE,
                                   UNENCRYPTED_DATAGRAM_HEADER, UNIT_TEST_QUEUE)

if typing.TYPE_CHECKING:
    from datetime           import datetime
    from multiprocessing    import Queue
    from src.common.gateway import Gateway
    QueueDict = Dict[bytes, Queue[Any]]


def src_incoming(queues:    'QueueDict',
                 gateway:   'Gateway',
                 unit_test: bool = False
                 ) -> None:
    """\
    Redirect datagrams received from Source Computer to appropriate queues.
    """
    commands_to_relay = queues[SRC_TO_RELAY_QUEUE]
    buf_key_queue     = queues[TX_BUF_KEY_QUEUE]

    buf_key = None

    while True:
        with ignored(EOFError, KeyboardInterrupt, SoftError):

            if buf_key is None and buf_key_queue.qsize() > 0:
                buf_key = buf_key_queue.get()

            ts, packet     = load_packet_from_queue(queues, gateway)
            header, packet = separate_header(packet, DATAGRAM_HEADER_LENGTH)

            if header == UNENCRYPTED_DATAGRAM_HEADER:
                commands_to_relay.put(packet)

            elif header in [COMMAND_DATAGRAM_HEADER, LOCAL_KEY_DATAGRAM_HEADER]:
                process_command_datagram(ts, packet, header, queues)

            elif header in [MESSAGE_DATAGRAM_HEADER, PUBLIC_KEY_DATAGRAM_HEADER] and buf_key is not None:
                process_message_datagram(ts, packet, header, buf_key, queues)

            elif header == FILE_DATAGRAM_HEADER and buf_key is not None:
                process_file_datagram(ts, packet, header, buf_key)

            elif header in [GROUP_MSG_INVITE_HEADER,
                            GROUP_MSG_JOIN_HEADER,
                            GROUP_MSG_MEMBER_ADD_HEADER,
                            GROUP_MSG_MEMBER_REM_HEADER,
                            GROUP_MSG_EXIT_GROUP_HEADER] and buf_key is not None:
                process_group_management_message(ts, packet, header, buf_key)

            if unit_test:
                break


def load_packet_from_queue(queues:  'QueueDict',
                           gateway: 'Gateway'
                           ) -> Tuple['datetime', bytes]:
    """Load packet from Source Computer.

    Perform error detection/correction before returning the packet.
    """
    packets_from_source_computer = queues[GATEWAY_QUEUE]

    while not packets_from_source_computer.qsize():
        time.sleep(0.01)
    ts, packet = packets_from_source_computer.get()  # type: datetime, bytes

    packet = gateway.detect_errors(packet)

    return ts, packet


def process_command_datagram(ts:      'datetime',
                             packet:  bytes,
                             header:  bytes,
                             queues:  'QueueDict'
                             ) -> None:
    """Process command datagram."""
    commands_to_dst = queues[DST_COMMAND_QUEUE]
    ts_bytes        = int_to_bytes(int(ts.strftime("%Y%m%d%H%M%S%f")[:-4]))

    commands_to_dst.put(header + ts_bytes + packet)

    p_type = "Command  " if header == COMMAND_DATAGRAM_HEADER else "Local key"
    rp_print(f"{p_type} to local Receiver", ts)


def process_message_datagram(ts:      'datetime',
                             packet:  bytes,
                             header:  bytes,
                             buf_key: bytes,
                             queues:  'QueueDict'
                             ) -> None:
    """Process message or public key datagram."""
    packets_to_dst = queues[DST_MESSAGE_QUEUE]

    onion_pub_key, payload = separate_header(packet, ONION_SERVICE_PUBLIC_KEY_LENGTH)
    packet_str             = header.decode() + b85encode(payload)
    ts_bytes               = int_to_bytes(int(ts.strftime("%Y%m%d%H%M%S%f")[:-4]))

    buffer_to_flask(packet_str, onion_pub_key, ts, header, buf_key)

    if header == MESSAGE_DATAGRAM_HEADER:
        packets_to_dst.put(header + ts_bytes + onion_pub_key + ORIGIN_USER_HEADER + payload)


def process_file_datagram(ts:      'datetime',
                          packet:  bytes,
                          header:  bytes,
                          buf_key: bytes,
                          ) -> None:
    """Process file datagram."""
    no_contacts_b, payload = separate_header(packet, ENCODED_INTEGER_LENGTH)
    no_contacts            = bytes_to_int(no_contacts_b)
    ser_accounts, file_ct  = separate_header(payload, no_contacts * ONION_SERVICE_PUBLIC_KEY_LENGTH)
    pub_keys               = split_byte_string(ser_accounts, item_len=ONION_SERVICE_PUBLIC_KEY_LENGTH)

    for onion_pub_key in pub_keys:
        buffer_to_flask(file_ct, onion_pub_key, ts, header, buf_key, file=True)


def process_group_management_message(ts:      'datetime',
                                     packet:  bytes,
                                     header:  bytes,
                                     buf_key: bytes,
                                     ) -> None:
    """Parse and display group management message."""
    header_str       = header.decode()
    group_id, packet = separate_header(packet, GROUP_ID_LENGTH)

    if header in [GROUP_MSG_INVITE_HEADER, GROUP_MSG_JOIN_HEADER]:
        pub_keys = split_byte_string(packet, ONION_SERVICE_PUBLIC_KEY_LENGTH)
        for onion_pub_key in pub_keys:
            others     = [k for k in pub_keys if k != onion_pub_key]
            packet_str = header_str + b85encode(group_id + b''.join(others))
            buffer_to_flask(packet_str, onion_pub_key, ts, header, buf_key)

    elif header in [GROUP_MSG_MEMBER_ADD_HEADER, GROUP_MSG_MEMBER_REM_HEADER]:
        first_list_len_b, packet  = separate_header(packet, ENCODED_INTEGER_LENGTH)
        first_list_length         = bytes_to_int(first_list_len_b)
        pub_keys                  = split_byte_string(packet, ONION_SERVICE_PUBLIC_KEY_LENGTH)
        before_adding = remaining = pub_keys[:first_list_length]
        new_in_group  = removable = pub_keys[first_list_length:]

        if header == GROUP_MSG_MEMBER_ADD_HEADER:

            process_add_or_group_remove_member(ts, header, buf_key, header_str, group_id, before_adding, new_in_group)

            for onion_pub_key in new_in_group:
                other_new  = [k for k in new_in_group if k != onion_pub_key]
                packet_str = (GROUP_MSG_INVITE_HEADER.decode()
                              + b85encode(group_id + b''.join(other_new + before_adding)))
                buffer_to_flask(packet_str, onion_pub_key, ts, header, buf_key)

        elif header == GROUP_MSG_MEMBER_REM_HEADER:
            process_add_or_group_remove_member(ts, header, buf_key, header_str, group_id, remaining, removable)

    elif header == GROUP_MSG_EXIT_GROUP_HEADER:
        process_group_exit_header(ts, packet, header, buf_key, header_str, group_id)


def process_add_or_group_remove_member(ts:         'datetime',
                                       header:     bytes,
                                       buf_key:    bytes,
                                       header_str: str,
                                       group_id:   bytes,
                                       remaining:  List[bytes],
                                       removable:  List[bytes]
                                       ) -> None:
    """Process group add or remove member packet."""
    packet_str = header_str + b85encode(group_id + b"".join(removable))
    for onion_pub_key in remaining:
        buffer_to_flask(packet_str, onion_pub_key, ts, header, buf_key)


def process_group_exit_header(ts:         'datetime',
                              packet:     bytes,
                              header:     bytes,
                              buf_key:    bytes,
                              header_str: str,
                              group_id:   bytes,
                              ) -> None:
    """Process group exit packet."""
    pub_keys   = split_byte_string(packet, ONION_SERVICE_PUBLIC_KEY_LENGTH)
    packet_str = header_str + b85encode(group_id)
    for onion_pub_key in pub_keys:
        buffer_to_flask(packet_str, onion_pub_key, ts, header, buf_key)


def buffer_to_flask(packet:        Union[bytes, str],
                    onion_pub_key: bytes,
                    ts:            'datetime',
                    header:        bytes,
                    buf_key:       bytes,
                    file:          bool = False
                    ) -> None:
    """Buffer outgoing datagram for Flask and print message."""
    p_type = {MESSAGE_DATAGRAM_HEADER:     'Message  ',
              PUBLIC_KEY_DATAGRAM_HEADER:  'Pub key  ',
              FILE_DATAGRAM_HEADER:        'File     ',
              GROUP_MSG_INVITE_HEADER:     'G invite ',
              GROUP_MSG_JOIN_HEADER:       'G join   ',
              GROUP_MSG_MEMBER_ADD_HEADER: 'G add    ',
              GROUP_MSG_MEMBER_REM_HEADER: 'G remove ',
              GROUP_MSG_EXIT_GROUP_HEADER: 'G exit   '}[header]

    if buf_key is None:
        raise SoftError("Error: No buffer key available for packet buffering.")

    if isinstance(packet, str):
        packet = packet.encode()

    file_name = RELAY_BUFFER_OUTGOING_FILE  if file else RELAY_BUFFER_OUTGOING_MESSAGE
    file_dir  = RELAY_BUFFER_OUTGOING_F_DIR if file else RELAY_BUFFER_OUTGOING_M_DIR
    sub_dir   = hashlib.blake2b(onion_pub_key, key=buf_key, digest_size=BLAKE2_DIGEST_LENGTH).hexdigest()

    enc_packet = encrypt_and_sign(packet, key=buf_key)

    store_unique(enc_packet, f"{file_dir}/{sub_dir}/", file_name)

    rp_print(f"{p_type} to contact {pub_key_to_short_address(onion_pub_key)}", ts)


def store_unique(file_data: bytes,  # File data to store
                 file_dir:  str,    # Directory to store file
                 file_name: str,    # Name of the file.
                 ) -> None:
    """Store file under a unique filename.

    Add trailing counter .# to ensure buffered packets are read in order.
    """
    ensure_dir(file_dir)

    try:
        file_numbers = [f[(len(file_name) + len('.')):] for f in os.listdir(file_dir) if f.startswith(file_name)]
        file_numbers = [n for n in file_numbers if n.isdigit()]
        greatest_num = sorted(file_numbers, key=int)[-1]
        ctr          = int(greatest_num) + 1
    except IndexError:
        ctr = 0

    with open(f"{file_dir}/{file_name}.{ctr}", 'wb+') as f:
        f.write(file_data)
        f.flush()
        os.fsync(f.fileno())


def dst_outgoing(queues:    'QueueDict',
                 gateway:   'Gateway',
                 unit_test: bool = False
                 ) -> None:
    """Output packets from queues to Destination Computer.

    Commands (and local keys) to local Destination Computer have higher
    priority than messages and public keys from contacts. Prioritization
    prevents contact from doing DoS on Receiver Program by filling the
    queue with packets.
    """
    c_queue = queues[DST_COMMAND_QUEUE]
    m_queue = queues[DST_MESSAGE_QUEUE]

    while True:
        try:
            if c_queue.qsize() == 0 and m_queue.qsize() == 0:
                time.sleep(0.01)

            while c_queue.qsize() != 0:
                gateway.write(c_queue.get())

            if m_queue.qsize() != 0:
                gateway.write(m_queue.get())

            if unit_test and queues[UNIT_TEST_QUEUE].qsize() > 0:
                break

        except (EOFError, KeyboardInterrupt):
            pass
