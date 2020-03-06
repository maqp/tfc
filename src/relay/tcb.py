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

import time
import typing

from typing import Any, Dict, List, Tuple, Union

from src.common.encoding   import b85encode, bytes_to_int, int_to_bytes, pub_key_to_short_address
from src.common.exceptions import SoftError
from src.common.misc       import ignored, separate_header, split_byte_string
from src.common.output     import rp_print
from src.common.statics    import (COMMAND_DATAGRAM_HEADER, DATAGRAM_HEADER_LENGTH, DST_COMMAND_QUEUE,
                                   DST_MESSAGE_QUEUE, ENCODED_INTEGER_LENGTH, FILE_DATAGRAM_HEADER, F_TO_FLASK_QUEUE,
                                   GATEWAY_QUEUE, GROUP_ID_LENGTH, GROUP_MSG_EXIT_GROUP_HEADER, GROUP_MSG_INVITE_HEADER,
                                   GROUP_MSG_JOIN_HEADER, GROUP_MSG_MEMBER_ADD_HEADER, GROUP_MSG_MEMBER_REM_HEADER,
                                   LOCAL_KEY_DATAGRAM_HEADER, MESSAGE_DATAGRAM_HEADER, M_TO_FLASK_QUEUE,
                                   ONION_SERVICE_PUBLIC_KEY_LENGTH, ORIGIN_USER_HEADER, PUBLIC_KEY_DATAGRAM_HEADER,
                                   SRC_TO_RELAY_QUEUE, UNENCRYPTED_DATAGRAM_HEADER, UNIT_TEST_QUEUE)

if typing.TYPE_CHECKING:
    from datetime           import datetime
    from multiprocessing    import Queue
    from src.common.gateway import Gateway
    QueueDict = Dict[bytes, Queue[Any]]


def queue_to_flask(packet:        Union[bytes, str],
                   onion_pub_key: bytes,
                   flask_queue:   'Queue[Tuple[Union[bytes, str], bytes]]',
                   ts:            'datetime',
                   header:        bytes
                   ) -> None:
    """Put packet to flask queue and print message."""
    p_type = {MESSAGE_DATAGRAM_HEADER:     'Message  ',
              PUBLIC_KEY_DATAGRAM_HEADER:  'Pub key  ',
              FILE_DATAGRAM_HEADER:        'File     ',
              GROUP_MSG_INVITE_HEADER:     'G invite ',
              GROUP_MSG_JOIN_HEADER:       'G join   ',
              GROUP_MSG_MEMBER_ADD_HEADER: 'G add    ',
              GROUP_MSG_MEMBER_REM_HEADER: 'G remove ',
              GROUP_MSG_EXIT_GROUP_HEADER: 'G exit   '}[header]

    flask_queue.put((packet, onion_pub_key))
    rp_print(f"{p_type} to contact {pub_key_to_short_address(onion_pub_key)}", ts)


def src_incoming(queues:    'QueueDict',
                 gateway:   'Gateway',
                 unit_test: bool = False
                 ) -> None:
    """\
    Redirect datagrams received from Source Computer to appropriate queues.
    """
    commands_to_relay = queues[SRC_TO_RELAY_QUEUE]
    messages_to_flask = queues[M_TO_FLASK_QUEUE]

    while True:
        with ignored(EOFError, KeyboardInterrupt, SoftError):
            ts, packet     = load_packet_from_queue(queues, gateway)
            header, packet = separate_header(packet, DATAGRAM_HEADER_LENGTH)

            if header == UNENCRYPTED_DATAGRAM_HEADER:
                commands_to_relay.put(packet)

            elif header in [COMMAND_DATAGRAM_HEADER, LOCAL_KEY_DATAGRAM_HEADER]:
                process_command_datagram(ts, packet, header, queues)

            elif header in [MESSAGE_DATAGRAM_HEADER, PUBLIC_KEY_DATAGRAM_HEADER]:
                process_message_datagram(ts, packet, header, queues)

            elif header == FILE_DATAGRAM_HEADER:
                process_file_datagram(ts, packet, header, queues)

            elif header in [GROUP_MSG_INVITE_HEADER,
                            GROUP_MSG_JOIN_HEADER,
                            GROUP_MSG_MEMBER_ADD_HEADER,
                            GROUP_MSG_MEMBER_REM_HEADER,
                            GROUP_MSG_EXIT_GROUP_HEADER]:
                process_group_management_message(ts, packet, header, messages_to_flask)

            if unit_test:
                break


def load_packet_from_queue(queues:  'QueueDict',
                           gateway: 'Gateway'
                           ) -> Tuple['datetime', bytes]:
    """Load packet from Source Computer.

    Perform error detection/correction.
    """
    packets_from_source_computer = queues[GATEWAY_QUEUE]

    while not packets_from_source_computer.qsize():
        time.sleep(0.01)
    ts, packet = packets_from_source_computer.get()  # type: datetime, bytes

    packet = gateway.detect_errors(packet)

    return ts, packet


def process_command_datagram(ts:     'datetime',
                             packet: bytes,
                             header: bytes,
                             queues: 'QueueDict'
                             ) -> None:
    """Process command datagram."""
    commands_to_dc = queues[DST_COMMAND_QUEUE]
    ts_bytes       = int_to_bytes(int(ts.strftime("%Y%m%d%H%M%S%f")[:-4]))

    commands_to_dc.put(header + ts_bytes + packet)

    p_type = "Command  " if header == COMMAND_DATAGRAM_HEADER else "Local key"
    rp_print(f"{p_type} to local Receiver", ts)


def process_message_datagram(ts:     'datetime',
                             packet: bytes,
                             header: bytes,
                             queues: 'QueueDict'
                             ) -> None:
    """Process message and public key datagram."""
    packets_to_dc     = queues[DST_MESSAGE_QUEUE]
    messages_to_flask = queues[M_TO_FLASK_QUEUE]

    onion_pub_key, payload = separate_header(packet, ONION_SERVICE_PUBLIC_KEY_LENGTH)
    packet_str             = header.decode() + b85encode(payload)
    ts_bytes               = int_to_bytes(int(ts.strftime("%Y%m%d%H%M%S%f")[:-4]))

    queue_to_flask(packet_str, onion_pub_key, messages_to_flask, ts, header)

    if header == MESSAGE_DATAGRAM_HEADER:
        packets_to_dc.put(header + ts_bytes + onion_pub_key + ORIGIN_USER_HEADER + payload)


def process_file_datagram(ts:     'datetime',
                          packet: bytes,
                          header: bytes,
                          queues: 'QueueDict'
                          ) -> None:
    """Process file datagram."""
    files_to_flask         = queues[F_TO_FLASK_QUEUE]
    no_contacts_b, payload = separate_header(packet, ENCODED_INTEGER_LENGTH)
    no_contacts            = bytes_to_int(no_contacts_b)
    ser_accounts, file_ct  = separate_header(payload, no_contacts * ONION_SERVICE_PUBLIC_KEY_LENGTH)
    pub_keys               = split_byte_string(ser_accounts, item_len=ONION_SERVICE_PUBLIC_KEY_LENGTH)

    for onion_pub_key in pub_keys:
        queue_to_flask(file_ct, onion_pub_key, files_to_flask, ts, header)


def process_group_management_message(ts:                'datetime',
                                     packet:            bytes,
                                     header:            bytes,
                                     messages_to_flask: 'Queue[Tuple[Union[bytes, str], bytes]]'
                                     ) -> None:
    """Parse and display group management message."""
    header_str       = header.decode()
    group_id, packet = separate_header(packet, GROUP_ID_LENGTH)

    if header in [GROUP_MSG_INVITE_HEADER, GROUP_MSG_JOIN_HEADER]:
        pub_keys = split_byte_string(packet, ONION_SERVICE_PUBLIC_KEY_LENGTH)
        for onion_pub_key in pub_keys:
            others     = [k for k in pub_keys if k != onion_pub_key]
            packet_str = header_str + b85encode(group_id + b''.join(others))
            queue_to_flask(packet_str, onion_pub_key, messages_to_flask, ts, header)

    elif header in [GROUP_MSG_MEMBER_ADD_HEADER, GROUP_MSG_MEMBER_REM_HEADER]:
        first_list_len_b, packet  = separate_header(packet, ENCODED_INTEGER_LENGTH)
        first_list_length         = bytes_to_int(first_list_len_b)
        pub_keys                  = split_byte_string(packet, ONION_SERVICE_PUBLIC_KEY_LENGTH)
        before_adding = remaining = pub_keys[:first_list_length]
        new_in_group  = removable = pub_keys[first_list_length:]

        if header == GROUP_MSG_MEMBER_ADD_HEADER:

            process_add_or_group_remove_member(ts, header, header_str, group_id, messages_to_flask,
                                               before_adding, new_in_group)

            for onion_pub_key in new_in_group:
                other_new  = [k for k in new_in_group if k != onion_pub_key]
                packet_str = (GROUP_MSG_INVITE_HEADER.decode()
                              + b85encode(group_id + b''.join(other_new + before_adding)))
                queue_to_flask(packet_str, onion_pub_key, messages_to_flask, ts, header)

        elif header == GROUP_MSG_MEMBER_REM_HEADER:
            process_add_or_group_remove_member(ts, header, header_str, group_id, messages_to_flask,
                                               remaining, removable)

    elif header == GROUP_MSG_EXIT_GROUP_HEADER:
        process_group_exit_header(ts, packet, header, header_str, group_id, messages_to_flask)


def process_add_or_group_remove_member(ts:                'datetime',
                                       header:            bytes,
                                       header_str:        str,
                                       group_id:          bytes,
                                       messages_to_flask: 'Queue[Tuple[Union[bytes, str], bytes]]',
                                       remaining:         List[bytes],
                                       removable:         List[bytes]
                                       ) -> None:
    """Process group add or remove member packet."""
    packet_str = header_str + b85encode(group_id + b"".join(removable))
    for onion_pub_key in remaining:
        queue_to_flask(packet_str, onion_pub_key, messages_to_flask, ts, header)


def process_group_exit_header(ts:                'datetime',
                              packet:            bytes,
                              header:            bytes,
                              header_str:        str,
                              group_id:          bytes,
                              messages_to_flask: 'Queue[Tuple[Union[bytes, str], bytes]]'
                              ) -> None:
    """Process group exit packet."""
    pub_keys   = split_byte_string(packet, ONION_SERVICE_PUBLIC_KEY_LENGTH)
    packet_str = header_str + b85encode(group_id)
    for onion_pub_key in pub_keys:
        queue_to_flask(packet_str, onion_pub_key, messages_to_flask, ts, header)


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
