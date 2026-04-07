#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
TFC - Onion-routed, endpoint secure messaging system
Copyright (C) 2013-2026  Markus Ottela

This file is part of TFC.
TFC is free software: you can redistribute it and/or modify it under the terms
of the GNU General Public License as published by the Free Software Foundation,
either version 3 of the License, or (at your option) any later version. TFC is
distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without
even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
See the GNU General Public License for more details. You should have received a
copy of the GNU General Public License along with TFC. If not, see
<https://www.gnu.org/licenses/>.
"""

import base64
import os
import random

from io import BytesIO
from typing import Any, Optional as O, TYPE_CHECKING

# noinspection PyPackageRequirements
from flask import Response, send_file

from src.common.crypto.keys.onion_service_keys import OnionServicePrivateKey
from src.common.statics import BufferFileDir, BufferFileName, CompoundFieldLength, DatagramHeader
from src.common.types_custom import FloatTMDelay, StrURLToken, StrUniqueBufferedFileName, StrContactBufferFileDir
from src.common.utils.io import ensure_dir, get_working_dir
from src.relay.server.url_token import validate_url_token
from src.transmitter.sender.sender_traffic_masking import HideRunTime

if TYPE_CHECKING:
    from src.common.queues import RelayQueue
    from src.relay.process_server_flask import PubKeyDict
    from src.common.crypto.keys.symmetric_key import BufferKey


MESSAGE_CHUNK_MIN     = 1
MESSAGE_CHUNK_MAX     = 50
MESSAGE_CHUNK_MEAN    = (MESSAGE_CHUNK_MIN + MESSAGE_CHUNK_MAX) / 2
MESSAGE_CHUNK_STDDEV  = (MESSAGE_CHUNK_MAX - MESSAGE_CHUNK_MIN) / 6
MESSAGE_PAYLOAD_BYTES = CompoundFieldLength.MESSAGE_DATAGRAM_PAYLOAD.value
FLASK_PREPARE_DELAY   = FloatTMDelay(0.3)
NOISE_ONION_ADDRESS   = OnionServicePrivateKey(bytes(range(1, 33))).onion_addr.encode()


def load_messages_from_server_buffer_file(purp_url_token : StrURLToken,
                                          queues         : 'RelayQueue',
                                          pub_key_dict   : 'PubKeyDict',
                                          buffer_key     : 'BufferKey',
                                          ) -> Response | str:
    """Read outgoing message that has been buffered on disk."""
    if not validate_url_token(purp_url_token, queues, pub_key_dict):
        return ''

    identified_onion_pub_key = pub_key_dict[purp_url_token]

    # Load outgoing messages for all contacts,
    # return the oldest message to the contact

    sub_dir     = identified_onion_pub_key.derive_relay_buffer_sub_dir(buffer_key)
    buf_dir_str = os.path.join(get_working_dir(), BufferFileDir.RELAY_BUF_OUTGOING_MESSAGES, sub_dir)
    buf_dir     = StrContactBufferFileDir(buf_dir_str)

    ensure_dir(buf_dir)

    with HideRunTime(duration=FLASK_PREPARE_DELAY):
        response_lines = prepare_message_chunk(buf_dir, buffer_key)

    return Response(response_lines, mimetype='text/plain')


def load_file_from_server_buffer_file(purp_url_token : StrURLToken,
                                      queues         : 'RelayQueue',
                                      pub_key_dict   : 'PubKeyDict',
                                      buffer_key     : 'BufferKey',
                                      ) -> Any:
    """Read outgoing file that has been buffered on disk."""
    if not validate_url_token(purp_url_token, queues, pub_key_dict):
        return ''

    identified_onion_pub_key = pub_key_dict[purp_url_token]

    sub_dir     = identified_onion_pub_key.derive_relay_buffer_sub_dir(buffer_key)
    buf_dir_str = os.path.join(get_working_dir(), BufferFileDir.RELAY_BUF_OUTGOING_FILES, sub_dir)
    buf_dir     = StrContactBufferFileDir(buf_dir_str)

    ensure_dir(buf_dir)

    buffer_files = list_buffer_files(buf_dir, BufferFileName.RELAY_BUF_OUTGOING_FILE)
    if buffer_files:
        packet = read_packet_from_buffer_file(buf_dir, buffer_files[0], buffer_key)
        if packet is None:
            return ''
        mem = BytesIO()
        mem.write(packet)
        mem.seek(0)
        return send_file(mem, mimetype='application/octet-stream')

    return ''


def prepare_message_chunk(buffer_file_dir: StrContactBufferFileDir,
                          buffer_key     : 'BufferKey',
                          ) -> list[bytes]:
    """Load a fixed-size chunk of real packets and masking packets."""
    rng          = random.SystemRandom()
    chunk_size   = max(MESSAGE_CHUNK_MIN, min(MESSAGE_CHUNK_MAX, round(rng.normalvariate(MESSAGE_CHUNK_MEAN, MESSAGE_CHUNK_STDDEV))))
    buffer_files = list_buffer_files(buffer_file_dir, BufferFileName.RELAY_BUF_OUTGOING_MESSAGE)
    chunk_lines  = []

    for file_name in buffer_files[:chunk_size]:
        packet = read_packet_from_buffer_file(buffer_file_dir, StrUniqueBufferedFileName(file_name), buffer_key)
        if packet is not None:
            chunk_lines.append(packet + b'\n')

    noise_packet = create_traffic_masking_packet()
    for _ in range(chunk_size - len(chunk_lines)):
        chunk_lines.append(noise_packet + b'\n')

    return chunk_lines


def create_traffic_masking_packet() -> bytes:
    """Create a syntactically valid masking packet matching message datagram length."""
    payload = base64.b85encode(NOISE_ONION_ADDRESS
                               + os.getrandom(CompoundFieldLength.CT_HEADER.value)
                               + os.getrandom(CompoundFieldLength.CT_ASSEMBLY_PACKET.value))
    return DatagramHeader.TRAFFIC_MASKING.value + payload


def list_buffer_files(buffer_file_dir  : StrContactBufferFileDir,
                      buffer_file_name : BufferFileName
                      ) -> list[StrUniqueBufferedFileName]:
    """Return buffered files sorted from oldest to newest."""
    prefix     = f'{buffer_file_name}.'
    prefix_len = len(prefix)

    file_numbers = [f[prefix_len:] for f in os.listdir(buffer_file_dir) if f.startswith(prefix)]

    return [StrUniqueBufferedFileName(f'{buffer_file_name}.{n}')
            for n in sorted((n for n in file_numbers if n.isdigit()), key=int)]


def read_packet_from_buffer_file(buffer_file_dir  : StrContactBufferFileDir,
                                 buffer_file_name : StrUniqueBufferedFileName,
                                 buffer_key       : 'BufferKey',
                                 ) -> O[bytes]:
    """Read and remove a specific buffered packet file."""
    buffer_file_path = os.path.join(buffer_file_dir, buffer_file_name)

    try:
        with open(buffer_file_path, 'rb') as f:
            packet_ct = f.read()
        os.remove(buffer_file_path)
    except FileNotFoundError:
        return None

    return buffer_key.auth_and_decrypt(packet_ct, database=buffer_file_path)
