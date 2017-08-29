#!/usr/bin/env python3.6
# -*- coding: utf-8 -*-

"""
Copyright (C) 2013-2017  Markus Ottela

This file is part of .

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
import datetime
import os
import typing
import zlib

from src.common.crypto       import byte_padding, csprng, encrypt_and_sign
from src.common.encoding     import int_to_bytes
from src.common.exceptions   import FunctionReturn
from src.common.misc         import readable_size, split_byte_string
from src.common.reed_solomon import RSCodec
from src.common.statics      import *

if typing.TYPE_CHECKING:
    from src.common.db_settings import Settings
    from src.common.gateway     import Gateway
    from src.tx.windows         import TxWindow


class File(object):
    """File object wraps methods around file data/header processing."""

    def __init__(self,
                 path:     str,
                 window:   'TxWindow',
                 settings: 'Settings',
                 gateway:  'Gateway') -> None:
        """Load file data from specified path and add headers."""
        self.path     = path
        self.window   = window
        self.settings = settings
        self.gateway  = gateway

        self.name = None  # type: bytes
        self.size = None  # type: bytes
        self.data = None  # type: bytes

        self.time_bytes = bytes(FILE_ETA_FIELD_LEN)
        self.time_print = ''
        self.size_print = ''
        self.plaintext  = b''

        self.load_file_data()
        self.process_file_data()
        self.finalize()

    def load_file_data(self) -> None:
        """Load file name, size and data from specified path."""
        if not os.path.isfile(self.path):
            raise FunctionReturn("Error: File not found.")

        self.name = (self.path.split('/')[-1]).encode()
        self.name_length_check()

        byte_size = os.path.getsize(self.path)
        if byte_size == 0:
            raise FunctionReturn("Error: Target file is empty.")
        self.size       = int_to_bytes(byte_size)
        self.size_print = readable_size(byte_size)

        with open(self.path, 'rb') as f:
            self.data = f.read()

    def process_file_data(self) -> None:
        """Compress, encrypt and encode file data.

        Compress file to reduce data transmission time. Add inner
        layer of encryption to provide sender-based control over
        partial transmission. Encode data with Base85. This prevents
        inner ciphertext from colliding with file header delimiters.
        """
        compressed = zlib.compress(self.data, level=COMPRESSION_LEVEL)

        file_key   = csprng()
        encrypted  = encrypt_and_sign(compressed, key=file_key)
        encrypted += file_key

        self.data = base64.b85encode(encrypted)

    def finalize(self) -> None:
        """Finalize packet and generate plaintext."""
        self.update_delivery_time()
        self.plaintext = self.time_bytes + self.size + self.name + US_BYTE + self.data

    def name_length_check(self) -> None:
        """Ensure that file header fits the first packet."""
        header  = bytes(FILE_PACKET_CTR_LEN + FILE_ETA_FIELD_LEN + FILE_SIZE_FIELD_LEN)
        header += self.name + US_BYTE
        if len(header) >= PADDING_LEN:
            raise FunctionReturn("Error: File name is too long.")

    def count_number_of_packets(self) -> int:
        """Count number of packets needed for file delivery."""
        packet_data = self.time_bytes + self.size + self.name + US_BYTE + self.data
        if len(packet_data) < PADDING_LEN:
            return 1
        else:
            packet_data += bytes(FILE_PACKET_CTR_LEN)
            packet_data  = byte_padding(packet_data)
            return len(split_byte_string(packet_data, item_len=PADDING_LEN))

    def update_delivery_time(self) -> None:
        """Calculate transmission time.

        Transmission time is based on average delays and settings.
        """
        no_packets = self.count_number_of_packets()

        if self.settings.session_traffic_masking:
            avg_delay = self.settings.traffic_masking_static_delay + (self.settings.traffic_masking_random_delay / 2)
            if self.settings.multi_packet_random_delay:
                avg_delay += (self.settings.max_duration_of_random_delay / 2)

            total_time  = len(self.window) * no_packets * avg_delay
            total_time *= 2  # Accommodate command packets between file packets
            total_time += no_packets * TRAFFIC_MASKING_QUEUE_CHECK_DELAY

        else:
            # Determine total data to be transmitted over serial
            rs         = RSCodec(2 * self.settings.session_serial_error_correction)
            total_data = 0
            for c in self.window:
                data        = os.urandom(PACKET_LENGTH) + c.rx_account.encode() + c.tx_account.encode()
                enc_data    = rs.encode(data)
                total_data += no_packets * len(enc_data)

            # Determine time required to send all data
            total_time = 0.0
            if self.settings.local_testing_mode:
                total_time += no_packets * LOCAL_TESTING_PACKET_DELAY
            else:
                total_bauds  = total_data * BAUDS_PER_BYTE
                total_time  += total_bauds / self.settings.session_serial_baudrate
                total_time  += no_packets * self.settings.txm_inter_packet_delay

            if self.settings.multi_packet_random_delay:
                total_time += no_packets * (self.settings.max_duration_of_random_delay / 2)

        # Update delivery time
        self.time_bytes = int_to_bytes(int(total_time))
        self.time_print = str(datetime.timedelta(seconds=int(total_time)))
