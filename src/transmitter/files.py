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

import datetime
import os
import typing
import zlib

from typing import Tuple

from src.common.crypto     import byte_padding, csprng, encrypt_and_sign
from src.common.encoding   import int_to_bytes
from src.common.exceptions import SoftError
from src.common.misc       import readable_size, split_byte_string
from src.common.statics    import (COMPRESSION_LEVEL, FILE_ETA_FIELD_LENGTH, FILE_PACKET_CTR_LENGTH,
                                   FILE_SIZE_FIELD_LENGTH, PADDING_LENGTH, TRAFFIC_MASKING_QUEUE_CHECK_DELAY, US_BYTE)

if typing.TYPE_CHECKING:
    from src.common.db_settings  import Settings
    from src.transmitter.windows import TxWindow


class File(object):
    """File object wraps methods around file data/header processing.

    The File object is only used when sending a file during traffic
    masking.
    """

    def __init__(self,
                 path:     str,
                 window:   'TxWindow',
                 settings: 'Settings'
                 ) -> None:
        """Load file data from specified path and add headers."""
        self.window   = window
        self.settings = settings

        self.name                    = self.get_name(path)
        data                         = self.load_file_data(path)
        size, self.size_hr           = self.get_size(path)
        processed                    = self.process_file_data(data)
        self.time_hr, self.plaintext = self.finalize(size, processed)

    @staticmethod
    def get_name(path: str) -> bytes:
        """Parse and validate file name."""
        name = (path.split('/')[-1]).encode()
        File.name_length_check(name)
        return name

    @staticmethod
    def name_length_check(name: bytes) -> None:
        """Ensure that file header fits the first packet."""
        full_header_length = (FILE_PACKET_CTR_LENGTH
                              + FILE_ETA_FIELD_LENGTH
                              + FILE_SIZE_FIELD_LENGTH
                              + len(name) + len(US_BYTE))

        if full_header_length >= PADDING_LENGTH:
            raise SoftError("Error: File name is too long.", head_clear=True)

    @staticmethod
    def load_file_data(path: str) -> bytes:
        """Load file name, size, and data from the specified path."""
        if not os.path.isfile(path):
            raise SoftError("Error: File not found.", head_clear=True)
        with open(path, 'rb') as f:
            data = f.read()
        return data

    @staticmethod
    def get_size(path: str) -> Tuple[bytes, str]:
        """Get size of file in bytes and in human readable form."""
        byte_size = os.path.getsize(path)
        if byte_size == 0:
            raise SoftError("Error: Target file is empty.", head_clear=True)
        size    = int_to_bytes(byte_size)
        size_hr = readable_size(byte_size)

        return size, size_hr

    @staticmethod
    def process_file_data(data: bytes) -> bytes:
        """Compress, encrypt and encode file data.

        Compress file to reduce data transmission time. Add an inner
        layer of encryption to provide sender-based control over partial
        transmission.
        """
        compressed = zlib.compress(data, level=COMPRESSION_LEVEL)
        file_key   = csprng()
        processed  = encrypt_and_sign(compressed, key=file_key)
        processed += file_key
        return processed

    def finalize(self, size: bytes, processed: bytes) -> Tuple[str, bytes]:
        """Finalize packet and generate plaintext."""
        time_bytes, time_print = self.update_delivery_time(self.name, size, processed, self.settings, self.window)
        packet_data            = time_bytes + size + self.name + US_BYTE + processed
        return time_print, packet_data

    @staticmethod
    def update_delivery_time(name:      bytes,
                             size:      bytes,
                             processed: bytes,
                             settings:  'Settings',
                             window:    'TxWindow'
                             ) -> Tuple[bytes, str]:
        """Calculate transmission time.

        Transmission time depends on delay settings, file size and
        number of members if the recipient is a group.
        """
        time_bytes = bytes(FILE_ETA_FIELD_LENGTH)
        no_packets = File.count_number_of_packets(name, size, processed, time_bytes)
        avg_delay  = settings.tm_static_delay + (settings.tm_random_delay / 2)

        total_time  = len(window) * no_packets * avg_delay
        total_time *= 2  # Accommodate command packets between file packets
        total_time += no_packets * TRAFFIC_MASKING_QUEUE_CHECK_DELAY

        # Update delivery time
        time_bytes = int_to_bytes(int(total_time))
        time_hr    = str(datetime.timedelta(seconds=int(total_time)))

        return time_bytes, time_hr

    @staticmethod
    def count_number_of_packets(name:       bytes,
                                size:       bytes,
                                processed:  bytes,
                                time_bytes: bytes
                                ) -> int:
        """Count number of packets needed for file delivery."""
        packet_data = time_bytes + size + name + US_BYTE + processed
        if len(packet_data) < PADDING_LENGTH:
            return 1

        packet_data += bytes(FILE_PACKET_CTR_LENGTH)
        packet_data  = byte_padding(packet_data)
        return len(split_byte_string(packet_data, item_len=PADDING_LENGTH))
