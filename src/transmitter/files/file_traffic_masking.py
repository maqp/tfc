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

import os
import statistics
import zlib

from datetime import timedelta
from pathlib import Path
from typing import TYPE_CHECKING

from src.common.entities.payload import FilePayload
from src.common.crypto.algorithms.padding import byte_padding
from src.common.crypto.pt_ct import FileInnerPT
from src.common.crypto.keys.symmetric_key import LongFileKey
from src.common.types_custom import BytesFile
from src.common.utils.encoding import int_to_bytes
from src.common.exceptions import SoftError
from src.common.utils.conversion import human_readable_size
from src.common.utils.strings import split_byte_string
from src.common.statics import CompressionLiterals, FieldLength, CryptoVarLength, Delay, Separator, CompoundFieldLength

if TYPE_CHECKING:
    from src.common.crypto.pt_ct import FileInnerCT
    from src.database.db_settings import Settings
    from src.ui.transmitter.window_tx import TxWindow


class TrafficMaskedFile:
    """\
    TrafficMaskedFile object wraps methods around file data/header processing.

    The object is only used when sending a file during traffic masking.
    """

    def __init__(self,
                 path_to_file : Path,
                 window       : 'TxWindow',
                 settings     : 'Settings'
                 ) -> None:
        """Create new TrafficMaskedFile object."""
        self.path_to_file = path_to_file
        self.window       = window
        self.settings     = settings

        self.validate_file()
        self._file_inner_ct                 = self.process_file_data()
        self.time_hr, self._plaintext_bytes = self.finalize()

    def to_payload(self) -> FilePayload:
        """Return the data as a FilePayload object."""
        return FilePayload.from_bytes(self._plaintext_bytes)

    # ┌─────────────────┐
    # │ File Properties │
    # └─────────────────┘

    @property
    def file_name(self) -> str:
        """Get the file name from path"""
        return self.path_to_file.name

    @property
    def file_name_bytes(self) -> bytes:
        """Return the encoded filename."""
        return self.file_name.encode()

    @property
    def file_size(self) -> int:
        """Return file size in bytes."""
        return os.path.getsize(self.path_to_file)

    @property
    def file_size_bytes(self) -> bytes:
        """Return file size in bytes."""
        return int_to_bytes(self.file_size)

    @property
    def file_size_hr(self) -> str:
        """Get human readable form of file size."""
        return human_readable_size(self.file_size)

    # ┌────────────┐
    # │ Validation │
    # └────────────┘

    def validate_file(self) -> None:
        """Validate file name and content before loading."""
        self.validate_file_exists()
        self.validate_file_is_not_empty()
        self.validate_filename_length()

    def validate_file_exists(self) -> None:
        """Ensure that the file exists."""
        if not os.path.isfile(self.path_to_file):
            raise SoftError('Error: File not found.', clear_before=True)

    def validate_file_is_not_empty(self) -> None:
        """Ensure that the file is not empty."""
        if self.file_size == 0:
            raise SoftError('Error: File is empty.', clear_before=True)

    def validate_filename_length(self) -> None:
        """Validate the filename length.

        The file name must fit into the fixed size file transmission header.
        """
        purp_header_length = CompoundFieldLength.FILE_HEADER.value + len(self.file_name.encode())
        if purp_header_length >= CryptoVarLength.PADDING.value:
            raise SoftError('Error: File name is too long.', clear_before=True)

    # ┌─────────────────┐
    # │ File Processing │
    # └─────────────────┘

    def load_file_data(self) -> bytes:
        """Load file data from the specified path."""
        with open(self.path_to_file, 'rb') as f:
            data = f.read()
        return data

    def process_file_data(self) -> 'FileInnerCT':
        """Compress and encrypt file data.

        Compress file to reduce data transmission time. Add an inner
        layer of encryption to provide sender-based control over partial
        transmission.

        This function makes an exception to key encapsulation as the security
        of the key isn't being protected in ways other than delivering it in
        the last assembly packet -- again for sender-based control over
        partial transmission.
        """
        file_bytes = self.load_file_data()
        compressed = zlib.compress(file_bytes, level=CompressionLiterals.COMPRESSION_LEVEL)

        long_file_key    = LongFileKey()
        file_ciphertext  = long_file_key.encrypt_and_sign(FileInnerPT(compressed))
        file_ciphertext  = file_ciphertext.add_sender_based_control_key(long_file_key)

        return file_ciphertext

    def finalize(self) -> tuple[str, BytesFile]:
        """Finalize plaintext packet."""
        time_bytes, time_hr = self.update_delivery_time()
        packet_data         = BytesFile(time_bytes + self.file_size_bytes + self.file_name_bytes + Separator.US_BYTE + self._file_inner_ct.ct_bytes)
        return time_hr, packet_data

    def update_delivery_time(self) -> tuple[bytes, str]:
        """Calculate transmission time.

        Transmission time depends on delay settings, file size and
        number of members if the recipient is a group.
        """
        no_packets = self.count_number_of_packets()
        avg_delay  = self.settings.tm_static_delay + statistics.mean([0, int(self.settings.tm_random_delay)])

        total_time  = len(self.window) * no_packets * avg_delay
        total_time *= 2  # Accommodate command packets between file packets
        total_time += no_packets * Delay.TRAFFIC_MASKING_QUEUE_CHECK_DELAY

        # Update delivery time
        time_bytes = int_to_bytes(round(total_time))
        time_hr    = str(timedelta(seconds=int(total_time)))

        return time_bytes, time_hr

    def count_number_of_packets(self) -> int:
        """Count the number of packets needed for file delivery."""
        time_bytes  = bytes(FieldLength.FILE_ETA_FIELD)  # Placeholder field
        packet_data = time_bytes + self.file_size_bytes + self.file_name_bytes + Separator.US_BYTE + self._file_inner_ct.ct_bytes

        if len(packet_data) < CryptoVarLength.PADDING:
            return 1

        packet_data += bytes(FieldLength.FILE_PACKET_CTR.value)
        packet_data  = byte_padding(packet_data)
        return len(split_byte_string(packet_data, item_len=CryptoVarLength.PADDING))
