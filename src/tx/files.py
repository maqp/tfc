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
import datetime
import os
import typing
import zlib

from src.common.crypto       import byte_padding, encrypt_and_sign, keygen
from src.common.encoding     import int_to_bytes
from src.common.errors       import FunctionReturn
from src.common.input        import yes
from src.common.misc         import split_byte_string
from src.common.path         import ask_path_gui
from src.common.reed_solomon import RSCodec
from src.common.statics      import *

if typing.TYPE_CHECKING:
    from multiprocessing        import Queue
    from src.common.db_settings import Settings
    from src.common.gateway     import Gateway
    from src.tx.windows         import Window

class File(object):
    """File object wraps methods around file data/header processing."""

    def __init__(self,
                 path:     str,
                 window:   'Window',
                 settings: 'Settings',
                 gateway:  'Gateway') -> None:
        """Load file data from specified path and add headers."""
        self.path     = path
        self.window   = window
        self.settings = settings
        self.gateway  = gateway
        self.type     = 'file'

        self.name = None  # type: bytes
        self.size = None  # type: bytes
        self.data = None  # type: bytes

        self.time_s    = ''
        self.time_l    = b'00d 00h 00m 00s'
        self.plaintext = b''

        self.verify_file_exists()
        self.get_file_size()
        self.get_file_name()
        self.load_file_data()
        self.compress_file_data()
        self.encrypt_file_data()
        self.encode_file_data()
        self.header_length_check()
        self.finalize()

    def verify_file_exists(self) -> None:
        """Check that file exists (when specified in CLI)."""
        if not os.path.isfile(self.path):
            raise FunctionReturn("Error: File not found.")

    def get_file_size(self) -> None:
        """Get size of file."""
        size_bytes = os.path.getsize(self.path)
        if size_bytes == 0:
            raise FunctionReturn("Error: Target file is empty. No file was sent.")
        self.size = File.readable_size(size_bytes)

    def get_file_name(self) -> None:
        """Parse name of file."""
        self.name = (self.path.split('/')[-1]).encode()

    def load_file_data(self) -> None:
        """Load binary data of file."""
        with open(self.path, 'rb') as f:
            self.data = f.read()

    def compress_file_data(self) -> None:
        """Compress file for faster delivery."""
        self.data = zlib.compress(self.data, level=9)

    def encrypt_file_data(self) -> None:
        """Encrypt file data with inner layer.

        This prevents decryption of partially received data if user cancels file transmission.
        """
        file_key   = keygen()
        self.data  = encrypt_and_sign(self.data, key=file_key)
        self.data += file_key

    def encode_file_data(self) -> None:
        """Encode file data with Base85.

        This prevents inner ciphertext from
        colliding with file header delimiters.
        """
        self.data = base64.b85encode(self.data)

    def header_length_check(self) -> None:
        """Ensure that file header fits the first packet."""
        header = US_BYTE.join([self.name, bytearray(8), self.size, self.time_l, US_BYTE])
        if len(header) > 254:
            raise FunctionReturn("Error: File name is too long. No file was sent.")

    def finalize(self) -> None:
        """Finalize packet and generate plaintext."""
        self.update_delivery_time()
        self.plaintext = US_BYTE.join([self.name, self.size, self.time_l, self.data])

    def update_delivery_time(self) -> None:
        """Calculate transmission time.

        Transmission time is based on average delays and settings.
        """
        packet_data  = US_BYTE.join([self.name, self.size, self.time_l, self.data])

        if len(packet_data) < 255:
            no_packets = 1
        else:
            packet_data = bytes(8) + packet_data
            packet_data = byte_padding(packet_data)
            no_packets  = len(split_byte_string(packet_data, item_len=255))

        no_recipients = len(self.window)

        if self.settings.session_trickle:
            avg_delay = self.settings.trickle_stat_delay + (self.settings.trickle_rand_delay / 2)

            if self.settings.long_packet_rand_d:
                avg_delay += (self.settings.max_val_for_rand_d / 2)

            # Multiply by two as trickle sends a command packet between every file packet.
            total_time = 2 * no_recipients * no_packets * avg_delay

            # Add constant time queue load time
            total_time += no_packets * TRICKLE_QUEUE_CHECK_DELAY

        else:
            total_data      = 0
            rs              = RSCodec(2 * self.settings.session_ec_ratio)
            static_data_len = (1 + 24 + 8 + 16 + 24 + 256 + 16 + 1)  # header + nonce + harac-ct + tag + nonce + ass. p. ct  + tag + US_BYTE
            for c in self.window.window_contacts:
                data_len     = static_data_len + (len(c.rx_account.encode()) + len(c.tx_account.encode()))
                enc_data_len = len(rs.encode((os.urandom(data_len))))
                total_data  += (no_packets * enc_data_len)

            total_time = 0.0
            if not self.settings.local_testing_mode:
                bauds_in_byte = 10
                total_bauds   = total_data * bauds_in_byte
                total_time   += total_bauds / self.settings.session_if_speed

            total_time += no_packets * self.gateway.delay

            if self.settings.long_packet_rand_d:
                total_time += no_packets * (self.settings.max_val_for_rand_d / 2)

        delta_seconds = datetime.timedelta(seconds=int(total_time))
        delivery_time = datetime.datetime(1, 1, 1) + delta_seconds

        # Format delivery time string
        if delivery_time.second == 0:
            self.time_s = '00s'
            self.time_l = b'00d 00h 00m 00s'
            return None

        time_l_str  = ''
        self.time_s = ''

        for i in [(delivery_time.day - 1, 'd'), (delivery_time.hour,   'h'),
                  (delivery_time.minute,  'm'), (delivery_time.second, 's')]:
            if i[0] > 0:
                self.time_s += str(i[0]).zfill(2) + f'{i[1]} '
            time_l_str      += str(i[0]).zfill(2) + f'{i[1]} '

        self.time_s = self.time_s.strip(' ')
        time_l_str.strip()
        self.time_l = time_l_str.encode()

    @classmethod
    def readable_size(cls, size: int) -> bytes:
        """Convert file size from bytes to human readable form."""
        f_size = float(size)
        for unit in ['', 'K', 'M', 'G', 'T', 'P', 'E', 'Z']:
            if abs(f_size) < 1024.0:
                return '{:3.1f}{}B'.format(f_size, unit).encode()
            f_size /= 1024.0

        return '{:.1f}{}B'.format(f_size, 'Y').encode()


def queue_file(window:   'Window',
               settings: 'Settings',
               f_queue:  'Queue',
               gateway:  'Gateway') -> None:
    """Ask file path and load file data."""
    path    = ask_path_gui("Select file to send...", settings, get_file=True)
    file    = File(path, window, settings, gateway)
    name    = file.name.decode()
    size    = file.size.decode()
    payload = file.plaintext

    if len(payload) < 255:
        padded      = byte_padding(payload)
        packet_list = [F_S_HEADER + padded]
    else:
        payload = bytes(8) + payload
        padded  = byte_padding(payload)
        p_list  = split_byte_string(padded, item_len=255)

        #                            <   number of packets   >
        packet_list = ([F_L_HEADER + int_to_bytes(len(p_list)) + p_list[0][8:]] +
                       [F_A_HEADER + p for p in p_list[1:-1]] +
                       [F_E_HEADER + p_list[-1]])

    for p in packet_list:
        assert len(p) == 256

    if settings.confirm_sent_files:
        if not yes(f"Send {name} ({size}) to {window.type} {window.name} "
                   f"({len(packet_list)} packets, time: {file.time_s})?", tail=1):
            raise FunctionReturn("File selection aborted.")

    if settings.session_trickle:
        log_m_dictionary = dict((c.rx_account, c.log_messages) for c in window)
        for p in packet_list:
            f_queue.put((p, log_m_dictionary))

    else:
        for c in window:
            for p in packet_list:
                f_queue.put((p, settings, c.rx_account, c.tx_account, c.log_messages, window.uid))
