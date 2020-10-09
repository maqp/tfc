#!/usr/bin/env python3
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

import base64
import os
import sys

BUFFER_FILE_DIR  = '/home/user/tfc/.buffered_incoming_packets'
BUFFER_FILE_NAME = 'buffered_incoming_packet'


def ensure_dir(directory: str) -> None:
    """Ensure directory exists."""
    name = os.path.dirname(directory)
    if not os.path.exists(name):
        try:
            os.makedirs(name)
        except FileExistsError:
            pass


def store_unique(file_data: bytes,  # File data to store
                 file_dir:  str,    # Directory to store file
                 file_name: str     # Preferred name for the file.
                 ) -> None:
    """Store file under a unique filename.

    If file exists, add trailing counter .# with value as large as
    needed to ensure existing file is not overwritten.
    """
    ensure_dir(f'{file_dir}/')

    ctr = 0
    while os.path.isfile(f"{file_dir}/{file_name}.{ctr}"):
        ctr += 1

    with open(f"{file_dir}/{file_name}.{ctr}", 'wb+') as f:
        f.write(file_data)
        f.flush()
        os.fsync(f.fileno())


def main() -> None:
    """Store data from STDIN to unique file for Relay/Receiver Program.

    To prevent adversaries from delivering malicious binaries on DestinationVM,
    this utility encodes received raw bytes with Base85, that is decoded by the
    Receiver Program prior to further authentication.
    """
    data = sys.stdin.buffer.read()

    store_unique(file_data=base64.b85encode(data),
                 file_dir=BUFFER_FILE_DIR,
                 file_name=BUFFER_FILE_NAME)


if __name__ == '__main__':
    main()
