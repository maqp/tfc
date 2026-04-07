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

from src.common.exceptions import SoftError, ignored
from src.common.statics import WorkingDir


def setup_working_dir() -> None:
    """Setup the the working directory for TFC."""
    working_dir = get_working_dir()
    ensure_dir(working_dir)
    os.chdir(working_dir)


def get_working_dir() -> WorkingDir:
    """Get the working directory for TFC."""
    from src.common.process import platform_is_tails
    return WorkingDir.TAILS if platform_is_tails() else WorkingDir.NORMAL


def ensure_dir(directory: str) -> None:
    """Ensure a directory exists.

    This function is run before checking a database exists in the
    specified directory or before storing data into a directory.
    It prevents errors in case the user has for some reason removed
    the directory.
    """
    if not directory.endswith('/'):
        directory += '/'
    name = os.path.dirname(directory)
    if not os.path.exists(name):
        with ignored(FileExistsError):
            try:
                os.makedirs(name)
            except PermissionError:
                pass


def store_unique(file_dir  : str,    # Directory to store file
                 file_name : str,    # Preferred name for the file.
                 file_data : bytes,  # File data to store
                 ) -> str:
    """Store file under a unique filename.

    Add trailing counter .# to ensure buffered packets are read in order.
    """
    ensure_dir(file_dir)

    prefix     = f'{file_name}.'
    prefix_len = len(prefix)

    file_numbers_str = [f[prefix_len:] for f in os.listdir(file_dir) if f.startswith(prefix)]
    file_numbers_int = [int(n)         for n in file_numbers_str     if n.isdigit()]
    ctr              = max(file_numbers_int, default=-1) + 1
    used_filename    = f'{file_name}.{ctr}'

    with open(f'{file_dir}/{used_filename}', 'wb+') as f:
        f.write(file_data)
        f.flush()
        os.fsync(f.fileno())

    return used_filename


def read_oldest_buffer_file(buffer_file_dir  : str,
                            buffer_file_name : str
                            ) -> tuple[bytes, str]:
    """Read and remove the oldest matching buffer file."""
    ensure_dir(buffer_file_dir)

    file_numbers = [f[(len(buffer_file_name) + len('.')):]
                    for f in os.listdir(buffer_file_dir)
                    if f.startswith(buffer_file_name)]
    file_numbers = [n for n in file_numbers if n.isdigit()]
    buffer_files = [f'{buffer_file_name}.{n}' for n in sorted(file_numbers, key=int)]

    try:
        oldest_buffer_file = buffer_files[0]
    except IndexError:
        raise SoftError('No packet was available.', output=False)

    buffer_file_path = f'{buffer_file_dir}/{oldest_buffer_file}'

    with open(buffer_file_path, 'rb') as f:
        packet = f.read()

    os.remove(buffer_file_path)

    return packet, oldest_buffer_file
