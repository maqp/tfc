#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
TFC - Onion-routed, endpoint secure messaging system
Copyright (C) 2013-2023  Markus Ottela

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

import os
import time

from typing import Dict


def generate_installer_hash_dict(working_dir: str) -> Dict[str, str]:
    """Return {file_path: hash} dictionary of TFC files in `install.sh`."""
    with open(f"{working_dir}/install.sh") as f:
        installer_lines = f.read().splitlines()

    lines_with_hashes = [line for line in installer_lines if line.startswith("    compare_digest") and "${" not in line]

    hash_dict = dict()
    for line in lines_with_hashes:
        split     = line.split()[1:]
        old_hash  = split[0]
        path      = split[1] if split[1] != "''" else ""
        file_name = split[2]
        file_path = path + file_name

        hash_dict[file_path] = old_hash

    return hash_dict


def generate_hash_file_hash_dict(working_dir: str) -> Dict[str, str]:
    """Return {file_path: hash} dictionary of TFC file hashes in `SHA512.list`."""
    with open(f"{working_dir}/SHA512.list") as f:
        hash_file_lines = f.read().splitlines()

    hash_dict = dict()
    for line in hash_file_lines:
        split     = line.split()
        new_hash  = split[0]
        file_path = split[1][2:]

        hash_dict[file_path] = new_hash

    return hash_dict


def main() -> None:
    """Replace the pinned SHA512 hashes of TFC files in the installer."""
    working_dir = f'{os.getenv("HOME")}/tfc'

    installer_hashes = generate_installer_hash_dict(working_dir)
    hash_file_hashes = generate_hash_file_hash_dict(working_dir)

    replace_tuples = []

    for file_path in installer_hashes:
        old_hash = installer_hashes[file_path]
        new_hash = hash_file_hashes[file_path]

        if old_hash != new_hash:
            replace_tuples.append((old_hash, new_hash, file_path))

    if replace_tuples:

        with open(f"{working_dir}/install.sh") as f:
            data = f.read()

        for old_hash, new_hash, file_path in replace_tuples:
            data = data.replace(old_hash, new_hash)
            print(f"Replaced the SHA512 hash of the file '{file_path}'.")

        with open(f"{working_dir}/install.sh", "w+") as f:
            f.write(data)

    else:
        print("No file hashes needed to be replaced.")

    time.sleep(0.5)


if __name__ == "__main__":
    main()
