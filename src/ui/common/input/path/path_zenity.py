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

import subprocess

from pathlib import Path

from src.common.exceptions import SoftError
from src.ui.common.input.path.path_cli import get_path_cli


def get_path_zenity(prompt_msg : str,
                    get_file   : bool = False
                    ) -> Path:
    """Prompt (file) path with Zenity / CLI prompt."""
    command = ['zenity', '--file-selection', f'--title={prompt_msg}']

    if not get_file:
        command.append('--directory')

    try:
        completed = subprocess.run(command, capture_output=True, text=True)
    except FileNotFoundError:
        return Path(get_path_cli(prompt_msg, get_file))

    if completed.returncode == 0:
        file_path = completed.stdout.rstrip('\r\n')
        if not file_path:
            raise SoftError(('File' if get_file else 'Path') + ' selection aborted.', clear_before=True)
        return Path(file_path)

    if completed.returncode == 1:
        raise SoftError(('File' if get_file else 'Path') + ' selection aborted.', clear_before=True)

    return Path(get_path_cli(prompt_msg, get_file))
