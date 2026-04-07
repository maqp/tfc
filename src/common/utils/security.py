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

import shutil
import subprocess

from pathlib import Path

from src.common.statics import ProgramID, DataDir
from src.common.utils.io import get_working_dir


def _command_exists(command: str) -> bool:
    """Return True if command is available on PATH."""
    if os.path.dirname(command):
        return os.path.isfile(command) and os.access(command, os.X_OK)

    for path_dir in os.get_exec_path():
        candidate = os.path.join(path_dir, command)
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return True

    return False


def clear_clipboard() -> bool:
    """Clear the clipboard on Wayland or X11."""
    if _command_exists('wl-copy') and 'WAYLAND_DISPLAY' in os.environ:
        subprocess.run(['wl-copy', '--clear'])
        return True

    if _command_exists('xclip') and 'DISPLAY' in os.environ:
        subprocess.run(
            ['xclip', '-selection', 'clipboard'],
            input=b"",
        )
        return True

    if _command_exists('xsel') and 'DISPLAY' in os.environ:
        subprocess.run(['xsel', '--clipboard', '--clear'])
        return True

    return False


def _shred_file(file_path: Path) -> None:
    """Overwrite a file with `shred` and ensure it is removed on success."""
    result = subprocess.run(['shred', '-n', '3', '-z', '-u', str(file_path)])
    if result.returncode == 0 and file_path.exists():
        file_path.unlink(missing_ok=True)


def _shred_tree(directory: Path) -> None:
    """Overwrite all files under `directory` recursively."""
    if not directory.exists():
        return

    for path in sorted(directory.rglob('*')):
        if path.is_file():
            _shred_file(path)


def _cwd_within(directory: Path) -> bool:
    """Return True when the current working directory is inside `directory`."""
    try:
        current_dir = Path.cwd().resolve()
    except FileNotFoundError:
        return False

    try:
        current_dir.relative_to(directory.resolve())
        return True
    except ValueError:
        return False


def shred_databases(software_operation: ProgramID) -> None:
    """Shred all local TFC user data and remove the directories afterwards."""
    working_dir = Path(get_working_dir())
    extra_dirs  = [Path(DataDir.RECEIVED_FILES)] if software_operation == ProgramID.RX else []

    _shred_tree(working_dir)
    for directory in extra_dirs:
        _shred_tree(directory)

    if _cwd_within(working_dir):
        os.chdir(working_dir.parent)

    shutil.rmtree(working_dir, ignore_errors=True)
    for directory in extra_dirs:
        shutil.rmtree(directory, ignore_errors=True)
