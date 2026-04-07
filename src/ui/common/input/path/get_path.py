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

from pathlib import Path
from typing import TYPE_CHECKING

from src.ui.common.input.path.path_cli import get_path_cli
from src.ui.common.input.path.path_zenity import get_path_zenity

if TYPE_CHECKING:
    from src.database.db_settings import Settings


def _has_gui_display() -> bool:
    """Return True when a graphical session is available for Zenity."""
    return any(os.environ.get(var) for var in ('DISPLAY', 'WAYLAND_DISPLAY'))


def get_path(prompt_msg : str,
             settings   : 'Settings',
             get_file   : bool = False
             ) -> Path:
    """Prompt (file) path with Zenity / CLI prompt."""
    if settings.disable_gui_dialog or not _has_gui_display():
        return get_path_cli(prompt_msg, get_file)
    else:
        return get_path_zenity(prompt_msg, get_file)
