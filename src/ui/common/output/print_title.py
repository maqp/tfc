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

from src.common.statics import ProgramName, ProgramLiterals
from src.ui.common.output.print_message import print_message


def print_title(program_name: 'ProgramName') -> None:
    """Print the TFC title."""
    print_message(f'{ProgramLiterals.NAME.value} - {program_name} {ProgramLiterals.VERSION}',
                  bold=True, clear_before=True, padding_top=1, padding_bottom=1)
