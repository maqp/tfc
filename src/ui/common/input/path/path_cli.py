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
import readline

from pathlib import Path
from typing import Any, Optional as O

from src.common.exceptions import SoftError
from src.ui.common.output.print_message import print_message
from src.ui.common.output.vt100_utils import clear_previous_lines


def get_path_cli(prompt_msg : str,          # File selection prompt
                 get_file   : bool = False  # When True, prompts for a file instead of a directory
                 ) -> Path:                  # Selected directory or file
    """\
    Prompt file location or store directory for a file with tab-complete
    supported CLI.
    """
    readline.set_completer_delims(' \t\n;')
    readline.parse_and_bind('tab: complete')
    readline.set_completer(Completer(get_file).complete)
    print('')

    func = cli_get_file if get_file else cli_get_path
    return Path(func(prompt_msg))


class Completer:
    """readline tab-completer for paths and files."""

    def __init__(self, get_file: bool) -> None:
        """Create new completer object."""
        self.get_file = get_file

    def listdir(self, root: Path) -> list[str]:
        """List directory 'root' appending the path separator to sub-dirs."""
        res = []
        for path in root.iterdir():
            name = path.name
            if path.is_dir():
                name += os.sep
                res.append(name)
            elif self.get_file:
                # Also append file names
                res.append(name)
        return res

    def complete_path(self, path: O[str] = None) -> list[str]:
        """Perform completion of the filesystem path."""
        if path is None or not path:
            return self.listdir(Path('.'))

        dir_name, rest = os.path.split(path)
        parent         = Path(dir_name) if dir_name else Path('.')
        prefix         = parent.as_posix() if dir_name else ''
        matches        = [str(Path(prefix) / entry) for entry in self.listdir(parent) if entry.startswith(rest)]
        candidate      = Path(path)

        # More than one match, or single match which does not exist (typo)
        if len(matches) > 1 or not candidate.exists():
            return matches

        # Resolved to a single directory: return list of files below it
        if candidate.is_dir():
            return [str(candidate / entry) for entry in self.listdir(candidate)]

        # Exact file match terminates this completion
        return [path + ' ']

    def path_complete(self, args: O[list[str]] = None) -> Any:
        """Return the list of directories from the current directory."""
        if not args:
            return self.complete_path('../../../../common')

        # Treat the last arg as a path and complete it
        return self.complete_path(args[-1])

    def complete(self, _: str, state: int) -> Any:
        """Generic readline completion entry point."""
        line = readline.get_line_buffer().split()
        return self.path_complete(line)[state]


def cli_get_file(prompt_msg: str) -> str:
    """Ask the user to specify file to load."""
    while True:
        try:
            path_to_file = input(prompt_msg + ': ')

            if not path_to_file:
                clear_previous_lines(no_lines=1)
                raise KeyboardInterrupt

            if os.path.isfile(path_to_file):
                if path_to_file.startswith('./'):
                    path_to_file = path_to_file[len('./'):]
                print('')
                return path_to_file

            print_message('File selection error.', padding_top=1, padding_bottom=1)
            clear_previous_lines(no_lines=4, delay=1)

        except (EOFError, KeyboardInterrupt):
            clear_previous_lines(no_lines=1)
            raise SoftError('File selection aborted.', clear_before=True)


def cli_get_path(prompt_msg: str) -> str:
    """Ask the user to specify path for file."""
    while True:
        try:
            directory = input(prompt_msg + ': ')

            if directory.startswith('./'):
                directory = directory[len('./'):]

            if not directory.endswith(os.sep):
                directory += os.sep

            if not os.path.isdir(directory):
                print_message('Error: Invalid directory.', padding_top=1, padding_bottom=1)
                clear_previous_lines(no_lines=4, delay=1)
                continue

            return directory

        except (EOFError, KeyboardInterrupt):
            clear_previous_lines(no_lines=1)
            raise SoftError('File path selection aborted.', clear_before=True)

    raise RuntimeError('Broke out of loop')
