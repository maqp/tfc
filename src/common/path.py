#!/usr/bin/env python3.7
# -*- coding: utf-8 -*-

"""
TFC - Onion-routed, endpoint secure messaging system
Copyright (C) 2013-2019  Markus Ottela

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
import readline
import _tkinter
import typing

from typing import Any, List, Optional

import tkinter
from tkinter import filedialog

from src.common.exceptions import FunctionReturn
from src.common.output     import m_print, print_on_previous_line

if typing.TYPE_CHECKING:
    from src.common.db_settings import Settings


def ask_path_gui(prompt_msg: str,          # Directory selection prompt
                 settings:   'Settings',   # Settings object
                 get_file:   bool = False  # When True, prompts for a path to file instead of a directory
                 ) -> str:                 # Selected directory or file
    """Prompt (file) path with Tkinter / CLI prompt."""
    try:
        if settings.disable_gui_dialog:
            raise _tkinter.TclError

        root = tkinter.Tk()
        root.withdraw()

        if get_file:
            file_path = filedialog.askopenfilename(title=prompt_msg)  # type: str
        else:
            file_path = filedialog.askdirectory(title=prompt_msg)

        root.destroy()

        if not file_path:
            raise FunctionReturn(("File" if get_file else "Path") + " selection aborted.", head_clear=True)

        return file_path

    except _tkinter.TclError:
        return ask_path_cli(prompt_msg, get_file)


class Completer(object):
    """readline tab-completer for paths and files."""

    def __init__(self, get_file: bool) -> None:
        """Create new completer object."""
        self.get_file = get_file

    def listdir(self, root: str) -> Any:
        """List directory 'root' appending the path separator to sub-dirs."""
        res = []
        for name in os.listdir(root):
            path = os.path.join(root, name)
            if os.path.isdir(path):
                name += os.sep
                res.append(name)
            elif self.get_file:
                # Also append file names
                res.append(name)
        return res

    def complete_path(self, path: Optional[str] = None) -> Any:
        """Perform completion of the filesystem path."""
        if not path:
            return self.listdir('.')

        dir_name, rest = os.path.split(path)
        tmp            = dir_name if dir_name else '.'
        matches        = [os.path.join(dir_name, p) for p in self.listdir(tmp) if p.startswith(rest)]

        # More than one match, or single match which does not exist (typo)
        if len(matches) > 1 or not os.path.exists(path):
            return matches

        # Resolved to a single directory: return list of files below it
        if os.path.isdir(path):
            return [os.path.join(path, p) for p in self.listdir(path)]

        # Exact file match terminates this completion
        return [path + ' ']

    def path_complete(self, args: Optional[List[str]] = None) -> Any:
        """Return the list of directories from the current directory."""
        if not args:
            return self.complete_path('.')

        # Treat the last arg as a path and complete it
        return self.complete_path(args[-1])

    def complete(self, _: str, state: int) -> Any:
        """Generic readline completion entry point."""
        line = readline.get_line_buffer().split()
        return self.path_complete(line)[state]


def ask_path_cli(prompt_msg: str,          # File selection prompt
                 get_file:   bool = False  # When True, prompts for a file instead of a directory
                 ) -> str:                 # Selected directory or file
    """\
    Prompt file location or store directory for a file with tab-complete
    supported CLI.
    """
    readline.set_completer_delims(' \t\n;')
    readline.parse_and_bind('tab: complete')
    readline.set_completer(Completer(get_file).complete)
    print('')

    if get_file:
        return cli_get_file(prompt_msg)
    else:
        return cli_get_path(prompt_msg)


def cli_get_file(prompt_msg: str) -> str:
    """Ask the user to specify file to load."""
    while True:
        try:
            path_to_file = input(prompt_msg + ": ")

            if not path_to_file:
                print_on_previous_line()
                raise KeyboardInterrupt

            if os.path.isfile(path_to_file):
                if path_to_file.startswith('./'):
                    path_to_file = path_to_file[len('./'):]
                print('')
                return path_to_file

            m_print("File selection error.", head=1, tail=1)
            print_on_previous_line(reps=4, delay=1)

        except (EOFError, KeyboardInterrupt):
            print_on_previous_line()
            raise FunctionReturn("File selection aborted.", head_clear=True)


def cli_get_path(prompt_msg: str) -> str:
    """Ask the user to specify path for file."""
    while True:
        try:
            directory = input(prompt_msg + ": ")

            if directory.startswith('./'):
                directory = directory[len('./'):]

            if not directory.endswith(os.sep):
                directory += os.sep

            if not os.path.isdir(directory):
                m_print("Error: Invalid directory.", head=1, tail=1)
                print_on_previous_line(reps=4, delay=1)
                continue

            return directory

        except (EOFError, KeyboardInterrupt):
            print_on_previous_line()
            raise FunctionReturn("File path selection aborted.", head_clear=True)
