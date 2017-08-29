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

import os
import readline
import time
import _tkinter
import typing

from tkinter import filedialog, Tk
from typing  import Union

from src.common.exceptions import FunctionReturn
from src.common.output     import c_print, print_on_previous_line

if typing.TYPE_CHECKING:
    from src.common.db_settings import Settings
    from src.nh.settings        import Settings as nhSettings


def ask_path_gui(prompt_msg: str,
                 settings:   Union['Settings', 'nhSettings'],
                 get_file:   bool = False) -> str:
    """Prompt (file) path with Tkinter / CLI prompt.

    :param prompt_msg: Directory selection prompt
    :param settings:   Settings object
    :param get_file:   When True, prompts for path to file instead of directory
    :return:           Selected directory / file
    """
    try:
        if settings.disable_gui_dialog:
            raise _tkinter.TclError

        root = Tk()
        root.withdraw()

        if get_file:
            file_path = filedialog.askopenfilename(title=prompt_msg)
        else:
            file_path = filedialog.askdirectory(title=prompt_msg)

        root.destroy()

        if not file_path:
            raise FunctionReturn(("File" if get_file else "Path") + " selection aborted.")

        return file_path

    except _tkinter.TclError:
        return ask_path_cli(prompt_msg, get_file)


class Completer(object):
    """readline tab-completer for paths and files."""

    def __init__(self, get_file):
        """Create new completer object."""
        self.get_file = get_file

    def listdir(self, root):
        """List directory 'root' appending the path separator to subdirs."""
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

    def complete_path(self, path=None):
        """Perform completion of filesystem path."""
        if not path:
            return self.listdir('.')

        dirname, rest = os.path.split(path)
        tmp           = dirname if dirname else '.'
        res           = [os.path.join(dirname, p) for p in self.listdir(tmp) if p.startswith(rest)]

        # More than one match, or single match which does not exist (typo)
        if len(res) > 1 or not os.path.exists(path):
            return res

        # Resolved to a single directory: return list of files below it
        if os.path.isdir(path):
            return [os.path.join(path, p) for p in self.listdir(path)]

        # Exact file match terminates this completion
        return [path + ' ']

    def path_complete(self, args=None):
        """Return list of directories from current directory."""
        if not args:
            return self.complete_path('.')

        # Treat the last arg as a path and complete it
        return self.complete_path(args[-1])

    def complete(self, _, state):
        """Generic readline completion entry point."""
        line = readline.get_line_buffer().split()
        return self.path_complete(line)[state]


def ask_path_cli(prompt_msg: str, get_file: bool = False) -> str:
    """\
    Prompt file location / store dir for
    file with tab-complete supported CLI.

    :param prompt_msg: File selection prompt
    :param get_file:   When True, prompts for file instead of directory
    :return:           Selected directory
    """
    comp = Completer(get_file)
    readline.set_completer_delims(' \t\n;')
    readline.parse_and_bind('tab: complete')
    readline.set_completer(comp.complete)
    print('')

    if get_file:
        while True:
            try:
                path_to_file = input(prompt_msg + ": ")

                if not path_to_file:
                    print_on_previous_line()
                    raise KeyboardInterrupt

                if os.path.isfile(path_to_file):
                    if path_to_file.startswith('./'):
                        path_to_file = path_to_file[2:]
                    print('')
                    return path_to_file

                c_print("File selection error.", head=1, tail=1)
                time.sleep(1.5)
                print_on_previous_line(reps=4)

            except KeyboardInterrupt:
                print_on_previous_line()
                raise FunctionReturn("File selection aborted.")

    else:
        while True:
            try:
                directory = input(prompt_msg + ": ")

                if directory.startswith('./'):
                    directory = directory[2:]

                if not directory.endswith(os.sep):
                    directory += os.sep

                if not os.path.isdir(directory):
                    c_print("Error: Invalid directory.", head=1, tail=1)
                    print_on_previous_line(reps=4, delay=1.5)
                    continue

                return directory

            except KeyboardInterrupt:
                raise FunctionReturn("File path selection aborted.")
