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
import typing

from src.common.errors import FunctionReturn
from src.common.output import c_print, print_on_previous_line

if typing.TYPE_CHECKING:
    from src.common.db_settings import Settings


def ask_path_gui(prompt_msg: str,
                 settings:   'Settings',
                 get_file:   bool = False) -> str:
    """Prompt PSK path with Tkinter dialog. Fallback to CLI if not available.

    :param prompt_msg: Directory selection prompt
    :param settings:   Settings object
    :param get_file:   When True, prompts for path to file instead of directory
    :return:           Selected directory / file
    """
    try:
        import _tkinter
        from tkinter import filedialog, Tk

        try:
            if settings.disable_gui_dialog:
                raise _tkinter.TclError

            root = Tk()
            root.withdraw()

            if get_file:
                f_path = filedialog.askopenfilename(title=prompt_msg)
            else:
                f_path = filedialog.askdirectory(title=prompt_msg)

            root.destroy()

            if not f_path:
                t = "File" if get_file else "Path"
                raise FunctionReturn(t + " selection aborted.")

            return f_path

        except _tkinter.TclError:
            return ask_path_cli(prompt_msg, get_file)

    # Fallback to CLI if Tkinter is not installed
    except ImportError:
        if 0:  # Remove warnings
            _tkinter, filedialog, Tk = None, None, None
            _, _, _ = _tkinter, filedialog, Tk
        return ask_path_cli(prompt_msg, get_file)


def ask_path_cli(prompt_msg: str, get_file: bool = False) -> str:
    """Prompt file location / store dir for PSK with tab-complete supported CLI.

    :param prompt_msg: File/PSK selection prompt
    :param get_file:   When True, prompts for file instead of directory
    :return:           Selected directory
    """
    class Completer(object):
        """readline tab-completer for paths and files."""

        @staticmethod
        def listdir(root):
            """Return list of subdirectories (and files)."""
            res = []
            for name in os.listdir(root):
                path = os.path.join(root, name)
                if os.path.isdir(path):
                    name += os.sep
                    res.append(name)
                elif get_file:
                    res.append(name)
            return res

        def complete_path(self, path=None):
            """Return list of directories."""
            # Return subdirectories
            if not path:
                return self.listdir('.')

            dirname, rest = os.path.split(path)
            tmp           = dirname if dirname else '.'
            res           = [os.path.join(dirname, p) for p in self.listdir(tmp) if p.startswith(rest)]

            # Multiple directories, return list of dirs
            if len(res) > 1 or not os.path.exists(path):
                return res

            # Single directory, return list of files
            if os.path.isdir(path):
                return [os.path.join(path, p) for p in self.listdir(path)]

            # Exact file match terminates this completion
            return [path + ' ']

        def path_complete(self, args):
            """Return list of directories from current directory."""
            if not args:
                return self.complete_path('.')

            # Treat the last arg as a path and complete it
            return self.complete_path(args[-1])

        def complete(self, _, state):
            """Return complete options."""
            line = readline.get_line_buffer().split()
            return (self.path_complete(line) + [None])[state]

    comp = Completer()
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
                print_on_previous_line(4)

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
