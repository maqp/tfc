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

import shutil
import time

from typing import Callable, TYPE_CHECKING

from src.common.exceptions import ignored
from src.common.statics import TFCSettingKey, VT100

if TYPE_CHECKING:
    from src.common.gateway import Gateway
    from src.database.db_groups import GroupList
    from src.database.db_settings import Settings
    from src.database.db_contacts import ContactList


def get_tab_complete_list(contact_list : 'ContactList',
                          group_list   : 'GroupList',
                          settings     : 'Settings',
                          gateway      : 'Gateway'
                          ) -> list[str]:
    """Return a list of tab-complete words."""
    commands = ['about',
                'add ',
                'clear',
                'cmd',
                'connect',
                'exit',
                'export ',
                'file',
                'group ',
                'help',
                'history ',
                'localkey',
                'logging ',
                'msg ',
                'names',
                'nick ',
                'notify ',
                'passwd ',
                'psk',
                'reset',
                'rmlogs ',
                'set ',
                'settings',
                'store ',
                'unread',
                'verify',
                'whisper ',
                'whois ']

    tc_list  = ['all', 'create ', 'false', 'False', 'join ', 'true', 'True']
    tc_list += commands
    tc_list += [(a          + ' ') for a in contact_list.get_list_of_addresses()]
    tc_list += [(n.value    + ' ') for n in contact_list.get_list_of_nicks()]
    tc_list += [(g.value    + ' ') for g in group_list.get_list_of_group_names()]
    tc_list += [(i.hr_value + ' ') for i in group_list.get_list_of_group_ids()]
    tc_list += [(s          + ' ') for s in settings.key_list]
    tc_list += [(s          + ' ') for s in gateway.settings.key_list
                if s in {TFCSettingKey.SERIAL_BAUDRATE.value, TFCSettingKey.SERIAL_ERROR_CORRECTION.value}]

    return tc_list


def get_tab_completer(contact_list : 'ContactList',
                      group_list   : 'GroupList',
                      settings     : 'Settings',
                      gateway      : 'Gateway'
                      ) -> Callable[..., str]:
    """Return the tab completer object."""

    def tab_complete(text: str, state: int) -> str:
        """Return tab-complete options."""
        tab_complete_list = get_tab_complete_list(contact_list, group_list, settings, gateway)
        options           = [t for t in tab_complete_list if t.startswith(text)]  # type: list[str]
        with ignored(IndexError):
            tc = options[state]
            return tc

    return tab_complete


def get_terminal_height() -> int:
    """Return the height of the terminal."""
    return shutil.get_terminal_size()[1]


def get_terminal_width() -> int:
    """Return the width of the terminal."""
    return shutil.get_terminal_size()[0]


def terminal_width_check(minimum_width: int) -> None:
    """Wait until user re-sizes their terminal to specified width. """
    if get_terminal_width() < minimum_width:
        print('Please make the terminal wider.')
        while get_terminal_width() < minimum_width:
            time.sleep(0.1)
        time.sleep(0.1)
        print(2*VT100.CURSOR_UP_ONE_LINE)
