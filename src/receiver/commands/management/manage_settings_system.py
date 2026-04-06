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

from datetime import datetime
from typing import TYPE_CHECKING

from src.common.exceptions import SoftError
from src.common.statics import Separator, TFCSettingKey

if TYPE_CHECKING:
    from src.common.entities.serialized_command import SerializedCommand
    from src.common.gateway import Gateway
    from src.common.queues import RxQueue
    from src.database.db_contacts import ContactList
    from src.database.db_groups import GroupList
    from src.database.db_keys import KeyStore
    from src.database.db_settings import Settings
    from src.ui.receiver.window_rx import WindowList


def change_setting(ser_cmd      : 'SerializedCommand',
                   ts           : datetime,
                   window_list  : 'WindowList',
                   contact_list : 'ContactList',
                   group_list   : 'GroupList',
                   settings     : 'Settings',
                   key_store    : 'KeyStore',
                   gateway      : 'Gateway',
                   queues       : 'RxQueue',
                   ) -> None:
    """Change TFC setting."""
    try:
        setting, value = [f.decode() for f in ser_cmd.command_bytes.split(Separator.US_BYTE)]
    except ValueError:
        raise SoftError('Error: Received invalid setting data.')

    if setting in settings.key_list:
        settings.change_setting(setting, value, contact_list, group_list)
    elif setting in gateway.settings.key_list:
        gateway.settings.change_setting(setting, value)
    else:
        raise SoftError(f"Error: Invalid setting '{setting}'.")

    sys_msg_win = window_list.sys_msg_win
    sys_msg_win.add_new_system_message(ts, f"Changed setting '{setting}' to '{value}'.", output=True)

    if setting == TFCSettingKey.REQUIRE_RESENDS:
        queues.dispatcher_setting_updates.put((TFCSettingKey.REQUIRE_RESENDS, settings.require_resends))
    elif setting == TFCSettingKey.AUTOREPLAY_LOOP:
        queues.dispatcher_setting_updates.put((TFCSettingKey.AUTOREPLAY_LOOP, settings.autoreplay_loop))

    if setting == 'max_number_of_contacts':
        contact_list.store_contacts()
        key_store.store_keys()
    if setting in ['max_number_of_group_members', 'max_number_of_groups']:
        group_list.store_groups()
