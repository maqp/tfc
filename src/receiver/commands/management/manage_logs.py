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

from src.common.entities.window_uid import WindowUID
from src.common.statics import FieldLength
from src.common.types_custom import BoolExportLog, IntMsgToLoad
from src.common.utils.encoding import bytes_to_int
from src.common.utils.strings import separate_header
from src.database.db_logs import MessageLog

if TYPE_CHECKING:
    from src.common.entities.serialized_command import SerializedCommand
    from src.database.db_contacts import ContactList
    from src.database.db_groups import GroupList
    from src.database.db_masterkey import MasterKey
    from src.database.db_settings import Settings
    from src.ui.receiver.window_rx import WindowList


def remove_message_log(ser_cmd      : 'SerializedCommand',
                       contact_list : 'ContactList',
                       group_list   : 'GroupList',
                       settings     : 'Settings',
                       master_key   : 'MasterKey'
                       ) -> None:
    """Remove log entries for contact or group."""
    MessageLog(master_key, settings).remove_logs(contact_list, group_list, ser_cmd.command_bytes)


def show_logs(ser_cmd      : 'SerializedCommand',
              window_list  : 'WindowList',
              contact_list : 'ContactList',
              group_list   : 'GroupList',
              settings     : 'Settings',
              master_key   : 'MasterKey'
              ) -> None:
    """Display the log file for the active window."""
    ser_no_msg, uid = separate_header(ser_cmd.command_bytes, FieldLength.ENCODED_INTEGER)
    no_messages     = IntMsgToLoad(bytes_to_int(ser_no_msg))
    window          = window_list.get_or_create_window(WindowUID(uid))

    MessageLog(master_key, settings).access_logs(window,
                                                      contact_list,
                                                      group_list,
                                                      msg_to_load = no_messages)


def export_logs(ser_cmd      : 'SerializedCommand',
                ts           : datetime,
                window_list  : 'WindowList',
                contact_list : 'ContactList',
                group_list   : 'GroupList',
                settings     : 'Settings',
                master_key   : 'MasterKey'
                ) -> None:
    """Display or export log file for the active window.

    Having the capability to export the log file from the encrypted
    database is a bad idea, but as it's required by the GDPR
    (https://gdpr-info.eu/art-20-gdpr/), it should be done as securely
    as possible.

    Therefore, before allowing export, TFC will ask for the master
    password to ensure no unauthorized user who gains momentary
    access to the system can the export logs from the database.
    """
    ser_no_msg, uid = separate_header(ser_cmd.command_bytes, FieldLength.ENCODED_INTEGER)
    no_messages     = IntMsgToLoad(bytes_to_int(ser_no_msg))
    window          = window_list.get_or_create_window(WindowUID(uid))

    MessageLog(master_key, settings).access_logs(window,
                                                      contact_list,
                                                      group_list,
                                                      msg_to_load = no_messages,
                                                      export      = BoolExportLog(True))
    sys_msg_win = window_list.sys_msg_win
    sys_msg_win.add_new_system_message(ts, f"Exported log file of {window.window_type} '{window.window_name}'.", output=True)
