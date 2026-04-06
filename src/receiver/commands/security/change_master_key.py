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
from src.common.statics import StatusMsg
from src.common.types_custom import BoolReplaceDB
from src.ui.common.output.print_message import print_message
from src.ui.common.output.phase import phase

if TYPE_CHECKING:
    from src.database.db_contacts import ContactList
    from src.database.db_groups import GroupList
    from src.database.db_keys import KeyStore
    from src.database.db_logs import MessageLog
    from src.database.db_masterkey import MasterKey
    from src.database.db_settings import Settings
    from src.ui.receiver.window_rx import WindowList


def change_master_key(msg_log      : 'MessageLog',
                      ts           : datetime,
                      window_list  : 'WindowList',
                      contact_list : 'ContactList',
                      group_list   : 'GroupList',
                      settings     : 'Settings',
                      master_key   : 'MasterKey',
                      key_store    : 'KeyStore'
                      ) -> None:
    """Prompt the user for a new master password and derive a new master key from that."""
    if not master_key.authenticate_action():
        raise SoftError('Error: Invalid password.', clear_after=True, clear_delay=1, padding_top=2)

    # Create new master key but do not store new master key data into any database.
    master_key.new_master_key(replace=BoolReplaceDB(False))
    phase('Re-encrypting databases')

    # Rekey data to temp database
    rekey_databases = (contact_list, key_store, group_list, settings, msg_log)
    for db in rekey_databases:
        db.rekey_to_temp_db(master_key)

    # At this point all temp files exist, and they have been checked to be valid by the respective
    # temp file writing function. It's now time to create a temp file for the new master key
    # database. Once the temp master key database is created, the `replace_database_data()` method
    # will also run the atomic `os.replace()` command for the master key database.
    master_key.replace_database_data()

    # Next we do the atomic `os.replace()` for all other files too.
    for db in rekey_databases:
        db.migrate_to_rekeyed_db()

    phase(StatusMsg.DONE)
    print_message('Master password successfully changed.', bold=True, clear_after=True, clear_delay=1, padding_top=1)

    sys_msg_win = window_list.sys_msg_win
    sys_msg_win.add_new_system_message(ts, 'Changed Receiver master password.')
