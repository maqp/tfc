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

import time

from typing import TYPE_CHECKING

from src.common.entities.serialized_command import SerializedCommand
from src.common.exceptions import SoftError, raise_if_traffic_masking
from src.common.statics import ProgramID, RxCommand, KeyDBMgmt, LogWriterMgmt, StatusMsg
from src.common.types_custom import BoolReplaceDB
from src.database.db_keys import KeyStore
from src.transmitter.queue_packet.queue_packet import queue_command
from src.ui.common.output.print_message import print_message
from src.ui.common.output.phase import phase

if TYPE_CHECKING:
    from src.common.queues import TxQueue
    from src.database.db_contacts import ContactList
    from src.database.db_groups import GroupList
    from src.database.db_logs import MessageLog
    from src.database.db_masterkey import MasterKey
    from src.database.db_onion import OnionService
    from src.database.db_settings import Settings
    from src.ui.transmitter.user_input import UserInput


def change_master_key(settings      : 'Settings',
                      queues        : 'TxQueue',
                      contact_list  : 'ContactList',
                      group_list    : 'GroupList',
                      user_input    : 'UserInput',
                      master_key    : 'MasterKey',
                      onion_service : 'OnionService',
                      message_log   : 'MessageLog',
                      ) -> None:
    """Change the master key on Transmitter/Receiver Program."""
    raise_if_traffic_masking(settings)

    try:
        device = ProgramID(user_input.plaintext.split()[1].lower())
    except IndexError:
        raise SoftError(f"Error: No target-system ('{ProgramID.TX.value}' or '{ProgramID.RX.value}') specified.", clear_before=True)
    except ValueError:
        raise SoftError(f'Error: Invalid target system.', clear_before=True)

    if device is ProgramID.RX:
        queue_command(settings, queues, SerializedCommand(RxCommand.CH_MASTER_KEY))
        return None

    authenticated = master_key.authenticate_action()

    if authenticated:
        # Create new master key but do not store new master key data into any database.
        master_key.new_master_key(replace=BoolReplaceDB(False))
        phase('Re-encrypting databases')

        # Halt `sender_loop` for the duration of database re-encryption.
        queues.key_store_mgmt.put((KeyDBMgmt.WAIT_FOR_SYNC,))
        wait_for_key_db_halt(queues)

        queues.log_writer_mgmt.put((LogWriterMgmt.WAIT_FOR_SYNC,))
        wait_for_log_writer_halt(queues)

        # Load old key_store from database file as it's not used on input_loop side.
        key_store = KeyStore(master_key, settings)

        # Rekey data to temp database.
        for rekey_db in (contact_list, group_list, message_log):
            rekey_db.rekey_to_temp_db(master_key)

        key_store.rekey_to_temp_db(master_key)
        settings.rekey_to_temp_db(master_key)
        onion_service.rekey_to_temp_db(master_key)

        # At this point all temp files exist, and they have been checked to be valid by the respective
        # temp file writing function. It's now time to create a temp file for the new master key
        # database. Once the temp master key database is created, the `replace_database_data()` method
        # will also run the atomic `os.replace()` command for the master key database.
        master_key.replace_database_data()

        # Next we do the atomic `os.replace()` for all other files too.
        for migrated_db in (contact_list, key_store, group_list, settings, onion_service, message_log):
            migrated_db.migrate_to_rekeyed_db()

        # Now all databases have been updated. It's time to let
        # the key database know what the new master key is.
        master_key.update_sender_key(queues)

        wait_for_key_db_ack(queues)

        phase(StatusMsg.DONE)
        print_message('Master key successfully changed.', bold=True, clear_after=True, clear_delay=1, padding_top=1)

    return None


def wait_for_key_db_halt(queues: 'TxQueue') -> None:
    """Wait for the key database to acknowledge it has halted output of packets."""
    while not queues.key_mgmt_ack.qsize():
        time.sleep(0.001)
    if queues.key_mgmt_ack.get() != (KeyDBMgmt.RELEASE_WAIT,):
        raise SoftError('Error: Key database returned wrong signal.')


def wait_for_key_db_ack(queues: 'TxQueue') -> None:
    """Wait for the key database to acknowledge it has replaced the master key."""
    while not queues.key_mgmt_ack.qsize():
        time.sleep(0.001)
    queue_data = queues.key_mgmt_ack.get()
    if len(queue_data) != 2 or queue_data[0] != KeyDBMgmt.UPDATE_MASTER_KEY:
        raise SoftError('Error: Key database returned wrong signal.')


def wait_for_log_writer_halt(queues: 'TxQueue') -> None:
    """Wait for the log writer to acknowledge it has halted output."""
    while not queues.log_writer_ack.qsize():
        time.sleep(0.001)
    if queues.log_writer_ack.get() != LogWriterMgmt.RELEASE_WAIT:
        raise SoftError('Error: Log writer returned wrong signal.')
