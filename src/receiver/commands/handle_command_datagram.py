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

from typing import TYPE_CHECKING

import nacl.exceptions

from src.common.entities.assembly_packet import CommandAssemblyPacket
from src.common.exceptions import SoftError
from src.common.statics import RxCommand
from src.ui.common.output.vt100_utils import clear_screen
from src.receiver.commands.management.manage_groups import (group_create, group_add, group_remove, group_delete,
                                                            group_rename)
from src.receiver.commands.management.manage_windows import win_activity, win_select
from src.receiver.commands.management.manage_logs import remove_message_log, export_logs, show_logs
from src.receiver.commands.security.change_master_key import change_master_key
from src.receiver.commands.management.manage_settings_contact import change_contact_setting
from src.receiver.commands.security.exit_wipe import exit_tfc, wipe_system
from src.receiver.commands.management.manage_contacts import delete_contact, change_nick
from src.receiver.commands.management.manage_settings_system import change_setting
from src.receiver.commands.security.clear_ciphertext_cache import clear_ciphertext_cache
from src.receiver.commands.security.clear_screens import reset_screen
from src.receiver.key_exchanges.pre_shared_key import key_ex_psk_tx, key_ex_psk_rx
from src.receiver.key_exchanges.x448 import key_ex_x448
from src.receiver.key_exchanges.local_key import local_key_rdy

if TYPE_CHECKING:
    from src.common.entities.payload_buffer import PayloadBuffer
    from src.common.gateway import Gateway
    from src.common.queues import RxQueue
    from src.database.db_contacts import ContactList
    from src.database.db_groups import GroupList
    from src.database.db_keys import KeyStore
    from src.database.db_local_key import LocalKeyDB
    from src.database.db_logs import MessageLog
    from src.database.db_masterkey import MasterKey
    from src.database.db_settings import Settings
    from src.datagrams.receiver.command import DatagramReceiverCommand
    from src.ui.receiver.window_rx import WindowList


def handle_command_datagram(datagram     : 'DatagramReceiverCommand',
                            window_list  : 'WindowList',
                            payload_buf  : 'PayloadBuffer',
                            contact_list : 'ContactList',
                            group_list   : 'GroupList',
                            key_store    : 'KeyStore',
                            local_key_db : 'LocalKeyDB',
                            msg_log      : 'MessageLog',
                            settings     : 'Settings',
                            master_key   : 'MasterKey',
                            gateway      : 'Gateway',
                            queues       : 'RxQueue'
                            ) -> None:
    """Decrypt command assembly packet and process command."""
    timestamp       = datagram.ts
    assembly_packet = decrypt_command_datagram(window_list, local_key_db, datagram)
    command_payload = payload_buf.get_command_payload()
    command_payload.add_assembly_packet(assembly_packet)

    if not command_payload.is_complete:
        raise SoftError('Incomplete command.', output=False)

    try:
        header, ser_cmd = command_payload.assemble_command(settings.max_decompress_size_mb)

        if   header == RxCommand.LOCAL_KEY_RDY  : local_key_rdy          (         timestamp, window_list, contact_list                                                  )
        elif header == RxCommand.WIN_ACTIVITY   : win_activity           (                    window_list                                                                )
        elif header == RxCommand.WIN_SELECT     : win_select             (ser_cmd,            window_list                                                                )
        elif header == RxCommand.CLEAR_CT_CACHE : clear_ciphertext_cache (timestamp,          window_list,                           settings, queues                    )
        elif header == RxCommand.CLEAR_SCREEN   : clear_screen           (                                                                                               )
        elif header == RxCommand.RESET_SCREEN   : reset_screen           (ser_cmd,            window_list                                                                )
        elif header == RxCommand.EXIT_PROGRAM   : exit_tfc               (                                                                     queues                    )
        elif header == RxCommand.LOG_DISPLAY    : show_logs              (ser_cmd,            window_list, contact_list, group_list, settings, master_key                )
        elif header == RxCommand.LOG_EXPORT     : export_logs            (ser_cmd, timestamp, window_list, contact_list, group_list, settings, master_key                )
        elif header == RxCommand.LOG_REMOVE     : remove_message_log     (ser_cmd,                         contact_list, group_list, settings, master_key                )
        elif header == RxCommand.CH_MASTER_KEY  : change_master_key      (msg_log, timestamp, window_list, contact_list, group_list, settings, master_key, key_store     )
        elif header == RxCommand.CH_NICKNAME    : change_nick            (ser_cmd, timestamp, window_list, contact_list,                                                 )
        elif header == RxCommand.CH_SETTING     : change_setting         (ser_cmd, timestamp, window_list, contact_list, group_list, settings, key_store, gateway, queues)
        elif header == RxCommand.CH_LOGGING     : change_contact_setting (ser_cmd, timestamp, window_list, contact_list, group_list,                      header         )
        elif header == RxCommand.CH_FILE_RECV   : change_contact_setting (ser_cmd, timestamp, window_list, contact_list, group_list,                      header         )
        elif header == RxCommand.CH_NOTIFY      : change_contact_setting (ser_cmd, timestamp, window_list, contact_list, group_list,                      header         )
        elif header == RxCommand.GROUP_CREATE   : group_create           (ser_cmd, timestamp, window_list, contact_list, group_list, settings                            )
        elif header == RxCommand.GROUP_ADD      : group_add              (ser_cmd, timestamp, window_list, contact_list, group_list, settings                            )
        elif header == RxCommand.GROUP_REMOVE   : group_remove           (ser_cmd, timestamp, window_list, contact_list, group_list                                      )
        elif header == RxCommand.GROUP_DELETE   : group_delete           (ser_cmd, timestamp, window_list,               group_list                                      )
        elif header == RxCommand.GROUP_RENAME   : group_rename           (ser_cmd, timestamp, window_list, contact_list, group_list                                      )
        elif header == RxCommand.KEY_EX_ECDHE   : key_ex_x448            (ser_cmd, timestamp, window_list, contact_list, settings, key_store                             )
        elif header == RxCommand.KEY_EX_PSK_TX  : key_ex_psk_tx          (ser_cmd, timestamp, window_list, contact_list,             settings, key_store                 )
        elif header == RxCommand.KEY_EX_PSK_RX  : key_ex_psk_rx          (ser_cmd, timestamp, window_list, contact_list,             settings, key_store                 )
        elif header == RxCommand.REMOVE_CONTACT : delete_contact         (ser_cmd, timestamp, window_list, contact_list, group_list, settings, key_store, master_key     )
        elif header == RxCommand.WIPE_SYSTEM    : wipe_system            (queues                                                                                         )
        raise SoftError('Command completed.', output=False)
    finally:
        command_payload.clear_assembly_packets()


def decrypt_command_datagram(window_list  : 'WindowList',
                             local_key_db : 'LocalKeyDB',
                             datagram     : 'DatagramReceiverCommand',
                             ) -> CommandAssemblyPacket:
    """Decrypt command datagram."""
    try:
        ratchet_offset = local_key_db.auth_and_decrypt_header(datagram.ct_header)
    except nacl.exceptions.CryptoError:
        raise SoftError(f'Warning! Received command had an invalid header MAC.', window=window_list.sys_msg_win)

    try:
        command_assembly_packet = local_key_db.auth_and_decrypt_packet(datagram.ct_assembly_packet, offset=ratchet_offset)
    except nacl.exceptions.CryptoError:
        raise SoftError(f'Warning! Received command had an invalid payload MAC.', window=window_list.sys_msg_win)

    return command_assembly_packet
