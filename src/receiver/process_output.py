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
import sys
import time

from typing import TYPE_CHECKING

from src.common.entities.payload_buffer import PayloadBuffer
from src.common.exceptions import SoftError
from src.common.types_compound import DatagramBufferDict, FileBufferDict, FileKeyDict
from src.ui.common.output.vt100_utils import clear_screen
from src.common.types_custom import BoolUnitTesting, IntStdInFD
from src.receiver.commands.handle_command_datagram import handle_command_datagram
from src.receiver.messages.handle_message_datagram import handle_message_datagram
from src.receiver.files.file_normal import cache_or_store_file, store_file
from src.receiver.key_exchanges.local_key import process_local_key
from src.ui.receiver.window_rx import WindowList

if TYPE_CHECKING:
    from src.common.crypto.keys.kek_hash import KEKHash
    from src.common.gateway import Gateway
    from src.common.queues import RxQueue
    from src.database.db_contacts import ContactList
    from src.database.db_groups import GroupList
    from src.database.db_keys import KeyStore
    from src.database.db_local_key import LocalKeyDB
    from src.database.db_logs import MessageLog
    from src.database.db_masterkey import MasterKey
    from src.database.db_settings import Settings


def process_output(queues       : 'RxQueue',
                   gateway      : 'Gateway',
                   settings     : 'Settings',
                   contact_list : 'ContactList',
                   key_store    : 'KeyStore',
                   local_key_db : 'LocalKeyDB',
                   group_list   : 'GroupList',
                   master_key   : 'MasterKey',
                   message_log  : 'MessageLog',
                   stdin_fd     : 'IntStdInFD',
                   unit_testing :  BoolUnitTesting = BoolUnitTesting(False)
                   ) -> None:
    """Process that loads and processes datagrams in queues, in the order of priority.

    The priority is handled by having each handler function throw SoftError
    at the end. This then has execution jump to the top, and the next datagram
    is the next in priority order.
    """
    sys.stdin = os.fdopen(stdin_fd)

    datagram_buffer : 'DatagramBufferDict' = dict()
    file_buffer     : 'FileBufferDict'     = dict()
    file_keys       : 'FileKeyDict'        = dict()
    kek_hashes      : list['KEKHash']      = []
    datagram_hashes : list[bytes]          = []

    payload_buf = PayloadBuffer()
    window_list = WindowList(settings, contact_list, group_list, payload_buf)

    clear_screen()
    while True:
        try:
            handle_queued_local_key_datagram(settings, queues, window_list,                                      local_key_db, kek_hashes,                                       datagram_hashes)
            handle_queued_command_datagram  (settings, queues, window_list, contact_list, group_list, key_store, local_key_db, payload_buf, message_log, master_key,             gateway)
            window_list.refresh_file_window_check()
            handle_cached_message_datagram  (settings,         window_list, contact_list, group_list, key_store,                            message_log, payload_buf, file_keys, datagram_buffer)
            handle_queued_message_datagram  (settings, queues, window_list, contact_list, group_list, key_store,                            message_log, payload_buf, file_keys, datagram_buffer)
            handle_cached_mc_file_datagram  (settings,         window_list, contact_list,                                                                             file_keys, file_buffer)
            handle_queued_mc_file_datagram  (settings, queues, window_list, contact_list,                                                                             file_keys, file_buffer)
            time.sleep(0.01)

            if unit_testing and queues.unit_test.qsize() != 0:
                sys.stdin.close()
                break

        except KeyError:
            SoftError('Error: Receiver state lookup failed.', window=window_list.sys_msg_win)
        except (KeyboardInterrupt, SoftError):
            pass


# ┌───────────────────────────────────────────────────────────────────────────┐
# │                                 Local Keys                                │
# └───────────────────────────────────────────────────────────────────────────┘

def handle_queued_local_key_datagram(settings        : 'Settings',
                                     queues          : 'RxQueue',
                                     window_list     : WindowList,
                                     local_key_db    : 'LocalKeyDB',
                                     kek_hashes      : list['KEKHash'],
                                     datagram_hashes : list[bytes]
                                     ) -> None:
    """Check local key queue for datagrams.

    This function also checks that local key is installed.
    """
    queue = queues.datagram_local_keys

    if queue.qsize() > 0:
        datagram = queue.get()

        process_local_key(datagram,
                          window_list,
                          local_key_db,
                          settings,
                          kek_hashes,
                          datagram_hashes,
                          queues)

    if not local_key_db.has_keyset:
        time.sleep(0.1)
        raise SoftError('No local key', output=False)


# ┌───────────────────────────────────────────────────────────────────────────┐
# │                                  Commands                                 │
# └───────────────────────────────────────────────────────────────────────────┘

def handle_queued_command_datagram(settings     : 'Settings',
                                   queues       : 'RxQueue',
                                   window_list  : WindowList,
                                   contact_list : 'ContactList',
                                   group_list   : 'GroupList',
                                   key_store    : 'KeyStore',
                                   local_key_db : 'LocalKeyDB',
                                   payload_buf  : PayloadBuffer,
                                   message_log  : 'MessageLog',
                                   master_key   : 'MasterKey',
                                   gateway      : 'Gateway'
                                   ) -> None:
    """Check command queue for command datagrams."""
    command_queue = queues.datagram_commands

    if command_queue.qsize() > 0:
        datagram = command_queue.get()

        handle_command_datagram(datagram,
                                window_list,
                                payload_buf,
                                contact_list,
                                group_list,
                                key_store,
                                local_key_db,
                                message_log,
                                settings,
                                master_key,
                                gateway,
                                queues)


# ┌───────────────────────────────────────────────────────────────────────────┐
# │                                  Messages                                 │
# └───────────────────────────────────────────────────────────────────────────┘

def handle_cached_message_datagram(settings        : 'Settings',
                                   window_list     : WindowList,
                                   contact_list    : 'ContactList',
                                   group_list      : 'GroupList',
                                   key_store       : 'KeyStore',
                                   message_log     : 'MessageLog',
                                   payload_buf     : PayloadBuffer,
                                   file_keys       : 'FileKeyDict',
                                   datagram_buffer : 'DatagramBufferDict'
                                   ) -> None:
    """Process cached message datagrams."""
    for onion_pub_key, datagrams in list(datagram_buffer.items()):
        if not datagrams:
            datagram_buffer.pop(onion_pub_key, None)
            continue

        if not contact_list.has_onion_pub_key(onion_pub_key):
            continue
        if not key_store.has_rx_mk(onion_pub_key):
            continue

        datagram = datagrams.pop(0)
        if not datagrams:
            datagram_buffer.pop(onion_pub_key, None)
        handle_message_datagram(datagram, window_list, payload_buf, contact_list, key_store, group_list, settings, file_keys, message_log)
        raise SoftError('Cached message processing complete.', output=False)


def handle_queued_message_datagram(settings        : 'Settings',
                                   queues          : 'RxQueue',
                                   window_list     : WindowList,
                                   contact_list    : 'ContactList',
                                   group_list      : 'GroupList',
                                   key_store       : 'KeyStore',
                                   message_log     : 'MessageLog',
                                   payload_buf     : PayloadBuffer,
                                   file_keys       : 'FileKeyDict',
                                   datagram_buffer : 'DatagramBufferDict'
                                   ) -> None:
    """Check message queue for datagrams."""
    queue = queues.datagram_messages

    if queue.qsize() > 0:
        datagram      = queue.get()
        onion_pub_key = datagram.pub_key_contact

        if not contact_list.has_onion_pub_key(onion_pub_key):
            raise SoftError(f'Received message from unknown onion address {onion_pub_key.onion_address}.', output=False)

        # Cache incoming (and outgoing!) messages until both keypairs are installed
        if key_store.has_rx_mk(onion_pub_key):
            handle_message_datagram(datagram, window_list, payload_buf, contact_list, key_store, group_list, settings, file_keys, message_log)
        else:
            datagram_buffer.setdefault(onion_pub_key, []).append(datagram)
            contact = contact_list.get_contact_by_pub_key(onion_pub_key)

            if datagram.is_from_user:
                raise SoftError(f"Error: Unable to decrypt messsage sent to {contact.nick.value} until you add their PSK with '/psk'.")
            else:
                raise SoftError(f"Error: Unable to decrypt message from {contact.nick.value} until you add their PSK with '/psk'.")

        raise SoftError('Message processing complete.', output=False)


# ┌───────────────────────────────────────────────────────────────────────────┐
# │                                   Files                                   │
# └───────────────────────────────────────────────────────────────────────────┘

def handle_cached_mc_file_datagram(settings     : 'Settings',
                                   window_list  : WindowList,
                                   contact_list : 'ContactList',
                                   file_keys    : 'FileKeyDict',
                                   file_buffer  : 'FileBufferDict'
                                   ) -> None:
    """Check if file key has been received for cached multi-cast file datagram."""
    if not file_keys:
        return

    for onion_pub_key, (ts, file_ct) in list(file_buffer.items()):
        dict_key = onion_pub_key.serialize() + file_ct.ct_hash

        if dict_key not in file_keys:
            continue

        file_buffer.pop(onion_pub_key)
        file_key = file_keys.pop(dict_key)
        store_file(ts, onion_pub_key, file_ct, file_key, contact_list, window_list, settings)
        raise SoftError('Cached file processing complete.', output=False)


def handle_queued_mc_file_datagram(settings     : 'Settings',
                                   queues       : 'RxQueue',
                                   window_list  : WindowList,
                                   contact_list : 'ContactList',
                                   file_keys    : 'FileKeyDict',
                                   file_buffer  : 'FileBufferDict'
                                   ) -> None:
    """Check file queue for multi-cast file datagrams."""
    queue = queues.datagram_mc_files

    if queue.qsize() > 0:
        file_datagram = queue.get()
        cache_or_store_file(file_datagram, file_keys, file_buffer, contact_list, window_list, settings)
        raise SoftError('File processing complete.', output=False)
