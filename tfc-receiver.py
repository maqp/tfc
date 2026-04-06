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

import sys

from multiprocessing import Process

from src.common.gateway import Gateway
from src.common.process import configure_multiprocessing_start_method, process_gateway_reader, monitor_processes
from src.common.launch_args import process_arguments_tcb
from src.common.queues import RxQueue
from src.common.types_custom import IntStdInFD
from src.common.utils.io import setup_working_dir
from src.database.db_contacts import ContactList
from src.database.db_groups import GroupList
from src.database.db_keys import KeyStore
from src.database.db_local_key import LocalKeyDB
from src.database.db_logs import MessageLog
from src.database.db_masterkey import MasterKey
from src.database.db_settings import Settings
from src.receiver.process_gateway_dispatcher_rx import process_dispatcher
from src.receiver.process_output import process_output
from src.ui.common.output.print_title import print_title


def receiver_program() -> None:
    """TFC Receiver Program.

    Receiver Program acts as the conversation window component
    of your typical messaging application. It receives encrypted
    messages and files from the Transmitter program of contacts.

    It also receives commands and duplicates of sent messages from
    the user's Transmitter Program, routed through the Relay Program.
    """
    setup_working_dir()
    configure_multiprocessing_start_method()
    launch_arguments = process_arguments_tcb()
    print_title(launch_arguments.program_name)

    queues   = RxQueue()
    stdin_fn = IntStdInFD(sys.stdin.fileno())

    master_key   = MasterKey   (             launch_arguments       )
    gateway      = Gateway     (             launch_arguments       )
    settings     = Settings    ( master_key, launch_arguments       )
    contact_list = ContactList ( master_key, settings               )
    key_store    = KeyStore    ( master_key, settings               )
    local_key_db = LocalKeyDB  ( master_key, settings               )
    group_list   = GroupList   ( master_key, settings, contact_list )
    message_log  = MessageLog  ( master_key, settings               )

    gateway_args    = (queues, gateway                                                                                                )
    dispatcher_args = (queues, gateway, settings                                                                                      )
    output_args     = (queues, gateway, settings, contact_list, key_store, local_key_db, group_list, master_key, message_log, stdin_fn)


    process_list = [Process(target=process_gateway_reader, args=gateway_args),
                    Process(target=process_dispatcher,     args=dispatcher_args),
                    Process(target=process_output,         args=output_args)]

    for p in process_list:
        p.start()

    monitor_processes(process_list, settings.program_id, queues)


if __name__ == '__main__':
    receiver_program()
