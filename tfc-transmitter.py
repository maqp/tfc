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

from src.common.utils.io import setup_working_dir
from src.common.queues import TxQueue
from src.common.types_custom import IntStdInFD
from src.database.db_contacts import ContactList
from src.database.db_groups import GroupList
from src.database.db_keys import KeyStore
from src.database.db_logs import MessageLog
from src.database.db_local_key import LocalKeyDB
from src.database.db_masterkey import MasterKey
from src.database.db_onion import OnionService
from src.database.db_settings import Settings
from src.common.gateway import Gateway
from src.common.process import configure_multiprocessing_start_method, monitor_processes
from src.common.launch_args import process_arguments_tcb

from src.transmitter.process_input import input_process
from src.transmitter.process_log_writer import process_log_writer
from src.transmitter.process_sender import process_sender
from src.transmitter.process_noise_generator import process_noise_command_generator, process_noise_message_generator
from src.transmitter.commands.management.manage_settings_system import enqueue_initial_relay_runtime_settings
from src.ui.common.output.print_title import print_title


def transmitter_program() -> None:
    """TFC Transmitter Program.

    Transmitter Program acts as the message input window element
    of your typical messaging application. It encrypts messages
    and files that it sends to contacts via the Relay Program,
    and it also reads commands from user that it forwards to the
    user's Receiver Program in encrypted state. The Relay Program
    is also controlled using Transmitter Program's (unencrypted)
    commands.
    """
    setup_working_dir()
    configure_multiprocessing_start_method()
    launch_arguments = process_arguments_tcb()
    print_title(launch_arguments.program_name)

    queues   = TxQueue()
    stdin_fn = IntStdInFD(sys.stdin.fileno())

    master_key    = MasterKey   (             launch_arguments       )
    gateway       = Gateway     (             launch_arguments       )
    settings      = Settings    ( master_key, launch_arguments       )
    onion_service = OnionService( master_key, settings               )
    contact_list  = ContactList ( master_key, settings               )
    key_store     = KeyStore    ( master_key, settings               )
    local_key_db  = LocalKeyDB  ( master_key, settings               )
    group_list    = GroupList   ( master_key, settings, contact_list )
    message_log   = MessageLog  ( master_key, settings               )

    input_process_args  = (queues, settings, gateway, contact_list, local_key_db, group_list, message_log, master_key, onion_service, stdin_fn)
    sender_process_args = (queues, settings, gateway, key_store,    local_key_db                                                              )
    process_log_w_args  = (queues, settings, message_log                                                                                      )
    process_nmg_args    = (queues,                                                                                                            )
    process_ncg_args    = (queues,                                                                                                            )

    enqueue_initial_relay_runtime_settings(settings, queues)

    process_list = [Process(target=input_process,                   args=input_process_args ),
                    Process(target=process_sender,                  args=sender_process_args),
                    Process(target=process_log_writer,              args=process_log_w_args ),
                    Process(target=process_noise_message_generator, args=process_nmg_args   ),
                    Process(target=process_noise_command_generator, args=process_ncg_args   )]

    for p in process_list:
        p.start()

    monitor_processes(process_list, settings.program_id, queues)


if __name__ == '__main__':
    transmitter_program()
