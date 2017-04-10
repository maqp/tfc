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
import sys
import time

from multiprocessing         import Process, Queue

from src.common.crypto       import init_entropy
from src.common.db_contacts  import ContactList
from src.common.db_groups    import GroupList
from src.common.db_keys      import KeyList
from src.common.db_logs      import log_writer
from src.common.db_masterkey import MasterKey
from src.common.db_settings  import Settings
from src.common.gateway      import Gateway, gw_incoming
from src.common.misc         import clear_screen, process_arguments
from src.common.output       import c_print
from src.common.statics      import *
from src.tx.sender_loop      import sender_loop
from src.tx.trickle          import noise_process
from src.tx.tx_loop          import tx_loop
from src.rx.receiver_loop    import receiver_loop
from src.rx.rx_loop          import rx_loop

__version__ = '0.17.04'


def main() -> None:
    """Derive master key, decrypt databases and initialize processes."""
    os.chdir(sys.path[0])
    init_entropy()

    operation, local_test, dd_sockets = process_arguments()

    clear_screen()
    c_print("TFC", head=1, tail=1)

    master_key   = MasterKey(              operation, local_test)
    settings     = Settings(   master_key, operation, local_test, dd_sockets)
    contact_list = ContactList(master_key, settings)
    key_list     = KeyList(    master_key, settings)
    group_list   = GroupList(  master_key, settings, contact_list)
    gateway      = Gateway(                settings)
    process_list = []

    if settings.software_operation == 'tx':

        queues = {MESSAGE_PACKET_QUEUE: Queue(),
                  FILE_PACKET_QUEUE:    Queue(),
                  COMMAND_PACKET_QUEUE: Queue(),
                  LOG_PACKET_QUEUE:     Queue(),
                  NOISE_PACKET_QUEUE:   Queue(),
                  NOISE_COMMAND_QUEUE:  Queue(),
                  KEY_MANAGEMENT_QUEUE: Queue(),
                  WINDOW_SELECT_QUEUE:  Queue()}

        if settings.session_trickle:
            np_filler = Process(target=noise_process, args=(P_N_HEADER, queues[NOISE_PACKET_QUEUE], contact_list))
            nc_filler = Process(target=noise_process, args=(C_N_HEADER, queues[NOISE_COMMAND_QUEUE]))
            process_list.extend([np_filler, nc_filler])
            for p in [np_filler, nc_filler]:
                p.start()
            while any([q.qsize() < 1000 for q in [queues[NOISE_PACKET_QUEUE], queues[NOISE_COMMAND_QUEUE]]]):
                time.sleep(0.1)

        sender_process = Process(target=sender_loop, args=(settings, queues, gateway, key_list))
        input_process  = Process(target=tx_loop,     args=(settings, queues, gateway, contact_list, group_list, master_key, sys.stdin.fileno()))
        log_process    = Process(target=log_writer,  args=(queues[LOG_PACKET_QUEUE],))
        process_list.extend([sender_process, input_process, log_process])
        for p in [sender_process, input_process, log_process]:
            p.start()

    elif settings.software_operation == 'rx':

        queues = {LOCAL_KEY_PACKET_HEADER:  Queue(),
                  PUBLIC_KEY_PACKET_HEADER: Queue(),
                  MESSAGE_PACKET_HEADER:    Queue(),
                  COMMAND_PACKET_HEADER:    Queue(),
                  IMPORTED_FILE_CT_HEADER:  Queue(),
                  GATEWAY_QUEUE:            Queue()}

        gateway_process  = Process(target=gw_incoming,   args=(gateway,  queues[GATEWAY_QUEUE]))
        receiver_process = Process(target=receiver_loop, args=(settings, queues))
        output_process   = Process(target=rx_loop,       args=(settings, queues, contact_list, key_list, group_list, master_key, sys.stdin.fileno()))
        process_list.extend([gateway_process, receiver_process, output_process])
        for p in [gateway_process, receiver_process, output_process]:
            p.start()

    while True:
        try:
            time.sleep(0.1)
            if not all([p.is_alive() for p in process_list]):
                for p in process_list:
                    p.terminate()
                exit()
        except (EOFError, KeyboardInterrupt):
            pass


if __name__ == '__main__':
    main()
