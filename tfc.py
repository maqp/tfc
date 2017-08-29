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
import subprocess
import sys
import time

from multiprocessing import Process, Queue

from src.common.crypto       import check_kernel_entropy, check_kernel_version
from src.common.db_contacts  import ContactList
from src.common.db_groups    import GroupList
from src.common.db_keys      import KeyList
from src.common.db_logs      import log_writer_loop
from src.common.db_masterkey import MasterKey
from src.common.db_settings  import Settings
from src.common.gateway      import Gateway, gateway_loop
from src.common.misc         import ignored, process_arguments
from src.common.output       import c_print, clear_screen
from src.common.statics      import *

from src.tx.input_loop      import input_loop
from src.tx.sender_loop     import sender_loop
from src.tx.traffic_masking import noise_loop

from src.rx.output_loop   import output_loop
from src.rx.receiver_loop import receiver_loop


def main() -> None:
    """Derive master key, decrypt databases and initialize processes."""
    os.chdir(sys.path[0])

    check_kernel_version()
    check_kernel_entropy()

    operation, local_test, dd_sockets = process_arguments()

    clear_screen()
    c_print(TFC, head=1, tail=1)

    master_key   = MasterKey(              operation, local_test)
    settings     = Settings(   master_key, operation, local_test, dd_sockets)
    contact_list = ContactList(master_key, settings)
    key_list     = KeyList(    master_key, settings)
    group_list   = GroupList(  master_key, settings, contact_list)
    gateway      = Gateway(                settings)

    if settings.software_operation == TX:
        queues = {MESSAGE_PACKET_QUEUE: Queue(),
                  FILE_PACKET_QUEUE:    Queue(),
                  COMMAND_PACKET_QUEUE: Queue(),
                  NH_PACKET_QUEUE:      Queue(),
                  LOG_PACKET_QUEUE:     Queue(),
                  EXIT_QUEUE:           Queue(),
                  NOISE_PACKET_QUEUE:   Queue(),
                  NOISE_COMMAND_QUEUE:  Queue(),
                  KEY_MANAGEMENT_QUEUE: Queue(),
                  WINDOW_SELECT_QUEUE:  Queue()}

        process_list = [Process(target=input_loop,      args=(queues, settings, gateway, contact_list, group_list, master_key, sys.stdin.fileno())),
                        Process(target=sender_loop,     args=(queues, settings, gateway, key_list)),
                        Process(target=log_writer_loop, args=(queues,))]

        if settings.session_traffic_masking:
            process_list.extend([Process(target=noise_loop, args=(P_N_HEADER, queues[NOISE_PACKET_QUEUE], contact_list)),
                                 Process(target=noise_loop, args=(C_N_HEADER, queues[NOISE_COMMAND_QUEUE]))])

    else:
        queues = {LOCAL_KEY_PACKET_HEADER:  Queue(),
                  PUBLIC_KEY_PACKET_HEADER: Queue(),
                  MESSAGE_PACKET_HEADER:    Queue(),
                  COMMAND_PACKET_HEADER:    Queue(),
                  IMPORTED_FILE_HEADER:     Queue(),
                  EXIT_QUEUE:               Queue(),
                  GATEWAY_QUEUE:            Queue()}

        process_list = [Process(target=gateway_loop,  args=(queues, gateway)),
                        Process(target=receiver_loop, args=(queues, settings)),
                        Process(target=output_loop,   args=(queues, settings, contact_list, key_list, group_list, master_key, sys.stdin.fileno()))]

    for p in process_list:
        p.start()

    while True:
        with ignored(EOFError, KeyboardInterrupt):
            time.sleep(0.1)
            if not all([p.is_alive() for p in process_list]):
                for p in process_list:
                    p.terminate()
                sys.exit(1)

            if not queues[EXIT_QUEUE].empty():
                command = queues[EXIT_QUEUE].get()
                for p in process_list:
                    p.terminate()
                if command == WIPE:
                    subprocess.Popen(f"find {DIR_USER_DATA} -name '{operation}*' -type f -exec shred -n 3 -z -u {{}} \;", shell=True).wait()
                    os.system('poweroff')
                else:
                    sys.exit(0)


if __name__ == '__main__':
    main()
