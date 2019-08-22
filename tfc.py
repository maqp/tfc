#!/usr/bin/env python3.7
# -*- coding: utf-8 -*-

"""
TFC - Onion-routed, endpoint secure messaging system
Copyright (C) 2013-2019  Markus Ottela

This file is part of TFC.

TFC is free software: you can redistribute it and/or modify it under the terms
of the GNU General Public License as published by the Free Software Foundation,
either version 3 of the License, or (at your option) any later version.

TFC is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with TFC. If not, see <https://www.gnu.org/licenses/>.
"""

import os
import sys

from multiprocessing import Process, Queue
from typing          import Any, Dict

from src.common.crypto       import check_kernel_version
from src.common.db_contacts  import ContactList
from src.common.db_groups    import GroupList
from src.common.db_keys      import KeyList
from src.common.db_logs      import log_writer_loop
from src.common.db_masterkey import MasterKey
from src.common.db_onion     import OnionService
from src.common.db_settings  import Settings
from src.common.gateway      import Gateway, gateway_loop
from src.common.misc         import ensure_dir, monitor_processes, process_arguments
from src.common.output       import print_title
from src.common.statics      import COMMAND_DATAGRAM_HEADER, COMMAND_PACKET_QUEUE, DIR_TFC, EXIT_QUEUE
from src.common.statics      import FILE_DATAGRAM_HEADER, GATEWAY_QUEUE, KEY_MANAGEMENT_QUEUE
from src.common.statics      import LOCAL_KEY_DATAGRAM_HEADER, LOG_PACKET_QUEUE, LOG_SETTING_QUEUE
from src.common.statics      import LOGFILE_MASKING_QUEUE, MESSAGE_DATAGRAM_HEADER, MESSAGE_PACKET_QUEUE
from src.common.statics      import RELAY_PACKET_QUEUE, SENDER_MODE_QUEUE, TM_COMMAND_PACKET_QUEUE, TM_FILE_PACKET_QUEUE
from src.common.statics      import TM_MESSAGE_PACKET_QUEUE, TM_NOISE_COMMAND_QUEUE, TM_NOISE_PACKET_QUEUE
from src.common.statics      import TRAFFIC_MASKING_QUEUE, TX, WINDOW_SELECT_QUEUE

from src.transmitter.input_loop      import input_loop
from src.transmitter.sender_loop     import sender_loop
from src.transmitter.traffic_masking import noise_loop

from src.receiver.output_loop   import output_loop
from src.receiver.receiver_loop import receiver_loop


def main() -> None:
    """Load persistent data and launch the Transmitter/Receiver Program.

    This function decrypts user data from databases and launches
    processes for Transmitter or Receiver Program. It then monitors the
    EXIT_QUEUE for EXIT/WIPE signals and each process in case one of
    them dies.

    If you're reading this code to get the big picture on how TFC works,
    start by looking at the loop functions below, defined as the target
    for each process, from top to bottom:
        From `input_loop` process, you can see how the Transmitter
    Program processes a message or command from the user, creates
    assembly packets for a message/file/command, and how those are
    eventually pushed into a multiprocessing queue, from where they are
    loaded by the `sender_loop`.
        The `sender_loop` process encrypts outgoing assembly packets,
    and outputs the encrypted datagrams to the Networked Computer. The
    process also sends assembly packets to the `log_writer_loop`.
        The `log_writer_loop` process filters out non-message assembly
    packets and if logging for contact is enabled, stores the message
    assembly packet into an encrypted log database.
        The `noise_loop` processes are used to provide the `sender_loop`
    an interface identical to that of the `input_loop`. The
    `sender_loop` uses the interface to load noise packets/commands when
    traffic masking is enabled.

    Refer to the file `relay.py` to see how the Relay Program on
    Networked Computer manages datagrams between the network and
    Source/Destination Computer.

    In Receiver Program (also launched by this file), the `gateway_loop`
    process acts as a buffer for incoming datagrams. This buffer is
    consumed by the `receiver_loop` process that organizes datagrams
    loaded from the buffer into a set of queues depending on datagram
    type. Finally, the `output_loop` process loads and processes
    datagrams from the queues in the order of priority.
    """
    working_dir = f'{os.getenv("HOME")}/{DIR_TFC}'
    ensure_dir(working_dir)
    os.chdir(working_dir)

    operation, local_test, data_diode_sockets = process_arguments()

    check_kernel_version()

    print_title(operation)

    master_key   = MasterKey(              operation, local_test)
    gateway      = Gateway(                operation, local_test, data_diode_sockets)
    settings     = Settings(   master_key, operation, local_test)
    contact_list = ContactList(master_key, settings)
    key_list     = KeyList(    master_key, settings)
    group_list   = GroupList(  master_key, settings, contact_list)

    if settings.software_operation == TX:
        onion_service = OnionService(master_key)

        queues = {MESSAGE_PACKET_QUEUE:    Queue(),  # Standard              messages
                  COMMAND_PACKET_QUEUE:    Queue(),  # Standard              commands
                  TM_MESSAGE_PACKET_QUEUE: Queue(),  # Traffic masking       messages
                  TM_FILE_PACKET_QUEUE:    Queue(),  # Traffic masking       files
                  TM_COMMAND_PACKET_QUEUE: Queue(),  # Traffic masking       commands
                  TM_NOISE_PACKET_QUEUE:   Queue(),  # Traffic masking noise packets
                  TM_NOISE_COMMAND_QUEUE:  Queue(),  # Traffic masking noise commands
                  RELAY_PACKET_QUEUE:      Queue(),  # Unencrypted datagrams to Networked Computer
                  LOG_PACKET_QUEUE:        Queue(),  # `log_writer_loop` assembly packets to be logged
                  LOG_SETTING_QUEUE:       Queue(),  # `log_writer_loop` logging state management between noise packets
                  TRAFFIC_MASKING_QUEUE:   Queue(),  # `log_writer_loop` traffic masking setting management commands
                  LOGFILE_MASKING_QUEUE:   Queue(),  # `log_writer_loop` logfile masking setting management commands
                  KEY_MANAGEMENT_QUEUE:    Queue(),  # `sender_loop` key database management commands
                  SENDER_MODE_QUEUE:       Queue(),  # `sender_loop` default/traffic masking mode switch commands
                  WINDOW_SELECT_QUEUE:     Queue(),  # `sender_loop` window selection commands during traffic masking
                  EXIT_QUEUE:              Queue()   # EXIT/WIPE signal from `input_loop` to `main`
                  }  # type: Dict[bytes, Queue[Any]]

        process_list = [Process(target=input_loop,      args=(queues, settings, gateway, contact_list, group_list,
                                                              master_key, onion_service, sys.stdin.fileno())),
                        Process(target=sender_loop,     args=(queues, settings, gateway, key_list)),
                        Process(target=log_writer_loop, args=(queues, settings)),
                        Process(target=noise_loop,      args=(queues, contact_list)),
                        Process(target=noise_loop,      args=(queues,))]

    else:
        queues = {GATEWAY_QUEUE:             Queue(),  # Buffer for incoming datagrams
                  LOCAL_KEY_DATAGRAM_HEADER: Queue(),  # Local key datagrams
                  MESSAGE_DATAGRAM_HEADER:   Queue(),  # Message   datagrams
                  FILE_DATAGRAM_HEADER:      Queue(),  # File      datagrams
                  COMMAND_DATAGRAM_HEADER:   Queue(),  # Command   datagrams
                  EXIT_QUEUE:                Queue()   # EXIT/WIPE signal from `output_loop` to `main`
                  }

        process_list = [Process(target=gateway_loop,  args=(queues, gateway)),
                        Process(target=receiver_loop, args=(queues, gateway)),
                        Process(target=output_loop,   args=(queues, gateway, settings, contact_list, key_list,
                                                            group_list, master_key, sys.stdin.fileno()))]

    for p in process_list:
        p.start()

    monitor_processes(process_list, settings.software_operation, queues)


if __name__ == '__main__':
    main()
