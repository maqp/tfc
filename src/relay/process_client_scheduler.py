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

from multiprocessing import Process
from typing import TYPE_CHECKING

from src.common.crypto.keys.onion_service_keys import OnionPublicKeyContact
from src.common.crypto.keys.x448_keys import X448PrivKey
from src.common.exceptions import ignored
from src.common.types_custom import BoolUnitTesting, BoolIsPending, IntPortNumberTor
from src.ui.common.output.print_log_message import print_log_message
from src.common.statics import QueueSignal
from src.relay.process_client import process_client

if TYPE_CHECKING:
    from src.common.gateway import Gateway
    from src.common.queues import RelayQueue
    from src.common.crypto.keys.onion_service_keys import OnionPublicKeyUser


ProcDict = dict[OnionPublicKeyContact, Process]


def process_client_scheduler(queues                : 'RelayQueue',
                             gateway               : 'Gateway',
                             url_token_private_key : X448PrivKey,
                             unit_testing          : BoolUnitTesting = BoolUnitTesting(False)
                             ) -> None:
    """Manage `client` processes."""
    proc_dict : ProcDict = dict()

    # Wait for Tor port from `onion_service` process.
    while True:
        with ignored(EOFError, KeyboardInterrupt):
            while queues.from_tor_to_sch_client_tor_data.qsize() == 0:
                time.sleep(0.1)
            tor_port, onion_addr_user = queues.from_tor_to_sch_client_tor_data.get()
            break

    while True:
        with ignored(EOFError, KeyboardInterrupt):

            while queues.from_rec_to_sch_client_contact_mgmt_commands.qsize() == 0:
                time.sleep(0.1)

            command, onion_pub_keys, is_pending_contact = queues.from_rec_to_sch_client_contact_mgmt_commands.get()

            if command == QueueSignal.RP_ADD_CONTACT_HEADER:
                add_new_client_process(queues, gateway, tor_port, proc_dict, onion_addr_user,
                                       onion_pub_keys, is_pending_contact, url_token_private_key)

            elif command == QueueSignal.RP_REMOVE_CONTACT_HEADER:
                remove_client_process(proc_dict, onion_pub_keys)

            if unit_testing and queues.unit_test.qsize() != 0:
                break


def add_new_client_process(queues                : 'RelayQueue',
                           gateway               : 'Gateway',
                           tor_port              : IntPortNumberTor,
                           proc_dict             : ProcDict,
                           onion_pub_key_user    : 'OnionPublicKeyUser',
                           onion_pub_keys        : list['OnionPublicKeyContact'],
                           is_pending_contact    : BoolIsPending,
                           url_token_private_key : X448PrivKey
                           ) -> None:
    """Add new client process."""
    for onion_pub_key in onion_pub_keys:

        # Avoid duplicates
        if onion_pub_key in proc_dict:
            continue

        pub_key_user = onion_pub_key_user if is_pending_contact else None
        args         = (queues, gateway, pub_key_user, onion_pub_key, url_token_private_key, tor_port)

        proc_dict[onion_pub_key] = Process(target=process_client, args=args)
        proc_dict[onion_pub_key].start()


def remove_client_process(proc_dict      : ProcDict,
                          onion_pub_keys : list['OnionPublicKeyContact'],
                          ) -> None:
    """Remove client process."""
    for onion_pub_key in onion_pub_keys:

        # Ignore missing keys
        if onion_pub_key not in proc_dict:
            continue

        process = proc_dict[onion_pub_key]
        process.terminate()
        proc_dict.pop(onion_pub_key)
        print_log_message(f'Removed {onion_pub_key.short_address}', bold=True)
