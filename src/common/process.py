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

import multiprocessing
import os
import sys
import time

from datetime import datetime
from multiprocessing import Process
from typing import TYPE_CHECKING

from src.common.exceptions import ignored
from src.common.types_custom import BoolUnitTesting
from src.common.utils.security import shred_databases
from src.common.statics import ProgramID, MonitorQueueSignal, ShellCommand, OSIdentifier

if TYPE_CHECKING:
    from src.common.queues import RxQueue, RelayQueue, TxQueue, DataDiodeQueue
    from src.common.gateway import Gateway


def process_gateway_reader(queues       : 'RxQueue|RelayQueue',
                           gateway      : 'Gateway',
                           unit_testing : BoolUnitTesting = BoolUnitTesting(False)
                           ) -> None:
    """Load data from serial interface or socket into a queue.

    Also place the current timestamp to queue to be delivered to the
    Receiver Program. The timestamp is used both to notify when the sent
    message was received by the Relay Program, and as part of a
    commitment scheme: For more information, see the section on 'Covert
    channel based on user interaction' under TFC's Security Design wiki
    article.
    """
    queue = queues.from_gwr_to_dispatcher_datagrams

    while True:
        with ignored(EOFError, KeyboardInterrupt):
            if gateway.test_run:
                time.sleep(0.1)
            else:
                data = gateway.read()
                queue.put((datetime.now(), data))
            if unit_testing:
                break


def configure_multiprocessing_start_method() -> None:
    """Use `fork` on Linux to preserve TFC's process initialization model.

    Python 3.14 changed Linux's default start method from `fork` to
    `forkserver`. TFC spawns worker processes with pre-initialized
    gateway/database objects that rely on fork semantics and are not
    designed to be serialized for forkserver/spawn startup.
    """
    if not sys.platform.startswith('linux'):
        return
    if 'fork' not in multiprocessing.get_all_start_methods():
        return
    if multiprocessing.get_start_method(allow_none=True) == 'fork':
        return

    multiprocessing.set_start_method('fork', force=True)


def monitor_processes(process_list       : list[Process],
                      software_operation : ProgramID,
                      queues             : 'TxQueue|RxQueue|RelayQueue|DataDiodeQueue',
                      error_exit_code    : int = 1
                      ) -> None:
    """Monitor the status of `process_list` and EXIT_QUEUE.

    This function monitors a list of processes. If one of them dies, it
    terminates the rest and closes TFC with exit code 1.

    If EXIT or WIPE signal is received to EXIT_QUEUE, the function
    terminates running processes and closes the program with exit code 0
    or overwrites existing user data and powers the system off.
    """
    while True:
        with ignored(EOFError, KeyboardInterrupt):
            time.sleep(0.1)

            if not all([p.is_alive() for p in process_list]):
                for p in process_list:
                    p.terminate()
                sys.exit(error_exit_code)

            if queues.to_process_monitor.qsize() > 0:
                command = queues.to_process_monitor.get()

                for p in process_list:
                    p.terminate()

                if command == MonitorQueueSignal.EXIT:
                    sys.exit(0)

                if command == MonitorQueueSignal.WIPE:
                    if not platform_is_tails():
                        shred_databases(software_operation)
                    os.system(ShellCommand.POWEROFF.value)


def platform_is_tails() -> bool:
    """Return True if Relay Program is running on Tails."""
    with open('/etc/os-release') as f:
        data = f.read()
    return OSIdentifier.TAILS.value in data
