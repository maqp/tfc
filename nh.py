#!/usr/bin/env python3.5
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

from src.common.misc    import ignored
from src.common.output  import c_print, clear_screen
from src.common.statics import *

from src.nh.commands import nh_command
from src.nh.gateway  import Gateway, gateway_loop
from src.nh.misc     import process_arguments
from src.nh.pidgin   import ensure_im_connection, im_command, im_incoming, im_outgoing
from src.nh.settings import Settings
from src.nh.tcb      import rxm_outgoing, txm_incoming


def main() -> None:
    """Load settings, establish gateway and initialize processes."""
    settings = Settings(*process_arguments())
    gateway  = Gateway(settings)

    clear_screen()
    c_print(TFC, head=1, tail=1)

    ensure_im_connection()

    queues = {TXM_INCOMING_QUEUE: Queue(),  # Packets from gateway to 'txm_incoming' process
              RXM_OUTGOING_QUEUE: Queue(),  # Packets from TxM/IM client to RxM
              TXM_TO_IM_QUEUE:    Queue(),  # Packets from TxM to IM client
              TXM_TO_NH_QUEUE:    Queue(),  # Commands from TxM to NH
              TXM_TO_RXM_QUEUE:   Queue(),  # Commands from TxM to RxM
              NH_TO_IM_QUEUE:     Queue(),  # Commands from NH to IM client
              EXIT_QUEUE:         Queue()}  # Signal for normal exit

    process_list = [Process(target=gateway_loop, args=(queues,           gateway           )),
                    Process(target=txm_incoming, args=(queues, settings                    )),
                    Process(target=rxm_outgoing, args=(queues, settings, gateway           )),
                    Process(target=im_incoming,  args=(queues,                             )),
                    Process(target=im_outgoing,  args=(queues, settings                    )),
                    Process(target=im_command,   args=(queues,                             )),
                    Process(target=nh_command,   args=(queues, settings, sys.stdin.fileno()))]

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
                    if TAILS in subprocess.check_output('lsb_release -a', shell=True):
                        os.system('sudo poweroff')
                    else:
                        subprocess.Popen("find {} -name '{}*' -type f -exec shred -n 3 -z -u {{}} \;".format(DIR_USER_DATA, NH), shell=True).wait()
                        subprocess.Popen("find {} -type f -exec shred -n 3 -z -u {{}} \;".format('$HOME/.purple/'),              shell=True).wait()
                        os.system('poweroff')
                else:
                    sys.exit(0)


if __name__ == '__main__':
    main()
