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

import sys
import time

from multiprocessing import Queue, Process

from src.nh.commands import nh_command
from src.nh.gateway  import Gateway, gw_incoming
from src.nh.misc     import c_print, clear_screen, process_arguments
from src.nh.pidgin   import ensure_im_connection, im_command, im_incoming, im_outgoing
from src.nh.settings import Settings
from src.nh.tcb      import rxm_outgoing, txm_incoming

__version__ = '0.17.04'


def main() -> None:
    """Start NH side IM plugin for TFC."""
    settings = Settings(*process_arguments())
    gateway  = Gateway(settings)

    clear_screen()
    c_print("TFC", head=1, tail=1)

    ensure_im_connection()

    q_to_tip = Queue()  # Packets from Gateway to 'tip process'
    q_to_rxm = Queue()  # Packets from TxM/IM client to RxM
    q_to_im  = Queue()  # Packets from TxM to IM client
    q_to_nh  = Queue()  # Packets from TxM to NH (commands)
    q_im_cmd = Queue()  # Commands from NH to IM client

    gip = Process(target=gw_incoming,  args=(          q_to_tip, gateway))
    tip = Process(target=txm_incoming, args=(settings, q_to_tip, q_to_rxm, q_to_im, q_to_nh))
    rop = Process(target=rxm_outgoing, args=(settings, q_to_rxm, gateway))
    iip = Process(target=im_incoming,  args=(settings, q_to_rxm))
    iop = Process(target=im_outgoing,  args=(settings, q_to_im))
    imc = Process(target=im_command,   args=(          q_im_cmd,))
    nhc = Process(target=nh_command,   args=(settings, q_to_nh, q_to_rxm, q_im_cmd, sys.stdin.fileno()))

    process_list = [gip, tip, rop, iip, iop, imc, nhc]
    for p in process_list:
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
