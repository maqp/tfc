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

import multiprocessing.connection
import multiprocessing
import socket
import sys
import time

from multiprocessing import Queue, Process


###############################################################################
#                         DATA DIODE ANIMATION FRAMES                         #
###############################################################################

def lr_upper() -> None:
    """Print high signal frame (left to right)."""
    print("""
       Data flow
           →
    ─────╮   ╭─────
      Tx │ > │ Rx
    ─────╯   ╰─────
    """)


def lr_lower() -> None:
    """Print low signal frame (left to right)."""
    print("""
       Data flow
           →
    ─────╮   ╭─────
      Tx │   │ Rx
    ─────╯   ╰─────
    """)


def lr_idle() -> None:
    """Print no signal frame (left to right)."""
    print("""
          Idle
    
    ─────╮   ╭─────
      Tx │   │ Rx
    ─────╯   ╰─────
    """)


def rl_upper() -> None:
    """Print high signal frame (right to left)."""
    print("""
       Data flow
           ←
    ─────╮   ╭─────
      Rx │ < │ Tx
    ─────╯   ╰─────
    """)


def rl_lower() -> None:
    """Print low signal frame (right to left)."""
    print("""
       Data flow
           ←
    ─────╮   ╭─────
      Rx │   │ Tx
    ─────╯   ╰─────
    """)


def rl_idle() -> None:
    """Print no signal frame (right to left)."""
    print("""
          Idle

    ─────╮   ╭─────
      Rx │   │ Tx
    ─────╯   ╰─────
    """)


###############################################################################
#                             DATA DIODE ANIMATORS                            #
###############################################################################

def clear_screen() -> None:
    """Clear terminal window."""
    sys.stdout.write('\x1b[2J\x1b[H')
    sys.stdout.flush()


def lr_animate() -> None:
    """Draw animation (left to right)."""
    for _ in range(8):
        clear_screen()
        lr_lower()
        time.sleep(0.04)
        clear_screen()
        lr_upper()
        time.sleep(0.04)
    clear_screen()


def rl_animate() -> None:
    """Draw animation (right to left)."""
    for _ in range(8):
        clear_screen()
        rl_lower()
        time.sleep(0.04)
        clear_screen()
        rl_upper()
        time.sleep(0.04)
    clear_screen()


###############################################################################
#                             DATA DIODE PROCESSES                            #
###############################################################################

def tx_process(io_queue:      'Queue',
               output_socket: int,
               argv:          str) -> None:
    """Process that sends to receiving computer."""
    if argv in ['txnhlr', 'nhrxrl']:
        lr_idle()
    if argv in ['txnhrl', 'nhrxlr']:
        rl_idle()

    while True:
        try:
            interface = multiprocessing.connection.Client(('localhost', output_socket))
            break
        except socket.error:
            time.sleep(0.01)

    while True:
        try:
            while io_queue.empty():
                time.sleep(0.01)

            msg = io_queue.get()

            if argv in ['txnhlr', 'nhrxrl']:
                lr_animate()
                lr_idle()

            if argv in ['txnhrl', 'nhrxlr']:
                rl_animate()
                rl_idle()

            interface.send(msg)

        except(EOFError, KeyboardInterrupt):
            pass


def rx_process(io_queue: 'Queue', input_socket: int) -> None:
    """Process that reads from sending computer."""
    listener  = multiprocessing.connection.Listener(('localhost', input_socket))
    interface = listener.accept()

    while True:
        time.sleep(0.01)
        try:
            io_queue.put(interface.recv())
        except (EOFError, KeyboardInterrupt):
            pass


def main() -> None:
    """Run data diode simulator."""
    output_socket = 0
    input_socket  = 0
    argv          = ''

    try:
        argv          = str(sys.argv[1])
        input_socket  = dict(txnhlr=5000, txnhrl=5000, nhrxlr=5002, nhrxrl=5002)[argv]
        output_socket = dict(txnhlr=5001, txnhrl=5001, nhrxlr=5003, nhrxrl=5003)[argv]
    except (IndexError, KeyError):
        clear_screen()
        print("\nUsage: python dd.py {txnh{lr,rl}, nhrx{lr,rl}}\n")
        exit()

    io_queue     = Queue()
    tx           = Process(target=tx_process, args=(io_queue, output_socket, argv))
    rx           = Process(target=rx_process, args=(io_queue, input_socket))
    process_list = [tx, rx]

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
