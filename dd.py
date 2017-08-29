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
import socket
import sys
import time

from multiprocessing import Process, Queue
from typing          import Tuple

from src.common.misc    import get_terminal_height, ignored
from src.common.output  import c_print, clear_screen
from src.common.statics import *


def draw_frame(argv: str, message: str, high: bool) -> None:
    """Draw data diode animation frame.

    :param argv:    Arguments for simulator position/orientation
    :param message: Status message to print
    :param high:    Determines signal's state (high/low)
    :return:        None
    """
    l, r, symbol, arrow = dict(txnhlr=('Tx', 'Rx', '>', '→'),
                               nhrxrl=('Tx', 'Rx', '>', '→'),
                               txnhrl=('Rx', 'Tx', '<', '←'),
                               nhrxlr=('Rx', 'Tx', '<', '←'))[argv]

    arrow = ' '    if message == 'Idle' else arrow
    blink = symbol if high              else ' '

    offset_from_center = 4
    print(((get_terminal_height() // 2) - offset_from_center) * '\n')

    c_print(message)
    c_print(arrow)
    c_print(  "─────╮ " +  ' '  +  " ╭─────" )
    c_print(f"  {l} │ " + blink + f" │ {r}  ")
    c_print(  "─────╯ " +  ' '  +  " ╰─────" )


def animate(argv: str) -> None:
    """Animate the data diode."""
    animation_length = 16
    for i in range(animation_length):
        clear_screen()
        draw_frame(argv, 'Data flow', high=(i % 2 == 0))
        time.sleep(0.04)
    clear_screen()
    draw_frame(argv, 'Idle', high=False)


def tx_loop(io_queue: 'Queue', output_socket: int, argv: str) -> None:
    """Loop that sends packets to receiving program."""
    draw_frame(argv, 'Idle', high=False)

    while True:
        try:
            interface = multiprocessing.connection.Client(('localhost', output_socket))
            break
        except socket.error:
            time.sleep(0.01)

    while True:
        with ignored(EOFError, KeyboardInterrupt):
            while io_queue.empty():
                time.sleep(0.01)
            animate(argv)
            interface.send(io_queue.get())


def rx_loop(io_queue: 'Queue', input_socket: int) -> None:
    """Loop that reads packets from transmitting program."""
    listener  = multiprocessing.connection.Listener(('localhost', input_socket))
    interface = listener.accept()

    while True:
        time.sleep(0.01)
        try:
            io_queue.put(interface.recv())
        except KeyboardInterrupt:
            pass
        except EOFError:
            sys.exit(0)


def process_arguments() -> Tuple[str, int, int]:
    """Load simulator settings from command line arguments."""
    try:
        argv                        = str(sys.argv[1])
        input_socket, output_socket = dict(txnhlr=(TXM_DD_LISTEN_SOCKET, NH_LISTEN_SOCKET),
                                           txnhrl=(TXM_DD_LISTEN_SOCKET, NH_LISTEN_SOCKET),
                                           nhrxlr=(RXM_DD_LISTEN_SOCKET, RXM_LISTEN_SOCKET),
                                           nhrxrl=(RXM_DD_LISTEN_SOCKET, RXM_LISTEN_SOCKET))[argv]

        return argv, input_socket, output_socket

    except (IndexError, KeyError):
        clear_screen()
        print("\nUsage: python3.6 dd.py [OPTION]\n\n"
              "\nMandatory arguments"
              "\n  txnhlr    Simulate data diode between TxM and NH (left to right)"
              "\n  txnhrl    Simulate data diode between TxM and NH (right to left)"
              "\n  nhrxlr    Simulate data diode between NH and RxM (left to right)"
              "\n  nhrxrl    Simulate data diode between NH and RxM (right to left)")
        sys.exit(1)


def main() -> None:
    """Read argument from command line and launch processes."""
    time.sleep(0.5)
    argv, input_socket, output_socket = process_arguments()

    io_queue     = Queue()
    process_list = [Process(target=tx_loop, args=(io_queue, output_socket, argv)),
                    Process(target=rx_loop, args=(io_queue, input_socket       ))]

    for p in process_list:
        p.start()

    while True:
        with ignored(EOFError, KeyboardInterrupt):
            time.sleep(0.1)
            if not all([p.is_alive() for p in process_list]):
                for p in process_list:
                    p.terminate()
                sys.exit(0)


if __name__ == '__main__':
    main()
