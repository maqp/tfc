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

import multiprocessing.connection
import socket
import sys
import time

from multiprocessing import Process, Queue
from typing          import Any, Dict, Tuple

from src.common.misc    import get_terminal_height, get_terminal_width, ignored, monitor_processes
from src.common.output  import clear_screen
from src.common.statics import (DATA_FLOW, DD_ANIMATION_LENGTH, DD_OFFSET_FROM_CENTER, DST_DD_LISTEN_SOCKET,
                                DST_LISTEN_SOCKET, EXIT_QUEUE, IDLE, LOCALHOST, NC, NCDCLR, NCDCRL, RP_LISTEN_SOCKET,
                                SCNCLR, SCNCRL, SRC_DD_LISTEN_SOCKET)


def draw_frame(argv:    str,          # Arguments for the simulator position/orientation
               message: str,          # Status message to print
               high:    bool = False  # Determines the signal's state (high/low)
               ) -> None:
    """Draw a data diode animation frame."""
    l, indicator, arrow, r = {NCDCLR: ('Rx', '<', '←', 'Tx'),
                              SCNCLR: ('Tx', '>', '→', 'Rx'),
                              NCDCRL: ('Tx', '>', '→', 'Rx'),
                              SCNCRL: ('Rx', '<', '←', 'Tx')}[argv]

    indicator = indicator if high            else ' '
    arrow     = arrow     if message != IDLE else ' '

    terminal_width = get_terminal_width()

    def c_print(string: str) -> None:
        """Print string on the center of the screen."""
        print(string.center(terminal_width))

    print('\n' * ((get_terminal_height() // 2) - DD_OFFSET_FROM_CENTER))

    c_print(message)
    c_print(arrow)
    c_print(  "────╮ " +    ' '    +  " ╭────" )
    c_print(f" {l} │ " + indicator + f" │ {r} ")
    c_print(  "────╯ " +    ' '    +  " ╰────" )


def animate(argv: str) -> None:
    """Animate the data diode transmission indicator."""
    for i in range(DD_ANIMATION_LENGTH):
        clear_screen()
        draw_frame(argv, DATA_FLOW, high=(i % 2 == 0))
        time.sleep(0.04)

    clear_screen()
    draw_frame(argv, IDLE)


def rx_loop(io_queue:     'Queue[Any]',  # Queue through which to push datagrams through
            input_socket: int            # Socket number for Transmitter/Relay Program
            ) -> None:
    """Read datagrams from a transmitting program."""
    listener  = multiprocessing.connection.Listener((LOCALHOST, input_socket))
    interface = listener.accept()

    while True:
        try:
            io_queue.put(interface.recv())
        except KeyboardInterrupt:
            pass
        except EOFError:
            sys.exit(0)


def tx_loop(io_queue:      'Queue[Any]',  # Queue through which to push datagrams through
            output_socket: int,           # Socket number for the Relay/Receiver Program
            argv:          str,           # Arguments for the simulator position/orientation
            unit_test:     bool = False   # Break out from the loop during unit testing
            ) -> None:
    """Send queued datagrams to a receiving program."""
    draw_frame(argv, IDLE)

    while True:
        try:
            interface = multiprocessing.connection.Client((LOCALHOST, output_socket))
            break
        except socket.error:
            time.sleep(0.01)

    while True:
        with ignored(EOFError, KeyboardInterrupt):
            while io_queue.qsize() == 0:
                time.sleep(0.01)
            animate(argv)
            interface.send(io_queue.get())

            if unit_test:
                break


def process_arguments() -> Tuple[str, int, int]:
    """Load simulator settings from the command line argument."""
    try:
        argv                        = str(sys.argv[1])
        input_socket, output_socket = {SCNCLR: (SRC_DD_LISTEN_SOCKET, RP_LISTEN_SOCKET),
                                       SCNCRL: (SRC_DD_LISTEN_SOCKET, RP_LISTEN_SOCKET),
                                       NCDCLR: (DST_DD_LISTEN_SOCKET, DST_LISTEN_SOCKET),
                                       NCDCRL: (DST_DD_LISTEN_SOCKET, DST_LISTEN_SOCKET)}[argv]

        return argv, input_socket, output_socket

    except (IndexError, KeyError):
        clear_screen()
        print(f"\nUsage: python3.7 dd.py [OPTION]\n\n"
              f"\nMandatory arguments"
              f"\n Argument  Simulate data diode between..."
              f"\n   {SCNCLR}    Source Computer    and Networked Computer   (left to right)"
              f"\n   {SCNCRL}    Source Computer    and Networked Computer   (right to left)"
              f"\n   {NCDCLR}    Networked Computer and Destination Computer (left to right)"
              f"\n   {NCDCRL}    Networked Computer and Destination Computer (right to left)")
        sys.exit(1)


def main(queues: Dict[bytes, 'Queue[Any]']) -> None:
    """\
    Read the argument from the command line and launch the data diode simulator.

    This application is the data diode simulator program used to
    visualize data transfer inside the data diode #1 between the Source
    Computer and the Networked Computer, or data transfer inside the
    data diode #2 between the Networked Computer and the Destination
    Computer. The local testing terminal multiplexer configurations that
    use data diode simulators run two instances of this program.

    The visualization is done with an indicator ('<' or '>') that blinks
    when data passes from one program to another. The data diode
    simulator does not provide any of the endpoint security properties
    that the hardware data diodes do.

    The visualization is designed to make data transfer between programs
    slower than is the case with actual serial interfaces. This allows
    the user to track the movement of data from one program to another
    with their eyes.
    """
    time.sleep(0.5)  # Wait for the terminal multiplexer size to stabilize

    argv, input_socket, output_socket = process_arguments()

    io_queue     = Queue()  # type: Queue[Any]
    process_list = [Process(target=rx_loop, args=(io_queue, input_socket       )),
                    Process(target=tx_loop, args=(io_queue, output_socket, argv))]

    for p in process_list:
        p.start()

    monitor_processes(process_list, NC, queues, error_exit_code=0)


if __name__ == '__main__':  # pragma: no cover
    main({EXIT_QUEUE: Queue()})
