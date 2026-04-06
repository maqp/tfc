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

import multiprocessing.connection
import socket
import sys
import time

from multiprocessing import Process, Queue

from src.common.process import configure_multiprocessing_start_method, monitor_processes
from src.common.queues import DataDiodeQueue
from src.ui.common.utils import get_terminal_height, get_terminal_width
from src.ui.common.output.vt100_utils import clear_screen
from src.common.statics import (DataDiodeLaunchArguments as DDLA,
                                DataDiodeSimState        as DDS,
                                ProgramID, SocketNumber, NetworkLiterals)

BLINKS_PER_ANIMATION = 8


def draw_frame(argv:    DDLA,         # Arguments for the simulator position/orientation
               message: str,          # Status message to print
               high:    bool = False  # Determines the signal's state (high/low)
               ) -> None:
    """Draw a data diode animation frame."""
    offset_from_center = 4

    l, indicator, arrow, r = {DDLA.NCDCLR : ('Rx', '<', '←', 'Tx'),
                              DDLA.SCNCLR : ('Tx', '>', '→', 'Rx'),
                              DDLA.NCDCRL : ('Tx', '>', '→', 'Rx'),
                              DDLA.SCNCRL : ('Rx', '<', '←', 'Tx')}[argv]

    indicator = indicator if high                else ' '
    arrow     = arrow     if message != DDS.IDLE else ' '

    terminal_width = get_terminal_width()

    def c_print(string: str) -> None:
        """Print string at the center of the screen."""
        print(string.center(terminal_width))

    print('\n' * ((get_terminal_height() // 2) - offset_from_center))

    c_print(message)
    c_print(arrow)
    c_print(  '────╮ ' +    ' '    +  ' ╭────' )
    c_print(f' {l} │ ' + indicator + f' │ {r} ')
    c_print(  '────╯ ' +    ' '    +  ' ╰────' )


def animate(argv: DDLA) -> None:
    """Animate the data diode transmission indicator."""
    for i in range(2 * BLINKS_PER_ANIMATION):
        clear_screen()
        draw_frame(argv, DDS.DATA_FLOW, high=(i % 2 == 0))
        time.sleep(0.04)

    clear_screen()
    draw_frame(argv, DDS.IDLE)


def accept_connection(input_socket: int) -> multiprocessing.connection.Connection:
    """Accept one incoming local-testing socket connection."""
    listener: multiprocessing.connection.Listener | None = None

    try:
        listener = multiprocessing.connection.Listener((NetworkLiterals.LOCALHOST, input_socket))
        return listener.accept()
    finally:
        if listener is not None:
            listener.close()


def connect_output(output_socket: int) -> multiprocessing.connection.Connection:
    """Connect to the output side of the local-testing socket path."""
    while True:
        try:
            return multiprocessing.connection.Client((NetworkLiterals.LOCALHOST, output_socket))
        except socket.error:
            time.sleep(0.01)


def rx_loop(io_queue:     'Queue[bytes]',  # Queue through which to push datagrams through
            input_socket: int              # Socket number for Transmitter/Relay Program
            ) -> None:
    """Read datagrams from a transmitting program."""
    while True:
        try:
            interface = accept_connection(input_socket)

            while True:
                io_queue.put(interface.recv())
        except (KeyboardInterrupt, EOFError, OSError):
            pass


def tx_loop(io_queue:      'Queue[bytes]',  # Queue through which to push datagrams through
            output_socket: int,             # Socket number for the Relay/Receiver Program
            argv:          DDLA,            # Arguments for the simulator position/orientation
            unit_test:     bool = False     # Break out from the loop during unit testing
            ) -> None:
    """Send queued datagrams to a receiving program."""
    draw_frame(argv, DDS.IDLE)

    while True:
        try:
            interface = connect_output(output_socket)

            while True:
                packet = io_queue.get()
                animate(argv)
                interface.send(packet)

                if unit_test:
                    return

        except (BrokenPipeError, KeyboardInterrupt, EOFError, OSError):
            pass


def process_arguments() -> tuple[str, int, int]:
    """Load simulator settings from the command line argument."""
    try:
        argv                        = DDLA(str(sys.argv[1]))
        input_socket, output_socket = {DDLA.SCNCLR: (SocketNumber.SRC_DD_LISTEN, SocketNumber.RP_LISTEN),
                                       DDLA.SCNCRL: (SocketNumber.SRC_DD_LISTEN, SocketNumber.RP_LISTEN),
                                       DDLA.NCDCLR: (SocketNumber.DST_DD_LISTEN, SocketNumber.DST_LISTEN),
                                       DDLA.NCDCRL: (SocketNumber.DST_DD_LISTEN, SocketNumber.DST_LISTEN)}[argv]

        return argv, input_socket, output_socket

    except (IndexError, ValueError):
        clear_screen()
        print(f'\nUsage: python3 dd.py [OPTION]\n\n'
              f'\nMandatory arguments'
              f'\n Argument  Simulate data diode between...'
              f'\n   {DDLA.SCNCLR}    Source Computer    and Networked Computer   (left to right)'
              f'\n   {DDLA.SCNCRL}    Source Computer    and Networked Computer   (right to left)'
              f'\n   {DDLA.NCDCLR}    Networked Computer and Destination Computer (left to right)'
              f'\n   {DDLA.NCDCRL}    Networked Computer and Destination Computer (right to left)')
        sys.exit(1)


def data_diode_simulator() -> None:
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
    configure_multiprocessing_start_method()

    argv, input_socket, output_socket = process_arguments()

    queues = DataDiodeQueue()

    process_list = [Process(target=rx_loop, args=(queues.io_queue, input_socket       )),
                    Process(target=tx_loop, args=(queues.io_queue, output_socket, argv))]

    for p in process_list:
        p.start()

    monitor_processes(process_list, ProgramID.NC, queues, error_exit_code=0)


if __name__ == '__main__':
    data_diode_simulator()
