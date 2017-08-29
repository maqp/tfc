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

import multiprocessing.connection
import os.path
import serial
import time
import typing

from serial.serialutil import SerialException
from typing            import Any, Dict

from src.common.exceptions import CriticalError, graceful_exit
from src.common.misc       import ignored
from src.common.output     import phase, print_on_previous_line
from src.common.statics    import *

if typing.TYPE_CHECKING:
    from multiprocessing import Queue
    from src.nh.settings import Settings


def gateway_loop(queues:   Dict[bytes, 'Queue'],
                 gateway:  'Gateway',
                 unittest: bool = False) -> None:
    """Loop that loads data from TxM side gateway to NH."""
    queue = queues[TXM_INCOMING_QUEUE]

    while True:
        with ignored(EOFError, KeyboardInterrupt):
            queue.put(gateway.read())
            if unittest:
                break


class Gateway(object):
    """Gateway object is a wrapper for interfaces that connect NH with TxM/RxM."""

    def __init__(self, settings: 'Settings') -> None:
        """Create a new Gateway object."""
        self.settings      = settings
        self.txm_interface = None  # type: Any
        self.rxm_interface = None  # type: Any

        # Set True when serial adapter is initially found so that further
        # serial interface searches know to announce disconnection.
        self.init_found = False

        if settings.local_testing_mode:
            self.establish_socket()
        else:
            self.txm_interface = self.rxm_interface = self.establish_serial()

    def write(self, packet: bytes) -> None:
        """Output data via socket/serial interface."""
        if self.settings.local_testing_mode:
            self.rxm_interface.send(packet)
        else:
            try:
                self.rxm_interface.write(packet)
                self.rxm_interface.flush()
                time.sleep(self.settings.transmit_delay)
            except SerialException:
                self.rxm_interface = self.establish_serial()
                self.write(packet)

    def read(self) -> bytes:
        """Read data via socket/serial interface."""
        if self.settings.local_testing_mode:
            while True:
                try:
                    return self.txm_interface.recv()
                except KeyboardInterrupt:
                    pass
                except EOFError:
                    graceful_exit("IPC client disconnected.")
        else:
            while True:
                try:
                    start_time  = 0.0
                    read_buffer = bytearray()
                    while True:
                        read = self.txm_interface.read(1000)
                        if read:
                            start_time = time.monotonic()
                            read_buffer.extend(read)
                        else:
                            if read_buffer:
                                delta = time.monotonic() - start_time
                                if delta > self.settings.receive_timeout:
                                    return bytes(read_buffer)
                            else:
                                time.sleep(0.001)

                except KeyboardInterrupt:
                    pass
                except SerialException:
                    self.txm_interface = self.establish_serial()
                    self.read()

    def establish_socket(self) -> None:
        """Establish local testing socket connections."""
        listener           = multiprocessing.connection.Listener(('localhost', NH_LISTEN_SOCKET))
        self.txm_interface = listener.accept()

        while True:
            try:
                rxm_socket         = RXM_DD_LISTEN_SOCKET if self.settings.data_diode_sockets else RXM_LISTEN_SOCKET
                self.rxm_interface = multiprocessing.connection.Client(('localhost', rxm_socket))
                break
            except ConnectionRefusedError:
                time.sleep(0.1)

    def establish_serial(self) -> Any:
        """Create a new Serial object."""
        try:
            serial_nh = self.search_serial_interface()
            return serial.Serial(serial_nh, self.settings.session_serial_baudrate, timeout=0)
        except SerialException:
            graceful_exit("SerialException. Ensure $USER is in the dialout group.")

    def search_serial_interface(self) -> str:
        """Search for serial interface."""
        if self.settings.serial_usb_adapter:
            search_announced = False

            if not self.init_found:
                print_on_previous_line()
                phase("Searching for USB-to-serial interface")

            while True:
                time.sleep(0.1)
                for f in sorted(os.listdir('/dev')):
                    if f.startswith('ttyUSB'):
                        if self.init_found:
                            time.sleep(1.5)
                        phase('Found', done=True)
                        if self.init_found:
                            print_on_previous_line(reps=2)
                        self.init_found = True
                        return '/dev/{}'.format(f)
                else:
                    if not search_announced:
                        if self.init_found:
                            phase("Serial adapter disconnected. Waiting for interface", head=1)
                        search_announced = True

        else:
            f = 'ttyS0'
            if f in sorted(os.listdir('/dev/')):
                return '/dev/{}'.format(f)
            raise CriticalError("Error: /dev/{} was not found.".format(f))
