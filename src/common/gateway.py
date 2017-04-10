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
import os.path
import platform
import serial
import socket
import time
import typing

from serial.serialutil import SerialException
from typing            import Any, Union

from src.common.errors import CriticalError, graceful_exit
from src.common.output import phase, print_on_previous_line

if typing.TYPE_CHECKING:
    from multiprocessing        import Queue
    from src.common.db_settings import Settings


def gw_incoming(gateway: 'Gateway', q_to_tip: 'Queue'):
    """Process that loads data from TxM side gateway."""
    while True:
        q_to_tip.put(gateway.read())


class Gateway(object):
    """Gateway object is a wrapper that provides interconnection between NH and TxM/RxM."""

    def __init__(self, settings: 'Settings') -> None:
        """Create a new gateway object."""
        self.settings  = settings
        self.interface = None  # type: Union[Any]

        # Set True when serial adapter is initially found so that further
        # serial interface searches know to announce disconnection.
        self.init_found = False
        bauds_per_byte  = 10
        bytes_per_s     = self.settings.serial_iface_speed / bauds_per_byte
        byte_travel_t   = 1 / bytes_per_s
        self.timeout    = max(2 * byte_travel_t, 0.01)
        self.delay      = 2 * self.timeout

        if self.settings.local_testing_mode:
            if self.settings.software_operation == 'tx':
                self.client_establish_socket()
            else:
                self.server_establish_socket()
        else:
            self.establish_serial()

    def write(self, packet: bytes) -> None:
        """Output data via socket/serial interface."""
        if self.settings.local_testing_mode:
            self.interface.send(packet)
        else:
            try:
                self.interface.write(packet)
                self.interface.flush()
                time.sleep(self.delay)
            except SerialException:
                self.establish_serial()
                self.write(packet)

    def read(self) -> bytes:
        """Read data via socket/serial interface."""
        if self.settings.local_testing_mode:
            while True:
                try:
                    return self.interface.recv()
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
                        read = self.interface.read(1000)
                        if read:
                            start_time = time.monotonic()
                            read_buffer.extend(read)
                        else:
                            if read_buffer:
                                delta = time.monotonic() - start_time
                                if delta > self.timeout:
                                    return bytes(read_buffer)
                            else:
                                time.sleep(0.001)

                except KeyboardInterrupt:
                    pass
                except SerialException:
                    self.establish_serial()
                    self.read()

    def server_establish_socket(self) -> None:
        """Establish IPC server."""
        listener       = multiprocessing.connection.Listener(('localhost', 5003))
        self.interface = listener.accept()

    def client_establish_socket(self) -> None:
        """Establish IPC client."""
        try:
            phase("Waiting for connection to NH", offset=11)
            while True:
                try:
                    socket_number  = 5000 if self.settings.data_diode_sockets else 5001
                    self.interface = multiprocessing.connection.Client(('localhost', socket_number))
                    phase("Established", done=True)
                    break
                except socket.error:
                    time.sleep(0.1)

        except KeyboardInterrupt:
            graceful_exit()

    def establish_serial(self):
        """Create new serial interface object."""
        try:
            serial_nh      = self.search_serial_interface()
            self.interface = serial.Serial(serial_nh, self.settings.session_if_speed, timeout=0)
        except SerialException:
            graceful_exit("SerialException. Ensure $USER is in dialout group.")

    def search_serial_interface(self) -> str:
        """Search for serial interface."""
        if self.settings.session_usb_iface:
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
            f = 'serial0' if 'Raspbian' in platform.platform() else 'ttyS0'
            if f in sorted(os.listdir('/dev/')):
                return '/dev/{}'.format(f)
            else:
                raise CriticalError("Error: /dev/{} was not found.".format(f))
