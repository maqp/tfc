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

import hashlib
import json
import multiprocessing.connection
import os
import os.path
import serial
import socket
import textwrap
import time
import typing

from datetime import datetime
from typing   import Any, Dict, Optional, Tuple, Union

from serial.serialutil import SerialException

from src.common.exceptions   import CriticalError, FunctionReturn, graceful_exit
from src.common.input        import yes
from src.common.misc         import calculate_race_condition_delay, ensure_dir, ignored, get_terminal_width
from src.common.misc         import separate_trailer
from src.common.output       import m_print, phase, print_on_previous_line
from src.common.reed_solomon import ReedSolomonError, RSCodec
from src.common.statics      import *

if typing.TYPE_CHECKING:
    from multiprocessing import Queue


def gateway_loop(queues:    Dict[bytes, 'Queue[Any]'],
                 gateway:   'Gateway',
                 unit_test: bool = False
                 ) -> None:
    """Load data from serial interface or socket into a queue.

    Also place the current timestamp to queue to be delivered to the
    Receiver Program. The timestamp is used both to notify when the sent
    message was received by Relay Program, and as part of a commitment
    scheme: For more information, see the section on "Covert channel
    based on user interaction" under TFC's Security Design wiki article.
    """
    queue = queues[GATEWAY_QUEUE]

    while True:
        with ignored(EOFError, KeyboardInterrupt):
            queue.put((datetime.now(), gateway.read()))
            if unit_test:
                break


class Gateway(object):
    """\
    Gateway object is a wrapper for interfaces that connect
    Source/Destination Computer with the Networked computer.
    """

    def __init__(self,
                 operation:  str,
                 local_test: bool,
                 dd_sockets: bool
                 ) -> None:
        """Create a new Gateway object."""
        self.settings  = GatewaySettings(operation, local_test, dd_sockets)
        self.tx_serial = None  # type: Optional[serial.Serial]
        self.rx_serial = None  # type: Optional[serial.Serial]
        self.rx_socket = None  # type: Optional[multiprocessing.connection.Connection]
        self.tx_socket = None  # type: Optional[multiprocessing.connection.Connection]

        # Initialize Reed-Solomon erasure code handler
        self.rs = RSCodec(2 * self.settings.session_serial_error_correction)

        # Set True when the serial interface is initially found so that
        # further interface searches know to announce disconnection.
        self.init_found = False

        if self.settings.local_testing_mode:
            if self.settings.software_operation in [TX, NC]:
                self.client_establish_socket()
            if self.settings.software_operation in [NC, RX]:
                self.server_establish_socket()
        else:
            self.establish_serial()

    def establish_serial(self) -> None:
        """Create a new Serial object.

        By setting the Serial object's timeout to 0, the method
        `Serial().read_all()` will return 0..N bytes where N is the serial
        interface buffer size (496 bytes for FTDI FT232R for example).
        This is not enough for large packets. However, in this case,
        `read_all` will return
            a) immediately when the buffer is full
            b) if no bytes are received during the time it would take
               to transmit the next byte of the datagram.

        This type of behaviour allows us to read 0..N bytes from the
        serial interface at a time, and add them to a bytearray buffer.

        In our implementation below, if the receiver side stops
        receiving data when it calls `read_all`, it starts a timer that
        is evaluated with every subsequent call of `read_all` that
        returns an empty string. If the timer exceeds the
        `settings.rx_receive_timeout` value (twice the time it takes to
        send the next byte with given baud rate), the gateway object
        will return the received packet.

        The timeout timer is triggered intentionally by the transmitter
        side Gateway object, that after each transmission sleeps for
        `settings.tx_inter_packet_delay` seconds. This value is set to
        twice the length of `settings.rx_receive_timeout`, or four times
        the time it takes to send one byte with given baud rate.
        """
        try:
            serial_interface                = self.search_serial_interface()
            baudrate                        = self.settings.session_serial_baudrate
            self.tx_serial = self.rx_serial = serial.Serial(serial_interface, baudrate, timeout=0)
        except SerialException:
            raise CriticalError("SerialException. Ensure $USER is in the dialout group by restarting this computer.")

    def write(self, orig_packet: bytes) -> None:
        """Add error correction data and output data via socket/serial interface.

        After outputting the packet via serial, sleep long enough to
        trigger the Rx-side timeout timer, or if local testing is
        enabled, add slight delay to simulate that introduced by the
        serial interface.
        """
        packet = self.add_error_correction(orig_packet)

        if self.settings.local_testing_mode and self.tx_socket is not None:
            try:
                self.tx_socket.send(packet)
                time.sleep(LOCAL_TESTING_PACKET_DELAY)
            except BrokenPipeError:
                raise CriticalError("Relay IPC server disconnected.", exit_code=0)
        elif self.tx_serial is not None:
            try:
                self.tx_serial.write(packet)
                self.tx_serial.flush()
                time.sleep(self.settings.tx_inter_packet_delay)
            except SerialException:
                self.establish_serial()
                self.write(orig_packet)

    def read(self) -> bytes:
        """Read data via socket/serial interface.

        Read 0..N bytes from serial interface, where N is the buffer
        size of the serial interface. Once `read_buffer` has data, and
        the interface hasn't returned data long enough for the timer to
        exceed the timeout value, return received data.
        """
        if self.settings.local_testing_mode and self.rx_socket is not None:
            while True:
                try:
                    packet = self.rx_socket.recv()  # type: bytes
                    return packet
                except KeyboardInterrupt:
                    pass
                except EOFError:
                    raise CriticalError("Relay IPC client disconnected.", exit_code=0)
        else:
            if self.rx_serial is None:
                raise CriticalError("Serial interface has not been initialized.")
            while True:
                try:
                    start_time  = 0.0
                    read_buffer = bytearray()
                    while True:
                        read = self.rx_serial.read_all()
                        if read:
                            start_time = time.monotonic()
                            read_buffer.extend(read)
                        else:
                            if read_buffer:
                                delta = time.monotonic() - start_time
                                if delta > self.settings.rx_receive_timeout:
                                    return bytes(read_buffer)
                            else:
                                time.sleep(0.0001)

                except (EOFError, KeyboardInterrupt):
                    pass
                except (OSError, SerialException):
                    self.establish_serial()

    def add_error_correction(self, packet: bytes) -> bytes:
        """Add error correction to packet that will be output.

        If the error correction setting is set to 1 or higher, TFC adds
        Reed-Solomon erasure codes to detect and correct errors during
        transmission over the serial interface. For more information on
        Reed-Solomon, see
            https://en.wikipedia.org/wiki/Reed%E2%80%93Solomon_error_correction
            https://www.cs.cmu.edu/~guyb/realworld/reedsolomon/reed_solomon_codes.html

        If error correction is set to 0, errors are only detected. This
        is done by using a BLAKE2b based, 128-bit checksum.
        """
        if self.settings.session_serial_error_correction:
            packet = self.rs.encode(packet)
        else:
            packet = packet + hashlib.blake2b(packet, digest_size=PACKET_CHECKSUM_LENGTH).digest()
        return packet

    def detect_errors(self, packet: bytes) -> bytes:
        """Handle received packet error detection and/or correction."""
        if self.settings.session_serial_error_correction:
            try:
                packet, _ = self.rs.decode(packet)
                return bytes(packet)
            except ReedSolomonError:
                raise FunctionReturn("Error: Reed-Solomon failed to correct errors in the received packet.", bold=True)
        else:
            packet, checksum = separate_trailer(packet, PACKET_CHECKSUM_LENGTH)
            if hashlib.blake2b(packet, digest_size=PACKET_CHECKSUM_LENGTH).digest() != checksum:
                raise FunctionReturn("Warning! Received packet had an invalid checksum.", bold=True)
            return packet

    def search_serial_interface(self) -> str:
        """Search for a serial interface."""
        if self.settings.session_usb_serial_adapter:
            search_announced = False

            if not self.init_found:
                phase("Searching for USB-to-serial interface", offset=len('Found'))

            while True:
                for f in sorted(os.listdir('/dev/')):
                    if f.startswith('ttyUSB'):
                        if self.init_found:
                            time.sleep(1)
                        phase('Found', done=True)
                        if self.init_found:
                            print_on_previous_line(reps=2)
                        self.init_found = True
                        return f'/dev/{f}'
                else:
                    time.sleep(0.1)
                    if self.init_found and not search_announced:
                        phase("Serial adapter disconnected. Waiting for interface", head=1, offset=len('Found'))
                        search_announced = True

        else:
            if self.settings.built_in_serial_interface in sorted(os.listdir('/dev/')):
                return f'/dev/{self.settings.built_in_serial_interface}'
            raise CriticalError(f"Error: /dev/{self.settings.built_in_serial_interface} was not found.")

    # Local testing

    def server_establish_socket(self) -> None:
        """Initialize the receiver (IPC server).

        The multiprocessing connection during local test does not
        utilize authentication keys* because a MITM-attack against the
        connection requires endpoint compromise, and in such situation,
        MITM attack is not nearly as effective as key/screen logging or
        RAM dump.

            * https://docs.python.org/3/library/multiprocessing.html#authentication-keys

        Similar to the case of standard mode of operation, all sensitive
        data that passes through the socket/serial interface and Relay
        Program is encrypted. A MITM attack between the sockets could of
        course be used to e.g. inject public keys, but like with all key
        exchanges, that would only work if the user neglects fingerprint
        verification.

        Another reason why the authentication key is useless, is the key
        needs to be pre-shared. This means there's two ways to share it:

            1) Hard-code the key to source file from where malware could
               read it.

            2) Force the user to manually copy the PSK from one program
               to another. This would change the workflow that the local
               test configuration tries to simulate.

        To conclude, the local test configuration should never be used
        under a threat model where endpoint security is of importance.
        """
        try:
            socket_number  = RP_LISTEN_SOCKET if self.settings.software_operation == NC else DST_LISTEN_SOCKET
            listener       = multiprocessing.connection.Listener((LOCALHOST, socket_number))
            self.rx_socket = listener.accept()
        except KeyboardInterrupt:
            graceful_exit()

    def client_establish_socket(self) -> None:
        """Initialize the transmitter (IPC client)."""
        try:
            target = RECEIVER if self.settings.software_operation == NC else RELAY
            phase(f"Connecting to {target}")
            while True:
                try:
                    if self.settings.software_operation == TX:
                        socket_number = SRC_DD_LISTEN_SOCKET if self.settings.data_diode_sockets else RP_LISTEN_SOCKET
                    else:
                        socket_number = DST_DD_LISTEN_SOCKET if self.settings.data_diode_sockets else DST_LISTEN_SOCKET

                    try:
                        self.tx_socket = multiprocessing.connection.Client((LOCALHOST, socket_number))
                    except ConnectionRefusedError:
                        time.sleep(0.1)
                        continue

                    phase(DONE)
                    break

                except socket.error:
                    time.sleep(0.1)

        except KeyboardInterrupt:
            graceful_exit()


class GatewaySettings(object):
    """\
    Gateway settings store settings for serial interface in an
    unencrypted JSON database.

    The reason these settings are in plaintext is it protects the system
    from inconsistent state of serial settings: Would the user reconfigure
    their serial settings, and would the setting altering packet to
    Receiver Program drop, Relay Program could in some situations no
    longer communicate with the Receiver Program.

    Serial interface settings are not sensitive enough to justify the
    inconvenience of encrypting the setting values.
    """

    def __init__(self,
                 operation:  str,
                 local_test: bool,
                 dd_sockets: bool
                 ) -> None:
        """Create a new Settings object.

        The settings below are altered from within the program itself.
        Changes made to the default settings are stored in the JSON
        file under $HOME/tfc/user_data from where, if needed, they can
        be manually altered by the user.
        """
        self.serial_baudrate           = 19200
        self.serial_error_correction   = 5
        self.use_serial_usb_adapter    = True
        self.built_in_serial_interface = 'ttyS0'

        self.software_operation = operation
        self.local_testing_mode = local_test
        self.data_diode_sockets = dd_sockets

        self.all_keys = list(vars(self).keys())
        self.key_list = self.all_keys[:self.all_keys.index('software_operation')]
        self.defaults = {k: self.__dict__[k] for k in self.key_list}

        self.file_name = f'{DIR_USER_DATA}{self.software_operation}_serial_settings.json'

        ensure_dir(DIR_USER_DATA)
        if os.path.isfile(self.file_name):
            self.load_settings()
        else:
            self.setup()
            self.store_settings()

        self.session_serial_baudrate         = self.serial_baudrate
        self.session_serial_error_correction = self.serial_error_correction
        self.session_usb_serial_adapter      = self.use_serial_usb_adapter

        self.tx_inter_packet_delay, self.rx_receive_timeout = self.calculate_serial_delays(self.session_serial_baudrate)

        self.race_condition_delay = calculate_race_condition_delay(self.session_serial_error_correction,
                                                                   self.serial_baudrate)

    @classmethod
    def calculate_serial_delays(cls, baud_rate: int) -> Tuple[float, float]:
        """Calculate the inter-packet delay and receive timeout.

        Although this calculation mainly depends on the baud rate, a
        minimal value will be set for rx_receive_timeout. This is to
        ensure high baud rates do not cause issues by having shorter
        delays than what the `time.sleep()` resolution allows.
        """
        bytes_per_sec = baud_rate / BAUDS_PER_BYTE
        byte_travel_t = 1 / bytes_per_sec

        rx_receive_timeout    = max(2 * byte_travel_t, SERIAL_RX_MIN_TIMEOUT)
        tx_inter_packet_delay = 2 * rx_receive_timeout

        return tx_inter_packet_delay, rx_receive_timeout

    def setup(self) -> None:
        """Prompt the user to enter initial serial interface setting.

        Ensure that the serial interface is available before proceeding.
        """
        if not self.local_testing_mode:
            name = {TX: TRANSMITTER, NC: RELAY, RX: RECEIVER}[self.software_operation]

            self.use_serial_usb_adapter = yes(f"Use USB-to-serial/TTL adapter for {name} Computer?", head=1, tail=1)

            if self.use_serial_usb_adapter:
                for f in sorted(os.listdir('/dev/')):
                    if f.startswith('ttyUSB'):
                        return None
                else:
                    m_print("Error: USB-to-serial/TTL adapter not found.")
                    self.setup()
            else:
                if self.built_in_serial_interface in sorted(os.listdir('/dev/')):
                    return None
                else:
                    m_print(f"Error: Serial interface /dev/{self.built_in_serial_interface} not found.")
                    self.setup()

    def store_settings(self) -> None:
        """Store serial settings in JSON format."""
        serialized = json.dumps(self, default=(lambda o: {k: self.__dict__[k] for k in self.key_list}), indent=4)
        with open(self.file_name, 'w+') as f:
            f.write(serialized)

    def invalid_setting(self, key: str, json_dict: Dict[str, Union[bool, int, str]]) -> None:
        """Notify about setting an invalid value to default value."""
        m_print([f"Error: Invalid value '{json_dict[key]}' for setting '{key}' in '{self.file_name}'.",
                 f"The value has been set to default ({self.defaults[key]})."], head=1, tail=1)
        setattr(self, key, self.defaults[key])

    def load_settings(self) -> None:
        """Load and validate JSON settings for serial interface."""
        with open(self.file_name) as f:
            try:
                json_dict = json.load(f)
            except json.decoder.JSONDecodeError:
                os.remove(self.file_name)
                self.store_settings()
                print(f"\nError: Invalid JSON format in '{self.file_name}'."
                      "\nSerial interface settings have been set to default values.\n")
                return None

        # Check for missing setting
        for key in self.key_list:
            if key not in json_dict:
                m_print([f"Error: Missing setting '{key}' in '{self.file_name}'.",
                         f"The value has been set to default ({self.defaults[key]})."], head=1, tail=1)
                setattr(self, key, self.defaults[key])
                continue

            # Closer inspection of each setting value
            if key == 'serial_baudrate' and json_dict[key] not in serial.Serial().BAUDRATES:
                self.invalid_setting(key, json_dict)
                continue

            elif key == 'serial_error_correction' and (not isinstance(json_dict[key], int) or json_dict[key] < 0):
                self.invalid_setting(key, json_dict)
                continue

            elif key == 'use_serial_usb_adapter':
                if not isinstance(json_dict[key], bool):
                    self.invalid_setting(key, json_dict)
                    continue

            elif key == 'built_in_serial_interface':
                if not isinstance(json_dict[key], str):
                    self.invalid_setting(key, json_dict)
                    continue
                if not any(json_dict[key] == f for f in os.listdir('/sys/class/tty')):
                    self.invalid_setting(key, json_dict)
                    continue

            setattr(self, key, json_dict[key])

        # Store after loading to add missing, to replace invalid settings,
        # and to remove settings that do not belong in the JSON file.
        self.store_settings()

    def change_setting(self, key: str, value_str: str) -> None:
        """Parse, update and store new setting value."""
        attribute = self.__getattribute__(key)
        try:
            if isinstance(attribute, bool):
                value = dict(true=True, false=False)[value_str.lower()]  # type: Union[bool, int]

            elif isinstance(attribute, int):
                value = int(value_str)
                if value < 0 or value > MAX_INT:
                    raise ValueError

            else:
                raise CriticalError("Invalid attribute type in settings.")

        except (KeyError, ValueError):
            raise FunctionReturn(f"Error: Invalid value '{value_str}'.", delay=1, tail_clear=True)

        self.validate_key_value_pair(key, value)

        setattr(self, key, value)
        self.store_settings()

    @staticmethod
    def validate_key_value_pair(key: str, value: Union[int, bool]) -> None:
        """\
        Perform further evaluation on settings the values of which have
        restrictions.
        """
        if key == 'serial_baudrate':
            if value not in serial.Serial().BAUDRATES:
                raise FunctionReturn("Error: The specified baud rate is not supported.")
            m_print("Baud rate will change on restart.", head=1, tail=1)

        if key == 'serial_error_correction':
            if value < 0:
                raise FunctionReturn("Error: Invalid value for error correction ratio.")
            m_print("Error correction ratio will change on restart.", head=1, tail=1)

    def print_settings(self) -> None:
        """\
        Print list of settings, their current and
        default values, and setting descriptions.
        """
        desc_d = {"serial_baudrate":         "The speed of serial interface in bauds per second",
                  "serial_error_correction": "Number of byte errors serial datagrams can recover from"}

        # Columns
        c1 = ['Serial interface setting']
        c2 = ['Current value']
        c3 = ['Default value']
        c4 = ['Description']

        terminal_width = get_terminal_width()
        description_indent = 64

        if terminal_width < description_indent + 1:
            raise FunctionReturn("Error: Screen width is too small.")

        # Populate columns with setting data
        for key in desc_d:
            c1.append(key)
            c2.append(str(self.__getattribute__(key)))
            c3.append(str(self.defaults[key]))

            description = desc_d[key]
            wrapper     = textwrap.TextWrapper(width=max(1, (terminal_width - description_indent)))
            desc_lines  = wrapper.fill(description).split('\n')
            desc_string = desc_lines[0]

            for line in desc_lines[1:]:
                desc_string += '\n' + description_indent * ' ' + line

            if len(desc_lines) > 1:
                desc_string += '\n'

            c4.append(desc_string)

        # Calculate column widths
        c1w, c2w, c3w = [max(len(v) for v in column) + SETTINGS_INDENT for column in [c1, c2, c3]]

        # Align columns by adding whitespace between fields of each line
        lines = [f'{f1:{c1w}}      {f2:{c2w}} {f3:{c3w}} {f4}' for f1, f2, f3, f4 in zip(c1, c2, c3, c4)]

        # Add a terminal-wide line between the column names and the data
        lines.insert(1, get_terminal_width() * '─')

        # Print the settings
        print('\n' + '\n'.join(lines) + '\n')
