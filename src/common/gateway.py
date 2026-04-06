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

import base64
import hashlib
import multiprocessing.connection
import os
import os.path
import serial
import socket
import subprocess
import time

from typing import TYPE_CHECKING, Optional as O

from serial.serialutil import SerialException

from src.common.replay import allocate_packet_number, cache_outgoing_packet, load_cached_outgoing_packet, make_numbered_packet
from src.common.exceptions import CriticalError, graceful_exit, SoftError
from src.common.utils.strings import separate_trailer
from src.common.utils.io import ensure_dir, read_oldest_buffer_file
from src.ui.common.output.phase import phase
from src.common.reed_solomon import ReedSolomonError, RSCodec
from src.common.statics import (StatusMsg, Delay, FieldLength, QubesLiterals, ProgramID,
                                SocketNumber, NetworkLiterals, ProgramName)
from src.database.db_settings_gateway import GatewaySettings
from src.datagrams.receiver.command import DatagramReceiverCommand
from src.datagrams.receiver.local_key import DatagramReceiverLocalKey
from src.datagrams.receiver.message import DatagramOutgoingMessage, DatagramIncomingMessage
from src.datagrams.receiver.public_key import DatagramPublicKey
from src.datagrams.relay.command.change_setting import DatagramRelayChangeSetting
from src.datagrams.relay.command.command_security import (DatagramRelayCommandScreenClear,
                                                          DatagramRelayCommandClearCiphertextCache,
                                                          DatagramRelayCommandScreenReset,
                                                          DatagramRelayCommandExitTFC,
                                                          DatagramRelayCommandWipeSystem)
from src.datagrams.relay.command.contact_add import DatagramRelayAddContact
from src.datagrams.relay.command.contact_remove import DatagramRelayRemoveContact
from src.datagrams.relay.diff_comparison.diff_comparison_account import DatagramRelayDiffComparisonAccount
from src.datagrams.relay.diff_comparison.diff_comparison_public_key import DatagramRelayDiffComparisonPublicKey
from src.datagrams.receiver.file_multicast import DatagramFileMulticast, DatagramFileMulticastFragment
from src.datagrams.relay.group_management.group_msg_add_rem import DatagramGroupAddMember, DatagramGroupRemMember
from src.datagrams.relay.command.setup_onion_service import DatagramRelaySetupOnionService
from src.datagrams.relay.group_management.group_msg_flat import DatagramGroupInvite, DatagramGroupJoin, DatagramGroupExit

if TYPE_CHECKING:
    from src.common.launch_args import LaunchArgumentsTCB, LaunchArgumentsRelay
    from src.datagrams.datagram import Datagram
    JSONDict = dict[str, int|bool|str]


class Gateway:
    """\
    Gateway object is a wrapper for interfaces that connect
    Source/Destination Computer with the Networked Computer.
    """

    def __init__(self, launch_arguments: 'LaunchArgumentsTCB|LaunchArgumentsRelay') -> None:
        """Create a new Gateway object."""
        self.settings  = GatewaySettings(launch_arguments)

        self.tx_serial : O[serial.Serial]                         = None
        self.rx_serial : O[serial.Serial]                         = None
        self.rx_socket : O[multiprocessing.connection.Connection] = None
        self.tx_socket : O[multiprocessing.connection.Connection] = None

        self.test_run = launch_arguments.test_run

        # Initialize Reed-Solomon erasure code handler
        self.rs = RSCodec(2 * self.settings.session_serial_error_correction)

        # Set True when the serial interface is initially found so that
        # further interface searches know to announce disconnection.
        self.init_found = False

        if self.settings.local_testing_mode:
            if self.settings.program_id in [ProgramID.TX, ProgramID.NC]:
                self.client_establish_socket()
            if self.settings.program_id in [ProgramID.NC, ProgramID.RX]:
                self.server_establish_socket()
        elif not self.settings.qubes and not self.test_run:
            self.establish_serial()

    # ┌───────────────────────────────────────────────────────────────────────────┐
    # │                          Transmitter Program API                          │
    # └───────────────────────────────────────────────────────────────────────────┘

    def write_command(self, datagram: DatagramReceiverCommand, *, cache_packet: bool = False) -> int:
        """Write a command datagram to the serial interface."""
        if not isinstance(datagram, DatagramReceiverCommand):
            raise CriticalError(f'Invalid command datagram {type(datagram)}')

        return self.__write(datagram.to_txp_rep_bytes(), cache_packet=cache_packet)

    def write_message(self, datagram: DatagramOutgoingMessage, *, cache_packet: bool = False) -> int:
        """Write a command datagram to the serial interface."""
        if not isinstance(datagram, DatagramOutgoingMessage):
            raise CriticalError(f'Invalid message datagram {type(datagram)}')

        return self.__write(datagram.to_txp_rep_bytes(), cache_packet=cache_packet)

    def write(self, datagram: 'Datagram', *, cache_packet: bool = False) -> int:
        """Write datagram to the serial interface."""
        valid_datagrams = (
            # Pre-encrypted datagrams to user's Receiver Program
            DatagramReceiverLocalKey,

            # Pre-encrypted datagrams to contact's Receiver Program
            DatagramFileMulticast,

            # Datagrams to contact's Relay Program
            DatagramPublicKey,
            DatagramGroupInvite,
            DatagramGroupJoin,
            DatagramGroupExit,
            DatagramGroupAddMember,
            DatagramGroupRemMember,

            # Datagrams to user's Relay Program
            DatagramRelayChangeSetting,
            DatagramRelayCommandScreenClear,
            DatagramRelayCommandClearCiphertextCache,
            DatagramRelayCommandScreenReset,
            DatagramRelayCommandExitTFC,
            DatagramRelayCommandWipeSystem,
            DatagramRelaySetupOnionService,
            DatagramRelayAddContact,
            DatagramRelayRemoveContact,
            DatagramRelayDiffComparisonAccount,
            DatagramRelayDiffComparisonPublicKey)

        if not isinstance(datagram, valid_datagrams):
            raise CriticalError(f'Invalid datagram {type(datagram)}')

        return self.__write(datagram.to_txp_rep_bytes(), cache_packet=cache_packet)


    # ┌───────────────────────────────────────────────────────────────────────────┐
    # │                             Relay Program API                             │
    # └───────────────────────────────────────────────────────────────────────────┘

    def write_rxp_datagram(self,
                           datagram: (DatagramReceiverLocalKey
                                      | DatagramReceiverCommand
                                      | DatagramIncomingMessage
                                      | DatagramOutgoingMessage
                                      | DatagramFileMulticast
                                      | DatagramFileMulticastFragment),
                           *,
                           cache_packet: bool = False,
                           ) -> int:
        """Write a datagram to the serial interface."""
        valid_datagrams = (DatagramReceiverLocalKey,
                           DatagramReceiverCommand,
                           DatagramIncomingMessage,
                           DatagramOutgoingMessage,
                           DatagramFileMulticast,
                           DatagramFileMulticastFragment)

        if not isinstance(datagram, valid_datagrams):
            raise SoftError(f'Invalid datagram type {type(datagram)}')

        return self.__write(datagram.to_rep_rxp_bytes(), cache_packet=cache_packet)

    # ┌───────────────────────────────────────────────────────────────────────────┐
    # │                                 Read/Write                                │
    # └───────────────────────────────────────────────────────────────────────────┘

    def __write(self, orig_packet: bytes, *, cache_packet: bool = False) -> int:
        """Number a packet and output it via socket/serial interface.

        The packet counter is prepended before the Reed-Solomon / checksum
        framing is applied so resends reuse the exact same numbered payload.
        """
        packet_number = allocate_packet_number(self.settings.program_id)
        packet = make_numbered_packet(packet_number, orig_packet)

        if cache_packet:
            cache_outgoing_packet(self.settings.program_id, packet_number, packet)

        self.__send_numbered_packet(packet)
        return packet_number

    def resend_cached_packet(self, packet_number: int) -> None:
        """Resend a cached numbered packet without changing its counter."""
        packet = load_cached_outgoing_packet(self.settings.program_id, packet_number)
        self.__send_numbered_packet(packet)

    def send_numbered_packet(self, packet: bytes) -> None:
        """Send a pre-numbered packet without modifying its payload."""
        self.__send_numbered_packet(packet)

    def __send_numbered_packet(self, packet: bytes) -> None:
        """Add error correction data and output a numbered packet.

        After outputting the packet via serial, sleep long enough to
        trigger the Rx-side timeout timer, or if local testing is
        enabled, add slight delay to simulate that introduced by the
        serial interface.
        """
        packet_ec = self.add_error_correction(packet)

        if self.settings.local_testing_mode and self.tx_socket is not None:
            try:
                self.tx_socket.send(packet_ec)
                time.sleep(Delay.LOCAL_TESTING_PACKET_DELAY)
            except (BrokenPipeError, EOFError, OSError):
                self.tx_socket = None
                self.client_establish_socket()
                self.__send_numbered_packet(packet)

        elif self.settings.qubes:
            self.send_over_qrexec(packet_ec)

        elif self.tx_serial is not None:
            try:
                self.tx_serial.write(packet_ec)
                self.tx_serial.flush()
                time.sleep(self.settings.tx_inter_packet_delay)
            except SerialException:
                self.establish_serial()
                self.__send_numbered_packet(packet)


    def read(self) -> bytes:
        """Read data via socket/qr-exec/serial interface."""
        if self.settings.local_testing_mode: return self.read_socket()
        if self.settings.qubes:              return self.read_qubes_buffer_file()
        else:                                return self.read_serial()


    # ┌───────────────────────────────────────────────────────────────────────────┐
    # │                              Serial Interface                             │
    # └───────────────────────────────────────────────────────────────────────────┘

    def search_loop(self) -> str:
        """Loop that searches for USB-to-serial interface."""
        while True:
            for f in sorted(os.listdir('/dev/')):
                if f.startswith('ttyUSB'):
                    self.init_found = True
                    return f'/dev/{f}'

    def search_serial_interface(self) -> str:
        """Search for a serial interface."""
        if self.settings.session_usb_serial_adapter:
            message = 'Searching for USB-to-serial interface' if self.init_found else 'Serial adapter disconnected. Waiting for reconnection'
            with phase(message, done_message='Found', padding_top=1):
                interface = self.search_loop()
        else:
            if self.settings.built_in_serial_interface not in sorted(os.listdir('/dev/')):
                raise CriticalError(f'Error: /dev/{self.settings.built_in_serial_interface} was not found.')
            interface = f'/dev/{self.settings.built_in_serial_interface}'

        return interface

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
            self.tx_serial = self.rx_serial = serial.Serial(self.search_serial_interface(),
                                                            self.settings.session_serial_baudrate,
                                                            timeout=0)
        except SerialException:
            raise CriticalError('SerialException. Ensure $USER is in the dialout group by restarting this computer.')

    def read_serial(self) -> bytes:
        """Read packet from serial interface.

        Read 0..N bytes from serial interface, where N is the buffer
        size of the serial interface. Once `read_buffer` has data, and
        the interface hasn't returned data long enough for the timer to
        exceed the timeout value, return received data.
        """
        if self.rx_serial is None:
            raise CriticalError('Serial interface has not been initialized.')

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


    # ┌───────────────────────────────────────────────────────────────────────────┐
    # │                                   Qubes                                   │
    # └───────────────────────────────────────────────────────────────────────────┘

    def send_over_qrexec(self, packet: bytes) -> None:
        """Send packet content over the Qubes' qrexec RPC.

        More information at https://www.qubes-os.org/doc/qrexec/

        The packet is encoded with ASCII85 to ensure e.g. 0x0a
        byte is not interpreted as line feed by the RPC service.
        """
        target_vm   = QubesLiterals.QUBES_NET_VM_NAME    if self.settings.program_id == ProgramID.TX else QubesLiterals.QUBES_DST_VM_NAME
        dom0_policy = QubesLiterals.QUBES_SRC_NET_POLICY if self.settings.program_id == ProgramID.TX else QubesLiterals.QUBES_NET_DST_POLICY

        subprocess.Popen(['/usr/bin/qrexec-client-vm', target_vm, dom0_policy],
                         stdin  = subprocess.PIPE,
                         stdout = subprocess.DEVNULL,
                         stderr = subprocess.DEVNULL
                         ).communicate(base64.b85encode(packet))

    @staticmethod
    def read_qubes_buffer_file() -> bytes:
        """Read packet from oldest buffer file."""
        incoming_packet = QubesLiterals.QUBES_BUFFER_INCOMING_PACKET
        incoming_dir    = QubesLiterals.QUBES_BUFFER_INCOMING_DIR

        ensure_dir(incoming_dir)

        while not any([f for f in os.listdir(incoming_dir) if f.startswith(incoming_packet)]):
            time.sleep(0.001)

        packet, _ = read_oldest_buffer_file(incoming_dir, incoming_packet)

        try:
            packet = base64.b85decode(packet)
        except ValueError:
            raise SoftError('Error: Received packet had invalid Base85 encoding.')

        return packet


    # ┌───────────────────────────────────────────────────────────────────────────┐
    # │                               Local Testing                               │
    # └───────────────────────────────────────────────────────────────────────────┘

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
        listener: O[multiprocessing.connection.Listener] = None
        try:
            socket_number  = (SocketNumber.RP_LISTEN if self.settings.program_id == ProgramID.NC else SocketNumber.DST_LISTEN)
            listener       = multiprocessing.connection.Listener((NetworkLiterals.LOCALHOST.value, socket_number))
            self.rx_socket = listener.accept()
        except KeyboardInterrupt:
            graceful_exit()
        finally:
            if listener is not None:
                listener.close()

    def client_establish_socket(self) -> None:
        """Initialize the transmitter (IPC client)."""
        try:
            target = ProgramName.RECEIVER.value if self.settings.program_id == ProgramID.NC else ProgramName.RELAY.value
            phase(f'Connecting to {target}')
            while True:
                try:
                    if self.settings.program_id == ProgramID.TX:
                        socket_number = SocketNumber.SRC_DD_LISTEN if self.settings.data_diode_sockets else SocketNumber.RP_LISTEN
                    else:
                        socket_number = SocketNumber.DST_DD_LISTEN if self.settings.data_diode_sockets else SocketNumber.DST_LISTEN

                    try:
                        self.tx_socket = multiprocessing.connection.Client((NetworkLiterals.LOCALHOST.value, socket_number))
                    except ConnectionRefusedError:
                        time.sleep(0.1)
                        continue

                    phase(StatusMsg.DONE.value)
                    break

                except socket.error:
                    time.sleep(0.1)

        except KeyboardInterrupt:
            graceful_exit()

    def read_socket(self) -> bytes:
        """Read packet from socket interface."""
        while True:
            if self.rx_socket is None:
                raise CriticalError('Socket interface has not been initialized.')

            rx_socket = self.rx_socket

            try:
                packet = rx_socket.recv()  # type: bytes
                return packet
            except KeyboardInterrupt:
                pass
            except EOFError:
                self.rx_socket = None
                self.server_establish_socket()
            except OSError:
                self.rx_socket = None
                self.server_establish_socket()


    # ┌───────────────────────────────────────────────────────────────────────────┐
    # │                         Error Correction/Detection                        │
    # └───────────────────────────────────────────────────────────────────────────┘

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

        If Qubes is used, Reed-Solomon is not used as it only slows down data transfer.
        """
        if self.settings.session_serial_error_correction and not self.settings.qubes:
            return bytes(self.rs.encode(packet))
        else:
            packet += hashlib.blake2b(packet, digest_size=FieldLength.PACKET_CHECKSUM).digest()
        return packet

    def detect_errors(self, packet: bytes) -> bytes:
        """Handle received packet error detection and/or correction."""
        if self.settings.qubes:
            try:
                packet = base64.b85decode(packet)
            except ValueError:
                raise SoftError('Error: Received packet had invalid Base85 encoding.')

        if self.settings.session_serial_error_correction and not self.settings.qubes:
            try:
                decoded_packet, _ = self.rs.decode(packet)
                return bytes(decoded_packet)
            except ReedSolomonError:
                raise SoftError('Error: Reed-Solomon failed to correct errors in the received packet.', bold=True)
        else:
            packet, checksum = separate_trailer(packet, FieldLength.PACKET_CHECKSUM)

            if hashlib.blake2b(packet, digest_size=FieldLength.PACKET_CHECKSUM).digest() != checksum:
                raise SoftError('Warning! Received packet had an invalid checksum.', bold=True)
            return packet
