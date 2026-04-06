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

import os
import random
import shlex
import shutil
import socket
import tempfile
import time

from datetime import timedelta
from typing import Any, Optional as O, TYPE_CHECKING

# noinspection PyPackageRequirements
import stem.control
# noinspection PyPackageRequirements
import stem.process
# noinspection PyPackageRequirements
from stem.control import Controller

from src.common.crypto.keys.onion_service_keys import OnionServicePrivateKey
from src.common.entities.confirm_code import ConfirmationCode
from src.common.crypto.keys.symmetric_key import BufferKey
from src.common.exceptions import CriticalError
from src.common.process import platform_is_tails
from src.common.types_custom import BoolTestRun, IntPortNumberFlask, IntPortNumberTor, StrTorPathToBinary, \
    StrTorPathToControlSocketFile, BytesActiveSetup
from src.ui.common.output.print_message import print_message
from src.ui.common.output.print_log_message import print_log_message
from src.common.statics import PortNumber

if TYPE_CHECKING:
    from src.common.queues import RelayQueue
    from src.datagrams.relay.command.setup_onion_service import DatagramRelaySetupOnionService


class Tor:
    """Tor class manages the starting and stopping of Tor client."""

    def __init__(self) -> None:
        self.tor_process        = None  # type: O[Any]
        self.controller         = None  # type: O[Controller]
        self.tor_data_directory = None  # type: O[tempfile.TemporaryDirectory[str]]

    def connect(self) -> IntPortNumberTor:
        """Launch Tor as a subprocess.

        If TFC is running on top of Tails, do not launch a separate
        instance of Tor.
        """
        port_number = self.get_available_port_number()

        if platform_is_tails():
            self.controller = Controller.from_port(port=PortNumber.TOR_CONTROL_PORT)

            self.controller.authenticate()

            return port_number

        path_to_tor             = self.get_tor_path()
        self.tor_data_directory = tempfile.TemporaryDirectory()

        path_to_control_socket_file = StrTorPathToControlSocketFile(os.path.join(self.tor_data_directory.name, 'control_socket'))

        self.launch_tor_process(port_number, path_to_control_socket_file, self.tor_data_directory, path_to_tor)

        start_ts        = time.monotonic()
        self.controller = stem.control.Controller.from_socket_file(path=path_to_control_socket_file)

        self.controller.authenticate()

        while True:
            time.sleep(0.1)
            try:
                response = self.controller.get_info('status/bootstrap-phase')
            except stem.SocketClosed:
                raise CriticalError('Tor socket closed.')

            res_parts = shlex.split(response)
            summary   = res_parts[4].split('=')[1]

            if summary == 'Done':
                tor_version = self.controller.get_version().version_str.split(' (')[0]
                print_log_message(f'Setup  70% - Tor {tor_version} is now running', bold=True)
                break

            if time.monotonic() - start_ts > 15:
                start_ts        = time.monotonic()
                self.controller = stem.control.Controller.from_socket_file(path=path_to_control_socket_file)
                self.controller.authenticate()

        return port_number

    def launch_tor_process(self,
                           port                        : IntPortNumberTor,
                           path_to_control_socket_file : StrTorPathToControlSocketFile,
                           tor_data_directory          : Any,
                           path_to_tor                 : StrTorPathToBinary
                           ) -> None:
        """Launch Tor process."""
        retry_for   = timedelta(minutes=2)
        retry_delay = 0.25
        start_ts    = time.monotonic()

        while True:
            try:
                self.tor_process = stem.process.launch_tor_with_config(
                    config={'DataDirectory'   : tor_data_directory.name,
                            'SocksPort'       : str(port),
                            'ControlSocket'   : path_to_control_socket_file,
                            'AvoidDiskWrites' : '1',
                            'Log'             : 'notice stdout',
                            'GeoIPFile'       : '/usr/share/tor/geoip',
                            'GeoIPv6File'     : '/usr/share/tor/geoip6'},
                    tor_cmd=path_to_tor)
                break

            except OSError as exc:
                if time.monotonic() - start_ts > retry_for.total_seconds():
                    raise CriticalError('Failed to launch Tor after repeated retries.') from exc

                time.sleep(retry_delay)
                retry_delay = min(retry_delay * 2, 5.0)

    def stop(self) -> None:
        """Stop the Tor subprocess."""
        if self.tor_process is not None:
            self.tor_process.terminate()
            time.sleep(0.1)
            if self.tor_process.poll() is None:
                self.tor_process.kill()
        if self.tor_data_directory is not None:
            self.tor_data_directory.cleanup()
            self.tor_data_directory = None

    @staticmethod
    def get_tor_path() -> StrTorPathToBinary:
        """Return the installed Tor executable path or exit."""
        # noinspection PyDeprecation
        tor_cmd = shutil.which('tor')
        if tor_cmd is None:
            raise CriticalError('Could not find Tor. Is it installed?')
        return StrTorPathToBinary(tor_cmd)

    @staticmethod
    def get_available_port_number() -> IntPortNumberTor:
        """Find a random available port number within the given range."""
        PORT_NUMBER_MIN = 1000
        PORT_NUMBER_MAX = 65535

        rng = random.SystemRandom()

        with socket.socket() as temp_sock:
            while True:
                try:
                    temp_sock.bind(('127.0.0.1', rng.randint(PORT_NUMBER_MIN,
                                                             PORT_NUMBER_MAX)))
                    break
                except OSError:
                    pass
            _ip_addr, port_number = temp_sock.getsockname()  # type: str, int

        if platform_is_tails():
            from src.common.statics import PortNumber
            return IntPortNumberTor(PortNumber.TOR_SOCKS_PORT)

        return IntPortNumberTor(port_number)

    @staticmethod
    def get_available_local_port() -> IntPortNumberFlask:
        """Return an available local TCP port for the relay's Flask server."""
        with socket.socket() as temp_sock:
            temp_sock.bind(('127.0.0.1', 0))
            return IntPortNumberFlask(temp_sock.getsockname()[1])


def drain_relay_status_messages(queues : 'RelayQueue') -> list[str]:
    """Drain queued Relay status messages for bundled printing."""
    messages = []

    while queues.relay_status_messages.qsize() > 0:
        messages.append(queues.relay_status_messages.get())

    return messages


def print_relay_status_messages(messages : list[str]) -> None:
    """Print Relay status messages as one centered block."""
    if messages:
        print_message(messages, padding_top=1, padding_bottom=1)


def process_onion_service(queues     : 'RelayQueue',
                          test_run   : BoolTestRun,
                          flask_port : IntPortNumberFlask
                          ) -> None:
    """Manage the Tor Onion Service and control Tor via stem."""
    print_log_message('Setup   0% - Waiting for Onion Service configuration...', bold=True)

    active_setup_bytes      = BytesActiveSetup(b'')
    startup_status_messages = drain_relay_status_messages(queues)

    queue = queues.from_rec_to_onion_service_process_onion_setup_data

    if test_run:
        private_key = OnionServicePrivateKey()
        buffer_key  = BufferKey()
        c_code      = ConfirmationCode(b'\x00')
    else:
        while queue.qsize() == 0:
            startup_status_messages.extend(drain_relay_status_messages(queues))
            time.sleep(0.1)
        setup_datagram     = queue.get()
        private_key        = setup_datagram.onion_service_private_key
        buffer_key         = setup_datagram.buffer_key
        c_code             = setup_datagram.confirmation_code
        active_setup_bytes = setup_datagram.to_txp_rep_bytes()

    try:
        startup_status_messages.extend(drain_relay_status_messages(queues))
        print_log_message('Setup  10% - Launching Tor...', bold=True)
        tor      = Tor()
        tor_port = tor.connect()
    except (EOFError, KeyboardInterrupt):
        return

    if tor.controller is None:
        raise CriticalError('No Tor controller')

    try:
        startup_status_messages.extend(drain_relay_status_messages(queues))
        print_log_message('Setup  75% - Launching Onion Service...', bold=True)

        response = tor.controller.create_ephemeral_hidden_service(ports             = {80: flask_port},
                                                                  key_type          = 'ED25519-V3',
                                                                  key_content       = private_key.stem_compatible_expanded_private_key,
                                                                  await_publication = True)
        print_log_message('Setup 100% - Onion Service is now published.', bold=True)
        startup_status_messages.extend(drain_relay_status_messages(queues))
        print_relay_status_messages(startup_status_messages)

        print_message(['Your TFC account is:',
                       private_key.onion_addr, '',
                 f'Onion Service confirmation code (to Transmitter): {c_code.hr_code}'], box=True)

        # Allow the client to start looking for contacts at this point.
        queues.from_tor_to_sch_client_tor_data    .put((tor_port, private_key.onion_pub_key))
        queues.from_rec_to_diff_comp_public_keys.put(private_key.onion_pub_key)

        # Pass buffer key to related processes
        queues.from_txp_to_sxy_buffer_key.put(buffer_key)
        queues.from_txp_to_srv_buffer_key.put(buffer_key)
        queues.from_txp_to_cli_buffer_key.put(buffer_key)

    except (KeyboardInterrupt, stem.SocketClosed):
        tor.stop()
        return

    monitor_queues(tor, response, queues, active_setup_bytes)


def is_duplicate_setup_datagram(active_setup_bytes : BytesActiveSetup,
                                setup_datagram     : 'DatagramRelaySetupOnionService'
                                ) -> bool:
    """Return True when setup datagram matches the active Onion Service configuration."""
    return setup_datagram.to_txp_rep_bytes() == active_setup_bytes


def monitor_queues(tor                : Tor,
                   response           : Any,
                   queues             : 'RelayQueue',
                   active_setup_bytes : BytesActiveSetup
                   ) -> None:
    """Monitor queues for incoming packets."""
    queue = queues.from_rec_to_onion_service_process_onion_setup_data

    while True:
        try:
            time.sleep(0.1)

            if queue.qsize() > 0:
                setup_datagram = queue.get()

                if is_duplicate_setup_datagram(active_setup_bytes, setup_datagram):
                    continue

                active_setup_bytes = setup_datagram.to_txp_rep_bytes()
                c_code = setup_datagram.confirmation_code

                print_message(['Onion Service is already running.', '',
                         f'Onion Service confirmation code (to Transmitter): {c_code.hr_code}'], box=True)

            print_relay_status_messages(drain_relay_status_messages(queues))

            if queues.close_onion_service_signal.qsize() > 0:
                command = queues.close_onion_service_signal.get()
                if tor.controller is not None:
                    tor.controller.remove_hidden_service(response.service_id)
                if not platform_is_tails():
                    tor.stop()
                queues.to_process_monitor.put(command)
                time.sleep(5)
                break

        except (EOFError, KeyboardInterrupt):
            pass
        except stem.SocketClosed:
            if tor.controller is not None:
                tor.controller.remove_hidden_service(response.service_id)
                tor.stop()
            break
