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

import base64
import hashlib
import os
import random
import shlex
import socket
import tempfile
import time

from multiprocessing import Queue
from typing          import Any, Dict

import nacl.signing

import stem.control
import stem.process

from src.common.encoding   import pub_key_to_onion_address
from src.common.exceptions import CriticalError
from src.common.output     import m_print, rp_print
from src.common.statics    import *


def get_available_port(min_port: int, max_port: int) -> str:
    """Find a random available port within the given range."""
    with socket.socket() as temp_sock:
        while True:
            try:
                temp_sock.bind(('127.0.0.1', random.randint(min_port, max_port)))
                break
            except OSError:
                pass
        _, port = temp_sock.getsockname()  # type: Any, str
    return port


class Tor(object):
    """Tor class manages the starting and stopping of Tor client."""

    def __init__(self) -> None:
        self.tor_process = None  # type: Any
        self.controller  = None  # type: Any

    def connect(self, port: str) -> None:
        """Launch Tor as a subprocess."""
        tor_data_directory = tempfile.TemporaryDirectory()
        tor_control_socket = os.path.join(tor_data_directory.name, 'control_socket')

        if not os.path.isfile('/usr/bin/tor'):
            raise CriticalError("Check that Tor is installed.")

        while True:
            try:
                self.tor_process = stem.process.launch_tor_with_config(
                    config={'DataDirectory':   tor_data_directory.name,
                            'SocksPort':       str(port),
                            'ControlSocket':   tor_control_socket,
                            'AvoidDiskWrites': '1',
                            'Log':             'notice stdout',
                            'GeoIPFile':       '/usr/share/tor/geoip',
                            'GeoIPv6File ':    '/usr/share/tor/geoip6'},
                    tor_cmd='/usr/bin/tor')
                break

            except OSError:
                pass  # Tor timed out. Try again.

        start_ts = time.monotonic()
        self.controller = stem.control.Controller.from_socket_file(path=tor_control_socket)
        self.controller.authenticate()

        while True:
            time.sleep(0.1)

            try:
                response = self.controller.get_info("status/bootstrap-phase")
            except stem.SocketClosed:
                raise CriticalError("Tor socket closed.")

            res_parts = shlex.split(response)
            summary   = res_parts[4].split('=')[1]

            if summary == 'Done':
                tor_version = self.controller.get_version().version_str.split(' (')[0]
                rp_print(f"Setup  70% - Tor {tor_version} is now running", bold=True)
                break

            if time.monotonic() - start_ts > 15:
                start_ts = time.monotonic()
                self.controller = stem.control.Controller.from_socket_file(path=tor_control_socket)
                self.controller.authenticate()

    def stop(self) -> None:
        """Stop the Tor subprocess."""
        if self.tor_process:
            self.tor_process.terminate()
            time.sleep(0.1)
            if not self.tor_process.poll():
                self.tor_process.kill()


def stem_compatible_ed25519_key_from_private_key(private_key: bytes) -> str:
    """Tor's custom encoding format for v3 Onion Service private keys.

    This code is based on Tor's testing code at
        https://github.com/torproject/tor/blob/8e84968ffbf6d284e8a877ddcde6ded40b3f5681/src/test/ed25519_exts_ref.py#L48
    """
    b = 256

    def bit(h: bytes, i: int) -> int:
        """\
        Output (i % 8 + 1) right-most bit of (i // 8) right-most byte
        of the digest.
        """
        return (h[i // 8] >> (i % 8)) & 1

    def encode_int(y: int) -> bytes:
        """Encode integer to 32-byte bytestring (little-endian format)."""
        bits = [(y >> i) & 1 for i in range(b)]
        return b''.join([bytes([(sum([bits[i * 8 + j] << j for j in range(8)]))]) for i in range(b // 8)])

    def expand_private_key(sk: bytes) -> bytes:
        """Expand private key to base64 blob."""
        h = hashlib.sha512(sk).digest()
        a = 2 ** (b - 2) + sum(2 ** i * bit(h, i) for i in range(3, b - 2))
        k = b''.join([bytes([h[i]]) for i in range(b // 8, b // 4)])

        return encode_int(a) + k

    if len(private_key) != ONION_SERVICE_PRIVATE_KEY_LENGTH:
        raise CriticalError("Onion Service private key had invalid length.")

    expanded_private_key = expand_private_key(private_key)

    return base64.b64encode(expanded_private_key).decode()


def onion_service(queues: Dict[bytes, 'Queue']) -> None:
    """Manage the Tor Onion Service and control Tor via stem."""
    rp_print("Setup   0% - Waiting for Onion Service configuration...", bold=True)
    while queues[ONION_KEY_QUEUE].qsize() == 0:
        time.sleep(0.1)

    private_key, c_code = queues[ONION_KEY_QUEUE].get()  # type: bytes, bytes
    public_key_user     = bytes(nacl.signing.SigningKey(seed=private_key).verify_key)
    onion_addr_user     = pub_key_to_onion_address(public_key_user)

    try:
        rp_print("Setup  10% - Launching Tor...", bold=True)
        tor_port = get_available_port(1000, 65535)
        tor      = Tor()
        tor.connect(tor_port)
    except (EOFError, KeyboardInterrupt):
        return

    try:
        rp_print("Setup  75% - Launching Onion Service...", bold=True)
        key_data = stem_compatible_ed25519_key_from_private_key(private_key)
        response = tor.controller.create_ephemeral_hidden_service(ports={80: 5000},
                                                                  key_type='ED25519-V3',
                                                                  key_content=key_data,
                                                                  await_publication=True)
        rp_print("Setup 100% - Onion Service is now published.", bold=True)

        m_print(["Your TFC account is:",
                 onion_addr_user, '',
                 f"Onion Service confirmation code (to Transmitter): {c_code.hex()}"], box=True)

        # Allow the client to start looking for contacts at this point.
        queues[TOR_DATA_QUEUE].put((tor_port, onion_addr_user))

    except (KeyboardInterrupt, stem.SocketClosed):
        tor.stop()
        return

    while True:
        try:
            time.sleep(0.1)

            if queues[ONION_KEY_QUEUE].qsize() > 0:
                _, c_code = queues[ONION_KEY_QUEUE].get()

                m_print(["Onion Service is already running.", '',
                         f"Onion Service confirmation code (to Transmitter): {c_code.hex()}"], box=True)

            if queues[ONION_CLOSE_QUEUE].qsize() > 0:
                command = queues[ONION_CLOSE_QUEUE].get()
                queues[EXIT_QUEUE].put(command)
                tor.controller.remove_hidden_service(response.service_id)
                tor.stop()
                break

        except (EOFError, KeyboardInterrupt):
            pass
        except stem.SocketClosed:
            tor.controller.remove_hidden_service(response.service_id)
            tor.stop()
            break
