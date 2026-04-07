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

import time

from multiprocessing import Queue
from typing import TYPE_CHECKING

from src.common.entities.assembly_packet import CommandAssemblyPacket, MessageAssemblyPacket
from src.common.exceptions import CriticalError
from src.common.crypto.keys.onion_service_keys import OnionPublicKeyContact
from src.common.types_custom import IntAutoreplayTimes, BoolCachePacket
from src.datagrams.receiver.command import DatagramReceiverCommand
from src.datagrams.receiver.message import DatagramOutgoingMessage

if TYPE_CHECKING:
    from src.common.gateway import Gateway
    from src.common.queues import TxQueue
    from src.common.types_compound import LogQueueData
    from src.common.types_custom import BoolLogAsPlaceHolder, BoolLogMessages
    from src.database.db_keys import KeyStore
    from src.database.db_local_key import LocalKeyDB


"""
These two functions are critical for Transmitter Program's security.

They need to ensure only encrypted packets are output through the
gateway, and that symmetric keys are never exposed.

The security is handled by following components:
    
    1. We validate the type of the object being encrypted with instance checks.
    2. We use LocalKeyDB and KeyStore objects to encapsulate the encryption keys
       inside name mangled variables, and use the database objects' cryptographic
       services to encrypt the messages and commands. This prevents the functions 
       below from accessing the keys.
    3. We separate sending commands and messages to separate functions to 
       control which services are available in the send-phase function.
    4. In Gateway object, we use type checks again to only allow export of the 
       DatagramReceiverCommand and DatagramOutgoingMessage objects through 
       dedicated methods gateway.write_command and gateway.write_message, that
       are only used here.
"""

def send_command(local_key_db     : 'LocalKeyDB',
                 gateway          : 'Gateway',
                 assembly_packet  : 'CommandAssemblyPacket',
                 autoreplay_times : IntAutoreplayTimes = IntAutoreplayTimes(1),
                 cache_packet     : BoolCachePacket    = BoolCachePacket(False),
                 ) -> None:
    """Encrypt and send command assembly packet."""
    if not isinstance(assembly_packet, CommandAssemblyPacket):
        raise CriticalError('Received packet was not CommandAssemblyPacket')

    command_header_ct, command_payload_ct = local_key_db.encrypt_and_sign_command(assembly_packet)
    command_datagram = DatagramReceiverCommand(command_header_ct, command_payload_ct)
    cache_packet     = BoolCachePacket(cache_packet or autoreplay_times > 1)
    packet_number    = gateway.write_command(command_datagram, cache_packet=cache_packet)

    for _ in range(max(0, autoreplay_times - 1)):
        gateway.resend_cached_packet(packet_number)


def send_message(key_store        : 'KeyStore',
                 gateway          : 'Gateway',
                 log_queue        : 'Queue[LogQueueData]',
                 assembly_packet  : 'MessageAssemblyPacket',
                 onion_pub_key    : 'OnionPublicKeyContact',
                 log_messages     : 'BoolLogMessages',
                 log_as_ph        : 'BoolLogAsPlaceHolder',
                 autoreplay_times : IntAutoreplayTimes = IntAutoreplayTimes(1),
                 cache_packet     : BoolCachePacket    = BoolCachePacket(False),
                 ) -> None:
    """Encrypt and send assembly packet."""
    if not isinstance(assembly_packet, MessageAssemblyPacket):
        raise CriticalError('Received assembly packet was not MessageAssemblyPacket')
    if not isinstance(onion_pub_key, OnionPublicKeyContact):
        raise CriticalError('Received onion_pub_key was not OnionPublicKeyContact')

    message_header_ct, message_payload_ct = key_store.encrypt_and_sign_message(assembly_packet, onion_pub_key)
    message_datagram = DatagramOutgoingMessage(onion_pub_key, message_header_ct, message_payload_ct)
    cache_packet     = BoolCachePacket(cache_packet or autoreplay_times > 1)
    packet_number    = gateway.write_message(message_datagram, cache_packet=cache_packet)

    for _ in range(max(0, autoreplay_times - 1)):
        gateway.resend_cached_packet(packet_number)

    log_queue.put((onion_pub_key, assembly_packet, log_messages, log_as_ph))


def monitor_proxy(queues: 'TxQueue', gateway: 'Gateway') -> None:
    """Process monitor proxy.

    This function ensures sender process has adequate time to deliver
    the exit / wipe signal to Relay/Receiver Program, before Transmitter
    Program itself runs the command in process monitor.
    """
    mp_queue = queues.to_monitor_proxy

    if mp_queue.qsize():
        monitor_signal = mp_queue.get()

        time.sleep(gateway.settings.local_testing_mode * 0.1)
        time.sleep(gateway.settings.data_diode_sockets * 1.5)

        queues.to_process_monitor.put(monitor_signal)
