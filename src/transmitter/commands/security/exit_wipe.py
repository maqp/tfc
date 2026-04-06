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

from typing import TYPE_CHECKING

from src.common.entities.serialized_command import SerializedCommand
from src.common.exceptions import SoftError
from src.common.statics import RxCommand, Delay, MonitorQueueSignal
from src.datagrams.relay.command.command_security import DatagramRelayCommandExitTFC, DatagramRelayCommandWipeSystem
from src.relay.commands.security.security import race_condition_delay
from src.transmitter.queue_packet.queue_packet import queue_command
from src.ui.common.input.get_yes import get_yes
from src.ui.common.output.vt100_utils import clear_screen, reset_terminal

if TYPE_CHECKING:
    from src.common.gateway import Gateway
    from src.common.queues import TxQueue
    from src.database.db_settings import Settings


def exit_tfc(settings : 'Settings',
             queues   : 'TxQueue',
             gateway  : 'Gateway'
             ) -> None:
    """Exit TFC on all three computers.

    The function drops queued outbound packets, queues the Receiver exit
    command, and then queues the unencrypted Relay exit command. The
    sender process forwards the local exit signal only after the Relay
    command has been sent.

    During local testing, this function adds some delays to prevent TFC
    programs from dying when sockets disconnect.
    """
    # Drop queued outbound packets so exit is the next command sent.
    for queue in (queues.message_packet,
                  queues.command_packet,
                  queues.tm_message_packet,
                  queues.tm_file_packet,
                  queues.tm_command_packet,
                  queues.relay_packet):
        while queue.qsize():
            queue.get()

    queue_command(settings, queues, SerializedCommand(RxCommand.EXIT_PROGRAM))

    if not settings.traffic_masking:
        if settings.local_testing_mode:
            time.sleep(Delay.LOCAL_TESTING_PACKET_DELAY.value)
            time.sleep(gateway.settings.data_diode_sockets * 1.5)
        else:
            race_condition_delay(gateway)

    queues.relay_packet.put( DatagramRelayCommandExitTFC() )
    queues.to_monitor_proxy.put(MonitorQueueSignal.EXIT)


def wipe(settings : 'Settings',
         queues   : 'TxQueue',
         gateway  : 'Gateway'
         ) -> None:
    """\
    Reset terminals, wipe all TFC user data from Source, Networked, and
    Destination Computer, and power all three systems off.

    The purpose of the wipe command is to provide additional protection
    against physical attackers, e.g. in situation where a dissident gets
    a knock on their door. By overwriting and deleting user data the
    program prevents access to encrypted databases. Additional security
    should be sought with full disk encryption (FDE).

    Unfortunately, no effective tool for overwriting RAM currently exists.
    However, as long as Source and Destination Computers use FDE and
    DDR3 memory, recovery of sensitive data becomes impossible very fast:
        https://www1.cs.fau.de/filepool/projects/coldboot/fares_coldboot.pdf
    """
    if not get_yes('Wipe all user data and power off systems?', abort=False):
        raise SoftError('Wipe command aborted.', clear_before=True)

    clear_screen()

    # Drop queued outbound packets so wipe is the next command sent.
    for queue in (queues.message_packet,
                  queues.command_packet,
                  queues.tm_message_packet,
                  queues.tm_file_packet,
                  queues.tm_command_packet,
                  queues.relay_packet):
        while queue.qsize():
            queue.get()

    queue_command(settings, queues, SerializedCommand(RxCommand.WIPE_SYSTEM))

    if not settings.traffic_masking:
        if settings.local_testing_mode:
            time.sleep(0.8)
            time.sleep(gateway.settings.data_diode_sockets * 2.2)
        else:
            race_condition_delay(gateway)

    queues.relay_packet.put( DatagramRelayCommandWipeSystem() )
    queues.to_monitor_proxy.put(MonitorQueueSignal.WIPE)

    reset_terminal()
