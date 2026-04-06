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

from src.common.entities.assembly_packet import CommandAssemblyPacket, MessageAssemblyPacket
from src.common.exceptions import ignored
from src.common.statics import AsmPacket, TrafficMaskingLiterals, CryptoVarLength
from src.common.types_custom import BoolLogAsPlaceHolder, BoolLogMessages, BoolUnitTesting

if TYPE_CHECKING:
    from src.common.queues import TxQueue


def process_noise_message_generator(queues    : 'TxQueue',
                                    unit_test : BoolUnitTesting = BoolUnitTesting(False)
                                    ) -> None:
    """Process that generates noise messages for traffic masking.

    This process ensures the noise packet queue always has
    noise assembly packets available.
    """
    log_messages = BoolLogMessages(True)    # This setting is ignored: settings.log_file_masking controls logging of noise packets.
    log_as_ph    = BoolLogAsPlaceHolder(True)

    header                = AsmPacket.P_N_HEADER
    noise_assembly_packet = MessageAssemblyPacket(header + bytes(CryptoVarLength.PADDING.value))

    # Noise packet
    queue   = queues.tm_noise_packet
    content = (noise_assembly_packet, log_messages, log_as_ph)

    logged_fill = False
    while True:
        with ignored(EOFError, KeyboardInterrupt):
            while queue.qsize() < TrafficMaskingLiterals.NOISE_PACKET_BUFFER.value:
                if not logged_fill:
                    logged_fill = True
                queue.put(content)
            time.sleep(0.1)

            if unit_test:
                break


def process_noise_command_generator(queues    : 'TxQueue',
                                    unit_test : BoolUnitTesting = BoolUnitTesting(False)
                                    ) -> None:
    """Process that generates noise commands for traffic masking.

    This process ensures noise command queue
    always has ~100 noise assembly packets available.
    """
    noise_assembly_packet = CommandAssemblyPacket(AsmPacket.C_N_HEADER + bytes(CryptoVarLength.PADDING.value))

    queue = queues.tm_noise_command

    logged_fill = False
    while True:
        with ignored(EOFError, KeyboardInterrupt):
            while queue.qsize() < TrafficMaskingLiterals.NOISE_PACKET_BUFFER.value:
                if not logged_fill:
                    logged_fill = True
                queue.put(noise_assembly_packet)
            time.sleep(0.1)

            if unit_test:
                break
