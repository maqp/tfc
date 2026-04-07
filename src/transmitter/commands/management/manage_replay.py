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

from typing import TYPE_CHECKING

from src.common.entities.serialized_command import SerializedCommand
from src.common.exceptions import SoftError, raise_if_traffic_masking
from src.common.replay import clear_cached_send_data
from src.common.statics import RxCommand
from src.datagrams.relay.command.command_security import DatagramRelayCommandClearCiphertextCache
from src.datagrams.relay.command.replay import DatagramRelayResendFile, DatagramRelayResendPackets
from src.transmitter.queue_packet.queue_packet import queue_command
from src.ui.common.output.print_message import print_message

if TYPE_CHECKING:
    from src.common.queues import TxQueue
    from src.database.db_settings import Settings
    from src.ui.transmitter.user_input import UserInput


def _parse_packet_numbers(user_input: 'UserInput') -> list[int]:
    try:
        packet_numbers = [int(field) for field in user_input.plaintext.split()[1:]]
    except ValueError:
        raise SoftError('Error: Packet numbers must be integers.', clear_before=True)

    if not packet_numbers or any(number <= 0 for number in packet_numbers):
        raise SoftError('Error: Packet numbers must be positive integers.', clear_before=True)

    return packet_numbers


def resend_from_txp_to_rep(settings   : 'Settings',
                           queues     : 'TxQueue',
                           user_input : 'UserInput'
                           ) -> None:
    """Queue a request for the local sender process to resend cached packets."""
    raise_if_traffic_masking(settings)
    queues.resend_packet_numbers.put(_parse_packet_numbers(user_input))


def resend_from_rep_to_rxp(settings   : 'Settings',
                           queues     : 'TxQueue',
                           user_input : 'UserInput'
                           ) -> None:
    """Queue a request for Relay to resend cached packets to Receiver."""
    raise_if_traffic_masking(settings)
    queues.relay_packet.put(DatagramRelayResendPackets(_parse_packet_numbers(user_input)))


def resend_received_file(settings   : 'Settings',
                         queues     : 'TxQueue',
                         user_input : 'UserInput'
                         ) -> None:
    """Queue a request for Relay to resend a cached file to Receiver."""
    raise_if_traffic_masking(settings)

    try:
        file_id = user_input.plaintext.split()[1]
    except IndexError:
        raise SoftError('Error: No cached file id specified.', clear_before=True)

    if not file_id.isalpha() or not file_id.islower():
        raise SoftError('Error: Cached file id must be lowercase letters.', clear_before=True)

    queues.relay_packet.put(DatagramRelayResendFile(file_id))


def clear_ciphertext_caches(settings : 'Settings',
                            queues   : 'TxQueue'
                            ) -> None:
    """Clear cached replay ciphertext data on Transmitter, Relay, and Receiver."""
    raise_if_traffic_masking(settings)

    cleared_packets = clear_cached_send_data(settings.program_id)
    queue_command(settings, queues, SerializedCommand(RxCommand.CLEAR_CT_CACHE))
    queues.relay_packet.put(DatagramRelayCommandClearCiphertextCache())

    print_message(f"Cleared {cleared_packets} cached replay packet{'s' if cleared_packets != 1 else ''} on"
                  f" Transmitter and queued cache clears for Relay and Receiver.",
                  padding_top=1, padding_bottom=1,)
