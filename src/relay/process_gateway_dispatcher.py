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

from collections import deque
from typing import Optional as O, TYPE_CHECKING

from src.common.crypto.algorithms.blake2b import blake2b
from src.common.replay import cache_incoming_packet, format_missing_packet_numbers, make_numbered_packet, split_numbered_packet
from src.common.exceptions import SoftError, ValidationError, ignored
from src.common.statics import FieldLength, DatagramHeader, ReplayLimits, TFCSettingKey
from src.common.types_custom import BoolRequireResends, BoolUnitTesting, BytesRelayCommand
from src.ui.common.output.print_message import print_message
from src.common.utils.strings import separate_header
from src.datagrams.receiver.command import DatagramReceiverCommand
from src.datagrams.receiver.local_key import DatagramReceiverLocalKey
from src.datagrams.receiver.message import DatagramOutgoingMessage
from src.datagrams.receiver.public_key import DatagramPublicKey
from src.datagrams.receiver.file_multicast import DatagramFileMulticast
from src.datagrams.relay.group_management.group_msg_add_rem import DatagramGroupAddMember, DatagramGroupRemMember
from src.datagrams.relay.group_management.group_msg_flat import DatagramGroupInvite, DatagramGroupJoin, \
    DatagramGroupExit
from src.relay.commands.relay_command_dispatcher import dispatch_relay_command

if TYPE_CHECKING:
    from src.common.gateway import Gateway
    from src.common.queues import RelayQueue


def process_gateway_dispatcher(queues       : 'RelayQueue',
                               gateway      : 'Gateway',
                               unit_testing : BoolUnitTesting = BoolUnitTesting(False)
                               ) -> None:
    """\
    Process reads packets from gateway.py's `process_gateway_reader`.

    Read packets are error-detected/corrected and delivered to the
    queues that can be processed in the order of priority.
    """
    gateway_queue = queues.from_gwr_to_dispatcher_datagrams

    recent_packet_hashes   : deque[bytes]       = deque(maxlen=ReplayLimits.HASH_WINDOW_SIZE.value)
    expected_packet_number : O[int]             = None
    missing_packet_numbers : set[int]           = set()
    require_resends        : BoolRequireResends = BoolRequireResends(False)
    autoreplay_loop        : bool               = False

    while True:
        with ignored(EOFError, KeyboardInterrupt):
            while queues.replay_cache_clear.qsize():
                queues.replay_cache_clear.get()
                missing_packet_numbers.clear()

            while queues.from_gwr_to_rpe_relay_runtime_settings.qsize():
                key, value = queues.from_gwr_to_rpe_relay_runtime_settings.get()
                if key == TFCSettingKey.REQUIRE_RESENDS:
                    require_resends = BoolRequireResends(bool(value))
                if key == TFCSettingKey.AUTOREPLAY_LOOP:
                    autoreplay_loop = bool(value)
                if not require_resends and not autoreplay_loop:
                    missing_packet_numbers.clear()

            # Wait until a packet is available
            if gateway_queue.qsize() == 0:
                time.sleep(0.01)

            ts, packet = gateway_queue.get()

            # Validation
            # ──────────
            # `process_gateway_reader` is a real-time process that does not
            # have time to validate packets between serial interface reads.
            # Thus, we do error detection and validation at dispatch phase.

            # Perform Reed-Solomon error correction or error checking
            try:
                packet = gateway.detect_errors(packet)
            except SoftError:
                continue

            # ┌──────────────────────┐
            # │ Handle packet resend │
            # └──────────────────────┘
            packet_hash = blake2b(packet)
            if packet_hash in recent_packet_hashes:
                continue

            packet_number, packet = split_numbered_packet(packet)

            if expected_packet_number is None:
                expected_packet_number = packet_number + 1

            elif packet_number in missing_packet_numbers:
                missing_packet_numbers.discard(packet_number)

            elif packet_number < expected_packet_number:
                continue

            elif packet_number > expected_packet_number:
                if require_resends or autoreplay_loop:
                    missing_packet_numbers.update(range(expected_packet_number, packet_number))
                expected_packet_number = packet_number + 1

            else:
                expected_packet_number = packet_number + 1

            if (require_resends or autoreplay_loop) and missing_packet_numbers:
                cache_incoming_packet(gateway.settings.program_id, packet_number, make_numbered_packet(packet_number, packet))
                print_message(f'Warning! Missing packets from Transmitter: {format_missing_packet_numbers(missing_packet_numbers)}.',
                              padding_top    = 1,
                              padding_bottom = 1)

            recent_packet_hashes.append(packet_hash)

            # ┌─────────────────┐
            # │ Validate header │
            # └─────────────────┘
            header, payload = separate_header(packet, header_length=FieldLength.DATAGRAM_HEADER)

            valid_headers = [DatagramHeader.LOCAL_KEY,
                             DatagramHeader.MESSAGE,
                             DatagramHeader.FILE,
                             DatagramHeader.COMMAND,
                             DatagramHeader.PUBLIC_KEY,
                             DatagramHeader.RELAY_COMMAND,
                             DatagramHeader.GROUP_INVITE,
                             DatagramHeader.GROUP_JOIN,
                             DatagramHeader.GROUP_ADD_MEMBER,
                             DatagramHeader.GROUP_REM_MEMBER,
                             DatagramHeader.GROUP_EXIT_GROUP]

            if header not in valid_headers:
                print_message(f'Error: Received packet had unknown header {header!r}.', padding_top=1, padding_bottom=1)
                continue

            # ┌──────────────────┐
            # │ Dispatch payload │
            # └──────────────────┘
            try:
                if header == DatagramHeader.LOCAL_KEY:
                    queues.from_txp_to_rxp_datagram_local_key.put(DatagramReceiverLocalKey.from_txp_rep_bytes(ts, payload))

                elif header == DatagramHeader.COMMAND:
                    queues.from_txp_to_rxp_datagram_command.put(DatagramReceiverCommand.from_txp_rep_bytes(ts, payload))

                elif header == DatagramHeader.RELAY_COMMAND:
                    dispatch_relay_command(queues, gateway, ts, BytesRelayCommand(payload))

                elif header == DatagramHeader.PUBLIC_KEY:
                    queues.from_txp_to_sxy_outgoing_x448_public_keys.put(DatagramPublicKey.from_txp_rep_bytes(ts, payload))

                elif header == DatagramHeader.MESSAGE:
                    queues.from_txp_to_sxy_datagram_messages.put(DatagramOutgoingMessage.from_txp_rep_bytes(ts, payload))

                elif header == DatagramHeader.FILE:
                    queues.from_txp_to_sxy_datagram_file_mcast.put(DatagramFileMulticast.from_txp_rep_bytes(ts, payload))

                elif header == DatagramHeader.GROUP_INVITE:
                    for di in DatagramGroupInvite.from_txp_rep_bytes(ts, payload):
                        queues.from_txp_to_srv_datagram_group_mgmt_invite.put(di)

                elif header == DatagramHeader.GROUP_JOIN:
                    for dj in DatagramGroupJoin.from_txp_rep_bytes(ts, payload):
                        queues.from_txp_to_srv_datagram_group_mgmt_join.put(dj)

                elif header == DatagramHeader.GROUP_ADD_MEMBER:
                    for da in DatagramGroupAddMember.from_txp_rep_bytes(ts, payload):
                        queues.from_txp_to_srv_datagram_group_mgmt_add.put(da)

                elif header == DatagramHeader.GROUP_REM_MEMBER:
                    for dr in DatagramGroupRemMember.from_txp_rep_bytes(ts, payload):
                        queues.from_txp_to_srv_datagram_group_mgmt_rem.put(dr)

                elif header == DatagramHeader.GROUP_EXIT_GROUP:
                    for de in DatagramGroupExit.from_txp_rep_bytes(ts, payload):
                        queues.from_txp_to_srv_datagram_group_mgmt_exit.put(de)

            except (SoftError, ValidationError, ValueError, TypeError) as e:
                print_message(f'Error: Received packet payload failed validation. {e.args[0]}', padding_top=1, padding_bottom=1)
                continue

            if unit_testing:
                break
