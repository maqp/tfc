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
from datetime import datetime
from typing import TYPE_CHECKING

from src.common.utils.encoding import bytes_to_int
from src.common.exceptions import SoftError, ValidationError
from src.common.replay import iter_recent_cached_packets, load_cached_file, resend_cached_packets
from src.common.statics import DatagramHeader, DatagramTypeHR, FieldLength, TFCSettingKey
from src.common.types_custom import BoolAutoreplayLoop, BoolRequireResends, IntAutoreplayTimes, BoolUnitTesting
from src.common.utils.strings import separate_headers
from src.datagrams.receiver.file_multicast import DatagramFileMulticast, DatagramFileMulticastFragment
from src.ui.common.output.print_log_message import print_log_message

if TYPE_CHECKING:
    from src.common.gateway import Gateway
    from src.common.queues import RelayQueue


def load_resend_file_fragments(gateway: 'Gateway', file_id: str) -> list[DatagramFileMulticastFragment]:
    """Load cached file fragments for a resend request."""
    try:
        cached_file = load_cached_file(gateway.settings.program_id, file_id)
        header, ts_bytes, payload = separate_headers(cached_file,
                                                     [FieldLength.DATAGRAM_HEADER.value,
                                                      FieldLength.TIMESTAMP_LONG.value])
        if header != DatagramHeader.FILE.value:
            raise SoftError(f"Error: Cached file '{file_id}' did not contain a file datagram.", clear_before=True)

        timestamp = datetime.strptime(str(bytes_to_int(ts_bytes)), '%Y%m%d%H%M%S%f')
        return DatagramFileMulticast.from_rep_rxp_bytes(timestamp, payload).to_fragments()

    except SoftError:
        return []
    except (ValidationError, ValueError) as e:
        SoftError(f"Error: Cached file '{file_id}' could not be resent. {e}", clear_before=True)
        return []


def process_dst_outgoing(queues       : 'RelayQueue',
                         gateway      : 'Gateway',
                         unit_testing : BoolUnitTesting = BoolUnitTesting(False)
                         ) -> None:
    """Process that sends received datagrams to Receiver Program on Destination Computer.

    The priority order of packets is
        1. Local keys (required for receiving any command)
        2. Commands (Might include EXIT/WIPE)
        3. Messages
        4. Multicasted files

    Prioritization prevents contact-based DoS of commands on Receiver Program.
    """
    local_key_queue        = queues.from_txp_to_rxp_datagram_local_key
    command_queue          = queues.from_txp_to_rxp_datagram_command
    outgoing_message_queue = queues.from_sxy_to_rxp_datagram_messages
    incoming_message_queue = queues.from_cli_to_rxp_datagram_messages
    file_mc_queue          = queues.from_cli_to_rxp_datagram_file_mcast
    resend_queue           = queues.from_txp_to_dst_resend_packet_numbers
    resend_file_queue      = queues.from_txp_to_dst_resend_file_ids
    settings_queue         = queues.relay_runtime_settings_to_dst
    pending_file_fragments : deque[DatagramFileMulticastFragment] = deque()

    require_resends  = BoolRequireResends(False)
    autoreplay_times = IntAutoreplayTimes(1)
    autoreplay_loop  = BoolAutoreplayLoop(False)

    idle_replay_index = 0
    while True:
        try:
            while settings_queue.qsize():

                settings_key, value = settings_queue.get()

                if settings_key == TFCSettingKey.REQUIRE_RESENDS:  require_resends  = BoolRequireResends(bool(value))
                if settings_key == TFCSettingKey.AUTOREPLAY_TIMES: autoreplay_times = IntAutoreplayTimes(int(value))
                if settings_key == TFCSettingKey.AUTOREPLAY_LOOP:  autoreplay_loop  = BoolAutoreplayLoop(bool(value))

            cache_packet = require_resends or autoreplay_times > 1 or autoreplay_loop

            if local_key_queue.qsize() > 0:
                local_key_datagram = local_key_queue.get()
                packet_number      = gateway.write_rxp_datagram(local_key_datagram, cache_packet=cache_packet)
                for _ in range(max(0, autoreplay_times - 1)):
                    gateway.resend_cached_packet(packet_number)
                print_log_message(f"{DatagramTypeHR.LOCAL_KEY:<9} {'to':<4} Receiver Program", local_key_datagram.ts)
                continue

            if command_queue.qsize() > 0:
                command_datagram = command_queue.get()
                packet_number    = gateway.write_rxp_datagram(command_datagram, cache_packet=cache_packet)
                for _ in range(max(0, autoreplay_times - 1)):
                    gateway.resend_cached_packet(packet_number)
                print_log_message(f"{DatagramTypeHR.COMMAND:<9} {'to':<4} Receiver Program", command_datagram.ts)
                continue

            elif resend_queue.qsize() > 0:
                resend_cached_packets(gateway, resend_queue.get())
                continue

            elif resend_file_queue.qsize() > 0:
                resend_fragments = load_resend_file_fragments(gateway, resend_file_queue.get())
                if not resend_fragments:
                    continue
                pending_file_fragments.extend(resend_fragments)
                packet_number = gateway.write_rxp_datagram(pending_file_fragments.popleft(), cache_packet=cache_packet)
                for _ in range(max(0, autoreplay_times - 1)):
                    gateway.resend_cached_packet(packet_number)
                continue

            elif incoming_message_queue.qsize() > 0:
                packet_number = gateway.write_rxp_datagram(incoming_message_queue.get(), cache_packet=cache_packet)
                for _ in range(max(0, autoreplay_times - 1)):
                    gateway.resend_cached_packet(packet_number)
                continue

            elif outgoing_message_queue.qsize() > 0:
                packet_number = gateway.write_rxp_datagram(outgoing_message_queue.get(), cache_packet=cache_packet)
                for _ in range(max(0, autoreplay_times - 1)):
                    gateway.resend_cached_packet(packet_number)
                continue

            elif pending_file_fragments:
                packet_number = gateway.write_rxp_datagram(pending_file_fragments.popleft(), cache_packet=cache_packet)
                for _ in range(max(0, autoreplay_times - 1)):
                    gateway.resend_cached_packet(packet_number)
                continue

            elif file_mc_queue.qsize() > 0:
                pending_file_fragments.extend(file_mc_queue.get().to_fragments())
                packet_number = gateway.write_rxp_datagram(pending_file_fragments.popleft(), cache_packet=cache_packet)
                for _ in range(max(0, autoreplay_times - 1)):
                    gateway.resend_cached_packet(packet_number)
                continue

            else:
                if autoreplay_loop:
                    replay_packets = iter_recent_cached_packets(gateway.settings.program_id)
                    if replay_packets:
                        gateway.send_numbered_packet(replay_packets[idle_replay_index % len(replay_packets)])
                        idle_replay_index += 1
                        continue
                time.sleep(0.01)

            if unit_testing and queues.unit_test.qsize() > 0:
                break

        except (EOFError, KeyboardInterrupt):
            pass
