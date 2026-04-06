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

import struct
import time

from collections import deque
from datetime import datetime
from typing import Optional as O, TYPE_CHECKING

from src.common.crypto.algorithms.blake2b import blake2b
from src.common.types_compound import MulticastFileFragmentDict
from src.common.types_custom import BoolUnitTesting
from src.common.utils.encoding import bytes_to_int
from src.common.exceptions import SoftError, ValidationError, ignored
from src.common.replay import cache_incoming_packet, format_missing_packet_numbers, make_numbered_packet, split_numbered_packet
from src.common.utils.strings import separate_headers
from src.ui.common.output.print_message import print_message
from src.common.statics import DatagramHeader, FieldLength, ReplayLimits, TFCSettingKey
from src.datagrams.receiver.command import DatagramReceiverCommand
from src.datagrams.receiver.file_multicast import DatagramFileMulticast, DatagramFileMulticastFragment
from src.datagrams.receiver.local_key import DatagramReceiverLocalKey
from src.datagrams.receiver.message import DatagramIncomingMessage

if TYPE_CHECKING:
    from src.common.crypto.keys.onion_service_keys import OnionPublicKeyContact
    from src.common.gateway import Gateway
    from src.common.queues import RxQueue
    from src.database.db_settings import Settings


def cache_file_fragment(fragment_cache : dict['OnionPublicKeyContact', list[DatagramFileMulticastFragment]],
                        fragment       : DatagramFileMulticastFragment,
                        ) -> O[DatagramFileMulticast]:
    """Cache a file fragment and return a complete datagram once all fragments arrive."""
    cached_fragments = fragment_cache.setdefault(fragment.pub_key_contact, [])

    # A new first fragment supersedes any incomplete transfer from the same sender.
    if fragment.packet_number == 1:
        cached_fragments.clear()

    cached_fragments[:] = [cached for cached in cached_fragments if cached.packet_number != fragment.packet_number]
    cached_fragments.append(fragment)

    if len(cached_fragments) < fragment.packet_total:
        return None

    try:
        datagram = DatagramFileMulticast.from_fragments(cached_fragments)
    except ValidationError:
        fragment_cache.pop(fragment.pub_key_contact, None)
        raise

    fragment_cache.pop(fragment.pub_key_contact, None)
    return datagram


def process_dispatcher(queues    : 'RxQueue',
                       gateway   : 'Gateway',
                       settings  : 'Settings',
                       unit_test : BoolUnitTesting = BoolUnitTesting(False)
                       ) -> None:
    """\
    Process that decodes packets from `process_gateway_reader`,
    and that forwards them to queues, that the `process_output`
    reads in prioritized order.
    """
    gateway_queue = queues.from_gwr_to_dispatcher_datagrams

    fragment_cache         : MulticastFileFragmentDict = {}
    recent_packet_hashes   : deque[bytes]              = deque(maxlen=ReplayLimits.HASH_WINDOW_SIZE.value)
    expected_packet_number : O[int]                    = None
    missing_packet_numbers : set[int]                  = set()

    while True:
        with ignored(EOFError, KeyboardInterrupt):
            while queues.replay_cache_clear.qsize():
                queues.replay_cache_clear.get()
                missing_packet_numbers.clear()

            while queues.dispatcher_setting_updates.qsize():
                setting_key, value = queues.dispatcher_setting_updates.get()
                if setting_key in [TFCSettingKey.REQUIRE_RESENDS, TFCSettingKey.AUTOREPLAY_LOOP]:
                    settings.set_setting_value(setting_key, value)
                    if not settings.require_resends and not settings.autoreplay_loop:
                        missing_packet_numbers.clear()

            # Wait until a packet is available
            if gateway_queue.qsize() == 0:
                time.sleep(0.01)

            # We ignore the `process_gateway_reader` timestamp, and instead use
            # the received-from-contact-timestamp bundled by the Relay Program.
            _timestamp, packet = gateway_queue.get()

            # Validation
            # ──────────
            # `process_gateway_reader` is a real-time process that does not
            # have time to validate packets between serial interface reads.
            # Thus, we do error detection and validation at dispatch phase.

            # Perform Reed-Solomon error correction
            try:
                packet = gateway.detect_errors(packet)
            except SoftError:
                continue

            packet_hash = blake2b(packet)
            if packet_hash in recent_packet_hashes:
                continue

            # ┌──────────────────────┐
            # │ Handle packet resend │
            # └──────────────────────┘
            packet_number, packet = split_numbered_packet(packet)

            if expected_packet_number is None:
                expected_packet_number = packet_number + 1

            elif packet_number in missing_packet_numbers:
                missing_packet_numbers.discard(packet_number)

            elif packet_number < expected_packet_number:
                continue

            elif packet_number > expected_packet_number:
                if settings.require_resends or settings.autoreplay_loop:
                    missing_packet_numbers.update(range(expected_packet_number, packet_number))
                expected_packet_number = packet_number + 1

            else:
                expected_packet_number = packet_number + 1

            if settings.require_resends and missing_packet_numbers:
                cache_incoming_packet(gateway.settings.program_id, packet_number, make_numbered_packet(packet_number, packet))
                print_message(f'Warning! Missing packets from Relay: {format_missing_packet_numbers(missing_packet_numbers)}.',
                              padding_top    = 1,
                              padding_bottom = 1)

            recent_packet_hashes.append(packet_hash)

            # ┌──────────────────┐
            # │ Validate Headers │
            # └──────────────────┘
            try:
                header, ts_bytes, payload = separate_headers(packet, [FieldLength.DATAGRAM_HEADER, FieldLength.TIMESTAMP_LONG])
            except ValueError:
                print_message(f'Error: Received packet incorrect number of headers.', padding_top=1, padding_bottom=1)
                continue

            if header not in [DatagramHeader.LOCAL_KEY,
                              DatagramHeader.MESSAGE,
                              DatagramHeader.FILE,
                              DatagramHeader.COMMAND]:
                print_message(f'Error: Received packet had unknown header {header!r}.', padding_top=1, padding_bottom=1)
                continue

            try:
                ts = datetime.strptime(str(bytes_to_int(ts_bytes)), '%Y%m%d%H%M%S%f')
            except (ValueError, struct.error):
                print_message('Error: Failed to decode timestamp in the received packet.', padding_top=1, padding_bottom=1)
                continue

            # ┌─────────────────┐
            # │ Process Payload │
            # └─────────────────┘
            try:
                if   header == DatagramHeader.LOCAL_KEY: queues.datagram_local_keys.put(DatagramReceiverLocalKey .from_rep_rxp_bytes(ts, payload))
                elif header == DatagramHeader.COMMAND:   queues.datagram_commands  .put(DatagramReceiverCommand  .from_rep_rxp_bytes(ts, payload))
                elif header == DatagramHeader.MESSAGE:   queues.datagram_messages  .put(DatagramIncomingMessage  .from_rep_rxp_bytes(ts, payload))
                elif header == DatagramHeader.FILE:
                    file_fragment = DatagramFileMulticastFragment.from_rep_rxp_bytes(ts, payload)
                    file_datagram = cache_file_fragment(fragment_cache, file_fragment)
                    if file_datagram is not None:
                        queues.datagram_mc_files.put(file_datagram)

            except (SoftError, ValidationError, ValueError) as e:
                print_message(f'Error: Received packet payload failed validation. {e.args[0]}', padding_top=1, padding_bottom=1)
                continue

            if unit_test:
                break
