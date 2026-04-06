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

import fcntl
import os

from pathlib import Path
from typing import Iterable, Optional as O, TYPE_CHECKING

from src.common.exceptions import SoftError
from src.common.statics import FieldLength, ReplayLimits
from src.common.types_custom import BoolAutoreplayLoop, BoolRequireResends, IntAutoreplayTimes, BoolCachePacket
from src.common.utils.encoding import int_to_bytes, encode_base26, decode_base26
from src.common.utils.io import get_working_dir
from src.common.utils.strings import separate_header

if TYPE_CHECKING:
    from src.common.gateway import Gateway


COUNTER_FILE_NAME   = '.packet_counter'
OUTGOING_DIR_NAME   = 'outgoing_datagrams'
INCOMING_DIR_NAME   = 'incoming_datagrams'
FILE_CACHE_DIR_NAME = 'received_files_cache'
PACKET_FILE_SUFFIX  = '.pkt'
FILE_CACHE_SUFFIX   = '.msg'


def _packet_file_name(packet_number: int) -> str:
    return f'{packet_number:020d}{PACKET_FILE_SUFFIX}'


def _packet_number_from_name(file_name: str) ->O[int]:
    if not file_name.endswith(PACKET_FILE_SUFFIX):
        return None
    number = file_name[:-len(PACKET_FILE_SUFFIX)]
    return int(number) if number.isdigit() else None


def _ensure_dir(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    return path


def _namespace_dir(directory_name: str, namespace: str) -> Path:
    return _ensure_dir(Path(get_working_dir()) / directory_name / namespace)


def outgoing_datagram_dir(namespace: str) -> Path:
    """Return the outgoing datagram cache directory for a program namespace."""
    return _namespace_dir(OUTGOING_DIR_NAME, namespace)


def incoming_datagram_dir(namespace: str) -> Path:
    """Return the received datagram cache directory for a program namespace."""
    return _namespace_dir(INCOMING_DIR_NAME, namespace)


def received_file_cache_dir(namespace: str) -> Path:
    """Return the cached incoming file directory for a program namespace."""
    return _namespace_dir(FILE_CACHE_DIR_NAME, namespace)


def _clear_cached_files(cache_dir: Path, *, preserved_names: tuple[str, ...] = ()) -> int:
    """Remove files from a cache directory, preserving selected file names."""
    cleared_files = 0

    for path in cache_dir.iterdir():
        if not path.is_file() or path.name in preserved_names:
            continue
        path.unlink(missing_ok=True)
        cleared_files += 1

    return cleared_files


def allocate_packet_number(namespace: str) -> int:
    """Allocate the next unique packet number for the namespace."""
    cache_dir    = outgoing_datagram_dir(namespace)
    counter_path = cache_dir / COUNTER_FILE_NAME

    with open(counter_path, 'a+b') as handle:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        handle.seek(0)
        current = handle.read().strip()
        if current:
            current_number = int(current.decode())
        else:
            current_number = max(packet_numbers_from_cache(namespace), default=0)
        next_number = current_number + 1
        handle.seek(0)
        handle.truncate()
        handle.write(str(next_number).encode())
        handle.flush()
        os.fsync(handle.fileno())
        fcntl.flock(handle.fileno(), fcntl.LOCK_UN)

    return next_number


def make_numbered_packet(packet_number: int, payload: bytes) -> bytes:
    """Prefix a packet number to raw datagram payload bytes."""
    return int_to_bytes(packet_number) + payload


def split_numbered_packet(packet: bytes) -> tuple[int, bytes]:
    """Return the packet number and the raw datagram payload."""
    packet_number_bytes, payload = separate_header(packet, FieldLength.ENCODED_INTEGER.value)
    return int.from_bytes(packet_number_bytes), payload


def cache_outgoing_packet(namespace: str, packet_number: int, packet: bytes) -> None:
    """Persist a numbered outgoing packet and trim the cache."""
    cache_dir   = outgoing_datagram_dir(namespace)
    packet_path = cache_dir / _packet_file_name(packet_number)

    with open(packet_path, 'wb+') as handle:
        handle.write(packet)
        handle.flush()
        os.fsync(handle.fileno())

    trim_packet_cache(cache_dir, ReplayLimits.OUTGOING_DATAGRAM_CACHE_SIZE.value)


def cache_incoming_packet(namespace: str, packet_number: int, packet: bytes) -> None:
    """Persist a numbered received packet for diagnostic recovery."""
    cache_dir   = incoming_datagram_dir(namespace)
    packet_path = cache_dir / _packet_file_name(packet_number)

    with open(packet_path, 'wb+') as handle:
        handle.write(packet)
        handle.flush()
        os.fsync(handle.fileno())

    trim_packet_cache(cache_dir, ReplayLimits.OUTGOING_DATAGRAM_CACHE_SIZE.value)


def trim_packet_cache(cache_dir: Path, max_packets: int) -> None:
    """Trim cached packet files to the most recent `max_packets` entries."""
    packet_files = sorted(
        (path for path in cache_dir.iterdir() if _packet_number_from_name(path.name) is not None),
        key=lambda path: path.name,
    )

    while len(packet_files) > max_packets:
        oldest = packet_files.pop(0)
        oldest.unlink(missing_ok=True)


def load_cached_outgoing_packet(namespace: str, packet_number: int) -> bytes:
    """Load a cached outgoing packet by packet number."""
    packet_path = outgoing_datagram_dir(namespace) / _packet_file_name(packet_number)
    try:
        return packet_path.read_bytes()
    except FileNotFoundError:
        raise SoftError(f'Error: Outgoing packet {packet_number} was not cached.', clear_before=True)


def iter_recent_cached_packets(namespace: str,
                               limit: int = ReplayLimits.IDLE_REPLAY_PACKET_COUNT.value,
                               ) -> list[bytes]:
    """Return up to `limit` most recent cached outgoing packets."""
    packet_files = sorted(
        (path for path in outgoing_datagram_dir(namespace).iterdir() if _packet_number_from_name(path.name) is not None),
        key=lambda path: path.name,
    )

    recent_packets = [path.read_bytes() for path in packet_files[-limit:]]
    return recent_packets


def packet_numbers_from_cache(namespace: str) -> list[int]:
    """Return cached outgoing packet numbers in ascending order."""
    numbers = []
    for path in outgoing_datagram_dir(namespace).iterdir():
        packet_number = _packet_number_from_name(path.name)
        if packet_number is not None:
            numbers.append(packet_number)
    return sorted(numbers)


def should_cache_gateway_packets(require_resends  : BoolRequireResends,
                                 autoreplay_times : IntAutoreplayTimes = IntAutoreplayTimes(1),
                                 autoreplay_loop  : BoolAutoreplayLoop = BoolAutoreplayLoop(False),
                                 ) -> BoolCachePacket:
    """Return True when outgoing gateway packets must be cached on disk."""
    return BoolCachePacket(require_resends or autoreplay_times > 1 or autoreplay_loop)


def cache_received_file(namespace: str, packet: bytes) -> str:
    """Persist a received Relay-side file packet using a base26 identifier."""
    cache_dir = received_file_cache_dir(namespace)
    existing_indices = []
    for path in cache_dir.iterdir():
        if path.suffix != FILE_CACHE_SUFFIX:
            continue
        try:
            existing_indices.append(decode_base26(path.stem))
        except ValueError:
            continue

    next_id   = encode_base26(max(existing_indices, default=-1) + 1)
    file_path = cache_dir / f'{next_id}{FILE_CACHE_SUFFIX}'

    with open(file_path, 'wb+') as handle:
        handle.write(packet)
        handle.flush()
        os.fsync(handle.fileno())

    return next_id


def clear_cached_send_data(namespace: str) -> int:
    """Remove cached outgoing replay packets while preserving the packet counter."""
    return _clear_cached_files(outgoing_datagram_dir(namespace), preserved_names=(COUNTER_FILE_NAME,))


def clear_cached_receive_data(namespace: str, *, clear_files: bool) -> int:
    """Remove cached incoming packets and optional Relay-side file ciphertexts."""
    cleared_files = _clear_cached_files(incoming_datagram_dir(namespace))

    if clear_files:
        cleared_files += _clear_cached_files(received_file_cache_dir(namespace))

    return cleared_files


def load_cached_file(namespace: str, file_id: str) -> bytes:
    """Load a cached Relay-side file packet by base26 identifier."""
    file_path = received_file_cache_dir(namespace) / f'{file_id.lower()}{FILE_CACHE_SUFFIX}'
    try:
        return file_path.read_bytes()
    except FileNotFoundError:
        raise SoftError(f"Error: Cached file '{file_id}' was not available.", clear_before=True)


def resend_cached_packets(gateway: 'Gateway', packet_numbers: Iterable[int]) -> int:
    """Resend cached packets, continuing past entries that are no longer available."""
    resent_packets = 0

    for packet_number in packet_numbers:
        try:
            gateway.resend_cached_packet(packet_number)
        except SoftError:
            continue
        resent_packets += 1

    return resent_packets


def format_missing_packet_numbers(packet_numbers: Iterable[int]) -> str:
    """Format missing packet numbers for warning output."""
    return ', '.join(str(number) for number in sorted(set(packet_numbers)))
