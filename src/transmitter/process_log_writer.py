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

from typing import TYPE_CHECKING, TypeGuard

from src.common.entities.assembly_packet import AssemblyPacket
from src.common.exceptions import CriticalError, ignored
from src.common.statics import AsmPacket, FieldLength, LogWriterMgmt, Origin, TrafficMaskingData
from src.common.types_compound import BoolLogThisAssemblyPacket
from src.common.types_custom import BoolLogMessages, BoolUnitTesting, BoolLogFileMasking, BoolTrafficMasking
from src.database.db_logs import MessageLog

if TYPE_CHECKING:
    from src.common.crypto.keys.symmetric_key import MasterKeyRekeying
    from src.common.queues import TxQueue
    from src.common.types_compound import LogWriterQueueData, LogWriterUpdateMasterKeyTuple
    from src.database.db_settings import Settings


def process_log_writer(queues       : 'TxQueue',
                       settings     : 'Settings',
                       message_log  : MessageLog,
                       unit_testing : BoolUnitTesting = BoolUnitTesting(False)
                       ) -> None:
    """Process that writes assembly packets to the log database."""
    log_this_packet = BoolLogThisAssemblyPacket(False)
    mask_log        = settings.log_file_masking
    traffic_masking = settings.traffic_masking
    waiting_logged  = False

    while True:
        with ignored(EOFError, KeyboardInterrupt):
            if queues.log_writer_mgmt.qsize():
                traffic_masking, mask_log, log_this_packet = manage_log_writer(queues, message_log, traffic_masking, mask_log, log_this_packet)
                waiting_logged = False
                continue

            while not queues.log_writer_mgmt.qsize() and queues.log_packet.qsize() == 0:
                if not waiting_logged:
                    waiting_logged = True
                time.sleep(0.01)

            if queues.log_writer_mgmt.qsize():
                continue

            traffic_masking, mask_log, log_this_packet = process_log_packet(queues, message_log, traffic_masking, mask_log, log_this_packet)
            waiting_logged = False

            if unit_testing and queues.unit_test.qsize():
                break


def manage_log_writer(queues          : 'TxQueue',
                      message_log     : MessageLog,
                      traffic_masking : 'BoolTrafficMasking',
                      logfile_masking : 'BoolLogFileMasking',
                      log_this_packet : BoolLogThisAssemblyPacket
                      ) -> tuple['BoolTrafficMasking', 'BoolLogFileMasking', BoolLogThisAssemblyPacket]:
    """Process log writer management commands."""
    log_writer_queue_data = queues.log_writer_mgmt.get()
    if is_log_writer_update(log_writer_queue_data):
        update_log_writer_master_key(message_log, log_writer_queue_data[1])
        return traffic_masking, logfile_masking, log_this_packet

    if log_writer_queue_data != (LogWriterMgmt.WAIT_FOR_SYNC,):
        raise CriticalError(f"Invalid log writer management command '{log_writer_queue_data[0]}'.")

    # Flush queued packets before acknowledging the halt so packets
    # already queued for logging are encrypted with the previous key.
    while queues.log_packet.qsize():
        traffic_masking, logfile_masking, log_this_packet = process_log_packet(queues, message_log, traffic_masking, logfile_masking, log_this_packet)

    # Let input process know it can now start re-keying the logfile.
    queues.log_writer_ack.put(LogWriterMgmt.RELEASE_WAIT)

    # Wait for rekeying and the master key.
    while queues.log_writer_mgmt.qsize() == 0:
        time.sleep(0.001)

    # Update the master-key for future logging
    next_queue_data = queues.log_writer_mgmt.get()
    if not is_log_writer_update(next_queue_data):
        raise CriticalError(f"Invalid log writer management command '{next_queue_data[0]}'.")
    update_log_writer_master_key(message_log, next_queue_data[1])

    # ---

    return traffic_masking, logfile_masking, log_this_packet


def update_log_writer_master_key(message_log    : MessageLog,
                                 new_master_key : 'MasterKeyRekeying'
                                 ) -> None:
    """Replace the active master key used by log writer."""
    message_log.master_key.replace_active_key(new_master_key.raw_bytes)


def is_log_writer_update(log_writer_queue_data: 'LogWriterQueueData') -> 'TypeGuard[LogWriterUpdateMasterKeyTuple]':
    """Return True when the log-writer command carries a replacement master key."""
    return len(log_writer_queue_data) == 2 and log_writer_queue_data[0] == LogWriterMgmt.UPDATE_MASTER_KEY


def process_log_packet(queues          : 'TxQueue',
                       message_log     : MessageLog,
                       traffic_masking : 'BoolTrafficMasking',
                       logfile_masking : 'BoolLogFileMasking',
                       log_this_packet : BoolLogThisAssemblyPacket
                       ) -> tuple['BoolTrafficMasking', 'BoolLogFileMasking', BoolLogThisAssemblyPacket]:
    """Process one queued log packet."""
    traffic_masking, logfile_masking = check_setting_queues(queues, traffic_masking, logfile_masking)

    onion_pub_key, assembly_packet, log_messages, log_as_ph = queues.log_packet.get()
    packet_to_log : AssemblyPacket = assembly_packet

    # Detect commands and ignore them
    if onion_pub_key is None:
        return traffic_masking, logfile_masking, log_this_packet

    log_this_packet = update_logging_state(assembly_packet,
                                           log_this_packet,
                                           log_messages,
                                           queues)

    # Detect if we are going to log the packet at all.
    if not log_this_packet:
        return traffic_masking, logfile_masking, log_this_packet

    # Only noise packets, whisper-messages, file key delivery
    # packets and file assembly packets have `log_as_ph`
    # enabled. These packets are stored as placeholder data
    # to hide metadata revealed by the differences in log
    # file size vs the number of sent assembly packets.
    if log_as_ph:

        # It's pointless to hide number of messages in the
        # log file if that information is revealed by
        # observing the Networked Computer when traffic
        # masking is disabled.
        if not traffic_masking:
            return traffic_masking, logfile_masking, log_this_packet

        # If traffic masking is enabled, log file masking
        # might still be unnecessary if the user does not
        # care to hide the tiny amount of metadata (total
        # amount of communication) from a physical attacker.
        if not logfile_masking:
            return traffic_masking, logfile_masking, log_this_packet

        packet_to_log = AssemblyPacket(TrafficMaskingData.PLACEHOLDER_DATA.value)

    MessageLog.write_log_entry(packet_to_log, onion_pub_key, message_log, Origin.USER)

    return traffic_masking, logfile_masking, log_this_packet


def check_setting_queues(queues          : 'TxQueue',
                         traffic_masking : 'BoolTrafficMasking',
                         logfile_masking : 'BoolLogFileMasking',
                         ) -> tuple['BoolTrafficMasking', 'BoolLogFileMasking']:
    """Check queues for updates to traffic masking and logging settings."""
    if queues.traffic_masking.qsize():
        traffic_masking = queues.traffic_masking.get()

    if queues.logfile_masking.qsize():
        logfile_masking = queues.logfile_masking.get()

    return traffic_masking, logfile_masking


def update_logging_state(assembly_packet : AssemblyPacket,
                         log_this_packet : BoolLogThisAssemblyPacket,
                         log_messages    : 'BoolLogMessages',
                         queues          : 'TxQueue'
                         ) -> BoolLogThisAssemblyPacket:
    """Update logging state."""
    if assembly_packet.raw_bytes[:FieldLength.ASSEMBLY_PACKET_HEADER] == AsmPacket.P_N_HEADER:
        if queues.log_setting.qsize():
            log_this_packet = queues.log_setting.get()
    else:
        log_this_packet = log_messages
    return log_this_packet
