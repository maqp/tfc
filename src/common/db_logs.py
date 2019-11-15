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

import os.path
import struct
import sys
import textwrap
import time
import typing

from datetime import datetime
from typing   import Any, Dict, List, Tuple, Union

from src.common.database   import MessageLog
from src.common.encoding   import b58encode, bytes_to_bool, bytes_to_timestamp, pub_key_to_short_address
from src.common.exceptions import CriticalError, FunctionReturn
from src.common.misc       import ensure_dir, get_terminal_width, ignored, separate_header, separate_headers
from src.common.output     import clear_screen
from src.common.statics    import (ASSEMBLY_PACKET_HEADER_LENGTH, DIR_USER_DATA, GROUP_ID_LENGTH, GROUP_MESSAGE_HEADER,
                                   GROUP_MSG_ID_LENGTH, LOGFILE_MASKING_QUEUE, LOG_ENTRY_LENGTH, LOG_PACKET_QUEUE,
                                   LOG_SETTING_QUEUE, MESSAGE, MESSAGE_HEADER_LENGTH, ONION_SERVICE_PUBLIC_KEY_LENGTH,
                                   ORIGIN_HEADER_LENGTH, ORIGIN_USER_HEADER, PLACEHOLDER_DATA, PRIVATE_MESSAGE_HEADER,
                                   P_N_HEADER, RX, TIMESTAMP_LENGTH, TRAFFIC_MASKING_QUEUE, TX, UNIT_TEST_QUEUE,
                                   WHISPER_FIELD_LENGTH, WIN_TYPE_CONTACT, WIN_TYPE_GROUP)

from src.receiver.packet  import PacketList
from src.receiver.windows import RxWindow

if typing.TYPE_CHECKING:
    from multiprocessing         import Queue
    from src.common.db_contacts  import ContactList
    from src.common.db_groups    import GroupList
    from src.common.db_masterkey import MasterKey
    from src.common.db_settings  import Settings
    from src.transmitter.windows import TxWindow

MsgTuple = Tuple[datetime, str, bytes, bytes, bool, bool]


def log_writer_loop(queues:      Dict[bytes, 'Queue[Any]'],  # Dictionary of queues
                    settings:    'Settings',                 # Settings object
                    message_log: 'MessageLog',               # MessageLog object
                    unit_test:   bool = False                # True, exits loop when UNIT_TEST_QUEUE is no longer empty.
                    ) -> None:
    """Write assembly packets to log database.

    When traffic masking is enabled, the fact this loop is run as a
    separate process, means the rate at which `sender_loop` outputs
    packets is not altered by i/o delays (caused by access to the log
    file). This hides metadata about when communication takes place,
    even from an adversary performing timing attacks from within the
    Networked Computer of the user.
    """
    log_packet_queue      = queues[LOG_PACKET_QUEUE]
    log_setting_queue     = queues[LOG_SETTING_QUEUE]
    traffic_masking_queue = queues[TRAFFIC_MASKING_QUEUE]
    logfile_masking_queue = queues[LOGFILE_MASKING_QUEUE]

    logging_state   = False
    logfile_masking = settings.log_file_masking
    traffic_masking = settings.traffic_masking

    while True:
        with ignored(EOFError, KeyboardInterrupt):

            while log_packet_queue.qsize() == 0:
                time.sleep(0.01)

            if traffic_masking_queue.qsize() != 0:
                traffic_masking = traffic_masking_queue.get()
            if logfile_masking_queue.qsize() != 0:
                logfile_masking = logfile_masking_queue.get()

            onion_pub_key, assembly_packet, log_messages, log_as_ph, master_key = log_packet_queue.get()

            # Update log database key
            message_log.database_key = master_key.master_key

            # Detect and ignore commands.
            if onion_pub_key is None:
                continue

            # `logging_state` retains the logging setting for noise packets
            # that do not know the log setting of the window. To prevent
            # logging of noise packets in situation where logging has
            # been disabled, but no new message assembly packet carrying
            # the logging setting is received, the LOG_SETTING_QUEUE
            # is checked for up-to-date logging setting for every
            # received noise packet.
            if assembly_packet[:ASSEMBLY_PACKET_HEADER_LENGTH] == P_N_HEADER:
                if log_setting_queue.qsize() != 0:
                    logging_state = log_setting_queue.get()
            else:
                logging_state = log_messages

            # Detect if we are going to log the packet at all.
            if not logging_state:
                continue

            # Only noise packets, whisper-messages, file key delivery
            # packets and file assembly packets have `log_as_ph` enabled.
            # These packets are stored as placeholder data to hide
            # metadata revealed by the differences in log file size vs
            # the number of sent assembly packets.
            if log_as_ph:

                # It's pointless to hide number of messages in the log
                # file if that information is revealed by observing the
                # Networked Computer when traffic masking is disabled.
                if not traffic_masking:
                    continue

                # If traffic masking is enabled, log file masking might
                # still be unnecessary if the user does not care to hide
                # the tiny amount of metadata (total amount of
                # communication) from a physical attacker. This after
                # all consumes 333 bytes of disk space per noise packet.
                # So finally we check that the user has opted in for log
                # file masking.
                if not logfile_masking:
                    continue

                assembly_packet = PLACEHOLDER_DATA

            write_log_entry(assembly_packet, onion_pub_key, message_log)

            if unit_test and queues[UNIT_TEST_QUEUE].qsize() != 0:
                break


def write_log_entry(assembly_packet: bytes,                       # Assembly packet to log
                    onion_pub_key:   bytes,                       # Onion Service public key of the associated contact
                    message_log:     MessageLog,                  # MessageLog object
                    origin:          bytes = ORIGIN_USER_HEADER,  # The direction of logged packet
                    ) -> None:
    """Add an assembly packet to the encrypted log database.

    Logging assembly packets allows reconstruction of conversation while
    protecting metadata about the length of messages alternative log
    file formats could reveal.

    Transmitter Program can only log sent messages. This is not useful
    for recalling conversations but it makes it possible to audit
    recipient's Destination Computer-side logs, where malware could have
    substituted content of the sent messages.

    Files are not produced or accessed by TFC. Thus, keeping a copy of
    file data in the log database is pointless and potentially dangerous,
    because the user should be right to assume deleting the file from
    `received_files` directory is enough. However, from the perspective
    of metadata, a difference between the number of logged packets and
    the number of output packets could reveal additional metadata about
    communication. Thus, during traffic masking, if
    `settings.log_file_masking` is enabled, instead of file data, TFC
    writes placeholder data to the log database.
    """
    timestamp = struct.pack('<L', int(time.time()))
    log_entry = onion_pub_key + timestamp + origin + assembly_packet

    if len(log_entry) != LOG_ENTRY_LENGTH:
        raise CriticalError("Invalid log entry length.")

    ensure_dir(DIR_USER_DATA)
    message_log.insert_log_entry(log_entry)


def check_log_file_exists(file_name: str) -> None:
    """Check that the log file exists."""
    ensure_dir(DIR_USER_DATA)
    if not os.path.isfile(file_name):
        raise FunctionReturn("No log database available.")


def access_logs(window:       Union['TxWindow', 'RxWindow'],
                contact_list: 'ContactList',
                group_list:   'GroupList',
                settings:     'Settings',
                master_key:   'MasterKey',
                msg_to_load:  int  = 0,
                export:       bool = False
                ) -> None:
    """\
    Load 'msg_to_load' last messages from log database and display or
    export them.

    The default value of zero for `msg_to_load` means all messages for
    the window will be retrieved from the log database.
    """
    file_name    = f'{DIR_USER_DATA}{settings.software_operation}_logs'
    packet_list  = PacketList(settings, contact_list)
    message_list = []  # type: List[MsgTuple]
    group_msg_id = b''

    check_log_file_exists(file_name)
    message_log = MessageLog(file_name, master_key.master_key)

    for log_entry in message_log:
        onion_pub_key, timestamp, origin, assembly_packet \
            = separate_headers(log_entry, [ONION_SERVICE_PUBLIC_KEY_LENGTH, TIMESTAMP_LENGTH, ORIGIN_HEADER_LENGTH])

        if window.type == WIN_TYPE_CONTACT and onion_pub_key != window.uid:
            continue

        packet = packet_list.get_packet(onion_pub_key, origin, MESSAGE, log_access=True)
        try:
            packet.add_packet(assembly_packet)
        except FunctionReturn:
            continue
        if not packet.is_complete:
            continue

        whisper_byte, header, message = separate_headers(packet.assemble_message_packet(), [WHISPER_FIELD_LENGTH,
                                                                                            MESSAGE_HEADER_LENGTH])
        whisper = bytes_to_bool(whisper_byte)

        if header == PRIVATE_MESSAGE_HEADER and window.type == WIN_TYPE_CONTACT:
            message_list.append(
                (bytes_to_timestamp(timestamp), message.decode(), onion_pub_key, packet.origin, whisper, False))

        elif header == GROUP_MESSAGE_HEADER and window.type == WIN_TYPE_GROUP:
            purp_group_id, message = separate_header(message, GROUP_ID_LENGTH)
            if window.group is not None and purp_group_id != window.group.group_id:
                continue

            purp_msg_id, message = separate_header(message, GROUP_MSG_ID_LENGTH)
            if packet.origin == ORIGIN_USER_HEADER:
                if purp_msg_id == group_msg_id:
                    continue
                group_msg_id = purp_msg_id

            message_list.append(
                (bytes_to_timestamp(timestamp), message.decode(), onion_pub_key, packet.origin, whisper, False))

    message_log.close_database()

    print_logs(message_list[-msg_to_load:], export, msg_to_load, window, contact_list, group_list, settings)


def print_logs(message_list: List[MsgTuple],
               export:       bool,
               msg_to_load:  int,
               window:       Union['TxWindow', 'RxWindow'],
               contact_list: 'ContactList',
               group_list:   'GroupList',
               settings:     'Settings'
               ) -> None:
    """Print list of logged messages to screen or export them to file."""
    terminal_width = get_terminal_width()
    system, m_dir  = {TX: ("Transmitter", "sent to"),
                      RX: ("Receiver",    "to/from")}[settings.software_operation]

    f_name = open(f"{system} - Plaintext log ({window.name})", 'w+') if export else sys.stdout
    subset = '' if msg_to_load == 0 else f"{msg_to_load} most recent "
    title  = textwrap.fill(f"Log file of {subset}message(s) {m_dir} {window.type} {window.name}", terminal_width)

    packet_list            = PacketList(settings, contact_list)
    log_window             = RxWindow(window.uid, contact_list, group_list, settings, packet_list)
    log_window.is_active   = True
    log_window.message_log = message_list

    if message_list:
        if not export:
            clear_screen()
        print(title,                 file=f_name)
        print(terminal_width * '═',  file=f_name)
        log_window.redraw(           file=f_name)
        print("<End of log file>\n", file=f_name)
    else:
        raise FunctionReturn(f"No logged messages for {window.type} '{window.name}'.", head_clear=True)

    if export:
        f_name.close()


def change_log_db_key(old_key:  bytes,
                      new_key:  bytes,
                      settings: 'Settings'
                      ) -> None:
    """Re-encrypt log database with a new master key."""
    ensure_dir(DIR_USER_DATA)
    file_name = f'{DIR_USER_DATA}{settings.software_operation}_logs'
    temp_name = f'{file_name}_temp'

    if not os.path.isfile(file_name):
        raise FunctionReturn("No log database available.")

    if os.path.isfile(temp_name):
        os.remove(temp_name)

    message_log_old = MessageLog(file_name, old_key)
    message_log_tmp = MessageLog(temp_name, new_key)

    for log_entry in message_log_old:
        message_log_tmp.insert_log_entry(log_entry)

    message_log_old.close_database()
    message_log_tmp.close_database()


def replace_log_db(settings: 'Settings') -> None:
    """Replace log database with temp file."""
    ensure_dir(DIR_USER_DATA)
    file_name = f'{DIR_USER_DATA}{settings.software_operation}_logs'
    temp_name = f'{file_name}_temp'

    if os.path.isfile(temp_name):
        os.replace(temp_name, file_name)


def remove_logs(contact_list: 'ContactList',
                group_list:   'GroupList',
                settings:     'Settings',
                master_key:   'MasterKey',
                selector:     bytes
                ) -> None:
    """\
    Remove log entries for selector (public key of an account/group ID).

    If the selector is a public key, all messages (both the private
    conversation and any associated group messages) sent to and received
    from the associated contact are removed. If the selector is a group
    ID, only messages for group determined by that group ID are removed.
    """
    ensure_dir(DIR_USER_DATA)
    file_name       = f'{DIR_USER_DATA}{settings.software_operation}_logs'
    temp_name       = f'{file_name}_temp'
    packet_list     = PacketList(settings, contact_list)
    entries_to_keep = []  # type: List[bytes]
    removed         = False
    contact         = len(selector) == ONION_SERVICE_PUBLIC_KEY_LENGTH

    check_log_file_exists(file_name)
    message_log = MessageLog(file_name, master_key.master_key)

    for log_entry in message_log:

        onion_pub_key, _, origin, assembly_packet = separate_headers(log_entry, [ONION_SERVICE_PUBLIC_KEY_LENGTH,
                                                                                 TIMESTAMP_LENGTH,
                                                                                 ORIGIN_HEADER_LENGTH])
        if contact:
            if onion_pub_key == selector:
                removed = True
            else:
                entries_to_keep.append(log_entry)

        else:  # Group
            packet = packet_list.get_packet(onion_pub_key, origin, MESSAGE, log_access=True)
            try:
                packet.add_packet(assembly_packet, log_entry)
            except FunctionReturn:
                continue
            if not packet.is_complete:
                continue

            _, header, message = separate_headers(packet.assemble_message_packet(), [WHISPER_FIELD_LENGTH,
                                                                                     MESSAGE_HEADER_LENGTH])

            if header == PRIVATE_MESSAGE_HEADER:
                entries_to_keep.extend(packet.log_ct_list)
                packet.clear_assembly_packets()

            elif header == GROUP_MESSAGE_HEADER:
                group_id, _ = separate_header(message, GROUP_ID_LENGTH)
                if group_id == selector:
                    removed = True
                else:
                    entries_to_keep.extend(packet.log_ct_list)
                    packet.clear_assembly_packets()

    message_log.close_database()

    message_log_temp = MessageLog(temp_name, master_key.master_key)

    for log_entry in entries_to_keep:
        message_log_temp.insert_log_entry(log_entry)
    message_log_temp.close_database()

    os.replace(temp_name, file_name)

    try:
        name = contact_list.get_nick_by_pub_key(selector) if contact else group_list.get_group_by_id(selector).name
    except StopIteration:
        name = pub_key_to_short_address(selector)         if contact else b58encode(selector)

    action   = "Removed" if removed else "Found no"
    win_type = "contact" if contact else "group"

    raise FunctionReturn(f"{action} log entries for {win_type} '{name}'.")
