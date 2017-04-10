#!/usr/bin/env python3.6
# -*- coding: utf-8 -*-

"""
Copyright (C) 2013-2017  Markus Ottela

This file is part of TFC.

TFC is free software: you can redistribute it and/or modify it under the terms
of the GNU General Public License as published by the Free Software Foundation,
either version 3 of the License, or (at your option) any later version.

TFC is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with TFC. If not, see <http://www.gnu.org/licenses/>.
"""

import datetime
import os.path
import struct
import sys
import textwrap
import time
import typing
import zlib

from typing import List, Tuple, Union

from src.common.crypto   import auth_and_decrypt, encrypt_and_sign, rm_padding_bytes
from src.common.errors   import FunctionReturn
from src.common.encoding import bytes_to_str, str_to_bytes
from src.common.misc     import clear_screen, ensure_dir, get_tty_w
from src.common.statics  import *

if typing.TYPE_CHECKING:
    from multiprocessing         import Queue
    from src.common.db_contacts  import ContactList
    from src.common.db_masterkey import MasterKey
    from src.common.db_settings  import Settings
    from src.rx.windows          import Window
    from src.tx.windows          import Window as Window_


def log_writer(l_queue: 'Queue') -> None:
    """Read log data from queue and write them to log database.

    This process separates writing to logfile from sender_loop to prevent IO
    delays caused by access to logfile from revealing metadata about when
    communication takes place.
    """
    while True:
        try:
            if l_queue.empty():
                time.sleep(0.01)
                continue

            packet, rx_account, settings, master_key = l_queue.get()

            if packet[0] == P_N_HEADER:
                continue

            # File assembly packet headers are capitalized
            if bytes([packet[0]]).isupper() and settings.log_dummy_file_a_p:
                # Log placeholder data instead of sent file
                packet = F_S_HEADER + bytes(255)

            write_log_entry(packet, rx_account, settings, master_key)

        except (EOFError, KeyboardInterrupt):
            pass


def write_log_entry(assembly_packet: bytes,
                    account:         str,
                    settings:        'Settings',
                    master_key:      'MasterKey',
                    origin:          bytes = ORIGIN_USER_HEADER) -> None:
    """Add assembly packet to encrypted logfile.

    This method of logging allows reconstruction of conversation while protecting
    the metadata about the length of messages other log file formats would reveal.

    TxM can only log sent messages. This is not useful for recalling conversations
    but serves an important role in audit of RxM-side logs, where malware could
    have substituted logged data on RxM.

    To protect possibly sensitive files that must not be logged, only placeholder
    data is logged about them. This helps hiding the amount of communication
    comparison with log file size and output packet count would otherwise reveal.

    :param assembly_packet: Assembly packet to log
    :param account:         Recipient's account (UID)
    :param origin:          Direction of logged packet
    :param settings:        Settings object
    :param master_key:      Master key object
    :return:                None
    """
    unix_timestamp  = int(time.time())
    timestamp_bytes = struct.pack('<L', unix_timestamp)
    encoded_account = str_to_bytes(account)

    pt_bytes = timestamp_bytes + origin + encoded_account + assembly_packet
    ct_bytes = encrypt_and_sign(pt_bytes, key=master_key.master_key)

    ensure_dir(f'{DIR_USER_DATA}/')
    file_name = f'{DIR_USER_DATA}/{settings.software_operation}_logs'
    with open(file_name, 'ab+') as f:
        f.write(ct_bytes)


def access_history(window:       Union['Window', 'Window_'],
                   contact_list: 'ContactList',
                   settings:     'Settings',
                   master_key:   'MasterKey',
                   msg_to_load:  int = 0,
                   export:       bool = False) -> None:
    """Decrypt 'msg_to_load' last messages from log database and display/export it.

    :param window:       Window object
    :param contact_list: ContactList object
    :param settings:     Settings object
    :param master_key:   Master key object
    :param msg_to_load:  Number of messages to load
    :param export:       When True, write logged messages into
                         plaintext file instead of printing them.
    :return:             None
    """

    def read_entry():
        """Read encrypted log entry.

        Length  |  Data type
        --------|--------------------------------
             24 |  XSalsa20 nonce
              4 |  Timestamp
              4 |  UTF-32 BOM
          4*255 |  Padded account (UTF-32)
              1 |  Origin header
              1 |  Assembly packet header
            255 |  Padded assembly packet (UTF-8)
             16 |  Poly1305 tag
        """
        return log_file.read(1325)

    ensure_dir(f'{DIR_USER_DATA}/')
    file_name = f'{DIR_USER_DATA}/{settings.software_operation}_logs'
    if not os.path.isfile(file_name):
        raise FunctionReturn(f"Error: Could not find '{file_name}'.")

    log_file          = open(file_name, 'rb')
    ts_message_list   = []  # type: List[Tuple[str, str, bytes, str]]
    assembly_p_buffer = dict()
    group_timestamp   = b''

    for ct in iter(read_entry, b''):
        pt      = auth_and_decrypt(ct, key=master_key.master_key)
        account = bytes_to_str(pt[5:1029])

        if window.type == 'contact' and window.uid != account:
            continue

        t_stamp         = parse_ts_bytes(pt[0:4], settings)
        origin_byte     = pt[4:5]
        origin          = origin_byte.decode()
        assembly_header = pt[1029:1030]
        assembly_pt     = pt[1030:]

        if assembly_header == M_S_HEADER:
            depadded     = rm_padding_bytes(assembly_pt)
            decompressed = zlib.decompress(depadded)
            if decompressed[:1] == PRIVATE_MESSAGE_HEADER:
                if window.type == 'group':
                    continue
                decoded = decompressed[1:].decode()

            elif decompressed[:1] == GROUP_MESSAGE_HEADER:

                group_name, decoded = [f.decode() for f in decompressed[9:].split(US_BYTE)]
                if group_name != window.name:
                    continue
                if group_timestamp == decompressed[1:9]:
                    continue
                else:
                    group_timestamp = decompressed[1:9]

            ts_message_list.append((t_stamp, account, origin_byte, decoded))

        elif assembly_header == M_L_HEADER:
            assembly_p_buffer[origin + account] = assembly_pt

        elif assembly_header == M_A_HEADER:
            if (origin + account) in assembly_p_buffer:
                assembly_p_buffer[origin + account] += assembly_pt

        elif assembly_header == M_E_HEADER:
            if (origin + account) in assembly_p_buffer:
                assembly_p_buffer[origin + account] += assembly_pt

                pt_buf       = assembly_p_buffer.pop(origin + account)
                inner_l      = rm_padding_bytes(pt_buf)
                msg_key      = inner_l[-32:]
                enc_msg      = inner_l[:-32]
                decrypted    = auth_and_decrypt(enc_msg, key=msg_key)
                decompressed = zlib.decompress(decrypted)

                if decompressed[:1] == PRIVATE_MESSAGE_HEADER:
                    if window.type == 'group':
                        continue
                    decoded = decompressed[1:].decode()

                elif decompressed[:1] == GROUP_MESSAGE_HEADER:
                    group_name, decoded = [f.decode() for f in decompressed[9:].split(US_BYTE)]
                    if group_name != window.name:
                        continue
                    if group_timestamp == decompressed[1:9]:  # Skip duplicates of outgoing messages
                        continue
                    else:
                        group_timestamp = decompressed[1:9]

                ts_message_list.append((t_stamp, account, origin_byte, decoded))

        elif assembly_header == M_C_HEADER:
            assembly_p_buffer.pop(origin + account, None)

    log_file.close()

    if not export:
        clear_screen()
        print('')

    tty_w  = get_tty_w()

    system = dict(tx="TxM",     rx="RxM",     ut="Unittest")[settings.software_operation]
    m_dir  = dict(tx="sent to", rx="to/from", ut="to/from")[settings.software_operation]

    f_name = open(f"{system} - Plaintext log ({window.name})", 'w+') if export else sys.stdout
    subset = '' if msg_to_load == 0 else f"{msg_to_load} most recent "
    title  = textwrap.fill(f"Log file of {subset}message(s) {m_dir} {window.name}", tty_w)

    print(title,       file=f_name)
    print(tty_w * '═', file=f_name)

    for timestamp, account, origin_, message in ts_message_list[-msg_to_load:]:

        nick = "Me" if origin_ == ORIGIN_USER_HEADER else contact_list.get_contact(account).nick

        print(textwrap.fill(f"{timestamp} {nick}:", tty_w), file=f_name)
        print('',                                           file=f_name)
        print(textwrap.fill(message, tty_w),                file=f_name)
        print('',                                           file=f_name)
        print(tty_w * '─',                                  file=f_name)

    if export:
        f_name.close()
    else:
        print('')


def re_encrypt(previous_key: bytes, new_key: bytes, settings: 'Settings') -> None:
    """Re-encrypt database with a new master key."""
    ensure_dir(f'{DIR_USER_DATA}/')
    file_name = f'{DIR_USER_DATA}/{settings.software_operation}_logs'
    temp_name = f'{DIR_USER_DATA}/{settings.software_operation}_logs_temp'

    if not os.path.isfile(file_name):
        raise FunctionReturn(f"Error: Could not find '{file_name}'.")

    if os.path.isfile(temp_name):
        os.remove(temp_name)

    f_old = open(file_name, 'rb')
    f_new = open(temp_name, 'ab+')

    def read_entry():
        """Read log entry."""
        return f_old.read(1325)

    for ct_old in iter(read_entry, b''):
        pt_new = auth_and_decrypt(ct_old, key=previous_key)
        f_new.write(encrypt_and_sign(pt_new, key=new_key))

    f_old.close()
    f_new.close()

    os.remove(file_name)
    os.rename(temp_name, file_name)


def parse_ts_bytes(ts_bytes: bytes, settings: 'Settings') -> str:
    """Convert bytes to timestamp string."""
    ts = struct.unpack('<L', ts_bytes)[0]
    return datetime.datetime.fromtimestamp(ts).strftime(settings.format_of_logfiles)
