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

import os.path
import re
import struct
import sys
import textwrap
import time
import typing
import zlib

from collections import defaultdict
from datetime    import datetime
from typing      import DefaultDict, Dict, List, Tuple, Union

from src.common.crypto     import auth_and_decrypt, encrypt_and_sign, rm_padding_bytes
from src.common.exceptions import FunctionReturn
from src.common.encoding   import bytes_to_str, str_to_bytes
from src.common.misc       import ensure_dir, get_terminal_width, ignored
from src.common.output     import c_print, clear_screen
from src.common.statics    import *

from src.rx.windows import RxWindow

if typing.TYPE_CHECKING:
    from multiprocessing         import Queue
    from src.common.db_contacts  import ContactList
    from src.common.db_groups    import GroupList
    from src.common.db_masterkey import MasterKey
    from src.common.db_settings  import Settings
    from src.tx.windows          import TxWindow


def log_writer_loop(queues: Dict[bytes, 'Queue'], unittest: bool = False) -> None:
    """Read log data from queue and write entry to log database.

    When traffic masking is enabled, this process separates writing to
    logfile from sender_loop to prevent IO delays (caused by access to
    logfile) from revealing metadata about when communication takes place.
    """
    queue = queues[LOG_PACKET_QUEUE]

    while True:
        with ignored(EOFError, KeyboardInterrupt):
            while queue.qsize() == 0:
                time.sleep(0.01)

            log_packet, log_as_ph, packet, rx_account, settings, master_key = queue.get()

            if rx_account is None or not log_packet:
                continue

            header = bytes([packet[0]])

            if header == P_N_HEADER or header.isupper() or log_as_ph:
                packet = PLACEHOLDER_DATA
                if not (settings.session_traffic_masking and settings.logfile_masking):
                    continue

            write_log_entry(packet, rx_account, settings, master_key)

            if unittest and queues[UNITTEST_QUEUE].qsize() != 0:
                break


def write_log_entry(assembly_packet: bytes,
                    account:         str,
                    settings:        'Settings',
                    master_key:      'MasterKey',
                    origin:          bytes = ORIGIN_USER_HEADER) -> None:
    """Add assembly packet to encrypted logfile.

    This method of logging allows reconstruction of conversation while
    protecting the metadata about the length of messages other logfile
    formats would reveal.

    TxM can only log sent messages. This is not useful for recalling
    conversations but serves an important role in audit of recipient's
    RxM-side logs, where malware could have substituted logged data.

    Files are not content produced or accessed by TFC, thus keeping a
    copy of file data in log database is pointless and potentially
    dangerous if user thinks they have deleted the file from their
    system. However, from the perspective of metadata, having a
    difference in number of logged packets when compared to number of
    output packets could reveal additional metadata about file
    transmission. To solve both issues, TFC only logs placeholder data.

    :param assembly_packet: Assembly packet to log
    :param account:         Recipient's account (UID)
    :param settings:        Settings object
    :param master_key:      Master key object
    :param origin:          Direction of logged packet
    :return:                None
    """
    encoded_account = str_to_bytes(account)
    unix_timestamp  = int(time.time())
    timestamp_bytes = struct.pack('<L', unix_timestamp)

    pt_bytes = encoded_account + timestamp_bytes + origin + assembly_packet
    ct_bytes = encrypt_and_sign(pt_bytes, key=master_key.master_key)

    assert len(ct_bytes) == LOG_ENTRY_LENGTH

    ensure_dir(DIR_USER_DATA)
    file_name = f'{DIR_USER_DATA}{settings.software_operation}_logs'
    with open(file_name, 'ab+') as f:
        f.write(ct_bytes)


def access_logs(window:       Union['TxWindow', 'RxWindow'],
                contact_list: 'ContactList',
                group_list:   'GroupList',
                settings:     'Settings',
                master_key:   'MasterKey',
                msg_to_load:  int  = 0,
                export:       bool = False) -> None:
    """\
    Decrypt 'msg_to_load' last messages from
    log database and display/export it.
    """
    ensure_dir(DIR_USER_DATA)
    file_name = f'{DIR_USER_DATA}{settings.software_operation}_logs'
    if not os.path.isfile(file_name):
        raise FunctionReturn(f"Error: Could not find log database.")

    log_file        = open(file_name, 'rb')
    ts_message_list = []                 # type: List[Tuple['datetime', str, str, bytes, bool]]
    assembly_p_buf  = defaultdict(list)  # type: DefaultDict[str, List[bytes]]
    group_msg_id    = b''

    for ct in iter(lambda: log_file.read(LOG_ENTRY_LENGTH), b''):
        pt      = auth_and_decrypt(ct, key=master_key.master_key)
        account = bytes_to_str(pt[0:1024])

        if window.type == WIN_TYPE_CONTACT and window.uid != account:
            continue

        time_stamp      = datetime.fromtimestamp(struct.unpack('<L', pt[1024:1028])[0])
        origin          = pt[1028:1029]
        assembly_header = pt[1029:1030]
        assembly_pt     = pt[1030:1325]
        key             = origin.decode() + account

        if assembly_header == M_C_HEADER:
            assembly_p_buf.pop(key, None)

        elif assembly_header == M_L_HEADER:
            assembly_p_buf[key] = [assembly_pt]

        elif assembly_header == M_A_HEADER:
            if key not in assembly_p_buf:
                continue
            assembly_p_buf[key].append(assembly_pt)

        elif assembly_header in [M_S_HEADER, M_E_HEADER]:

            if assembly_header == M_S_HEADER:
                depadded     = rm_padding_bytes(assembly_pt)
                decompressed = zlib.decompress(depadded)
            else:
                if key not in assembly_p_buf:
                    continue
                assembly_p_buf[key].append(assembly_pt)

                pt_buffer    = b''.join(assembly_p_buf.pop(key))
                inner_layer  = rm_padding_bytes(pt_buffer)
                decrypted    = auth_and_decrypt(nonce_ct_tag=inner_layer[:-KEY_LENGTH],
                                                key         =inner_layer[-KEY_LENGTH:])
                decompressed = zlib.decompress(decrypted)

            header = decompressed[:1]
            if header == PRIVATE_MESSAGE_HEADER:
                if window.type == WIN_TYPE_GROUP:
                    continue
                message = decompressed[1:].decode()
                ts_message_list.append((time_stamp, message, account, origin, False))

            elif header == GROUP_MESSAGE_HEADER:
                purp_msg_id         = decompressed[1:1+GROUP_MSG_ID_LEN]
                group_name, message = [f.decode() for f in decompressed[1+GROUP_MSG_ID_LEN:].split(US_BYTE)]
                if group_name != window.name:
                    continue
                if origin == ORIGIN_USER_HEADER:
                    if purp_msg_id == group_msg_id:  # Skip duplicates of outgoing messages
                        continue
                    group_msg_id = purp_msg_id
                ts_message_list.append((time_stamp, message, account, origin, False))

    log_file.close()

    print_logs(ts_message_list[-msg_to_load:], export, msg_to_load, window, contact_list, group_list, settings)


def print_logs(ts_message_list: List[Tuple['datetime', str, str, bytes, bool]],
               export:          bool,
               msg_to_load:     int,
               window:          Union['TxWindow', 'RxWindow'],
               contact_list:    'ContactList',
               group_list:      'GroupList',
               settings:        'Settings') -> None:
    """Print list of logged messages to screen."""
    terminal_width = get_terminal_width()

    system, m_dir = dict(tx=("TxM", "sent to"),
                         rx=("RxM", "to/from"),
                         ut=("UtM", "to/from"))[settings.software_operation]

    f_name = open(f"{system} - Plaintext log ({window.name})", 'w+') if export else sys.stdout
    subset = '' if msg_to_load == 0 else f"{msg_to_load} most recent "
    title  = textwrap.fill(f"Logfile of {subset}message{'' if msg_to_load == 1 else 's'} {m_dir} {window.name}", terminal_width)

    log_window             = RxWindow(window.uid, contact_list, group_list, settings)
    log_window.is_active   = True
    log_window.message_log = ts_message_list

    if ts_message_list:
        if not export:
            clear_screen()
        print(title + '\n' + terminal_width * '═', file=f_name)
        log_window.redraw(                         file=f_name)
        print("<End of logfile>\n",                file=f_name)
    else:
        raise FunctionReturn(f"No logged messages for '{window.uid}'")

    if export:
        f_name.close()


def re_encrypt(previous_key: bytes, new_key: bytes, settings: 'Settings') -> None:
    """Re-encrypt log database with new master key."""
    ensure_dir(DIR_USER_DATA)
    file_name = f'{DIR_USER_DATA}{settings.software_operation}_logs'
    temp_name = f'{DIR_USER_DATA}{settings.software_operation}_logs_temp'

    if not os.path.isfile(file_name):
        raise FunctionReturn(f"Error: Could not find log database.")

    if os.path.isfile(temp_name):
        os.remove(temp_name)

    f_old = open(file_name, 'rb')
    f_new = open(temp_name, 'ab+')

    for ct_old in iter(lambda: f_old.read(LOG_ENTRY_LENGTH), b''):
        pt_new = auth_and_decrypt(ct_old,    key=previous_key)
        f_new.write(encrypt_and_sign(pt_new, key=new_key))

    f_old.close()
    f_new.close()

    os.remove(file_name)
    os.rename(temp_name, file_name)


def remove_logs(selector:    str,
                settings:    'Settings',
                master_key:  'MasterKey') -> None:
    """Remove log entries for selector (group name / account).

    If selector is a contact, all messages sent to and received from
    the contact are removed. If selector is a group, only messages
    for that group are removed.
    """
    ensure_dir(DIR_USER_DATA)
    file_name = f'{DIR_USER_DATA}{settings.software_operation}_logs'
    if not os.path.isfile(file_name):
        raise FunctionReturn(f"Error: Could not find log database.")

    log_file       = open(file_name, 'rb')
    ct_to_keep     = []                 # type: List[bytes]
    maybe_keep_buf = defaultdict(list)  # type: DefaultDict[str, List[bytes]]
    assembly_p_buf = defaultdict(list)  # type: DefaultDict[str, List[bytes]]
    removed        = False
    window_type    = WIN_TYPE_CONTACT if re.match(ACCOUNT_FORMAT, selector) else WIN_TYPE_GROUP

    for ct in iter(lambda: log_file.read(LOG_ENTRY_LENGTH), b''):
        pt      = auth_and_decrypt(ct, key=master_key.master_key)
        account = bytes_to_str(pt[0:1024])

        if window_type == WIN_TYPE_CONTACT:
            if selector == account:
                removed = True
                continue
            else:
                ct_to_keep.append(ct)

        # To remove messages for specific group, messages in log database must
        # be assembled to reveal their group name. Assembly packets' ciphertexts are
        # buffered to 'maybe_keep_buf', from where they will be moved to 'ct_to_keep'
        # if their associated group name differs from the one selected for log removal.
        elif window_type == WIN_TYPE_GROUP:
            origin          = pt[1028:1029]
            assembly_header = pt[1029:1030]
            assembly_pt     = pt[1030:1325]
            key             = origin.decode() + account

            if assembly_header == M_C_HEADER:
                # Since log database is being altered anyway, also discard
                # sequences of assembly packets that end in cancel packet.
                assembly_p_buf.pop(key, None)
                maybe_keep_buf.pop(key, None)

            elif assembly_header == M_L_HEADER:
                maybe_keep_buf[key] = [ct]
                assembly_p_buf[key] = [assembly_pt]

            elif assembly_header == M_A_HEADER:
                if key not in assembly_p_buf:
                    continue
                maybe_keep_buf[key].append(ct)
                assembly_p_buf[key].append(assembly_pt)

            elif assembly_header in [M_S_HEADER, M_E_HEADER]:

                if assembly_header == M_S_HEADER:
                    maybe_keep_buf[key] = [ct]
                    depadded            = rm_padding_bytes(assembly_pt)
                    decompressed        = zlib.decompress(depadded)
                else:
                    if key not in assembly_p_buf:
                        continue
                    maybe_keep_buf[key].append(ct)
                    assembly_p_buf[key].append(assembly_pt)

                    buffered_pt  = b''.join(assembly_p_buf.pop(key))
                    inner_layer  = rm_padding_bytes(buffered_pt)
                    decrypted    = auth_and_decrypt(nonce_ct_tag=inner_layer[:-KEY_LENGTH],
                                                    key         =inner_layer[-KEY_LENGTH:])
                    decompressed = zlib.decompress(decrypted)

                # The message is assembled by this point. We thus know if the
                # long message was a group message, and if it's to be removed.
                header = decompressed[:1]

                if header == PRIVATE_MESSAGE_HEADER:
                    ct_to_keep.extend(maybe_keep_buf.pop(key))

                elif header == GROUP_MESSAGE_HEADER:
                    group_name, *_ = [f.decode() for f in decompressed[1+GROUP_MSG_ID_LEN:].split(US_BYTE)]  # type: Tuple[str, Union[str, List[str]]]
                    if group_name == selector:
                        removed = True
                    else:
                        ct_to_keep.extend(maybe_keep_buf[key])
                    maybe_keep_buf.pop(key)

                elif header in [GROUP_MSG_INVITEJOIN_HEADER, GROUP_MSG_MEMBER_ADD_HEADER,
                                GROUP_MSG_MEMBER_REM_HEADER, GROUP_MSG_EXIT_GROUP_HEADER]:
                    group_name, *_ = [f.decode() for f in decompressed[1:].split(US_BYTE)]
                    if group_name == selector:
                        removed = True
                    else:
                        ct_to_keep.extend(maybe_keep_buf[key])
                    maybe_keep_buf.pop(key)

    log_file.close()

    with open(file_name, 'wb+') as f:
        if ct_to_keep:
            f.write(b''.join(ct_to_keep))

    w_type = {WIN_TYPE_GROUP: 'group', WIN_TYPE_CONTACT: 'contact'}[window_type]

    if not removed:
        raise FunctionReturn(f"Found no log entries for {w_type} '{selector}'")

    c_print(f"Removed log entries for {w_type} '{selector}'", head=1, tail=1)
