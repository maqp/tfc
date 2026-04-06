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

import os
import shutil
import struct
import subprocess
import sys
import textwrap
import time

from datetime import datetime
from typing import Iterator, Optional as O, TYPE_CHECKING

import nacl.exceptions

from src.common.entities.assembly_packet import MessageAssemblyPacket
from src.common.entities.group_id import GroupID
from src.common.entities.payload import MessagePayload
from src.common.entities.payload_buffer import PayloadBuffer
from src.common.crypto.keys.onion_service_keys import OnionPublicKeyContact
from src.common.entities.window_uid import WindowUID
from src.common.exceptions import CriticalError, SoftError, ValidationError
from src.common.statics import (CompoundFieldLength, CryptoVarLength, DataDir, DBName, FieldLength,
                                MessageHeader, Origin, ProgramID, WindowType)
from src.common.types_custom import BoolRekeyDB, BoolExportLog, BoolIsWhisperedMessage, IntMsgToLoad
from src.common.utils.date_time import get_fname_safe_ts
from src.ui.common.output.vt100_utils import clear_screen
from src.ui.common.utils import get_terminal_width
from src.common.utils.encoding import b58encode, bytes_to_bool, bytes_to_timestamp
from src.common.utils.io import ensure_dir, get_working_dir
from src.common.utils.strings import separate_header, separate_headers
from src.ui.receiver.window_rx import Message, RxWindow, SystemMessage

if TYPE_CHECKING:
    from src.common.entities.assembly_packet import AssemblyPacket
    from src.common.entities.contact import Contact
    from src.database.db_contacts import ContactList
    from src.database.db_groups import GroupList
    from src.database.db_masterkey import MasterKey
    from src.database.db_settings import Settings
    from src.ui.transmitter.window_tx import TxWindow


MessageLogDict             = dict[datetime, Message | SystemMessage]
MessageLogPayloadDict      = dict[tuple[OnionPublicKeyContact, Origin], MessagePayload]
MessageLogPayloadEntryDict = dict[tuple[OnionPublicKeyContact, Origin], list[bytes]]


class MessageLog:
    """Flat encrypted message log with fixed-size ciphertext records."""

    def __init__(self,
                 master_key : 'MasterKey',
                 settings   : 'Settings'
                 ) -> None:
        self.settings   = settings
        self.master_key = master_key

        ensure_dir(self.database_dir)
        self.check_for_temp_database()

        if not os.path.isfile(self.path_to_db):
            self._write_file(self.path_to_db, b'')

    def __iter__(self) -> Iterator[bytes]:
        """Iterate over decrypted log entries."""
        yield from self._iter_plaintext_entries(self.path_to_db)

    # ┌───────────────────────────────────────────────────────────────────────────┐
    # │                            File Names and Paths                           │
    # └───────────────────────────────────────────────────────────────────────────┘

    @property
    def database_name(self) -> str:
        """Return the log database name."""
        return f'{self.settings.db_prefix}_{DBName.MESSAGE_LOG}'

    @property
    def database_dir(self) -> str:
        """Return the database directory."""
        return f'{get_working_dir()}/{DataDir.USER_DATA}'

    @property
    def path_to_db(self) -> str:
        """Return the path to the database."""
        return f'{self.database_dir}/{self.database_name}'

    @property
    def path_to_temp_db(self) -> str:
        """Return the path to the temporary database."""
        return f'{self.path_to_db}_temp'

    @property
    def path_to_rekey_db(self) -> str:
        """Return the path to the temporary rekey database."""
        return f'{self.path_to_db}_rekey'

    @property
    def ciphertext_length(self) -> int:
        """Return the length of one encrypted log entry."""
        return CompoundFieldLength.ENC_LOG_ENTRY

    # ┌───────────────────────────────────────────────────────────────────────────┐
    # │                              Database Storage                             │
    # └───────────────────────────────────────────────────────────────────────────┘

    @staticmethod
    def _write_file(path_to_file: str, data: bytes, mode: str = 'wb+') -> None:
        """Write data to file and flush it to disk."""
        with open(path_to_file, mode) as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())

    def _iter_ciphertext_entries(self, path_to_file: str) -> Iterator[bytes]:
        """Iterate over ciphertext entries in a flat log file."""
        with open(path_to_file, 'rb') as f:
            while True:
                ciphertext = f.read(self.ciphertext_length)

                if not ciphertext:
                    break

                if len(ciphertext) != self.ciphertext_length:
                    raise CriticalError(f'Invalid log database size for {path_to_file}.')

                yield ciphertext

    def _iter_plaintext_entries(self,
                                path_to_file : str,
                                rekey        : BoolRekeyDB = BoolRekeyDB(False)
                                ) -> Iterator[bytes]:
        """Iterate over decrypted plaintext entries in a flat log file."""
        for ciphertext in self._iter_ciphertext_entries(path_to_file):
            yield self.master_key.auth_and_decrypt(ciphertext,
                                                   database = path_to_file,
                                                   rekey    = rekey)

    def _store_entries(self,
                       path_to_file    : str,
                       plaintext_list  : list[bytes],
                       master_key      : 'MasterKey',
                       rekey           : BoolRekeyDB = BoolRekeyDB(False)
                       ) -> None:
        """Store plaintext entries to file encrypted with the provided key."""
        ciphertext = bytearray()

        for plaintext in plaintext_list:
            ciphertext.extend(master_key.encrypt_and_sign(plaintext, rekey=rekey))

        self._write_file(path_to_file, bytes(ciphertext))

    def insert_log_entry(self, pt_log_entry: bytes) -> None:
        """Encrypt and append a log entry to the database."""
        ciphertext = self.master_key.encrypt_and_sign(pt_log_entry)

        if len(ciphertext) != self.ciphertext_length:
            raise CriticalError('Invalid encrypted log entry length.')

        self._write_file(self.path_to_db, ciphertext, mode='ab')

    @staticmethod
    def write_log_entry(assembly_packet : 'AssemblyPacket',
                        onion_pub_key   : 'OnionPublicKeyContact',
                        message_log     : 'MessageLog',
                        origin          : Origin,
                        ) -> None:
        """Add an assembly packet to the encrypted log database."""
        timestamp = struct.pack('<L', int(time.time()))
        log_entry = onion_pub_key.public_bytes_raw + timestamp + origin.value + assembly_packet.raw_bytes

        if len(log_entry) != CompoundFieldLength.LOG_ENTRY:
            raise CriticalError('Invalid log entry length.')

        ensure_dir(DataDir.USER_DATA)
        message_log.insert_log_entry(log_entry)

    # ┌───────────────────────────────────────────────────────────────────────────┐
    # │                              Database Status                              │
    # └───────────────────────────────────────────────────────────────────────────┘

    def verify_file(self,
                    path_to_file : str,
                    rekey        : BoolRekeyDB = BoolRekeyDB(False)
                    ) -> bool:
        """Verify the integrity of a log file."""
        if not os.path.isfile(path_to_file):
            return False

        try:
            for ciphertext in self._iter_ciphertext_entries(path_to_file):
                self.master_key.auth_and_decrypt(ciphertext, rekey=rekey)
        except (CriticalError, nacl.exceptions.CryptoError, OSError):
            return False

        return True

    def check_for_temp_database(self) -> None:
        """Replace current database with a valid temp database if one exists."""
        if os.path.isfile(self.path_to_temp_db):
            if self.verify_file(self.path_to_temp_db):
                self.replace_database()
            else:
                os.remove(self.path_to_temp_db)

    @staticmethod
    def check_log_file_exists(file_name: str) -> None:
        """Check that the log file exists."""
        ensure_dir(DataDir.USER_DATA)
        if not os.path.isfile(file_name):
            raise SoftError('No log database available.')

    # ┌───────────────────────────────────────────────────────────────────────────┐
    # │                                  Getters                                  │
    # └───────────────────────────────────────────────────────────────────────────┘

    def access_logs(self,
                    window       : 'TxWindow | RxWindow',
                    contact_list : 'ContactList',
                    group_list   : 'GroupList',
                    msg_to_load  : IntMsgToLoad  = IntMsgToLoad(0),
                    export       : BoolExportLog = BoolExportLog(False)
                    ) -> None:
        """Load messages from the log database and display or export them."""
        message_payloads : MessageLogPayloadDict = {}
        message_log      : MessageLogDict        = {}
        group_msg_id     = b''

        MessageLog.check_log_file_exists(self.path_to_db)

        header_list = [CryptoVarLength.ONION_SERVICE_PUBLIC_KEY.value,
                       FieldLength.TIMESTAMP_SHORT.value,
                       FieldLength.ORIGIN_HEADER.value]

        for log_entry in self:

            enc_onion_address, timestamp_bytes, origin_header_bytes, assembly_packet \
                = separate_headers(log_entry, header_list)

            timestamp             = bytes_to_timestamp(timestamp_bytes)
            onion_pub_key_contact = OnionPublicKeyContact(enc_onion_address)
            contact               = contact_list.get_contact_by_pub_key(onion_pub_key_contact)
            origin                = Origin.USER if origin_header_bytes == Origin.USER.value else Origin.CONTACT

            if window.is_contact_window and window.window_uid != WindowUID.for_contact(contact):
                continue

            message_payload = MessageLog.get_message_payload(message_payloads,
                                                             onion_pub_key_contact,
                                                             origin)

            try:
                message_payload.add_assembly_packet(MessageAssemblyPacket(assembly_packet))
            except (CriticalError, SoftError):
                continue

            if not message_payload.is_complete:
                continue

            try:
                group_msg_id = MessageLog.add_complete_message_to_message_list(window,
                                                                               contact,
                                                                               timestamp,
                                                                               group_msg_id,
                                                                               message_log,
                                                                               message_payload,
                                                                               origin)
            except (SoftError, UnicodeError, ValueError):
                continue
            finally:
                message_payload.clear_assembly_packets()

        conversation_start = min(message_log) if message_log else None

        MessageLog.print_logs(MessageLog.limit_message_log(message_log, msg_to_load),
                              export,
                              msg_to_load,
                              window,
                              contact_list,
                              group_list,
                              self.settings,
                              conversation_start)

    @staticmethod
    def limit_message_log(message_log: MessageLogDict,
                          msg_to_load: IntMsgToLoad
                          ) -> MessageLogDict:
        """Return the full message log or only the last requested messages."""
        if msg_to_load == 0 or len(message_log) <= msg_to_load:
            return message_log
        return dict(list(message_log.items())[-msg_to_load:])

    @staticmethod
    def add_complete_message_to_message_list(window       : 'TxWindow | RxWindow',
                                             contact      : 'Contact',
                                             timestamp    : datetime,
                                             group_msg_id : bytes,
                                             message_log  : MessageLogDict,
                                             payload      : MessagePayload,
                                             origin       : Origin,
                                             ) -> bytes:
        """Add complete log file message to `message_log`."""
        whisper_byte, header, message = separate_headers(payload.assemble_message_packet(),
                                                         [FieldLength.MESSAGE_HEADER, FieldLength.MESSAGE_HEADER])

        whisper = BoolIsWhisperedMessage(bytes_to_bool(whisper_byte))

        if header == MessageHeader.PRIVATE_MESSAGE and window.window_type == WindowType.CONTACT:
            message_log[timestamp] = Message(timestamp    = timestamp,
                                             contact      = contact,
                                             msg_origin   = origin,
                                             msg_content  = message.decode(),
                                             is_whispered = whisper,
                                             is_event_msg = False)

        elif header == MessageHeader.GROUP_MESSAGE and window.window_type == WindowType.GROUP:
            purp_group_id, message = separate_header(message, FieldLength.GROUP_ID)
            if window.group is not None and purp_group_id != window.group.group_id:
                return group_msg_id

            purp_msg_id, message = separate_header(message, FieldLength.GROUP_MSG_ID)
            if origin == Origin.USER:
                if purp_msg_id == group_msg_id:
                    return group_msg_id
                group_msg_id = purp_msg_id

            message_log[timestamp] = Message(timestamp    = timestamp,
                                             contact      = contact,
                                             msg_origin   = origin,
                                             msg_content  = message.decode(),
                                             is_whispered = whisper,
                                             is_event_msg = False)

        return group_msg_id

    @staticmethod
    def print_logs(message_log        : MessageLogDict,
                   export             : BoolExportLog,
                   msg_to_load        : IntMsgToLoad,
                   window             : 'TxWindow | RxWindow',
                   contact_list       : 'ContactList',
                   group_list         : 'GroupList',
                   settings           : 'Settings',
                   conversation_start : O[datetime],
                   ) -> None:
        """Print list of logged messages to screen or export them to file."""
        if not message_log:
            raise SoftError(f"No logged messages for {window.window_type} '{window.window_name}'.", clear_before=True)

        terminal_width = get_terminal_width()

        m_dir = 'sent to' if settings.program_id == ProgramID.TX else 'to/from'

        export_file_dir  = os.path.abspath(DataDir.EXPORTED_LOGS)
        export_file_name = f'{settings.program_name} - Plaintext log ({window.window_name}) [{get_fname_safe_ts()}]'
        path_to_file     = os.path.join(export_file_dir, export_file_name)

        if export:
            ensure_dir(export_file_dir)

        f_name = open(path_to_file, 'w+', encoding='utf-8') if export else sys.stdout
        subset = f'{msg_to_load} most recent ' if msg_to_load != 0 else ''
        title  = textwrap.fill(f'Log file of {subset}message(s) {m_dir} {window.window_type} {window.window_name}',
                               terminal_width)

        payload_buffer         = PayloadBuffer()
        log_window             = RxWindow(settings, contact_list, group_list, payload_buffer, window.window_uid)
        log_window.is_active   = True
        log_window.message_log = message_log

        try:
            first_displayed_message = min(message_log)
            log_window.last_read_msg_timestamp = first_displayed_message

            if not export:
                clear_screen()
            print(title,                 file=f_name)
            print(terminal_width * '═',  file=f_name)
            print(f'Conversation started on {(conversation_start or first_displayed_message):%Y-%m-%d}', file=f_name)
            log_window.redraw(           file=f_name, show_unread_marker=False)
            print('<End of log file>\n', file=f_name)
        finally:
            if export:
                f_name.close()

        if export:
            MessageLog.open_export_directory(export_file_dir)

    @staticmethod
    def open_export_directory(directory: str) -> None:
        """Open the exported-log directory with xdg-open when available."""
        xdg_open = shutil.which('xdg-open')
        if xdg_open is None:
            return

        try:
            subprocess.Popen([xdg_open, os.path.abspath(directory)],
                             stdin             = subprocess.DEVNULL,
                             stdout            = subprocess.DEVNULL,
                             stderr            = subprocess.DEVNULL,
                             start_new_session = True)
        except OSError:
            return

    # ┌───────────────────────────────────────────────────────────────────────────┐
    # │                                  Deleters                                 │
    # └───────────────────────────────────────────────────────────────────────────┘

    def remove_logs(self,
                    contact_list : 'ContactList',
                    group_list   : 'GroupList',
                    selector     : bytes
                    ) -> None:
        """Remove log entries for selector (public key of an account/group ID)."""
        ensure_dir(DataDir.USER_DATA)

        message_payloads    : MessageLogPayloadDict      = {}
        payload_log_entries : MessageLogPayloadEntryDict = {}
        entries_to_keep     = []  # type: list[bytes]
        removed             = False

        selector, contact = self.normalize_log_selector(selector)

        MessageLog.check_log_file_exists(self.path_to_db)

        header_list = [CryptoVarLength.ONION_SERVICE_PUBLIC_KEY.value,
                       FieldLength.TIMESTAMP_SHORT.value,
                       FieldLength.ORIGIN_HEADER.value]

        for log_entry in self:

            enc_onion_addr, _timestamp, origin_header_bytes, assembly_packet = separate_headers(log_entry, header_list)

            origin        = Origin.USER if origin_header_bytes == Origin.USER.value else Origin.CONTACT
            onion_pub_key = OnionPublicKeyContact(enc_onion_addr)

            if contact:
                if onion_pub_key.public_bytes_raw == selector:
                    removed = True
                else:
                    entries_to_keep.append(log_entry)

            else:
                message_payload = MessageLog.get_message_payload    (message_payloads,    onion_pub_key, origin)
                log_entryies    = MessageLog.get_payload_log_entries(payload_log_entries, onion_pub_key, origin)

                try:
                    message_payload.add_assembly_packet(MessageAssemblyPacket(assembly_packet))
                except (CriticalError, SoftError):
                    log_entryies.clear()
                    continue

                log_entryies.append(log_entry)

                if not message_payload.is_complete:
                    continue

                try:
                    removed = MessageLog.check_message_payload_fate(entries_to_keep = entries_to_keep,
                                                                    payload         = message_payload,
                                                                    payload_entries = log_entryies,
                                                                    removed         = removed,
                                                                    selector        = selector)
                except (SoftError, UnicodeError, ValueError):
                    continue
                finally:
                    message_payload.clear_assembly_packets()
                    log_entryies.clear()

        self._store_entries(self.path_to_temp_db, entries_to_keep, self.master_key)
        self.replace_database()

        try:
            if contact:
                onion_pub_key = OnionPublicKeyContact(selector)
                handle        = contact_list.get_nick_by_pub_key(onion_pub_key).value
            else:
                handle = group_list.get_group_by_id(GroupID(selector)).group_name.value
        except KeyError:
            if contact:
                onion_pub_key = OnionPublicKeyContact(selector)
                handle        = onion_pub_key.short_address
            else:
                handle = b58encode(selector)

        action   = 'Removed' if removed else 'Found no'
        win_type = 'contact' if contact else 'group'

        raise SoftError(f"{action} log entries for {win_type} '{handle}'.")

    @staticmethod
    def normalize_log_selector(selector: bytes) -> tuple[bytes, bool]:
        """Normalize contact selectors to raw public bytes and identify selector type."""
        if len(selector) == CryptoVarLength.ONION_SERVICE_PUBLIC_KEY.value:
            return selector, True

        if len(selector) == FieldLength.ONION_ADDRESS.value:
            try:
                onion_pub_key = OnionPublicKeyContact.from_onion_address_bytes(selector)
            except (UnicodeError, ValidationError) as exc:
                raise SoftError('Error: Invalid account selector.', output=False) from exc
            return onion_pub_key.public_bytes_raw, True

        if len(selector) == FieldLength.GROUP_ID.value:
            return selector, False

        raise SoftError('Error: Invalid log selector.', output=False)

    @staticmethod
    def check_message_payload_fate(*,
                                   entries_to_keep : list[bytes],
                                   payload         : MessagePayload,
                                   payload_entries : list[bytes],
                                   removed         : bool,
                                   selector        : bytes
                                   ) -> bool:
        """Check whether the packet should be kept."""
        _, header, message = separate_headers(payload.assemble_message_packet(),
                                              [FieldLength.MESSAGE_HEADER, FieldLength.MESSAGE_HEADER])

        if header == MessageHeader.PRIVATE_MESSAGE:
            entries_to_keep.extend(payload_entries)

        elif header == MessageHeader.GROUP_MESSAGE:
            group_id, _ = separate_header(message, FieldLength.GROUP_ID)
            if group_id == selector:
                removed = True
            else:
                entries_to_keep.extend(payload_entries)

        return removed

    @staticmethod
    def get_message_payload(message_payloads : MessageLogPayloadDict,
                            onion_pub_key    : OnionPublicKeyContact,
                            origin           : Origin,
                            ) -> MessagePayload:
        """Get the local message payload accumulator for a contact and direction."""
        return message_payloads.setdefault((onion_pub_key, origin), MessagePayload())

    @staticmethod
    def get_payload_log_entries(payload_log_entries : MessageLogPayloadEntryDict,
                                onion_pub_key       : OnionPublicKeyContact,
                                origin              : Origin,
                                ) -> list[bytes]:
        """Get the local log entry list for a contact and direction."""
        return payload_log_entries.setdefault((onion_pub_key, origin), [])

    # ┌───────────────────────────────────────────────────────────────────────────┐
    # │                                  Rekeying                                 │
    # └───────────────────────────────────────────────────────────────────────────┘

    def rekey_to_temp_db(self, new_master_key: 'MasterKey') -> None:
        """Re-encrypt the log database to a temporary database file."""
        plaintext_entries = list(self)
        self._store_entries(self.path_to_rekey_db, plaintext_entries, new_master_key, rekey=BoolRekeyDB(True))

        if not self.verify_file(self.path_to_rekey_db, rekey=BoolRekeyDB(True)):
            raise CriticalError(f"Writing to database '{self.path_to_rekey_db}' failed verification.")

    def migrate_to_rekeyed_db(self) -> None:
        """Replace the active log database with the rekeyed copy."""
        os.replace(self.path_to_rekey_db, self.path_to_db)

    def replace_database(self) -> None:
        """Replace the active log database with the temp file."""
        if os.path.isfile(self.path_to_temp_db):
            os.replace(self.path_to_temp_db, self.path_to_db)
