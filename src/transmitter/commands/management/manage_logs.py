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

import struct

from src.common.crypto.keys.onion_service_keys import OnionPublicKeyContact
from src.common.entities.group_name import GroupName
from src.common.entities.serialized_command import SerializedCommand
from src.common.exceptions import SoftError, ValidationError
from src.common.statics import RxCommand, FieldLength
from src.common.types_custom import StrSelection, BoolExportLog, IntMsgToLoad
from src.common.utils.encoding import int_to_bytes, b58decode
from src.common.utils.validators import validate_onion_addr, validate_second_field
from src.database.db_logs import MessageLog
from src.transmitter.queue_packet.queue_packet import queue_command
from src.ui.common.input.get_yes import get_yes

if TYPE_CHECKING:
    from src.common.queues import TxQueue
    from src.database.db_contacts import ContactList
    from src.database.db_groups import GroupList
    from src.database.db_masterkey import MasterKey
    from src.database.db_settings import Settings
    from src.ui.transmitter.user_input import UserInput
    from src.ui.transmitter.window_tx import TxWindow


def log_command(settings     : 'Settings',
                queues       : 'TxQueue',
                window       : 'TxWindow',
                contact_list : 'ContactList',
                group_list   : 'GroupList',
                user_input   : 'UserInput',
                master_key   : 'MasterKey'
                ) -> None:
    """Display message logs or export them to plaintext file on TCBs.

    Transmitter Program processes sent, Receiver Program sent and
    received, messages of all participants in the active window.

    Having the capability to export the log file from the encrypted
    database is a bad idea, but as it's required by the GDPR
    (https://gdpr-info.eu/art-20-gdpr/), it should be done as securely
    as possible.

    Therefore, before allowing export, TFC will ask for the master
    password to ensure no unauthorized user who gains momentary
    access to the system can the export logs from the database.
    """
    cmd            = user_input.plaintext.split()[0]
    export, header = dict(export =(BoolExportLog( True), RxCommand.LOG_EXPORT),
                          history=(BoolExportLog(False), RxCommand.LOG_DISPLAY))[cmd]

    try:
        msg_to_load = IntMsgToLoad(int(user_input.plaintext.split()[1]))
    except ValueError:
        raise SoftError('Error: Invalid number of messages.', clear_before=True)
    except IndexError:
        msg_to_load = IntMsgToLoad(0)

    try:
        command = SerializedCommand(header, int_to_bytes(msg_to_load) + window.uid_bytes)
    except struct.error:
        raise SoftError('Error: Invalid number of messages.', clear_before=True)

    if export and not get_yes(f"Export logs for '{window.window_name}' in plaintext?", abort=False):
        raise SoftError('Log file export aborted.', clear_after=True, padding_top=0, clear_delay=1)

    authenticated = master_key.authenticate_action() if settings.ask_password_for_log_access else True

    if authenticated:
        queue_command(settings, queues, command)
        MessageLog(master_key, settings).access_logs(window, contact_list, group_list, msg_to_load, export=export)

        if export:
            raise SoftError(f"Exported log file of {window.window_type} '{window.window_name}'.", clear_before=True)


def remove_log(settings     : 'Settings',
               queues       : 'TxQueue',
               contact_list : 'ContactList',
               group_list   : 'GroupList',
               user_input   : 'UserInput',
               master_key   : 'MasterKey'
               ) -> None:
    """Remove log entries for contact or group."""
    selection = validate_second_field(user_input, key='contact or group')

    if not get_yes(f'Remove logs for {selection}?', abort=False, head=1):
        raise SoftError('Log file removal aborted.', clear_after=True, clear_delay=1, padding_top=0)

    selector = determine_selector(StrSelection(selection), contact_list, group_list)

    queue_command(settings, queues, SerializedCommand(RxCommand.LOG_REMOVE, selector))

    MessageLog(master_key, settings).remove_logs(contact_list, group_list, selector)


def determine_selector(selection    : StrSelection,
                       contact_list : 'ContactList',
                       group_list   : 'GroupList'
                       ) -> bytes:
    """Determine selector (group ID or Onion Service public key)."""
    if selection in contact_list.get_contact_selectors():
        selector_bytes = contact_list.get_contact_by_address_or_nick(selection).onion_pub_key.public_bytes_raw

    elif selection in group_list.get_list_of_group_names():
        selector_bytes = group_list.get_group(GroupName(selection)).group_id.raw_bytes

    elif len(selection) == FieldLength.ONION_ADDRESS:
        try:
            validate_onion_addr(selection)
        except ValidationError:
            raise SoftError('Error: Invalid account.', clear_before=True)

        selector_bytes = OnionPublicKeyContact.from_onion_address(selection).public_bytes_raw

    elif len(selection) == FieldLength.GROUP_ID_ENC:
        try:
            selector_bytes = b58decode(selection)
        except ValueError:
            raise SoftError('Error: Invalid group ID.', clear_before=True)

    else:
        raise SoftError('Error: Unknown selector.', clear_before=True)

    return selector_bytes
