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

import typing

from typing import Any, Dict

from src.common.db_logs import remove_logs
from src.common.encoding import onion_address_to_pub_key
from src.common.exceptions import SoftError
from src.common.input import box_input, yes
from src.common.misc import (
    ignored,
    validate_key_exchange,
    validate_nick,
    validate_onion_addr,
)
from src.common.output import m_print
from src.common.statics import (
    ALL,
    CH_FILE_RECV,
    CH_LOGGING,
    CH_NICKNAME,
    CH_NOTIFY,
    CONTACT_REM,
    DISABLE,
    ECDHE,
    ENABLE,
    KDB_REMOVE_ENTRY_HEADER,
    KEY_MANAGEMENT_QUEUE,
    LOGGING,
    LOG_SETTING_QUEUE,
    NOTIFY,
    ONION_ADDRESS_LENGTH,
    PSK,
    RELAY_PACKET_QUEUE,
    STORE,
    TRUNC_ADDRESS_LENGTH,
    UNENCRYPTED_ADD_NEW_CONTACT,
    UNENCRYPTED_DATAGRAM_HEADER,
    UNENCRYPTED_REM_CONTACT,
    WIN_TYPE_CONTACT,
    WIN_TYPE_GROUP,
)

from src.transmitter.commands_g import group_rename
from src.transmitter.key_exchanges import create_pre_shared_key, start_key_exchange
from src.transmitter.packet import queue_command, queue_to_nc

if typing.TYPE_CHECKING:
    from multiprocessing import Queue
    from src.common.db_contacts import ContactList
    from src.common.db_groups import GroupList
    from src.common.db_masterkey import MasterKey
    from src.common.db_onion import OnionService
    from src.common.db_settings import Settings
    from src.transmitter.user_input import UserInput
    from src.transmitter.windows import TxWindow

    QueueDict = Dict[bytes, Queue[Any]]


def add_new_contact(
    contact_list: "ContactList",
    group_list: "GroupList",
    settings: "Settings",
    queues: "QueueDict",
    onion_service: "OnionService",
) -> None:
    """Prompt for contact account details and initialize desired key exchange.

    This function requests the minimum amount of data about the
    recipient as possible. The TFC account of contact is the same as the
    Onion URL of contact's v3 Tor Onion Service. Since the accounts are
    random and hard to remember, the user has to choose a nickname for
    their contact. Finally, the user must select the key exchange method:
    ECDHE for convenience in a pre-quantum world, or PSK for situations
    where physical key exchange is possible, and ciphertext must remain
    secure even after sufficient QTMs are available to adversaries.

    Before starting the key exchange, Transmitter Program exports the
    public key of contact's Onion Service to Relay Program on their
    Networked Computer so that a connection to the contact can be
    established.
    """
    try:
        if settings.traffic_masking:
            raise SoftError(
                "Error: Command is disabled during traffic masking.", head_clear=True
            )

        if len(contact_list) >= settings.max_number_of_contacts:
            raise SoftError(
                f"Error: TFC settings only allow {settings.max_number_of_contacts} accounts.",
                head_clear=True,
            )

        m_print("Add new contact", head=1, bold=True, head_clear=True)

        m_print(
            [
                "Your TFC account is",
                onion_service.user_onion_address,
                "",
                "Warning!",
                "Anyone who knows this account",
                "can see when your TFC is online",
            ],
            box=True,
        )

        contact_address = box_input(
            "Contact account",
            expected_len=ONION_ADDRESS_LENGTH,
            validator=validate_onion_addr,
            validator_args=onion_service.user_onion_address,
        ).strip()
        onion_pub_key = onion_address_to_pub_key(contact_address)

        contact_nick = box_input(
            "Contact nick",
            expected_len=ONION_ADDRESS_LENGTH,  # Limited to 255 but such long nick is unpractical.
            validator=validate_nick,
            validator_args=(contact_list, group_list, onion_pub_key),
        ).strip()

        key_exchange = box_input(
            f"Key exchange ([{ECDHE}],PSK) ",
            default=ECDHE,
            expected_len=28,
            validator=validate_key_exchange,
        ).strip()

        relay_command = (
            UNENCRYPTED_DATAGRAM_HEADER + UNENCRYPTED_ADD_NEW_CONTACT + onion_pub_key
        )
        queue_to_nc(relay_command, queues[RELAY_PACKET_QUEUE])

        if key_exchange.upper() in ECDHE:
            start_key_exchange(
                onion_pub_key, contact_nick, contact_list, settings, queues
            )

        elif key_exchange.upper() in PSK:
            create_pre_shared_key(
                onion_pub_key,
                contact_nick,
                contact_list,
                settings,
                onion_service,
                queues,
            )

    except (EOFError, KeyboardInterrupt):
        raise SoftError("Contact creation aborted.", head=2, delay=1, tail_clear=True)


def remove_contact(
    user_input: "UserInput",
    window: "TxWindow",
    contact_list: "ContactList",
    group_list: "GroupList",
    settings: "Settings",
    queues: "QueueDict",
    master_key: "MasterKey",
) -> None:
    """Remove contact from TFC."""
    if settings.traffic_masking:
        raise SoftError(
            "Error: Command is disabled during traffic masking.", head_clear=True
        )

    try:
        selection = user_input.plaintext.split()[1]
    except IndexError:
        raise SoftError("Error: No account specified.", head_clear=True)

    if not yes(f"Remove contact '{selection}'?", abort=False, head=1):
        raise SoftError("Removal of contact aborted.", head=0, delay=1, tail_clear=True)

    if selection in contact_list.contact_selectors():
        onion_pub_key = contact_list.get_contact_by_address_or_nick(
            selection
        ).onion_pub_key

    else:
        if validate_onion_addr(selection):
            raise SoftError(
                "Error: Invalid selection.", head=0, delay=1, tail_clear=True
            )
        onion_pub_key = onion_address_to_pub_key(selection)

    receiver_command = CONTACT_REM + onion_pub_key
    queue_command(receiver_command, settings, queues)

    with ignored(SoftError):
        remove_logs(contact_list, group_list, settings, master_key, onion_pub_key)

    queues[KEY_MANAGEMENT_QUEUE].put((KDB_REMOVE_ENTRY_HEADER, onion_pub_key))

    relay_command = (
        UNENCRYPTED_DATAGRAM_HEADER + UNENCRYPTED_REM_CONTACT + onion_pub_key
    )
    queue_to_nc(relay_command, queues[RELAY_PACKET_QUEUE])

    target = determine_target(selection, onion_pub_key, contact_list)

    if any([g.remove_members([onion_pub_key]) for g in group_list]):
        m_print(f"Removed {target} from group(s).", tail=1)

    check_for_window_deselection(onion_pub_key, window, group_list)


def determine_target(
    selection: str, onion_pub_key: bytes, contact_list: "ContactList"
) -> str:
    """Determine name of the target that will be removed."""
    if onion_pub_key in contact_list.get_list_of_pub_keys():
        contact = contact_list.get_contact_by_pub_key(onion_pub_key)
        target = f"{contact.nick} ({contact.short_address})"
        contact_list.remove_contact_by_pub_key(onion_pub_key)
        m_print(f"Removed {target} from contacts.", head=1, tail=1)
    else:
        target = f"{selection[:TRUNC_ADDRESS_LENGTH]}"
        m_print(f"Transmitter has no {target} to remove.", head=1, tail=1)

    return target


def check_for_window_deselection(
    onion_pub_key: bytes, window: "TxWindow", group_list: "GroupList"
) -> None:
    """\
    Check if the window should be deselected after contact is removed.
    """
    if window.type == WIN_TYPE_CONTACT:
        if onion_pub_key == window.uid:
            window.deselect()
    if window.type == WIN_TYPE_GROUP:
        for c in window:
            if c.onion_pub_key == onion_pub_key:
                window.update_window(group_list)

                # If the last member of the group is removed, deselect
                # the group. Deselection is not done in
                # `TxWindow.update_window()` because it would prevent
                # selecting the empty group for group related commands
                # such as notifications.
                if not window.window_contacts:
                    window.deselect()


def change_nick(
    user_input: "UserInput",
    window: "TxWindow",
    contact_list: "ContactList",
    group_list: "GroupList",
    settings: "Settings",
    queues: "QueueDict",
) -> None:
    """Change nick of contact."""
    try:
        nick = user_input.plaintext.split()[1]
    except IndexError:
        raise SoftError("Error: No nick specified.", head_clear=True)

    if window.type == WIN_TYPE_GROUP:
        group_rename(nick, window, contact_list, group_list, settings, queues)

    if window.contact is None:
        raise SoftError("Error: Window does not have contact.")

    onion_pub_key = window.contact.onion_pub_key
    error_msg = validate_nick(nick, (contact_list, group_list, onion_pub_key))
    if error_msg:
        raise SoftError(error_msg, head_clear=True)

    window.contact.nick = nick
    window.name = nick
    contact_list.store_contacts()

    command = CH_NICKNAME + onion_pub_key + nick.encode()
    queue_command(command, settings, queues)


def contact_setting(
    user_input: "UserInput",
    window: "TxWindow",
    contact_list: "ContactList",
    group_list: "GroupList",
    settings: "Settings",
    queues: "QueueDict",
) -> None:
    """\
    Change logging, file reception, or notification setting of a group
    or (all) contact(s).
    """
    try:
        parameters = user_input.plaintext.split()
        cmd_key = parameters[0]
        cmd_header = {LOGGING: CH_LOGGING, STORE: CH_FILE_RECV, NOTIFY: CH_NOTIFY}[
            cmd_key
        ]

        setting, b_value = dict(on=(ENABLE, True), off=(DISABLE, False))[parameters[1]]

    except (IndexError, KeyError):
        raise SoftError("Error: Invalid command.", head_clear=True)

    # If second parameter 'all' is included, apply setting for all contacts and groups
    try:
        win_uid = b""
        if parameters[2] == ALL:
            cmd_value = setting.upper()
        else:
            raise SoftError("Error: Invalid command.", head_clear=True)
    except IndexError:
        win_uid = window.uid
        cmd_value = setting + win_uid

    if win_uid:
        change_setting_for_selected_contact(
            cmd_key, b_value, window, contact_list, group_list
        )

    else:
        change_setting_for_all_contacts(cmd_key, b_value, contact_list, group_list)

    command = cmd_header + cmd_value

    if settings.traffic_masking and cmd_key == LOGGING:
        # Send `log_writer_loop` the new logging setting that is loaded
        # when the next noise packet is loaded from `noise_packet_loop`.
        queues[LOG_SETTING_QUEUE].put(b_value)

    window.update_log_messages()

    queue_command(command, settings, queues)


def change_setting_for_selected_contact(
    cmd_key: str,
    b_value: bool,
    window: "TxWindow",
    contact_list: "ContactList",
    group_list: "GroupList",
) -> None:
    """Change setting for selected contact."""
    if window.type == WIN_TYPE_CONTACT and window.contact is not None:
        if cmd_key == LOGGING:
            window.contact.log_messages = b_value
        if cmd_key == STORE:
            window.contact.file_reception = b_value
        if cmd_key == NOTIFY:
            window.contact.notifications = b_value
        contact_list.store_contacts()

    if window.type == WIN_TYPE_GROUP and window.group is not None:
        if cmd_key == LOGGING:
            window.group.log_messages = b_value
        if cmd_key == STORE:
            for c in window:
                c.file_reception = b_value
        if cmd_key == NOTIFY:
            window.group.notifications = b_value
        group_list.store_groups()


def change_setting_for_all_contacts(
    cmd_key: str, b_value: bool, contact_list: "ContactList", group_list: "GroupList"
) -> None:
    """Change setting for all contacts."""
    for contact in contact_list:
        if cmd_key == LOGGING:
            contact.log_messages = b_value
        if cmd_key == STORE:
            contact.file_reception = b_value
        if cmd_key == NOTIFY:
            contact.notifications = b_value

    contact_list.store_contacts()

    for group in group_list:
        if cmd_key == LOGGING:
            group.log_messages = b_value
        if cmd_key == NOTIFY:
            group.notifications = b_value

    group_list.store_groups()
