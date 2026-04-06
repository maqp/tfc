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

from src.common.entities.serialized_command import SerializedCommand
from src.common.exceptions import SoftError
from src.common.statics import ContactSettingKey, ContactSettingValue, RxCommand, ContactSettingValueHeader, WindowType
from src.common.types_custom import BoolFileReception, BoolLogMessages, BoolShowNotifications
from src.transmitter.queue_packet.queue_packet import queue_command

if TYPE_CHECKING:
    from src.common.queues import TxQueue
    from src.database.db_contacts import ContactList
    from src.database.db_groups import GroupList
    from src.database.db_settings import Settings
    from src.ui.transmitter.user_input import UserInput
    from src.ui.transmitter.window_tx import TxWindow


def change_contact_setting(settings     : 'Settings',
                           queues       : 'TxQueue',
                           window       : 'TxWindow',
                           contact_list : 'ContactList',
                           group_list   : 'GroupList',
                           user_input   : 'UserInput',
                           ) -> None:
    """\
    Change logging, file reception, or notification setting of a group
    or (all) contact(s).
    """
    # ┌──────────────┐
    # │ Parse Fields │
    # └──────────────┘
    try:
        parameters = user_input.plaintext.split()
        setting_k  = parameters[0]
        setting_v  = parameters[1]
    except IndexError:
        missing = 'key and value' if len(user_input.plaintext.split()) == 2 else 'value'
        raise SoftError(f'Error: missing setting {missing}.', clear_before=True)

    try:
        setting_a = parameters[2]
    except IndexError:
        setting_a = None

    # ┌─────────────────┐
    # │ Validate Fields │
    # └─────────────────┘
    try:
        setting_key = ContactSettingKey(setting_k)
    except ValueError:
        raise SoftError('Error: Invalid setting.', clear_before=True)

    try:
        enable = ContactSettingValue(setting_v) == ContactSettingValue.ON
    except ValueError:
        raise SoftError('Error: Invalid setting value.', clear_before=True)

    if setting_a is not None and setting_a != 'all':
        raise SoftError("Error: Second parameter can only be 'all'.", clear_before=True)

    change_all = False
    if setting_a is not None and setting_a == 'all':
        change_all = True

    # ┌─────────────────────────────┐
    # │ Apply setting value locally │
    # └─────────────────────────────┘

    if setting_key == ContactSettingKey.LOGGING:
        log_setting = BoolLogMessages(enable)
        if change_all: change_logging_for_all_contacts   (log_setting, contact_list, group_list)
        else:          change_logging_for_selected_window(log_setting, contact_list, group_list, window)

        if settings.traffic_masking:
            # Send `log_writer_loop` the new logging setting that is loaded
            # when the next noise packet is loaded from `noise_packet_loop`.
            queues.log_setting.put(log_setting)
        rx_command = RxCommand.CH_LOGGING

    elif setting_key == ContactSettingKey.STORE:
        file_reception_setting = BoolFileReception(enable)
        if change_all: change_file_reception_for_all_contacts   (file_reception_setting, contact_list)
        else:          change_file_reception_for_selected_window(file_reception_setting, contact_list, window)
        rx_command = RxCommand.CH_FILE_RECV

    else:
        notification_setting = BoolShowNotifications(enable)
        if change_all: change_notifications_for_all_contacts   (notification_setting, contact_list, group_list)
        else:          change_notifications_for_selected_window(notification_setting, contact_list, group_list, window)
        rx_command = RxCommand.CH_NOTIFY

    if enable: value_header = ContactSettingValueHeader.ENABLE_ALL.value  if change_all else ContactSettingValueHeader.ENABLE.value
    else:      value_header = ContactSettingValueHeader.DISABLE_ALL.value if change_all else ContactSettingValueHeader.DISABLE.value

    if change_all: command = SerializedCommand(rx_command, value_header)
    else:          command = SerializedCommand(rx_command, value_header + window.uid_bytes)
    queue_command(settings, queues, command)


def change_logging_for_selected_window(bool_setting : BoolLogMessages,
                                       contact_list : 'ContactList',
                                       group_list   : 'GroupList',
                                       window       : 'TxWindow',
                                       ) -> None:
    """Change the logging setting for the selected window."""
    if window.window_type == WindowType.CONTACT and window.contact is not None:
        window.contact.log_messages = bool_setting
        contact_list.store_contacts()

    if window.window_type == WindowType.GROUP and window.group is not None:
        window.group.log_messages = bool_setting
        group_list.store_groups()


def change_file_reception_for_selected_window(bool_setting : BoolFileReception,
                                              contact_list : 'ContactList',
                                              window       : 'TxWindow',
                                              ) -> None:
    """Change the file-reception setting for the selected window."""
    if window.window_type == WindowType.CONTACT and window.contact is not None:
        window.contact.file_reception = bool_setting
        contact_list.store_contacts()

    if window.window_type == WindowType.GROUP and window.group is not None:
        for contact in window:
            contact.file_reception = bool_setting
        contact_list.store_contacts()


def change_notifications_for_selected_window(bool_setting : BoolShowNotifications,
                                             contact_list : 'ContactList',
                                             group_list   : 'GroupList',
                                             window       : 'TxWindow',
                                             ) -> None:
    """Change the notification setting for the selected window."""
    if window.window_type == WindowType.CONTACT and window.contact is not None:
        window.contact.notifications = bool_setting
        contact_list.store_contacts()

    if window.window_type == WindowType.GROUP and window.group is not None:
        window.group.notifications = bool_setting
        group_list.store_groups()


def change_logging_for_all_contacts(bool_setting : BoolLogMessages,
                                    contact_list : 'ContactList',
                                    group_list   : 'GroupList'
                                    ) -> None:
    """Change the logging setting for all contacts and groups."""
    for contact in contact_list:
        contact.log_messages = bool_setting
    contact_list.store_contacts()

    for group in group_list:
        group.log_messages = bool_setting
    group_list.store_groups()


def change_file_reception_for_all_contacts(bool_setting : BoolFileReception,
                                           contact_list : 'ContactList',
                                           ) -> None:
    """Change the file-reception setting for all contacts."""
    for contact in contact_list:
        contact.file_reception = bool_setting
    contact_list.store_contacts()


def change_notifications_for_all_contacts(bool_setting : BoolShowNotifications,
                                          contact_list : 'ContactList',
                                          group_list   : 'GroupList'
                                          ) -> None:
    """Change the notification setting for all contacts and groups."""
    for contact in contact_list:
        contact.notifications = bool_setting
    contact_list.store_contacts()

    for group in group_list:
        group.notifications = bool_setting
    group_list.store_groups()
