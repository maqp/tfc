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

import textwrap

from collections.abc import Sequence
from typing import Optional as O, TYPE_CHECKING

from src.common.exceptions import SoftError
from src.common.statics import KexStatus, KexType
from src.ui.common.output.vt100_utils import clear_screen
from src.ui.common.utils import get_terminal_width

if TYPE_CHECKING:
    from src.database.db_contacts import ContactList
    from src.database.db_groups import GroupList
    from src.database.db_settings import Settings
    from src.database.db_settings_gateway import GatewaySettings


class TablePrinter:
    """Render and print a terminal table."""

    DEFAULT_COLUMN_GAP = 3

    def __init__(self,
                 column_names: tuple[str, ...],
                 rows        : Sequence[tuple[str, ...]],
                 column_gaps : O[tuple[int, ...]] = None) -> None:
        if not column_names:
            raise ValueError('At least one column name is required.')

        if any(len(row) != len(column_names) for row in rows):
            raise ValueError('Every row must match the number of columns.')

        default_column_gaps = (self.DEFAULT_COLUMN_GAP,) * max(0, len(column_names) - 1)
        self.column_names = column_names
        self.rows = rows
        self.column_gaps = default_column_gaps if column_gaps is None else column_gaps

        if len(self.column_gaps) != max(0, len(column_names) - 1):
            raise ValueError('Column gaps must be specified for each non-final column.')

        self.column_widths = self._get_column_widths()

    @staticmethod
    def _get_cell_lines(value: str) -> list[str]:
        """Split a cell into display lines."""
        return value.split('\n')

    def _get_column_widths(self) -> tuple[int, ...]:
        """Return rendered widths for each column."""
        widths = []

        for index, column_name in enumerate(self.column_names):
            column_values = [column_name]
            column_values.extend(row[index] for row in self.rows)

            width = max(len(line) for value in column_values for line in self._get_cell_lines(value))
            widths.append(width)

        return tuple(widths)

    def _render_row(self, row: tuple[str, ...]) -> list[str]:
        """Render one logical row into one or more output lines."""
        cell_lines = [self._get_cell_lines(cell) for cell in row]
        line_count = max(len(lines) for lines in cell_lines)
        rendered   = []

        for line_index in range(line_count):
            line_parts = []

            for column_index, lines in enumerate(cell_lines):
                value = lines[line_index] if line_index < len(lines) else ''

                if column_index == len(cell_lines) - 1:
                    line_parts.append(value)
                else:
                    gap = self.column_gaps[column_index] * ' '
                    line_parts.append(f'{value:{self.column_widths[column_index]}}{gap}')

            rendered.append(''.join(line_parts))

        return rendered

    def get_column_start(self, column_index: int) -> int:
        """Return the display offset where a column starts."""
        if column_index < 0 or column_index >= len(self.column_names):
            raise ValueError('Column index is out of range.')

        return sum(self.column_widths[:column_index]) + sum(self.column_gaps[:column_index])

    def render(self) -> list[str]:
        """Render the whole table into display lines."""
        lines = self._render_row(self.column_names)
        lines.append(get_terminal_width() * '─')

        for row in self.rows:
            lines.extend(self._render_row(row))

        return lines

    def print(self) -> None:
        """Print the rendered table."""
        print('\n'.join(self.render()))


def print_table(column_names: tuple[str, ...], rows: Sequence[tuple[str, ...]]) -> None:
    """Print a terminal-wide table with aligned columns."""
    TablePrinter(column_names, rows).print()


def print_contacts(contact_list: 'ContactList') -> None:
    """Print the list of contacts.

    Neatly printed contact list allows easy contact management:
    It allows the user to check active logging, file reception and
    notification settings, as well as what key exchange was used
    and what is the state of that key exchange. The contact list
    also shows and what the account displayed by the Relay Program
    corresponds to what nick etc.
    """
    column_names = ('Contact',
                    'Account',
                    'Logging',
                    'Notify',
                    'Files',
                    'Key Ex')

    kex_dict = {KexStatus.KEX_STATUS_PENDING    : f'{KexType.ECDHE} (Pending)',
                KexStatus.KEX_STATUS_UNVERIFIED : f'{KexType.ECDHE} (Unverified)',
                KexStatus.KEX_STATUS_VERIFIED   : f'{KexType.ECDHE} (Verified)',
                KexStatus.KEX_STATUS_NO_RX_PSK  : f'{KexType.PSK}  (No contact key)',
                KexStatus.KEX_STATUS_HAS_RX_PSK : KexType.PSK}

    rows = []
    for contact in contact_list.get_list_of_contacts():
        rows.append((contact.nick.value,
                     contact.short_address,
                     'Yes' if contact.log_messages else 'No',
                     'Yes' if contact.notifications else 'No',
                     'Accept' if contact.file_reception else 'Reject',
                     kex_dict[KexStatus(contact.kex_status)]))

    clear_screen()
    print()
    TablePrinter(column_names, rows, column_gaps=(4, 4, 4, 4, 4)).print()
    print()
    print()


def print_groups(group_list: 'GroupList') -> None:
    """Print list of groups.

    Neatly printed group list allows easy group management, and it
    also allows the user to check active logging and notification
    setting, as well as what group ID Relay Program shows
    corresponds to what group, and which contacts are in the group.
    """
    column_names = ('Group',
                    'Group ID',
                    'Logging',
                    'Notify',
                    'Members')

    groups = list(group_list)

    rows = [(group.group_name.value,
             group.group_id.hr_value,
             'Yes' if group.log_messages else 'No',
             'Yes' if group.notifications else 'No',
             '')  for group in groups]

    printer = TablePrinter(column_names, rows, column_gaps=(4, 4, 4, 4))
    members_column_width = max(1, get_terminal_width() - printer.get_column_start(4))
    wrapper = textwrap.TextWrapper(width=members_column_width)

    rows = [(group.group_name.value,
             group.group_id.hr_value,
             'Yes' if group.log_messages else 'No',
             'Yes' if group.notifications else 'No',
             '<Empty group>' if group.empty() else wrapper.fill(', '.join(sorted(m.nick.value for m in group.members))))
            for group in groups]

    TablePrinter(column_names, rows, column_gaps=(4, 4, 4, 4)).print()
    print()


def print_system_settings(settings: 'Settings') -> None:
    """\
    Print list of settings, their current and
    default values, and setting descriptions.
    """
    desc_d = {
        # Common settings
        'disable_gui_dialog'            : 'True replaces GUI dialogs with CLI prompts',
        'max_number_of_group_members'   : 'Maximum number of members in a group',
        'max_number_of_groups'          : 'Maximum number of groups',
        'max_number_of_contacts'        : 'Maximum number of contacts',
        'log_messages_by_default'       : 'Default logging setting for new contacts/groups',
        'accept_files_by_default'       : 'Default file reception setting for new contacts',
        'show_notifications_by_default' : 'Default message notification setting for new contacts/groups',
        'log_file_masking'              : 'True hides real size of log file during traffic masking',
        'ask_password_for_log_access'   : 'False disables password prompt when viewing/exporting logs',

        # Transmitter settings
        'nc_bypass_messages'            : 'False removes Networked Computer bypass interrupt messages',
        'confirm_tm_files'              : 'True shows confirmation dialogue with traffic masking packet details',
        'double_space_exits'            : 'True exits, False clears screen with double space command',
        'traffic_masking'               : 'True enables traffic masking to hide metadata',
        'tm_static_delay'               : 'The static delay between traffic masking packets',
        'tm_random_delay'               : 'Max random delay for traffic masking timing obfuscation',
        'require_resends'               : 'True enables packet-gap tracking and on-disk resend caches',
        'autoreplay_times'              : 'Number of times each sent packet is replayed automatically',
        'autoreplay_loop'               : 'True replays the 50 most recent cached datagrams while the gateway is idle',

        # Relay settings
        'allow_contact_requests'        : 'When False, does not show TFC contact requests',

        # Receiver settings
        'new_message_notify_preview'    : 'When True, shows a preview of the received message',
        'new_message_notify_duration'   : 'Number of seconds new message notification appears',
        'max_decompress_size_mb'        : 'Max size Receiver accepts when decompressing file (in MB)'}

    column_names = ('Setting name',
                    'Current value',
                    'Default value',
                    'Description')
    terminal_width = get_terminal_width()
    rows = [(key,
             str(settings.get_setting_value(key)),
             str(settings.defaults[key]),
             '')
            for key in settings.defaults]
    printer = TablePrinter(column_names, rows, column_gaps=(3, 3, 3))
    description_indent = printer.get_column_start(3)

    if terminal_width < description_indent + 1:
        raise SoftError('Error: Screen width is too small.', clear_before=True)

    wrapper = textwrap.TextWrapper(width=max(1, terminal_width - description_indent))

    rows = [(key,
             str(settings.get_setting_value(key)),
             str(settings.defaults[key]),
             wrapper.fill(desc_d.get(key, 'No description available.')))
            for key in settings.defaults]

    clear_screen()
    print()
    TablePrinter(column_names, rows, column_gaps=(3, 3, 3)).print()


def print_gateway_settings(gateway: 'GatewaySettings') -> None:
    """\
    Print list of gateway settings, their current and
    default values, and setting descriptions.
    """
    desc_d = {'serial_baudrate'         : 'The speed of serial interface in bauds per second',
              'serial_error_correction' : 'Number of byte errors serial datagrams can recover from'}

    column_names = ('Serial interface setting',
                    'Current value',
                    'Default value',
                    'Description')
    terminal_width = get_terminal_width()
    rows = [(key,
             str(gateway.get_setting_value(key)),
             str(gateway.defaults[key]),
             '')
            for key in desc_d]

    printer = TablePrinter(column_names, rows, column_gaps=(8, 3, 3))

    description_indent = printer.get_column_start(3)

    if terminal_width < description_indent + 1:
        raise SoftError('Error: Screen width is too small.')

    wrapper = textwrap.TextWrapper(width=max(1, terminal_width - description_indent))

    rows = [(key,
             str(gateway.get_setting_value(key)),
             str(gateway.defaults[key]),
             wrapper.fill(desc_d[key]))
            for key in desc_d]

    print()
    TablePrinter(column_names, rows, column_gaps=(8, 3, 3)).print()
    print()
