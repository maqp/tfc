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

import os
import typing

from typing import Any, Dict

from src.common.db_logs   import access_history, re_encrypt
from src.common.encoding  import bytes_to_int
from src.common.errors    import FunctionReturn, graceful_exit
from src.common.misc      import clear_screen, ensure_dir, validate_nick
from src.common.output    import box_print, phase, print_on_previous_line
from src.common.statics   import *
from src.rx.commands_g    import group_add_member, group_create, group_rm_member, remove_group
from src.rx.key_exchanges import ecdhe_command, local_key_installed, psk_command, psk_import
from src.rx.packet        import decrypt_assembly_packet

if typing.TYPE_CHECKING:
    from datetime                import datetime
    from src.common.db_contacts  import ContactList
    from src.common.db_groups    import GroupList
    from src.common.db_keys      import KeyList
    from src.common.db_masterkey import MasterKey
    from src.common.db_settings  import Settings
    from src.rx.packet           import PacketList
    from src.rx.windows          import WindowList


def process_command(ts:                 'datetime',
                    assembly_packet_ct: bytes,
                    window_list:        'WindowList',
                    packet_list:        'PacketList',
                    contact_list:       'ContactList',
                    key_list:           'KeyList',
                    group_list:         'GroupList',
                    settings:           'Settings',
                    master_key:         'MasterKey',
                    pubkey_buf:         Dict[str, str]) -> None:
    """Decrypt command assembly packet and process command."""

    assembly_packet, account, origin = decrypt_assembly_packet(assembly_packet_ct,
                                                               window_list,
                                                               contact_list,
                                                               key_list)

    cmd_packet = packet_list.get_packet(account, origin, 'command')
    cmd_packet.add_packet(assembly_packet)

    if not cmd_packet.is_complete:
        return None

    command  = cmd_packet.assemble_command_packet()
    header   = command[:2]
    cmd_data = command[2:]

    #             Keyword                       Function to run     (                                     Parameters                                    )
    #             ---------------------------------------------------------------------------------------------------------------------------------------
    function_d = {LOCAL_KEY_INSTALLED_HEADER:  (local_key_installed,           ts, window_list, contact_list                                            ),
                  SHOW_WINDOW_ACTIVITY_HEADER: (show_win_activity,                 window_list                                                          ),
                  WINDOW_CHANGE_HEADER:        (select_win_cmd,      cmd_data,     window_list                                                          ),
                  CLEAR_SCREEN_HEADER:         (clear_active_window,                                                                                    ),
                  RESET_SCREEN_HEADER:         (reset_active_window, cmd_data,     window_list                                                          ),
                  EXIT_PROGRAM_HEADER:         (graceful_exit,                                                                                          ),
                  LOG_DISPLAY_HEADER:          (display_logs,        cmd_data,     window_list, contact_list,                       settings, master_key),
                  LOG_EXPORT_HEADER:           (export_logs,         cmd_data, ts, window_list, contact_list,                       settings, master_key),
                  CHANGE_MASTER_K_HEADER:      (change_master_key,             ts, window_list, contact_list, group_list, key_list, settings, master_key),
                  CHANGE_NICK_HEADER:          (change_nick,         cmd_data, ts, window_list, contact_list, group_list                                ),
                  CHANGE_SETTING_HEADER:       (change_setting,      cmd_data, ts, window_list, contact_list, group_list,           settings,           ),
                  CHANGE_LOGGING_HEADER:       (contact_setting,     cmd_data, ts, window_list, contact_list, group_list,                     'L'       ),
                  CHANGE_FILE_R_HEADER:        (contact_setting,     cmd_data, ts, window_list, contact_list, group_list,                     'F'       ),
                  CHANGE_NOTIFY_HEADER:        (contact_setting,     cmd_data, ts, window_list, contact_list, group_list,                     'N'       ),
                  GROUP_CREATE_HEADER:         (group_create,        cmd_data, ts, window_list, contact_list, group_list,           settings            ),
                  GROUP_ADD_HEADER:            (group_add_member,    cmd_data, ts, window_list, contact_list, group_list,           settings            ),
                  GROUP_REMOVE_M_HEADER:       (group_rm_member,     cmd_data, ts, window_list, contact_list, group_list,                               ),
                  GROUP_DELETE_HEADER:         (remove_group,        cmd_data, ts, window_list,               group_list,                               ),
                  KEY_EX_ECDHE_HEADER:         (ecdhe_command,       cmd_data, ts, window_list, contact_list,             key_list, settings, pubkey_buf),
                  KEY_EX_PSK_TX_HEADER:        (psk_command,         cmd_data, ts, window_list, contact_list,             key_list, settings, pubkey_buf),
                  KEY_EX_PSK_RX_HEADER:        (psk_import,          cmd_data, ts, window_list, contact_list,             key_list, settings            ),
                  CONTACT_REMOVE_HEADER:       (remove_contact,      cmd_data, ts, window_list, contact_list, group_list, key_list,                     )}  # type: Dict[bytes, Any]

    if header not in function_d:
        raise FunctionReturn("Received packet had an invalid command header.")

    from_dict  = function_d[header]
    func       = from_dict[0]
    parameters = from_dict[1:]
    func(*parameters)


def show_win_activity(window_list: 'WindowList') -> None:
    """Show number of unread messages in each window."""
    unread_wins = [w for w in window_list if (w.uid != 'local' and w.unread_messages > 0)]
    print_list  = ["Window activity"] if unread_wins else ["No window activity"]
    for w in unread_wins:
        print_list.append(f"{w.name}: {w.unread_messages}")
    box_print(print_list)
    print_on_previous_line(reps=(len(print_list) + 2), delay=1.5)


def select_win_cmd(cmd_data: bytes, window_list: 'WindowList') -> None:
    """Select window specified by TxM."""
    window_uid = cmd_data.decode()
    if cmd_data == FILE_R_WIN_ID_BYTES:
        clear_screen()
    window_list.select_rx_window(window_uid)


def clear_active_window() -> None:
    """Clear active screen."""
    clear_screen()


def reset_active_window(cmd_data: bytes, window_list: 'WindowList') -> None:
    """Reset window specified by TxM."""
    uid    = cmd_data.decode()
    window = window_list.get_window(uid)
    window.reset_window()


def display_logs(cmd_data: bytes,
                 window_list:  'WindowList',
                 contact_list: 'ContactList',
                 settings:     'Settings',
                 master_key:   'MasterKey') -> None:
    """Display log file for active window."""
    win_uid, no_msg_bytes = cmd_data.split(US_BYTE)
    no_messages           = bytes_to_int(no_msg_bytes)
    window                = window_list.get_window(win_uid.decode())
    access_history(window, contact_list, settings, master_key, msg_to_load=no_messages)


def export_logs(cmd_data:     bytes,
                ts:           'datetime',
                window_list:  'WindowList',
                contact_list: 'ContactList',
                settings:     'Settings',
                master_key:   'MasterKey') -> None:
    """Export log file for active window."""
    win_uid, no_msg_bytes = cmd_data.split(US_BYTE)
    no_messages           = bytes_to_int(no_msg_bytes)
    window                = window_list.get_window(win_uid.decode())
    access_history(window, contact_list, settings, master_key, msg_to_load=no_messages, export=True)

    local_win = window_list.get_window('local')
    local_win.print_new(ts, f"Exported logfile of {window.type} {window.name}.")


def change_master_key(ts:           'datetime',
                      window_list:  'WindowList',
                      contact_list: 'ContactList',
                      group_list:   'GroupList',
                      key_list:     'KeyList',
                      settings:     'Settings',
                      master_key:   'MasterKey') -> None:
    """Derive new master key based on master password delivered by TxM."""
    old_master_key = master_key.master_key[:]
    master_key.new_master_key()
    new_master_key = master_key.master_key

    ensure_dir(f'{DIR_USER_DATA}/')
    file_name = f'{DIR_USER_DATA}/{settings.software_operation}_logs'
    if os.path.isfile(file_name):
        phase("Re-encrypting log-file")
        re_encrypt(old_master_key, new_master_key, settings)
        phase('Done')

    key_list.store_keys()
    settings.store_settings()
    contact_list.store_contacts()
    group_list.store_groups()

    box_print("Master key successfully changed.", head=1)
    clear_screen(delay=1.5)

    local_win = window_list.get_window('local')
    local_win.print_new(ts, "Changed RxM master key.", print_=False)


def change_nick(cmd_data:     bytes,
                ts:           'datetime',
                window_list:  'WindowList',
                contact_list: 'ContactList',
                group_list:   'GroupList') -> None:
    """Change contact nick."""
    account, nick      = [f.decode() for f in cmd_data.split(US_BYTE)]
    success, error_msg = validate_nick(nick, (contact_list, group_list, account))
    if not success:
        raise FunctionReturn(error_msg)

    c_window      = window_list.get_window(account)
    c_window.name = nick
    contact       = contact_list.get_contact(account)
    contact.nick  = nick
    contact_list.store_contacts()

    cmd_win = window_list.get_local_window()
    cmd_win.print_new(ts, f"Changed {account} nick to {nick}.")


def change_setting(cmd_data:     bytes,
                   ts:           'datetime',
                   window_list:  'WindowList',
                   contact_list: 'ContactList',
                   group_list:   'GroupList',
                   settings:     'Settings') -> None:
    """Change TFC setting."""
    key, value = [f.decode() for f in cmd_data.split(US_BYTE)]

    if key not in settings.key_list:
        raise FunctionReturn(f"Invalid setting {key}.")

    settings.change_setting(key, value, contact_list, group_list)
    local_win = window_list.get_local_window()
    local_win.print_new(ts, f"Changed setting {key} to {value}.")


def contact_setting(cmd_data:     bytes,
                    ts:           'datetime',
                    window_list:  'WindowList',
                    contact_list: 'ContactList',
                    group_list:   'GroupList',
                    setting_type: str) -> None:
    """Change contact/group related setting."""
    attr = dict(L='log_messages',
                F='file_reception',
                N='notifications')[setting_type]

    desc = dict(L='logging of messages',
                F='reception of files',
                N='message notifications')[setting_type]

    if cmd_data[:1].islower():

        setting, win_uid, = [f.decode() for f in cmd_data.split(US_BYTE)]

        if not window_list.has_window(win_uid):
            raise FunctionReturn(f"Error: Found no window for {win_uid}.")

        b_value, header = dict(e=(True, "Enabled"), d=(False, "Disabled"))[setting]
        window          = window_list.get_window(win_uid)
        trailer         = f"for {window.type} {window.name}"

        if window.type == 'group' and setting_type == 'F':
            trailer = f"for members in group {window.name}"

        if window.type == 'group':
            group = group_list.get_group(win_uid)
            if setting_type == 'F':
                for c in contact_list:
                    c.file_reception = b_value
                contact_list.store_contacts()
            else:
                setattr(group, attr, b_value)
                group_list.store_groups()

        elif window.type == 'contact':
            contact = contact_list.get_contact(win_uid)
            setattr(contact, attr, b_value)
            contact_list.store_contacts()

    # For all
    else:
        setting         = cmd_data[:1].decode()
        b_value, header = dict(E=(True, "Enabled"), D=(False, "Disabled"))[setting]
        trailer         = "for all contacts" + (' and groups' if setting_type != 'F' else '')

        for c in contact_list:
            setattr(c, attr, b_value)
        contact_list.store_contacts()

        if setting_type != 'F':
            for g in group_list:
                setattr(g, attr, b_value)
            group_list.store_groups()

    local_win = window_list.get_window('local')
    local_win.print_new(ts, f"{header} {desc} {trailer}.")


def remove_contact(cmd_data:     bytes,
                   ts:           'datetime',
                   window_list:  'WindowList',
                   contact_list: 'ContactList',
                   group_list:   'GroupList',
                   key_list:     'KeyList') -> None:
    """Remove contact from RxM."""
    rx_account = cmd_data.decode()

    key_list.remove_keyset(rx_account)

    if rx_account in contact_list.get_list_of_accounts():
        nick = contact_list.get_contact(rx_account).nick
        contact_list.remove_contact(rx_account)
        box_print(f"Removed {nick} from contacts.", head=1, tail=1)

        local_win = window_list.get_local_window()
        local_win.print_new(ts, f"Removed {nick} from RxM.", print_=False)

    else:
        box_print(f"RxM has no account {rx_account} to remove.",  head=1, tail=1)

    if any([g.remove_members([rx_account]) for g in group_list]):
        box_print(f"Removed {rx_account} from group(s).", tail=1)
