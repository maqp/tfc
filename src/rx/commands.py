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

from typing import Any, Dict, Union

from src.common.db_logs    import access_logs, re_encrypt, remove_logs
from src.common.encoding   import bytes_to_int
from src.common.exceptions import FunctionReturn
from src.common.misc       import ensure_dir
from src.common.output     import box_print, clear_screen, phase, print_on_previous_line
from src.common.statics    import *

from src.rx.commands_g    import group_add_member, group_create, group_rm_member, remove_group
from src.rx.key_exchanges import add_psk_tx_keys, add_x25519_keys, import_psk_rx_keys, local_key_installed
from src.rx.packet        import decrypt_assembly_packet

if typing.TYPE_CHECKING:
    from datetime                import datetime
    from multiprocessing         import Queue
    from src.common.db_contacts  import Contact, ContactList
    from src.common.db_groups    import Group, GroupList
    from src.common.db_keys      import KeyList
    from src.common.db_masterkey import MasterKey
    from src.common.db_settings  import Settings
    from src.rx.packet           import PacketList
    from src.rx.windows          import WindowList


def process_command(ts:           'datetime',
                    assembly_ct:  bytes,
                    window_list:  'WindowList',
                    packet_list:  'PacketList',
                    contact_list: 'ContactList',
                    key_list:     'KeyList',
                    group_list:   'GroupList',
                    settings:     'Settings',
                    master_key:   'MasterKey',
                    pubkey_buf:   Dict[str, bytes],
                    exit_queue:   'Queue') -> None:
    """Decrypt command assembly packet and process command."""
    assembly_packet, account, origin = decrypt_assembly_packet(assembly_ct, window_list, contact_list, key_list)

    cmd_packet = packet_list.get_packet(account, origin, COMMAND)
    cmd_packet.add_packet(assembly_packet)

    if not cmd_packet.is_complete:
        raise FunctionReturn("Incomplete command.", output=False)

    command  = cmd_packet.assemble_command_packet()
    header   = command[:2]
    cmd_data = command[2:]

    #    Keyword                       Function to run     (                                      Parameters                                     )
    #    -----------------------------------------------------------------------------------------------------------------------------------------
    d = {LOCAL_KEY_INSTALLED_HEADER:  (local_key_installed,             ts, window_list, contact_list                                            ),
         SHOW_WINDOW_ACTIVITY_HEADER: (show_win_activity,                   window_list                                                          ),
         WINDOW_SELECT_HEADER:        (select_win_cmd,      cmd_data,       window_list                                                          ),
         CLEAR_SCREEN_HEADER:         (clear_active_window,                                                                                      ),
         RESET_SCREEN_HEADER:         (reset_active_window, cmd_data,       window_list                                                          ),
         EXIT_PROGRAM_HEADER:         (exit_tfc,                                                                                       exit_queue),
         LOG_DISPLAY_HEADER:          (log_command,         cmd_data, None, window_list, contact_list, group_list,           settings, master_key),
         LOG_EXPORT_HEADER:           (log_command,         cmd_data, ts,   window_list, contact_list, group_list,           settings, master_key),
         LOG_REMOVE_HEADER:           (remove_log,          cmd_data,                                                        settings, master_key),
         CHANGE_MASTER_K_HEADER:      (change_master_key,             ts,   window_list, contact_list, group_list, key_list, settings, master_key),
         CHANGE_NICK_HEADER:          (change_nick,         cmd_data, ts,   window_list, contact_list,                                           ),
         CHANGE_SETTING_HEADER:       (change_setting,      cmd_data, ts,   window_list, contact_list, group_list,           settings,           ),
         CHANGE_LOGGING_HEADER:       (contact_setting,     cmd_data, ts,   window_list, contact_list, group_list,                     header    ),
         CHANGE_FILE_R_HEADER:        (contact_setting,     cmd_data, ts,   window_list, contact_list, group_list,                     header    ),
         CHANGE_NOTIFY_HEADER:        (contact_setting,     cmd_data, ts,   window_list, contact_list, group_list,                     header    ),
         GROUP_CREATE_HEADER:         (group_create,        cmd_data, ts,   window_list, contact_list, group_list,           settings            ),
         GROUP_ADD_HEADER:            (group_add_member,    cmd_data, ts,   window_list, contact_list, group_list,           settings            ),
         GROUP_REMOVE_M_HEADER:       (group_rm_member,     cmd_data, ts,   window_list, contact_list, group_list,                               ),
         GROUP_DELETE_HEADER:         (remove_group,        cmd_data, ts,   window_list,               group_list,                               ),
         KEY_EX_X25519_HEADER:        (add_x25519_keys,     cmd_data, ts,   window_list, contact_list,             key_list, settings, pubkey_buf),
         KEY_EX_PSK_TX_HEADER:        (add_psk_tx_keys,     cmd_data, ts,   window_list, contact_list,             key_list, settings, pubkey_buf),
         KEY_EX_PSK_RX_HEADER:        (import_psk_rx_keys,  cmd_data, ts,   window_list, contact_list,             key_list, settings            ),
         CONTACT_REMOVE_HEADER:       (remove_contact,      cmd_data, ts,   window_list, contact_list, group_list, key_list,                     ),
         WIPE_USER_DATA_HEADER:       (wipe,                                                                                           exit_queue)}  # type: Dict[bytes, Any]

    try:
        from_dict = d[header]
    except KeyError:
        raise FunctionReturn("Error: Received an invalid command.")

    func       = from_dict[0]
    parameters = from_dict[1:]
    func(*parameters)


def show_win_activity(window_list: 'WindowList') -> None:
    """Show number of unread messages in each window."""
    unread_wins = [w for w in window_list if (w.uid != LOCAL_ID and w.unread_messages > 0)]
    print_list  = ["Window activity"] if unread_wins else ["No window activity"]
    print_list += [f"{w.name}: {w.unread_messages}" for w in unread_wins]

    box_print(print_list)
    print_on_previous_line(reps=(len(print_list) + 2), delay=1.5)


def select_win_cmd(cmd_data: bytes, window_list: 'WindowList') -> None:
    """Select window specified by TxM."""
    window_uid = cmd_data.decode()
    if window_uid == WIN_TYPE_FILE:
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
    os.system('reset')


def exit_tfc(exit_queue: 'Queue') -> None:
    """Exit TFC."""
    exit_queue.put(EXIT)


def log_command(cmd_data:     bytes,
                ts:           'datetime',
                window_list:  'WindowList',
                contact_list: 'ContactList',
                group_list:   'GroupList',
                settings:     'Settings',
                master_key:   'MasterKey') -> None:
    """Display or export logfile for active window."""
    export                = ts is not None
    win_uid, no_msg_bytes = cmd_data.split(US_BYTE)
    no_messages           = bytes_to_int(no_msg_bytes)
    window                = window_list.get_window(win_uid.decode())
    access_logs(window, contact_list, group_list, settings, master_key, msg_to_load=no_messages, export=export)

    if export:
        local_win = window_list.get_window(LOCAL_ID)
        local_win.add_new(ts, f"Exported logfile of {window.type_print} {window.name}.", output=True)


def remove_log(cmd_data:   bytes,
               settings:   'Settings',
               master_key: 'MasterKey') -> None:
    """Remove log entries for contact."""
    window_name = cmd_data.decode()
    remove_logs(window_name, settings, master_key)


def change_master_key(ts:           'datetime',
                      window_list:  'WindowList',
                      contact_list: 'ContactList',
                      group_list:   'GroupList',
                      key_list:     'KeyList',
                      settings:     'Settings',
                      master_key:   'MasterKey') -> None:
    """Prompt user for new master password and derive new master key from that."""
    try:
        old_master_key = master_key.master_key[:]
        master_key.new_master_key()

        phase("Re-encrypting databases")

        ensure_dir(DIR_USER_DATA)
        file_name = f'{DIR_USER_DATA}{settings.software_operation}_logs'
        if os.path.isfile(file_name):
            re_encrypt(old_master_key, master_key.master_key, settings)

        key_list.store_keys()
        settings.store_settings()
        contact_list.store_contacts()
        group_list.store_groups()

        phase(DONE)
        box_print("Master key successfully changed.", head=1)
        clear_screen(delay=1.5)

        local_win = window_list.get_window(LOCAL_ID)
        local_win.add_new(ts, "Changed RxM master key.")

    except KeyboardInterrupt:
        raise FunctionReturn("Password change aborted.", delay=1, head=3, tail_clear=True)


def change_nick(cmd_data:     bytes,
                ts:           'datetime',
                window_list:  'WindowList',
                contact_list: 'ContactList') -> None:
    """Change contact nick."""
    account, nick = [f.decode() for f in cmd_data.split(US_BYTE)]

    window      = window_list.get_window(account)
    window.name = nick

    window.handle_dict[account] = (contact_list.get_contact(account).nick
                                   if contact_list.has_contact(account) else account)

    contact_list.get_contact(account).nick = nick
    contact_list.store_contacts()

    cmd_win = window_list.get_local_window()
    cmd_win.add_new(ts, f"Changed {account} nick to '{nick}'", output=True)


def change_setting(cmd_data:     bytes,
                   ts:           'datetime',
                   window_list:  'WindowList',
                   contact_list: 'ContactList',
                   group_list:   'GroupList',
                   settings:     'Settings') -> None:
    """Change TFC setting."""
    setting, value = [f.decode() for f in cmd_data.split(US_BYTE)]

    if setting not in settings.key_list:
        raise FunctionReturn(f"Error: Invalid setting '{setting}'")

    settings.change_setting(setting, value, contact_list, group_list)

    local_win = window_list.get_local_window()
    local_win.add_new(ts, f"Changed setting {setting} to '{value}'", output=True)


def contact_setting(cmd_data:     bytes,
                    ts:           'datetime',
                    window_list:  'WindowList',
                    contact_list: 'ContactList',
                    group_list:   'GroupList',
                    header:       bytes) -> None:
    """Change contact/group related setting."""
    setting, win_uid = [f.decode() for f in cmd_data.split(US_BYTE)]

    attr, desc, file_cmd = {CHANGE_LOGGING_HEADER: ('log_messages',   'Logging of messages',   False),
                            CHANGE_FILE_R_HEADER:  ('file_reception', 'Reception of files',    True ),
                            CHANGE_NOTIFY_HEADER:  ('notifications',  'Message notifications', False)}[header]

    action, b_value = {ENABLE:  ('enable',  True),
                       DISABLE: ('disable', False)}[setting.lower().encode()]

    if setting.isupper():
        # Change settings for all contacts (and groups)
        enabled  = [getattr(c, attr) for c in contact_list.get_list_of_contacts()]
        enabled += [getattr(g, attr) for g in group_list] if not file_cmd else []
        status   = "was already" if ((    all(enabled) and     b_value)
                                  or (not any(enabled) and not b_value)) else 'has been'
        specifier = 'every '
        w_type    = 'contact'
        w_name    = '.' if file_cmd else ' and group.'

        # Set values
        for c in contact_list.get_list_of_contacts():
            setattr(c, attr, b_value)
        contact_list.store_contacts()

        if not file_cmd:
            for g in group_list:
                setattr(g, attr, b_value)
            group_list.store_groups()

    else:
        # Change setting for contacts in specified window
        if not window_list.has_window(win_uid):
            raise FunctionReturn(f"Error: Found no window for '{win_uid}'")
        window         = window_list.get_window(win_uid)
        group_window   = window.type == WIN_TYPE_GROUP
        contact_window = window.type == WIN_TYPE_CONTACT

        if contact_window:
            target = contact_list.get_contact(win_uid)  # type: Union[Contact, Group]
        else:
            target = group_list.get_group(win_uid)

        if file_cmd:
            enabled = [getattr(m, attr) for m in window.window_contacts]
            changed = not all(enabled) if b_value else any(enabled)
        else:
            changed = getattr(target, attr) != b_value
        status    = "has been"    if changed                     else "was already"
        specifier = 'members in ' if (file_cmd and group_window) else ''
        w_type    = window.type_print
        w_name    = f" {window.name}."

        # Set values
        if contact_window or (group_window and file_cmd):
            for c in window.window_contacts:
                setattr(c, attr, b_value)
            contact_list.store_contacts()

        elif window.type == WIN_TYPE_GROUP:
            setattr(group_list.get_group(win_uid), attr, b_value)
            group_list.store_groups()

    message   = f"{desc} {status} {action}d for {specifier}{w_type}{w_name}"
    local_win = window_list.get_window(LOCAL_ID)
    local_win.add_new(ts, message, output=True)


def remove_contact(cmd_data:     bytes,
                   ts:           'datetime',
                   window_list:  'WindowList',
                   contact_list: 'ContactList',
                   group_list:   'GroupList',
                   key_list:     'KeyList') -> None:
    """Remove contact from RxM."""
    rx_account = cmd_data.decode()

    key_list.remove_keyset(rx_account)
    window_list.remove_window(rx_account)

    if not contact_list.has_contact(rx_account):
        raise FunctionReturn(f"RxM has no account '{rx_account}' to remove.")

    nick = contact_list.get_contact(rx_account).nick
    contact_list.remove_contact(rx_account)

    message = f"Removed {nick} from contacts."
    box_print(message, head=1, tail=1)

    local_win = window_list.get_local_window()
    local_win.add_new(ts, message)

    if any([g.remove_members([rx_account]) for g in group_list]):
        box_print(f"Removed {rx_account} from group(s).", tail=1)


def wipe(exit_queue: 'Queue') -> None:
    """Reset terminals, wipe all user data on RxM and power off system.

    No effective RAM overwriting tool currently exists, so as long as TxM/RxM
    use FDE and DDR3 memory, recovery of user data becomes impossible very fast:

        https://www1.cs.fau.de/filepool/projects/coldboot/fares_coldboot.pdf
    """
    os.system('reset')
    exit_queue.put(WIPE)
