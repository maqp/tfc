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

from typing import Any, Dict, Tuple, Union

from src.common.db_logs import (
    access_logs,
    change_log_db_key,
    remove_logs,
    replace_log_db,
)
from src.common.encoding import bytes_to_int, pub_key_to_short_address
from src.common.exceptions import SoftError
from src.common.misc import ignored, reset_terminal, separate_header
from src.common.output import clear_screen, m_print, phase, print_on_previous_line
from src.common.statics import (
    CH_FILE_RECV,
    CH_LOGGING,
    CH_MASTER_KEY,
    CH_NICKNAME,
    CH_NOTIFY,
    CH_SETTING,
    CLEAR_SCREEN,
    COMMAND,
    CONTACT_REM,
    CONTACT_SETTING_HEADER_LENGTH,
    DISABLE,
    DONE,
    ENABLE,
    ENCODED_INTEGER_LENGTH,
    ENCRYPTED_COMMAND_HEADER_LENGTH,
    EXIT,
    EXIT_PROGRAM,
    GROUP_ADD,
    GROUP_CREATE,
    GROUP_DELETE,
    GROUP_REMOVE,
    GROUP_RENAME,
    KEY_EX_ECDHE,
    KEY_EX_PSK_RX,
    KEY_EX_PSK_TX,
    LOCAL_KEY_RDY,
    LOCAL_PUBKEY,
    LOG_DISPLAY,
    LOG_EXPORT,
    LOG_REMOVE,
    ONION_SERVICE_PUBLIC_KEY_LENGTH,
    ORIGIN_USER_HEADER,
    RESET_SCREEN,
    US_BYTE,
    WIN_ACTIVITY,
    WIN_SELECT,
    WIN_TYPE_CONTACT,
    WIN_TYPE_GROUP,
    WIN_UID_COMMAND,
    WIN_UID_FILE,
    WIPE,
    WIPE_USR_DATA,
)

from src.receiver.commands_g import (
    group_add,
    group_create,
    group_delete,
    group_remove,
    group_rename,
)
from src.receiver.key_exchanges import (
    key_ex_ecdhe,
    key_ex_psk_rx,
    key_ex_psk_tx,
    local_key_rdy,
)
from src.receiver.packet import decrypt_assembly_packet

if typing.TYPE_CHECKING:
    from datetime import datetime
    from multiprocessing import Queue
    from src.common.db_contacts import Contact, ContactList
    from src.common.db_groups import Group, GroupList
    from src.common.db_keys import KeyList
    from src.common.db_masterkey import MasterKey
    from src.common.db_settings import Settings
    from src.common.gateway import Gateway
    from src.receiver.packet import PacketList
    from src.receiver.windows import WindowList


def process_command(
    ts: "datetime",
    assembly_ct: bytes,
    window_list: "WindowList",
    packet_list: "PacketList",
    contact_list: "ContactList",
    key_list: "KeyList",
    group_list: "GroupList",
    settings: "Settings",
    master_key: "MasterKey",
    gateway: "Gateway",
    exit_queue: "Queue[bytes]",
) -> None:
    """Decrypt command assembly packet and process command."""
    assembly_packet = decrypt_assembly_packet(
        assembly_ct,
        LOCAL_PUBKEY,
        ORIGIN_USER_HEADER,
        window_list,
        contact_list,
        key_list,
    )

    cmd_packet = packet_list.get_packet(LOCAL_PUBKEY, ORIGIN_USER_HEADER, COMMAND)
    cmd_packet.add_packet(assembly_packet)

    if not cmd_packet.is_complete:
        raise SoftError("Incomplete command.", output=False)

    header, cmd = separate_header(
        cmd_packet.assemble_command_packet(), ENCRYPTED_COMMAND_HEADER_LENGTH
    )
    no = None

    #    Keyword        Function to run (                                 Parameters                                  )
    #    --------------------------------------------------------------------------------------------------------------
    d = {
        LOCAL_KEY_RDY: (local_key_rdy, ts, window_list, contact_list),
        WIN_ACTIVITY: (win_activity, window_list),
        WIN_SELECT: (win_select, cmd, window_list),
        CLEAR_SCREEN: (clear_screen,),
        RESET_SCREEN: (reset_screen, cmd, window_list),
        EXIT_PROGRAM: (exit_tfc, exit_queue),
        LOG_DISPLAY: (
            log_command,
            cmd,
            no,
            window_list,
            contact_list,
            group_list,
            settings,
            master_key,
        ),
        LOG_EXPORT: (
            log_command,
            cmd,
            ts,
            window_list,
            contact_list,
            group_list,
            settings,
            master_key,
        ),
        LOG_REMOVE: (remove_log, cmd, contact_list, group_list, settings, master_key),
        CH_MASTER_KEY: (
            ch_master_key,
            ts,
            window_list,
            contact_list,
            group_list,
            key_list,
            settings,
            master_key,
        ),
        CH_NICKNAME: (ch_nick, cmd, ts, window_list, contact_list,),
        CH_SETTING: (
            ch_setting,
            cmd,
            ts,
            window_list,
            contact_list,
            group_list,
            key_list,
            settings,
            gateway,
        ),
        CH_LOGGING: (
            ch_contact_s,
            cmd,
            ts,
            window_list,
            contact_list,
            group_list,
            header,
        ),
        CH_FILE_RECV: (
            ch_contact_s,
            cmd,
            ts,
            window_list,
            contact_list,
            group_list,
            header,
        ),
        CH_NOTIFY: (
            ch_contact_s,
            cmd,
            ts,
            window_list,
            contact_list,
            group_list,
            header,
        ),
        GROUP_CREATE: (
            group_create,
            cmd,
            ts,
            window_list,
            contact_list,
            group_list,
            settings,
        ),
        GROUP_ADD: (
            group_add,
            cmd,
            ts,
            window_list,
            contact_list,
            group_list,
            settings,
        ),
        GROUP_REMOVE: (group_remove, cmd, ts, window_list, contact_list, group_list),
        GROUP_DELETE: (group_delete, cmd, ts, window_list, group_list),
        GROUP_RENAME: (group_rename, cmd, ts, window_list, contact_list, group_list),
        KEY_EX_ECDHE: (
            key_ex_ecdhe,
            cmd,
            ts,
            window_list,
            contact_list,
            key_list,
            settings,
        ),
        KEY_EX_PSK_TX: (
            key_ex_psk_tx,
            cmd,
            ts,
            window_list,
            contact_list,
            key_list,
            settings,
        ),
        KEY_EX_PSK_RX: (
            key_ex_psk_rx,
            cmd,
            ts,
            window_list,
            contact_list,
            key_list,
            settings,
        ),
        CONTACT_REM: (
            contact_rem,
            cmd,
            ts,
            window_list,
            contact_list,
            group_list,
            key_list,
            settings,
            master_key,
        ),
        WIPE_USR_DATA: (wipe, exit_queue),
    }  # type: Dict[bytes, Any]

    try:
        from_dict = d[header]
    except KeyError:
        raise SoftError("Error: Received an invalid command.")

    func = from_dict[0]
    parameters = from_dict[1:]
    func(*parameters)

    raise SoftError("Command completed.", output=False)


def win_activity(window_list: "WindowList") -> None:
    """Show number of unread messages in each window."""
    unread_wins = [
        w for w in window_list if (w.uid != WIN_UID_COMMAND and w.unread_messages > 0)
    ]
    print_list = ["Window activity"] if unread_wins else ["No window activity"]
    print_list += [f"{w.name}: {w.unread_messages}" for w in unread_wins]

    m_print(print_list, box=True)
    print_on_previous_line(reps=(len(print_list) + 2), delay=1)


def win_select(window_uid: bytes, window_list: "WindowList") -> None:
    """Select window specified by the Transmitter Program."""
    if window_uid == WIN_UID_FILE:
        clear_screen()
    window_list.set_active_rx_window(window_uid)


def reset_screen(win_uid: bytes, window_list: "WindowList") -> None:
    """Reset window specified by the Transmitter Program."""
    window = window_list.get_window(win_uid)
    window.reset_window()
    reset_terminal()


def exit_tfc(exit_queue: "Queue[str]") -> None:
    """Exit TFC."""
    exit_queue.put(EXIT)


def log_command(
    cmd_data: bytes,
    ts: "datetime",
    window_list: "WindowList",
    contact_list: "ContactList",
    group_list: "GroupList",
    settings: "Settings",
    master_key: "MasterKey",
) -> None:
    """Display or export log file for the active window.

    Having the capability to export the log file from the encrypted
    database is a bad idea, but as it's required by the GDPR
    (https://gdpr-info.eu/art-20-gdpr/), it should be done as securely
    as possible.

    Therefore, before allowing export, TFC will ask for the master
    password to ensure no unauthorized user who gains momentary
    access to the system can the export logs from the database.
    """
    export = ts is not None
    ser_no_msg, uid = separate_header(cmd_data, ENCODED_INTEGER_LENGTH)
    no_messages = bytes_to_int(ser_no_msg)
    window = window_list.get_window(uid)

    access_logs(
        window,
        contact_list,
        group_list,
        settings,
        master_key,
        msg_to_load=no_messages,
        export=export,
    )

    if export:
        cmd_win = window_list.get_command_window()
        cmd_win.add_new(
            ts, f"Exported log file of {window.type} '{window.name}'.", output=True
        )


def remove_log(
    cmd_data: bytes,
    contact_list: "ContactList",
    group_list: "GroupList",
    settings: "Settings",
    master_key: "MasterKey",
) -> None:
    """Remove log entries for contact or group."""
    remove_logs(contact_list, group_list, settings, master_key, selector=cmd_data)


def ch_master_key(
    ts: "datetime",
    window_list: "WindowList",
    contact_list: "ContactList",
    group_list: "GroupList",
    key_list: "KeyList",
    settings: "Settings",
    master_key: "MasterKey",
) -> None:
    """Prompt the user for a new master password and derive a new master key from that."""
    if not master_key.authenticate_action():
        raise SoftError("Error: Invalid password.", tail_clear=True, delay=1, head=2)

    # Cache old master key to allow log file re-encryption.
    old_master_key = master_key.master_key[:]

    # Create new master key but do not store new master key data into any database.
    new_master_key = master_key.master_key = master_key.new_master_key(replace=False)
    phase("Re-encrypting databases")

    # Update encryption keys for databases
    contact_list.database.database_key = new_master_key
    key_list.database.database_key = new_master_key
    group_list.database.database_key = new_master_key
    settings.database.database_key = new_master_key

    # Create temp databases for each database, do not replace original.
    with ignored(SoftError):
        change_log_db_key(old_master_key, new_master_key, settings)
    contact_list.store_contacts(replace=False)
    key_list.store_keys(replace=False)
    group_list.store_groups(replace=False)
    settings.store_settings(replace=False)

    # At this point all temp files exist and they have been checked to be valid by the respective
    # temp file writing function. It's now time to create a temp file for the new master key
    # database. Once the temp master key database is created, the `replace_database_data()` method
    # will also run the atomic `os.replace()` command for the master key database.
    master_key.replace_database_data()

    # Next we do the atomic `os.replace()` for all other files too.
    replace_log_db(settings)
    contact_list.database.replace_database()
    key_list.database.replace_database()
    group_list.database.replace_database()
    settings.database.replace_database()

    phase(DONE)
    m_print(
        "Master password successfully changed.",
        bold=True,
        tail_clear=True,
        delay=1,
        head=1,
    )

    cmd_win = window_list.get_command_window()
    cmd_win.add_new(ts, "Changed Receiver master password.")


def ch_nick(
    cmd_data: bytes,
    ts: "datetime",
    window_list: "WindowList",
    contact_list: "ContactList",
) -> None:
    """Change nickname of contact."""
    onion_pub_key, nick_bytes = separate_header(
        cmd_data, header_length=ONION_SERVICE_PUBLIC_KEY_LENGTH
    )
    nick = nick_bytes.decode()
    short_addr = pub_key_to_short_address(onion_pub_key)

    try:
        contact = contact_list.get_contact_by_pub_key(onion_pub_key)
    except StopIteration:
        raise SoftError(f"Error: Receiver has no contact '{short_addr}' to rename.")

    contact.nick = nick
    contact_list.store_contacts()

    window = window_list.get_window(onion_pub_key)
    window.name = nick
    window.handle_dict[onion_pub_key] = nick

    if window.type == WIN_TYPE_CONTACT:
        window.redraw()

    cmd_win = window_list.get_command_window()
    cmd_win.add_new(ts, f"Changed {short_addr} nick to '{nick}'.", output=True)


def ch_setting(
    cmd_data: bytes,
    ts: "datetime",
    window_list: "WindowList",
    contact_list: "ContactList",
    group_list: "GroupList",
    key_list: "KeyList",
    settings: "Settings",
    gateway: "Gateway",
) -> None:
    """Change TFC setting."""
    try:
        setting, value = [f.decode() for f in cmd_data.split(US_BYTE)]
    except ValueError:
        raise SoftError("Error: Received invalid setting data.")

    if setting in settings.key_list:
        settings.change_setting(setting, value, contact_list, group_list)
    elif setting in gateway.settings.key_list:
        gateway.settings.change_setting(setting, value)
    else:
        raise SoftError(f"Error: Invalid setting '{setting}'.")

    cmd_win = window_list.get_command_window()
    cmd_win.add_new(ts, f"Changed setting '{setting}' to '{value}'.", output=True)

    if setting == "max_number_of_contacts":
        contact_list.store_contacts()
        key_list.store_keys()
    if setting in ["max_number_of_group_members", "max_number_of_groups"]:
        group_list.store_groups()


def ch_contact_s(
    cmd_data: bytes,
    ts: "datetime",
    window_list: "WindowList",
    contact_list: "ContactList",
    group_list: "GroupList",
    header: bytes,
) -> None:
    """Change contact/group related setting."""
    setting, win_uid = separate_header(cmd_data, CONTACT_SETTING_HEADER_LENGTH)
    attr, desc, file_cmd = {
        CH_LOGGING: ("log_messages", "Logging of messages", False),
        CH_FILE_RECV: ("file_reception", "Reception of files", True),
        CH_NOTIFY: ("notifications", "Message notifications", False),
    }[header]

    action, b_value = {ENABLE: ("enabled", True), DISABLE: ("disabled", False)}[
        setting.lower()
    ]

    if setting.isupper():
        specifier, status, w_name, w_type = change_setting_for_all_contacts(
            attr, file_cmd, b_value, contact_list, group_list
        )
    else:
        status, specifier, w_type, w_name = change_setting_for_one_contact(
            attr, file_cmd, b_value, win_uid, window_list, contact_list, group_list
        )

    message = f"{desc} {status} {action} for {specifier}{w_type}{w_name}"
    cmd_win = window_list.get_command_window()
    cmd_win.add_new(ts, message, output=True)


def change_setting_for_one_contact(
    attr: str,
    file_cmd: bool,
    b_value: bool,
    win_uid: bytes,
    window_list: "WindowList",
    contact_list: "ContactList",
    group_list: "GroupList",
) -> Tuple[str, str, str, str]:
    """Change setting for contacts in specified window."""
    if not window_list.has_window(win_uid):
        raise SoftError(
            f"Error: Found no window for '{pub_key_to_short_address(win_uid)}'."
        )

    window = window_list.get_window(win_uid)
    group_window = window.type == WIN_TYPE_GROUP
    contact_window = window.type == WIN_TYPE_CONTACT

    if contact_window:
        target = contact_list.get_contact_by_pub_key(
            win_uid
        )  # type: Union[Contact, Group]
    else:
        target = group_list.get_group_by_id(win_uid)

    if file_cmd:
        enabled = [getattr(m, attr) for m in window.window_contacts]
        changed = not all(enabled) if b_value else any(enabled)
    else:
        changed = getattr(target, attr) != b_value

    status = "has been" if changed else "was already"
    specifier = "members in " if (file_cmd and group_window) else ""
    w_type = window.type
    w_name = f" {window.name}."

    # Set values
    if contact_window or (group_window and file_cmd):
        for c in window.window_contacts:
            setattr(c, attr, b_value)
        contact_list.store_contacts()

    elif group_window:
        setattr(group_list.get_group_by_id(win_uid), attr, b_value)
        group_list.store_groups()

    return status, specifier, w_type, w_name


def change_setting_for_all_contacts(
    attr: str,
    file_cmd: bool,
    b_value: bool,
    contact_list: "ContactList",
    group_list: "GroupList",
) -> Tuple[str, str, str, str]:
    """Change settings for all contacts (and groups)."""
    enabled = [getattr(c, attr) for c in contact_list.get_list_of_contacts()]
    enabled += [getattr(g, attr) for g in group_list] if not file_cmd else []

    status = (
        "was already"
        if ((all(enabled) and b_value) or (not any(enabled) and not b_value))
        else "has been"
    )
    specifier = "every "
    w_type = "contact"
    w_name = "." if file_cmd else " and group."

    # Set values
    for c in contact_list.get_list_of_contacts():
        setattr(c, attr, b_value)

    contact_list.store_contacts()

    if not file_cmd:
        for g in group_list:
            setattr(g, attr, b_value)
        group_list.store_groups()

    return status, specifier, w_type, w_name


def contact_rem(
    onion_pub_key: bytes,
    ts: "datetime",
    window_list: "WindowList",
    contact_list: "ContactList",
    group_list: "GroupList",
    key_list: "KeyList",
    settings: "Settings",
    master_key: "MasterKey",
) -> None:
    """Remove contact from Receiver Program."""
    key_list.remove_keyset(onion_pub_key)
    window_list.remove_window(onion_pub_key)
    short_addr = pub_key_to_short_address(onion_pub_key)

    try:
        contact = contact_list.get_contact_by_pub_key(onion_pub_key)
    except StopIteration:
        raise SoftError(f"Receiver has no account '{short_addr}' to remove.")

    nick = contact.nick
    in_group = any([g.remove_members([onion_pub_key]) for g in group_list])

    contact_list.remove_contact_by_pub_key(onion_pub_key)

    message = f"Removed {nick} ({short_addr}) from contacts{' and groups' if in_group else ''}."
    m_print(message, bold=True, head=1, tail=1)

    cmd_win = window_list.get_command_window()
    cmd_win.add_new(ts, message)

    remove_logs(contact_list, group_list, settings, master_key, onion_pub_key)


def wipe(exit_queue: "Queue[str]") -> None:
    """\
    Reset terminals, wipe all TFC user data on Destination Computer and
    power off the system.

    No effective RAM overwriting tool currently exists, so as long as
    Source and Destination Computers use FDE and DDR3 memory, recovery
    of user data becomes impossible very fast:
        https://www1.cs.fau.de/filepool/projects/coldboot/fares_coldboot.pdf
    """
    reset_terminal()
    exit_queue.put(WIPE)
