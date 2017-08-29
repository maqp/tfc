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
import struct
import textwrap
import time
import typing
import zlib

from multiprocessing import Queue
from typing          import Any, Dict, List, Tuple, Union

from src.common.crypto     import csprng, encrypt_and_sign
from src.common.db_logs    import access_logs, re_encrypt, remove_logs
from src.common.encoding   import int_to_bytes, str_to_bytes
from src.common.exceptions import FunctionReturn
from src.common.input      import yes
from src.common.misc       import ensure_dir, get_terminal_width
from src.common.output     import box_print, clear_screen, phase, print_key, print_on_previous_line
from src.common.path       import ask_path_gui
from src.common.statics    import *

from src.tx.commands_g    import process_group_command
from src.tx.contact       import add_new_contact, change_nick, contact_setting, show_fingerprints, remove_contact
from src.tx.key_exchanges import new_local_key, rxm_load_psk
from src.tx.packet        import cancel_packet, queue_command, queue_message, queue_to_nh
from src.tx.user_input    import UserInput
from src.tx.windows       import select_window

if typing.TYPE_CHECKING:
    from src.common.db_contacts  import ContactList
    from src.common.db_groups    import GroupList
    from src.common.db_masterkey import MasterKey
    from src.common.db_settings  import Settings
    from src.tx.windows          import TxWindow


def process_command(user_input:   'UserInput',
                    window:       'TxWindow',
                    settings:     'Settings',
                    queues:       Dict[bytes, 'Queue'],
                    contact_list: 'ContactList',
                    group_list:   'GroupList',
                    master_key:   'MasterKey') -> None:
    """\
    Select function based on first keyword of issued
    command and pass relevant parameters to it.
    """
    c = COMMAND_PACKET_QUEUE
    m = MESSAGE_PACKET_QUEUE
    n = NH_PACKET_QUEUE

    #    Keyword          Function to run         (                                 Parameters                                  )
    #    ------------------------------------------------------------------------------------------------------------------------
    d = {'about':        (print_about,                                                                                          ),
         'add':          (add_new_contact,                             contact_list, group_list, settings, queues               ),
         'clear':        (clear_screens,           user_input, window,                           settings, queues               ),
         'cmd':          (rxm_show_sys_win,        user_input, window,                           settings, queues[c]            ),
         'cm':           (cancel_packet,           user_input, window,                           settings, queues               ),
         'cf':           (cancel_packet,           user_input, window,                           settings, queues               ),
         'exit':         (exit_tfc,                                                              settings, queues               ),
         'export':       (log_command,             user_input, window, contact_list, group_list, settings, queues[c], master_key),
         'fingerprints': (show_fingerprints,                   window                                                           ),
         'fe':           (export_file,                                                           settings, queues[n]            ),
         'fi':           (import_file,                                                           settings, queues[n]            ),
         'fw':           (rxm_show_sys_win,        user_input, window,                           settings, queues[c]            ),
         'group':        (process_group_command,   user_input,         contact_list, group_list, settings, queues,    master_key),
         'help':         (print_help,                                                            settings                       ),
         'history':      (log_command,             user_input, window, contact_list, group_list, settings, queues[c], master_key),
         'localkey':     (new_local_key,                               contact_list,             settings, queues,              ),
         'logging':      (contact_setting,         user_input, window, contact_list, group_list, settings, queues[c]            ),
         'msg':          (select_window,           user_input, window,                           settings, queues               ),
         'names':        (print_recipients,                            contact_list, group_list,                                ),
         'nick':         (change_nick,             user_input, window, contact_list, group_list, settings, queues[c]            ),
         'notify':       (contact_setting,         user_input, window, contact_list, group_list, settings, queues[c]            ),
         'passwd':       (change_master_key,       user_input,         contact_list, group_list, settings, queues,    master_key),
         'psk':          (rxm_load_psk,                        window, contact_list,             settings, queues[c]            ),
         'reset':        (clear_screens,           user_input, window,                           settings, queues               ),
         'rm':           (remove_contact,          user_input, window, contact_list, group_list, settings, queues,    master_key),
         'rmlogs':       (remove_log,              user_input,         contact_list,             settings, queues[c], master_key),
         'set':          (change_setting,          user_input,         contact_list, group_list, settings, queues               ),
         'settings':     (settings.print_settings,                                                                              ),
         'store':        (contact_setting,         user_input, window, contact_list, group_list, settings, queues[c]            ),
         'unread':       (rxm_display_unread,                                                    settings, queues[c]            ),
         'whisper':      (whisper,                 user_input, window,                           settings, queues[m]            ),
         'wipe':         (wipe,                                                                  settings, queues               )}  # type: Dict[str, Any]

    try:
        cmd_key   = user_input.plaintext.split()[0]
        from_dict = d[cmd_key]
    except KeyError:
        raise FunctionReturn(f"Error: Invalid command '{cmd_key}'")
    except (IndexError, UnboundLocalError):
        raise FunctionReturn(f"Error: Invalid command.")

    func       = from_dict[0]
    parameters = from_dict[1:]
    func(*parameters)


def print_about() -> None:
    """Print URLs that direct to TFC's project site and documentation."""
    clear_screen()
    print(f"\n Tinfoil Chat {VERSION}                           \n\n"
           " Website:     https://github.com/maqp/tfc/            \n"
           " Wikipage:    https://github.com/maqp/tfc/wiki        \n"
           " White paper: https://cs.helsinki.fi/u/oottela/tfc.pdf\n")


def clear_screens(user_input: 'UserInput',
                  window:     'TxWindow',
                  settings:   'Settings',
                  queues:     Dict[bytes, 'Queue']) -> None:
    """Clear/reset TxM, RxM and NH screens.

    Only send unencrypted command to NH if traffic masking is disabled and
    if some related IM account can be bound to active window.

    Since reset command removes ephemeral message log on RxM, TxM decides
    the window to reset (in case e.g. previous window selection command
    packet dropped and active window state is inconsistent between TxM/RxM).
    """
    cmd = user_input.plaintext.split()[0]

    command = CLEAR_SCREEN_HEADER if cmd == CLEAR else RESET_SCREEN_HEADER + window.uid.encode()
    queue_command(command, settings, queues[COMMAND_PACKET_QUEUE])

    clear_screen()

    if not settings.session_traffic_masking and window.imc_name is not None:
        im_window = window.imc_name.encode()
        pt_cmd    = UNENCRYPTED_SCREEN_CLEAR if cmd == CLEAR else UNENCRYPTED_SCREEN_RESET
        packet    = UNENCRYPTED_PACKET_HEADER + pt_cmd + im_window
        queue_to_nh(packet, settings, queues[NH_PACKET_QUEUE])

    if cmd == RESET:
        os.system('reset')


def rxm_show_sys_win(user_input: 'UserInput',
                     window:     'TxWindow',
                     settings:   'Settings',
                     c_queue:    'Queue') -> None:
    """Display system window on RxM until user presses Enter."""
    cmd      = user_input.plaintext.split()[0]
    win_name = dict(cmd=LOCAL_ID, fw=WIN_TYPE_FILE)[cmd]

    command = WINDOW_SELECT_HEADER + win_name.encode()
    queue_command(command, settings, c_queue)

    box_print(f"<Enter> returns RxM to {window.name}'s window", manual_proceed=True)
    print_on_previous_line(reps=4, flush=True)

    command = WINDOW_SELECT_HEADER + window.uid.encode()
    queue_command(command, settings, c_queue)


def exit_tfc(settings: 'Settings', queues: Dict[bytes, 'Queue']) -> None:
    """Exit TFC on TxM/RxM/NH."""
    for q in [COMMAND_PACKET_QUEUE, NH_PACKET_QUEUE]:
        while queues[q].qsize() != 0:
            queues[q].get()

    queue_command(EXIT_PROGRAM_HEADER, settings, queues[COMMAND_PACKET_QUEUE])

    if not settings.session_traffic_masking:
        if settings.local_testing_mode:
            time.sleep(0.8)
            if settings.data_diode_sockets:
               time.sleep(2.2)
        else:
            time.sleep(settings.race_condition_delay)

    queue_to_nh(UNENCRYPTED_PACKET_HEADER + UNENCRYPTED_EXIT_COMMAND, settings, queues[NH_PACKET_QUEUE])


def log_command(user_input:   'UserInput',
                window:       'TxWindow',
                contact_list: 'ContactList',
                group_list:   'GroupList',
                settings:     'Settings',
                c_queue:      'Queue',
                master_key:   'MasterKey') -> None:
    """Display message logs or export them to plaintext file on TxM/RxM.

    TxM processes sent messages, RxM processes sent and
    received messages for all participants in active window.
    """
    cmd = user_input.plaintext.split()[0]

    export, header = dict(export =(True,  LOG_EXPORT_HEADER),
                          history=(False, LOG_DISPLAY_HEADER))[cmd]

    try:
        msg_to_load = int(user_input.plaintext.split()[1])
    except ValueError:
        raise FunctionReturn("Error: Invalid number of messages.")
    except IndexError:
        msg_to_load = 0

    if export and not yes(f"Export logs for '{window.name}' in plaintext?", head=1, tail=1):
        raise FunctionReturn("Logfile export aborted.")

    try:
        command = header + window.uid.encode() + US_BYTE + int_to_bytes(msg_to_load)
    except struct.error:
        raise FunctionReturn("Error: Invalid number of messages.")

    queue_command(command, settings, c_queue)

    access_logs(window, contact_list, group_list, settings, master_key, msg_to_load, export)


def export_file(settings: 'Settings', nh_queue: 'Queue') -> None:
    """Encrypt and export file to NH.

    This is a faster method to send large files. It is used together
    with file import (/fi) command that uploads ciphertext to RxM for
    RxM-side decryption. Key is generated automatically so that bad
    passwords selected by users do not affect security of ciphertexts.
    """
    if settings.session_traffic_masking:
        raise FunctionReturn("Error: Command is disabled during traffic masking.")

    path = ask_path_gui("Select file to export...", settings, get_file=True)
    name = path.split('/')[-1]
    data = bytearray()
    data.extend(str_to_bytes(name))

    if not os.path.isfile(path):
        raise FunctionReturn("Error: File not found.")

    if os.path.getsize(path) == 0:
        raise FunctionReturn("Error: Target file is empty.")

    phase("Reading data")
    with open(path, 'rb') as f:
        data.extend(f.read())
    phase(DONE)

    phase("Compressing data")
    comp = bytes(zlib.compress(bytes(data), level=COMPRESSION_LEVEL))
    phase(DONE)

    phase("Encrypting data")
    file_key = csprng()
    file_ct  = encrypt_and_sign(comp, key=file_key)
    phase(DONE)

    phase("Exporting data")
    queue_to_nh(EXPORTED_FILE_HEADER + file_ct, settings, nh_queue)
    phase(DONE)

    print_key(f"Decryption key for file '{name}':", file_key, settings, no_split=True, file_key=True)


def import_file(settings: 'Settings', nh_queue: 'Queue') -> None:
    """\
    Send unencrypted command to NH that tells it to open
    RxM upload prompt for received (exported) file.
    """
    if settings.session_traffic_masking:
        raise FunctionReturn("Error: Command is disabled during traffic masking.")

    queue_to_nh(UNENCRYPTED_PACKET_HEADER + UNENCRYPTED_IMPORT_COMMAND, settings, nh_queue)


def print_help(settings: 'Settings') -> None:
    """Print the list of commands."""

    def help_printer(tuple_list: List[Union[Tuple[str, str, bool]]]) -> None:
        """Print list of commands.

        Style depends on terminal width and settings.
        """
        len_longest_command = max(len(t[0]) for t in tuple_list) + 1  # Add one for spacing

        for help_cmd, description, display in tuple_list:
            if not display:
                continue

            wrapper     = textwrap.TextWrapper(width=max(1, terminal_width - len_longest_command))
            desc_lines  = wrapper.fill(description).split('\n')
            desc_indent = (len_longest_command - len(help_cmd)) * ' '

            print(help_cmd + desc_indent + desc_lines[0])

            # Print wrapped description lines with indent
            if len(desc_lines) > 1:
                for line in desc_lines[1:]:
                    print(len_longest_command * ' ' + line)
                print('')

    notm   = not settings.session_traffic_masking
    common = [("/about",                    "Show links to project resources",                     True),
              ("/add",                      "Add new contact",                                     notm),
              ("/cf",                       "Cancel file transmission to active contact/group",    True),
              ("/cm",                       "Cancel message transmission to active contact/group", True),
              ("/clear, '  '",              "Clear screens from TxM, RxM and IM client",           True),
              ("/cmd, '//'",                "Display command window on RxM",                       True),
              ("/exit",                     "Exit TFC on TxM, NH and RxM",                         True),
              ("/export (n)",               "Export (n) messages from recipient's logfile",        True),
              ("/file",                     "Send file to active contact/group",                   True),
              ("/fingerprints",             "Print public key fingerprints of user and contact",   True),
              ("/fe",                       "Encrypt and export file to NH",                       notm),
              ("/fi",                       "Import file from NH to RxM",                          notm),
              ("/fw",                       "Display file reception window on RxM",                True),
              ("/help",                     "Display this list of commands",                       True),
              ("/history (n)",              "Print (n) messages from recipient's logfile",         True),
              ("/localkey",                 "Generate new local key pair",                         notm),
              ("/logging {on,off}(' all')", "Change message log setting (for all contacts)",       True),
              ("/msg {A,N}",                "Change active recipient to account A or nick N",      notm),
              ("/names",                    "List contacts and groups",                            True),
              ("/nick N",                   "Change nickname of active recipient to N",            True),
              ("/notify {on,off} (' all')", "Change notification settings (for all contacts)",     True),
              ("/passwd {tx,rx}",           "Change master password on TxM/RxM",                   notm),
              ("/psk",                      "Open PSK import dialog on RxM",                       notm),
              ("/reset",                    "Reset ephemeral session log on TxM/RxM/IM client",    True),
              ("/rm {A,N}",                 "Remove account A or nick N from TxM and RxM",         notm),
              ("/rmlogs {A,N}",             "Remove log entries for A/N on TxM and RxM",           True),
              ("/set S V",                  "Change setting S to value V on TxM/RxM(/NH)",         True),
              ("/settings",                 "List setting names, values and descriptions",         True),
              ("/store {on,off} (' all')",  "Change file reception (for all contacts)",            True),
              ("/unread, ' '",              "List windows with unread messages on RxM",            True),
              ("/whisper M",                "Send message M, asking it not to be logged",          True),
              ("/wipe",                     "Wipe all TFC/IM user data and power off systems",     True),
              ("Shift + PgUp/PgDn",         "Scroll terminal up/down",                             True),]

    groupc = [("/group create G A₁ .. Aₙ ", "Create group G and add accounts A₁ .. Aₙ",            notm),
              ("/group add G A₁ .. Aₙ",     "Add accounts A₁ .. Aₙ to group G",                    notm),
              ("/group rm G A₁ .. Aₙ",      "Remove accounts A₁ .. Aₙ from group G",               notm),
              ("/group rm G",               "Remove group G",                                      notm)]

    terminal_width = get_terminal_width()

    clear_screen()

    print(textwrap.fill("List of commands:", width=terminal_width))
    print('')
    help_printer(common)
    print(terminal_width * '─')

    if settings.session_traffic_masking:
        print('')
    else:
        print("Group management:\n")
        help_printer(groupc)
        print(terminal_width * '─' + '\n')


def print_recipients(contact_list: 'ContactList', group_list: 'GroupList') -> None:
    """Print list of contacts and groups."""
    contact_list.print_contacts()
    group_list.print_groups()


def change_master_key(user_input:   'UserInput',
                      contact_list: 'ContactList',
                      group_list:   'GroupList',
                      settings:     'Settings',
                      queues:       Dict[bytes, 'Queue'],
                      master_key:   'MasterKey') -> None:
    """Change master key on TxM/RxM."""
    try:
        if settings.session_traffic_masking:
            raise FunctionReturn("Error: Command is disabled during traffic masking.")

        try:
            device = user_input.plaintext.split()[1].lower()
        except IndexError:
            raise FunctionReturn("Error: No target system specified.")

        if device not in [TX, RX]:
            raise FunctionReturn("Error: Invalid target system.")

        if device == RX:
            queue_command(CHANGE_MASTER_K_HEADER, settings, queues[COMMAND_PACKET_QUEUE])
            return None

        old_master_key = master_key.master_key[:]
        master_key.new_master_key()
        new_master_key = master_key.master_key

        phase("Re-encrypting databases")

        queues[KEY_MANAGEMENT_QUEUE].put((KDB_CHANGE_MASTER_KEY_HEADER, master_key))

        ensure_dir(DIR_USER_DATA)
        file_name = f'{DIR_USER_DATA}{settings.software_operation}_logs'
        if os.path.isfile(file_name):
            re_encrypt(old_master_key, new_master_key, settings)

        settings.store_settings()
        contact_list.store_contacts()
        group_list.store_groups()

        phase(DONE)
        box_print("Master key successfully changed.", head=1)
        clear_screen(delay=1.5)

    except KeyboardInterrupt:
        raise FunctionReturn("Password change aborted.", delay=1, head=3, tail_clear=True)


def remove_log(user_input:   'UserInput',
               contact_list: 'ContactList',
               settings:     'Settings',
               c_queue:      'Queue',
               master_key:   'MasterKey') -> None:
    """Remove log entries for contact."""
    try:
        selection = user_input.plaintext.split()[1]
    except IndexError:
        raise FunctionReturn("Error: No contact/group specified.")

    if not yes(f"Remove logs for {selection}?", head=1):
        raise FunctionReturn("Logfile removal aborted.")

    # Swap specified nick to rx_account
    if selection in contact_list.get_list_of_nicks():
        selection = contact_list.get_contact(selection).rx_account

    command = LOG_REMOVE_HEADER + selection.encode()
    queue_command(command, settings, c_queue)

    remove_logs(selection, settings, master_key)


def change_setting(user_input:   'UserInput',
                   contact_list: 'ContactList',
                   group_list:   'GroupList',
                   settings:     'Settings',
                   queues:       Dict[bytes, 'Queue']) -> None:
    """Change setting on TxM / RxM."""
    try:
        setting = user_input.plaintext.split()[1]
    except IndexError:
        raise FunctionReturn("Error: No setting specified.")

    if setting not in settings.key_list:
        raise FunctionReturn(f"Error: Invalid setting '{setting}'")

    try:
        value = user_input.plaintext.split()[2]
    except IndexError:
        raise FunctionReturn("Error: No value for setting specified.")

    pt_cmd = dict(serial_error_correction=UNENCRYPTED_EC_RATIO,
                  serial_baudrate        =UNENCRYPTED_BAUDRATE,
                  disable_gui_dialog     =UNENCRYPTED_GUI_DIALOG)

    if setting in pt_cmd:
        if settings.session_traffic_masking:
            raise FunctionReturn("Error: Can't change this setting during traffic masking.")

    settings.change_setting(setting, value, contact_list, group_list)

    command = CHANGE_SETTING_HEADER + setting.encode() + US_BYTE + value.encode()
    queue_command(command, settings, queues[COMMAND_PACKET_QUEUE])

    if setting in pt_cmd:
        packet = UNENCRYPTED_PACKET_HEADER + pt_cmd[setting] + value.encode()
        queue_to_nh(packet, settings, queues[NH_PACKET_QUEUE])


def rxm_display_unread(settings: 'Settings', c_queue: 'Queue') -> None:
    """Temporarily display list of windows with unread messages on RxM."""
    queue_command(SHOW_WINDOW_ACTIVITY_HEADER, settings, c_queue)


def whisper(user_input: 'UserInput', window: 'TxWindow', settings: 'Settings', m_queue: 'Queue') -> None:
    """Send a message to contact that overrides enabled logging setting.

    The functionality of this feature is impossible to enforce, but if
    the recipient can be trusted, it can be used to send keys for to be
    imported files as well as off-the-record messages, without worrying
    they are stored into log files, ruining forward secrecy for imported
    (and later deleted) files.
    """
    message = user_input.plaintext[len('whisper '):]

    queue_message(user_input=UserInput(message, MESSAGE),
                  window    =window,
                  settings  =settings,
                  m_queue   =m_queue,
                  header    =WHISPER_MESSAGE_HEADER,
                  log_as_ph =True)


def wipe(settings: 'Settings', queues: Dict[bytes, 'Queue']) -> None:
    """Reset terminals, wipe all user data from TxM/RxM/NH and power off systems.

    No effective RAM overwriting tool currently exists, so as long as TxM/RxM
    use FDE and DDR3 memory, recovery of user data becomes impossible very fast:

        https://www1.cs.fau.de/filepool/projects/coldboot/fares_coldboot.pdf
    """
    if not yes("Wipe all user data and power off systems?"):
        raise FunctionReturn("Wipe command aborted.")

    clear_screen()

    for q in [COMMAND_PACKET_QUEUE, NH_PACKET_QUEUE]:
        while queues[q].qsize() != 0:
            queues[q].get()

    queue_command(WIPE_USER_DATA_HEADER, settings, queues[COMMAND_PACKET_QUEUE])

    if not settings.session_traffic_masking:
        if settings.local_testing_mode:
            time.sleep(0.8)
            if settings.data_diode_sockets:
               time.sleep(2.2)
        else:
            time.sleep(settings.race_condition_delay)

    queue_to_nh(UNENCRYPTED_PACKET_HEADER + UNENCRYPTED_WIPE_COMMAND, settings, queues[NH_PACKET_QUEUE])

    os.system('reset')
