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
import textwrap
import time
import typing
import zlib

from multiprocessing import Queue
from typing          import Any, Dict, List, Tuple, Union

from src.common.crypto    import encrypt_and_sign, keygen
from src.common.db_logs   import access_history, re_encrypt
from src.common.encoding  import b58encode, int_to_bytes, str_to_bytes
from src.common.errors    import FunctionReturn, graceful_exit
from src.common.input     import yes
from src.common.misc      import clear_screen, ensure_dir, get_tty_w
from src.common.output    import box_print, phase, print_on_previous_line
from src.common.path      import ask_path_gui
from src.common.statics   import *
from src.tx.commands_g    import process_group_command
from src.tx.contact       import add_new_contact, change_nick, remove_contact, contact_setting, fingerprints
from src.tx.key_exchanges import new_local_key, rxm_load_psk
from src.tx.packet        import cancel_packet, queue_command, transmit
from src.tx.windows       import select_window

if typing.TYPE_CHECKING:
    from src.common.db_contacts  import ContactList
    from src.common.db_groups    import GroupList
    from src.common.db_masterkey import MasterKey
    from src.common.db_settings  import Settings
    from src.common.gateway      import Gateway
    from src.tx.user_input       import UserInput
    from src.tx.windows          import Window


class Command(object):
    """Commands are created only after user input has been interpreted."""

    def __init__(self, plaintext: str) -> None:
        self.plaintext = plaintext
        self.type      = 'command'


def process_command(user_input:   'UserInput',
                    window:       'Window',
                    settings:     'Settings',
                    queues:       Dict[bytes, 'Queue'],
                    contact_list: 'ContactList',
                    group_list:   'GroupList',
                    gateway:      'Gateway',
                    master_key:   'MasterKey') -> None:
    """Process command based on user input."""
    c = COMMAND_PACKET_QUEUE
    #    Keyword          Function to run         (                                      Parameters                                      )
    #    ---------------------------------------------------------------------------------------------------------------------------------
    d = {'about':        (print_about,                                                                                                   ),
         'add':          (add_new_contact,                             contact_list, group_list, settings, queues,    gateway            ),
         'clear':        (clear_screens,                       window,                           settings, queues[c], gateway            ),
         'cmd':          (rxm_show_cmd_win,                    window,                           settings, queues[c]                     ),
         'cm':           (cancel_packet,           user_input, window,                           settings, queues                        ),
         'cf':           (cancel_packet,           user_input, window,                           settings, queues                        ),
         'exit':         (exit_tfc,                                                              settings, queues[c], gateway            ),
         'export':       (export_logs,             user_input, window, contact_list,             settings, queues[c],          master_key),
         'fingerprints': (fingerprints,                        window                                                                    ),
         'fe':           (export_file,                                                           settings,              gateway          ),
         'fi':           (import_file,                                                           settings,              gateway          ),
         'fw':           (rxm_display_f_win,                   window,                           settings, queues[c]                     ),
         'group':        (process_group_command,   user_input,         contact_list, group_list, settings, queues                        ),
         'help':         (print_help,                                                            settings                                ),
         'history':      (print_logs,              user_input, window, contact_list,             settings, queues[c],          master_key),
         'localkey':     (new_local_key,                               contact_list,             settings, queues,      gateway          ),
         'logging':      (contact_setting,         user_input, window, contact_list, group_list, settings, queues[c]                     ),
         'msg':          (select_window,           user_input, window,                           settings, queues                        ),
         'names':        (print_recipients,                            contact_list, group_list,                                         ),
         'nick':         (change_nick,             user_input, window, contact_list, group_list, settings, queues[c]                     ),
         'notify':       (contact_setting,         user_input, window, contact_list, group_list, settings, queues[c]                     ),
         'passwd':       (change_master_key,       user_input,         contact_list, group_list, settings, queues,             master_key),
         'psk':          (rxm_load_psk,                        window, contact_list,             settings, queues[c]                     ),
         'reset':        (reset_screens,                       window,                           settings, queues[c], gateway            ),
         'rm':           (remove_contact,          user_input, window, contact_list, group_list, settings, queues                        ),
         'set':          (change_setting,          user_input,         contact_list, group_list, settings, queues[c], gateway            ),
         'settings':     (settings.print_settings,                                                                                       ),
         'store':        (contact_setting,         user_input, window, contact_list, group_list, settings, queues[c]                     ),
         'unread':       (rxm_display_unread,                                                    settings, queues[c]                     )}  # type: Dict[str, Any]

    cmd_key = user_input.plaintext.split()[0]
    if cmd_key not in d:
        raise FunctionReturn(f"Invalid command '{cmd_key}'.")

    from_dict  = d[cmd_key]
    func       = from_dict[0]
    parameters = from_dict[1:]
    func(*parameters)


def print_about() -> None:
    """Print URLs that direct to TFC project site and documentation."""
    from tfc import __version__

    clear_screen()

    print(f"\n Tinfoil Chat {__version__}                       \n\n"
           " Website:     https://github.com/maqp/tfc/            \n"
           " Wikipage:    https://github.com/maqp/tfc/wiki        \n"
           " White paper: https://cs.helsinki.fi/u/oottela/tfc.pdf\n")


def clear_screens(window:   'Window',
                  settings: 'Settings',
                  c_queue:  'Queue',
                  gateway:  'Gateway') -> None:
    """Clear TxM, RxM and NH screens."""
    clear_screen()
    queue_command(CLEAR_SCREEN_HEADER, settings, c_queue)
    if not settings.session_trickle:
        if window.imc_name is not None:
            im_window = window.imc_name.encode()
            time.sleep(0.5)
            transmit(UNENCRYPTED_PACKET_HEADER + UNENCRYPTED_SCREEN_CLEAR + im_window, settings, gateway)


def rxm_show_cmd_win(window:   'Window',
                     settings: 'Settings',
                     c_queue:  'Queue') -> None:
    """Show command window on RxM until user presses Enter."""
    packet = WINDOW_CHANGE_HEADER + LOCAL_WIN_ID_BYTES
    queue_command(packet, settings, c_queue)

    box_print(f"<Enter> returns RxM to {window.name}'s window", manual_proceed=True)
    print_on_previous_line(reps=4, flush=True)

    packet = WINDOW_CHANGE_HEADER + window.uid.encode()
    queue_command(packet, settings, c_queue)


def exit_tfc(settings: 'Settings',
             c_queue:  'Queue',
             gateway:  'Gateway') -> None:
    """Exit TFC on TxM/RxM/NH."""
    queue_command(EXIT_PROGRAM_HEADER, settings, c_queue)
    time.sleep(0.5)

    transmit(UNENCRYPTED_PACKET_HEADER + UNENCRYPTED_EXIT_COMMAND, settings, gateway)

    if settings.local_testing_mode:
        time.sleep(0.8)
    if settings.data_diode_sockets:
        time.sleep(2.2)

    graceful_exit()


def export_logs(user_input:   'UserInput',
                window:       'Window',
                contact_list: 'ContactList',
                settings:     'Settings',
                c_queue:      'Queue',
                master_key:   'MasterKey') -> None:
    """Export log files to plaintext file on TxM/RxM.

    TxM only exports sent messages, RxM exports full conversation.
    """
    try:
        no_messages_str = user_input.plaintext.split()[1]
        if not no_messages_str.isdigit():
            raise FunctionReturn("Specified invalid number of messages to export.")
        no_messages = int(no_messages_str)
    except IndexError:
        no_messages = 0

    if not yes(f"Export logs for {window.name} in plaintext?", head=1, tail=1):
        raise FunctionReturn("Logfile export aborted.")

    packet = LOG_EXPORT_HEADER + window.uid.encode() + US_BYTE + int_to_bytes(no_messages)
    queue_command(packet, settings, c_queue)

    access_history(window, contact_list, settings, master_key, no_messages, export=True)


def export_file(settings: 'Settings', gateway: 'Gateway'):
    """Encrypt and export file to NH.

    This is a faster method of sending large files. It is used together with '/fi' import_file
    command that loads ciphertext to RxM for later decryption. Key is generated automatically
    so that bad passwords by users do not affect security of ciphertexts.

    As use of this command reveals use of TFC, it is disabled during trickle connection.
    """
    if settings.session_trickle:
        raise FunctionReturn("Command disabled during trickle connection.")

    path = ask_path_gui("Select file to export...", settings, get_file=True)
    name = path.split('/')[-1]
    data = bytearray()
    data.extend(str_to_bytes(name))

    if not os.path.isfile(path):
        raise FunctionReturn("Error: File not found.")

    if os.path.getsize(path) == 0:
        raise FunctionReturn("Error: Target file is empty. No file was sent.")

    phase("Reading data")
    with open(path, 'rb') as f:
        data.extend(f.read())
    phase("Done")

    phase("Compressing data")
    comp  = bytes(zlib.compress(bytes(data), level=9))
    phase("Done")

    phase("Encrypting data")
    file_key = keygen()
    file_ct  = encrypt_and_sign(comp, key=file_key)
    phase("Done")

    phase("Exporting data")
    transmit(EXPORTED_FILE_CT_HEADER + file_ct, settings, gateway)
    phase("Done")

    box_print([f"Decryption key for file {name}:", '', b58encode(file_key)], head=1, tail=1)


def import_file(settings: 'Settings', gateway: 'Gateway'):
    """Import files from NH to RxM and decrypt them."""
    if settings.session_trickle:
        raise FunctionReturn("Command disabled during trickle connection.")

    transmit(UNENCRYPTED_PACKET_HEADER + UNENCRYPTED_IMPORT_COMMAND, settings, gateway)


def rxm_display_f_win(window:   'Window',
                      settings: 'Settings',
                      c_queue:  'Queue'):
    """Show file reception window on RxM until user presses Enter."""
    packet = WINDOW_CHANGE_HEADER + FILE_R_WIN_ID_BYTES
    queue_command(packet, settings, c_queue)

    box_print(f"<Enter> returns RxM to {window.name}'s window", manual_proceed=True)
    print_on_previous_line(reps=4, flush=True)

    packet = WINDOW_CHANGE_HEADER + window.uid.encode()
    queue_command(packet, settings, c_queue)


def print_help(settings: 'Settings') -> None:
    """Print the list of commands."""

    def help_printer(tuple_list: List[Union[Tuple[str, str, bool]]]) -> None:
        """Print help menu, style depending on terminal width and display conditions.

        :param tuple_list: List of command-description-display tuples
        """
        longest_command = ''
        for t in tuple_list:
            longest_command = max(t[0], longest_command, key=len)
        longest_command += ' '  # Add spacing

        for help_cmd, description, display_condition in tuple_list:

            if not display_condition:
                continue

            wrapper    = textwrap.TextWrapper(width=max(1, (get_tty_w() - len(longest_command))))
            desc_lines = wrapper.fill(description).split('\n')
            spacing    = (len(longest_command) - len(help_cmd)) * ' '

            print(help_cmd + spacing + desc_lines[0])

            # Print wrapped description lines with indent
            if len(desc_lines) > 1:
                for line in desc_lines[1:]:
                    print(len(longest_command) * ' ' + line)
                print('')

    common = [("/about",                    "Show links to project resources",                   True),
              ("/add",                      "Add new contact",                                   not settings.session_trickle),
              ("/cf",                       "Cancel file transmission to recipients",            True),
              ("/cm",                       "Cancel message transmission to recipients",         True),
              ("/clear, '  '",              "Clear screens from TxM, RxM and IM client",         True),
              ("/cmd, '//'",                "Display command window on RxM",                     True),
              ("/exit",                     "Exit TFC on TxM, NH and RxM",                       True),
              ("/export (n)",               "Export (n) messages from recipient's logfile",      True),
              ("/file",                     "Send file to active contact/group",                 True),
              ("/fingerprints",             "Print public key fingerprints of user and contact", True),
              ("/fe",                       "Encrypt and export file to NH",                     not settings.session_trickle),
              ("/fi",                       "Import file from NH to RxM",                        not settings.session_trickle),
              ("/fw",                       "Display file reception window on RxM",              True),
              ("/help",                     "Display this list of commands",                     True),
              ("/history (n)",              "Print (n) messages from recipient's logfile",       True),
              ("/localkey",                 "Generate new local key pair",                       not settings.session_trickle),
              ("/logging {on,off}(' all')", "Change log_messages setting (for all contacts)",    True),
              ("/msg",                      "Change active recipient",                           not settings.session_trickle),
              ("/names",                    "List contacts and groups",                          True),
              ("/nick N",                   "Change nickname of active recipient to N",          True),
              ("/notify {on,off} (' all')", "Change notification settings (for all contacts)",   True),
              ("/passwd {tx,rx}",           "Change master password on TxM/RxM",                 not settings.session_trickle),
              ("/psk",                      "Open PSK import dialog on RxM",                     True),
              ("/reset",                    "Reset ephemeral session log on TxM/RxM/IM client",  not settings.session_trickle),
              ("/rm A",                     "Remove account A from TxM and RxM",                 not settings.session_trickle),
              ("/set S V",                  "Change setting S to value V on TxM/RxM",            not settings.session_trickle),
              ("/settings",                 "List settings, default values and descriptions",    not settings.session_trickle),
              ("/store {on,off} (' all')",  "Change file reception (for all contacts)",          True),
              ("/unread, ' '",              "List windows with unread messages on RxM",          True),
              ("Shift + PgUp/PgDn",         "Scroll terminal up/down",                           True)]

    groupc = [("/group create G A1 .. An",  "Create group G and add accounts A1 .. An",          not settings.session_trickle),
              ("/group add G A1 .. An",     "Add accounts A1 .. An to group G",                  not settings.session_trickle),
              ("/group rm G A1 .. An",      "Remove accounts A1 .. An from group G",             not settings.session_trickle),
              ("/group rm G",               "Remove group G",                                    not settings.session_trickle)]

    terminal_width = get_tty_w()

    clear_screen()

    print(textwrap.fill("List of commands:", width=terminal_width))
    print('')
    help_printer(common)
    print(terminal_width * '-')

    if settings.session_trickle:
        print('')
    else:
        print("Group management:\n")
        help_printer(groupc)
        print(terminal_width * '-' + '\n')


def print_logs(user_input:   'UserInput',
               window:       'Window',
               contact_list: 'ContactList',
               settings:     'Settings',
               c_queue:      'Queue',
               master_key:   'MasterKey') -> None:
    """Print log files on screen."""
    try:
        no_messages_str = user_input.plaintext.split()[1]
        if not no_messages_str.isdigit():
            raise FunctionReturn("Specified invalid number of messages to print.")
        no_messages = int(no_messages_str)
    except IndexError:
        no_messages = 0

    packet = LOG_DISPLAY_HEADER + window.uid.encode() + US_BYTE + int_to_bytes(no_messages)
    queue_command(packet, settings, c_queue)

    access_history(window, contact_list, settings, master_key, no_messages)


def print_recipients(contact_list: 'ContactList', group_list: 'GroupList') -> None:
    """Print list of contacts and groups."""
    contact_list.print_contacts(spacing=True)
    group_list.print_groups()


def change_master_key(user_input:   'UserInput',
                      contact_list: 'ContactList',
                      group_list:   'GroupList',
                      settings:     'Settings',
                      queues:       Dict[bytes, 'Queue'],
                      master_key:   'MasterKey') -> None:
    """Change master key on TxM/RxM."""
    try:
        if settings.session_trickle:
            raise FunctionReturn("Command disabled during trickle connection.")

        try:
            device = user_input.plaintext.split()[1]
        except IndexError:
            raise FunctionReturn("No target system specified.")

        if device.lower() not in ['tx', 'txm', 'rx', 'rxm']:
            raise FunctionReturn("Invalid target system.")

        if device.lower() in ['rx', 'rxm']:
            queue_command(CHANGE_MASTER_K_HEADER, settings, queues[COMMAND_PACKET_QUEUE])
            print('')
            return None

        old_master_key = master_key.master_key[:]
        master_key.new_master_key()
        new_master_key = master_key.master_key

        ensure_dir(f'{DIR_USER_DATA}/')
        file_name = f'{DIR_USER_DATA}/{settings.software_operation}_logs'
        if os.path.isfile(file_name):
            phase("Re-encrypting log-file")
            re_encrypt(old_master_key, new_master_key, settings)
            phase("Done")

        queues[KEY_MANAGEMENT_QUEUE].put(('KEY', master_key))

        settings.store_settings()
        contact_list.store_contacts()
        group_list.store_groups()

        box_print("Master key successfully changed.", head=1)
        clear_screen(delay=1.5)
    except KeyboardInterrupt:
        raise FunctionReturn("Password change aborted.")


def reset_screens(window:   'Window',
                  settings: 'Settings',
                  c_queue:  'Queue',
                  gateway:  'Gateway') -> None:
    """Reset screens on TxM/RxM/NH."""
    queue_command(RESET_SCREEN_HEADER + window.uid.encode(), settings, c_queue)

    if not settings.session_trickle:
        if window.imc_name is not None:
            im_window = window.imc_name.encode()
            time.sleep(0.5)
            transmit(UNENCRYPTED_PACKET_HEADER + UNENCRYPTED_SCREEN_RESET + im_window, settings, gateway)

    os.system('reset')


def change_setting(user_input:   'UserInput',
                   contact_list: 'ContactList',
                   group_list:   'GroupList',
                   settings:     'Settings',
                   c_queue:      'Queue',
                   gateway:      'Gateway') -> None:
    """Change setting on TxM / RxM."""
    try:
        key = user_input.plaintext.split()[1]
    except IndexError:
        raise FunctionReturn("No setting specified.")

    try:
        _ = user_input.plaintext.split()[2]
    except IndexError:
        raise FunctionReturn("No value for setting specified.")

    value = ' '.join(user_input.plaintext.split()[2:])

    if key not in settings.key_list:
        raise FunctionReturn(f"Invalid setting {key}.")

    if settings.session_trickle:
        if key in ['e_correction_ratio', 'serial_iface_speed']:
            raise FunctionReturn("Change of setting disabled during trickle connection.")

    settings.change_setting(key, value, contact_list, group_list)

    if key == 'e_correction_ratio':
        time.sleep(0.5)
        transmit(UNENCRYPTED_PACKET_HEADER + UNENCRYPTED_EC_RATIO + value.encode(), settings, gateway)

    if key == 'serial_iface_speed':
        time.sleep(0.5)
        transmit(UNENCRYPTED_PACKET_HEADER + UNENCRYPTED_BAUDRATE + value.encode(), settings, gateway)

    if key == 'disable_gui_dialog':
        time.sleep(0.5)
        transmit(UNENCRYPTED_PACKET_HEADER + UNENCRYPTED_GUI_DIALOG + value.encode(), settings, gateway)

    packet = CHANGE_SETTING_HEADER + key.encode() + US_BYTE + value.encode()
    queue_command(packet, settings, c_queue)


def rxm_display_unread(settings: 'Settings', c_queue: 'Queue') -> None:
    """Temporarily display list of windows with unread messages on RxM."""
    queue_command(SHOW_WINDOW_ACTIVITY_HEADER, settings, c_queue)
