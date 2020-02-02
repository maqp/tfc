#!/usr/bin/env python3.7
# -*- coding: utf-8 -*-

"""
TFC - Onion-routed, endpoint secure messaging system
Copyright (C) 2013-2020  Markus Ottela

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

import readline
import struct
import textwrap
import time
import typing

from multiprocessing import Queue
from typing          import Any, Dict, List, Tuple, Union

from src.common.db_logs    import access_logs, change_log_db_key, remove_logs, replace_log_db
from src.common.db_keys    import KeyList
from src.common.encoding   import b58decode, b58encode, bool_to_bytes, int_to_bytes, onion_address_to_pub_key
from src.common.exceptions import CriticalError, SoftError
from src.common.input      import yes
from src.common.misc       import get_terminal_width, ignored, reset_terminal, validate_onion_addr
from src.common.output     import clear_screen, m_print, phase, print_on_previous_line
from src.common.statics    import (CH_MASTER_KEY, CH_SETTING, CLEAR, CLEAR_SCREEN, COMMAND_PACKET_QUEUE, DONE,
                                   EXIT_PROGRAM, GROUP_ID_ENC_LENGTH, KDB_HALT_ACK_HEADER, KDB_M_KEY_CHANGE_HALT_HEADER,
                                   KDB_UPDATE_SIZE_HEADER, KEX_STATUS_UNVERIFIED, KEX_STATUS_VERIFIED,
                                   KEY_MANAGEMENT_QUEUE, KEY_MGMT_ACK_QUEUE, LOCAL_TESTING_PACKET_DELAY,
                                   LOGFILE_MASKING_QUEUE, LOG_DISPLAY, LOG_EXPORT, LOG_REMOVE, MESSAGE,
                                   ONION_ADDRESS_LENGTH, RELAY_PACKET_QUEUE, RESET_SCREEN, RX, SENDER_MODE_QUEUE,
                                   TRAFFIC_MASKING_QUEUE, TX, UNENCRYPTED_BAUDRATE, UNENCRYPTED_DATAGRAM_HEADER,
                                   UNENCRYPTED_EC_RATIO, UNENCRYPTED_EXIT_COMMAND, UNENCRYPTED_MANAGE_CONTACT_REQ,
                                   UNENCRYPTED_SCREEN_CLEAR, UNENCRYPTED_SCREEN_RESET, UNENCRYPTED_WIPE_COMMAND,
                                   US_BYTE, VERSION, WIN_ACTIVITY, WIN_SELECT, WIN_TYPE_GROUP, WIN_UID_COMMAND,
                                   WIN_UID_FILE, WIPE_USR_DATA)

from src.transmitter.commands_g    import process_group_command
from src.transmitter.contact       import add_new_contact, change_nick, contact_setting, remove_contact
from src.transmitter.key_exchanges import export_onion_service_data, new_local_key, rxp_load_psk, verify_fingerprints
from src.transmitter.packet        import cancel_packet, queue_command, queue_message, queue_to_nc
from src.transmitter.user_input    import UserInput
from src.transmitter.windows       import select_window

if typing.TYPE_CHECKING:
    from src.common.db_contacts  import ContactList
    from src.common.db_groups    import GroupList
    from src.common.db_masterkey import MasterKey
    from src.common.db_onion     import OnionService
    from src.common.db_settings  import Settings
    from src.common.gateway      import Gateway
    from src.transmitter.windows import TxWindow
    QueueDict = Dict[bytes, Queue[Any]]


def process_command(user_input:    'UserInput',
                    window:        'TxWindow',
                    contact_list:  'ContactList',
                    group_list:    'GroupList',
                    settings:      'Settings',
                    queues:        'QueueDict',
                    master_key:    'MasterKey',
                    onion_service: 'OnionService',
                    gateway:       'Gateway'
                    ) -> None:
    """\
    Select function based on the first keyword of the
    issued command, and pass relevant parameters to it.
    """
    #    Keyword      Function to run         (                                            Parameters                                            )
    #    -----------------------------------------------------------------------------------------------------------------------------------------
    d = {'about':    (print_about,                                                                                                               ),
         'add':      (add_new_contact,                             contact_list, group_list, settings, queues,             onion_service         ),
         'cf':       (cancel_packet,           user_input, window,                           settings, queues                                    ),
         'cm':       (cancel_packet,           user_input, window,                           settings, queues                                    ),
         'clear':    (clear_screens,           user_input, window,                           settings, queues                                    ),
         'cmd':      (rxp_show_sys_win,        user_input, window,                           settings, queues                                    ),
         'connect':  (send_onion_service_key,                      contact_list,             settings,                     onion_service, gateway),
         'exit':     (exit_tfc,                                                              settings, queues,                            gateway),
         'export':   (log_command,             user_input, window, contact_list, group_list, settings, queues, master_key                        ),
         'fw':       (rxp_show_sys_win,        user_input, window,                           settings, queues                                    ),
         'group':    (process_group_command,   user_input,         contact_list, group_list, settings, queues, master_key                        ),
         'help':     (print_help,                                                            settings                                            ),
         'history':  (log_command,             user_input, window, contact_list, group_list, settings, queues, master_key                        ),
         'localkey': (new_local_key,                               contact_list,             settings, queues,                                   ),
         'logging':  (contact_setting,         user_input, window, contact_list, group_list, settings, queues                                    ),
         'msg':      (select_window,           user_input, window,                           settings, queues,             onion_service, gateway),
         'names':    (print_recipients,                            contact_list, group_list,                                                     ),
         'nick':     (change_nick,             user_input, window, contact_list, group_list, settings, queues                                    ),
         'notify':   (contact_setting,         user_input, window, contact_list, group_list, settings, queues                                    ),
         'passwd':   (change_master_key,       user_input,         contact_list, group_list, settings, queues, master_key, onion_service         ),
         'psk':      (rxp_load_psk,                        window, contact_list,             settings, queues                                    ),
         'reset':    (clear_screens,           user_input, window,                           settings, queues                                    ),
         'rm':       (remove_contact,          user_input, window, contact_list, group_list, settings, queues, master_key                        ),
         'rmlogs':   (remove_log,              user_input,         contact_list, group_list, settings, queues, master_key                        ),
         'set':      (change_setting,          user_input, window, contact_list, group_list, settings, queues, master_key,                gateway),
         'settings': (print_settings,                                                        settings,                                    gateway),
         'store':    (contact_setting,         user_input, window, contact_list, group_list, settings, queues                                    ),
         'unread':   (rxp_display_unread,                                                    settings, queues                                    ),
         'verify':   (verify,                              window, contact_list                                                                  ),
         'whisper':  (whisper,                 user_input, window,                           settings, queues                                    ),
         'whois':    (whois,                   user_input,         contact_list, group_list                                                      ),
         'wipe':     (wipe,                                                                  settings, queues,                            gateway)
         }  # type: Dict[str, Any]

    try:
        cmd_key = user_input.plaintext.split()[0]
    except (IndexError, UnboundLocalError):
        raise SoftError("Error: Invalid command.", head_clear=True)

    try:
        from_dict = d[cmd_key]
    except KeyError:
        raise SoftError(f"Error: Invalid command '{cmd_key}'.", head_clear=True)

    func       = from_dict[0]
    parameters = from_dict[1:]
    func(*parameters)


def print_about() -> None:
    """Print URLs that direct to TFC's project site and documentation."""
    clear_screen()
    print(f"\n Tinfoil Chat {VERSION}\n\n"
          " Website:     https://github.com/maqp/tfc/\n"
          " Wikipage:    https://github.com/maqp/tfc/wiki\n")


def clear_screens(user_input: 'UserInput',
                  window:     'TxWindow',
                  settings:   'Settings',
                  queues:     'QueueDict'
                  ) -> None:
    """Clear/reset screen of Source, Destination, and Networked Computer.

    Only send an unencrypted command to Networked Computer if traffic
    masking is disabled.

    With clear command, sending only the command header is enough.
    However, as reset command removes the ephemeral message log on
    Receiver Program, Transmitter Program must define the window to
    reset (in case, e.g., previous window selection command packet
    dropped, and active window state is inconsistent between the
    TCB programs).
    """
    clear = user_input.plaintext.split()[0] == CLEAR

    command = CLEAR_SCREEN if clear else RESET_SCREEN + window.uid
    queue_command(command, settings, queues)

    clear_screen()

    if not settings.traffic_masking:
        pt_cmd = UNENCRYPTED_SCREEN_CLEAR if clear else UNENCRYPTED_SCREEN_RESET
        packet = UNENCRYPTED_DATAGRAM_HEADER + pt_cmd
        queue_to_nc(packet, queues[RELAY_PACKET_QUEUE])

    if not clear:
        readline.clear_history()
        reset_terminal()


def rxp_show_sys_win(user_input: 'UserInput',
                     window:     'TxWindow',
                     settings:   'Settings',
                     queues:     'QueueDict',
                     ) -> None:
    """\
    Display a system window on Receiver Program until the user presses
    Enter.

    Receiver Program has a dedicated window, WIN_UID_LOCAL, for system
    messages that shows information about received commands, status
    messages etc.

    Receiver Program also has another window, WIN_UID_FILE, that shows
    progress of file transmission from contacts that have traffic
    masking enabled.
    """
    cmd     = user_input.plaintext.split()[0]
    win_uid = dict(cmd=WIN_UID_COMMAND, fw=WIN_UID_FILE)[cmd]

    command = WIN_SELECT + win_uid
    queue_command(command, settings, queues)

    try:
        m_print(f"<Enter> returns Receiver to {window.name}'s window", manual_proceed=True, box=True)
    except (EOFError, KeyboardInterrupt):
        pass

    print_on_previous_line(reps=4, flush=True)

    command = WIN_SELECT + window.uid
    queue_command(command, settings, queues)


def exit_tfc(settings: 'Settings',
             queues:   'QueueDict',
             gateway:  'Gateway'
             ) -> None:
    """Exit TFC on all three computers.

    To exit TFC as fast as possible, this function starts by clearing
    all command queues before sending the exit command to Receiver
    Program. It then sends an unencrypted exit command to Relay Program
    on Networked Computer. As the `sender_loop` process loads the
    unencrypted exit command from queue, it detects the user's
    intention, and after outputting the packet, sends the EXIT signal to
    Transmitter Program's main() method that's running the
    `monitor_processes` loop. Upon receiving the EXIT signal,
    `monitor_processes` kills all Transmitter Program's processes and
    exits the program.

    During local testing, this function adds some delays to prevent TFC
    programs from dying when sockets disconnect.
    """
    for q in [COMMAND_PACKET_QUEUE, RELAY_PACKET_QUEUE]:
        while queues[q].qsize() > 0:
            queues[q].get()

    queue_command(EXIT_PROGRAM, settings, queues)

    if not settings.traffic_masking:
        if settings.local_testing_mode:
            time.sleep(LOCAL_TESTING_PACKET_DELAY)
            time.sleep(gateway.settings.data_diode_sockets * 1.5)
        else:
            time.sleep(gateway.settings.race_condition_delay)

    relay_command = UNENCRYPTED_DATAGRAM_HEADER + UNENCRYPTED_EXIT_COMMAND
    queue_to_nc(relay_command, queues[RELAY_PACKET_QUEUE])


def log_command(user_input:   'UserInput',
                window:       'TxWindow',
                contact_list: 'ContactList',
                group_list:   'GroupList',
                settings:     'Settings',
                queues:       'QueueDict',
                master_key:   'MasterKey'
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
    export, header = dict(export =(True,  LOG_EXPORT),
                          history=(False, LOG_DISPLAY))[cmd]

    try:
        msg_to_load = int(user_input.plaintext.split()[1])
    except ValueError:
        raise SoftError("Error: Invalid number of messages.", head_clear=True)
    except IndexError:
        msg_to_load = 0

    try:
        command = header + int_to_bytes(msg_to_load) + window.uid
    except struct.error:
        raise SoftError("Error: Invalid number of messages.", head_clear=True)

    if export and not yes(f"Export logs for '{window.name}' in plaintext?", abort=False):
        raise SoftError("Log file export aborted.", tail_clear=True, head=0, delay=1)

    authenticated = master_key.authenticate_action() if settings.ask_password_for_log_access else True

    if authenticated:
        queue_command(command, settings, queues)
        access_logs(window, contact_list, group_list, settings, master_key, msg_to_load, export=export)

        if export:
            raise SoftError(f"Exported log file of {window.type} '{window.name}'.", head_clear=True)


def send_onion_service_key(contact_list:  'ContactList',
                           settings:      'Settings',
                           onion_service: 'OnionService',
                           gateway:       'Gateway'
                           ) -> None:
    """Resend Onion Service key to Relay Program on Networked Computer.

    This command is used in cases where Relay Program had to be
    restarted for some reason (e.g. due to system updates).
    """
    try:
        if settings.traffic_masking:
            m_print(["Warning!",
                     "Exporting Onion Service data to Networked Computer ",
                     "during traffic masking can reveal to an adversary ",
                     "TFC is being used at the moment. You should only do ",
                     "this if you've had to restart the Relay Program."], bold=True, head=1, tail=1)
            if not yes("Proceed with the Onion Service data export?", abort=False):
                raise SoftError("Onion Service data export canceled.", tail_clear=True, delay=1, head=0)

        export_onion_service_data(contact_list, settings, onion_service, gateway)
    except (EOFError, KeyboardInterrupt):
        raise SoftError("Onion Service data export canceled.", tail_clear=True, delay=1, head=2)


def print_help(settings: 'Settings') -> None:
    """Print the list of commands."""

    def help_printer(tuple_list: List[Union[Tuple[str, str, bool]]]) -> None:
        """Print list of commands and their descriptions.

        Style in which commands are printed depends on terminal width.
        Depending on whether traffic masking is enabled, some commands
        are either displayed or hidden.
        """
        len_longest_command = max(len(t[0]) for t in tuple_list) + 1  # Add one for spacing
        wrapper             = textwrap.TextWrapper(width=max(1, terminal_width - len_longest_command))

        for help_cmd, description, display in tuple_list:
            if not display:
                continue

            desc_lines  = wrapper.fill(description).split('\n')
            desc_indent = (len_longest_command - len(help_cmd)) * ' '

            print(help_cmd + desc_indent + desc_lines[0])

            # Print wrapped description lines with indent
            if len(desc_lines) > 1:
                for line in desc_lines[1:]:
                    print(len_longest_command * ' ' + line)
                print('')

    # ------------------------------------------------------------------------------------------------------------------

    y_tm = settings.traffic_masking
    n_tm = not y_tm

    common_commands = [("/about",                    "Show links to project resources",                     True),
                       ("/add",                      "Add new contact",                                     n_tm),
                       ("/cf",                       "Cancel file transmission to active contact/group",    y_tm),
                       ("/cm",                       "Cancel message transmission to active contact/group", True),
                       ("/clear, '  '",              "Clear TFC screens",                                   True),
                       ("/cmd, '//'",                "Display command window on Receiver",                  True),
                       ("/connect",                  "Resend Onion Service data to Relay",                  True),
                       ("/exit",                     "Exit TFC on all three computers",                     True),
                       ("/export (n)",               "Export (n) messages from recipient's log file",       True),
                       ("/file",                     "Send file to active contact/group",                   True),
                       ("/fw",                       "Display file reception window on Receiver",           y_tm),
                       ("/help",                     "Display this list of commands",                       True),
                       ("/history (n)",              "Print (n) messages from recipient's log file",        True),
                       ("/localkey",                 "Generate new local key pair",                         n_tm),
                       ("/logging {on,off}(' all')", "Change message log setting (for all contacts)",       True),
                       ("/msg {A,N,G}",              "Change recipient to Account, Nick, or Group",         n_tm),
                       ("/names",                    "List contacts and groups",                            True),
                       ("/nick N",                   "Change nickname of active recipient/group to N",      True),
                       ("/notify {on,off} (' all')", "Change notification settings (for all contacts)",     True),
                       ("/passwd {tx,rx}",           "Change master password on target system",             n_tm),
                       ("/psk",                      "Open PSK import dialog on Receiver",                  n_tm),
                       ("/reset",                    "Reset ephemeral session log for active window",       True),
                       ("/rm {A,N}",                 "Remove contact specified by account A or nick N",     n_tm),
                       ("/rmlogs {A,N}",             "Remove log entries for account A or nick N",          True),
                       ("/set S V",                  "Change setting S to value V",                         True),
                       ("/settings",                 "List setting names, values and descriptions",         True),
                       ("/store {on,off} (' all')",  "Change file reception (for all contacts)",            True),
                       ("/unread, ' '",              "List windows with unread messages on Receiver",       True),
                       ("/verify",                   "Verify fingerprints with active contact",             True),
                       ("/whisper M",                "Send message M, asking it not to be logged",          True),
                       ("/whois {A,N}",              "Check which A corresponds to N or vice versa",        True),
                       ("/wipe",                     "Wipe all TFC user data and power off systems",        True),
                       ("Shift + PgUp/PgDn",         "Scroll terminal up/down",                             True)]

    group_commands  = [("/group create G A₁..Aₙ",    "Create group G and add accounts A₁..Aₙ",              n_tm),
                       ("/group join ID G A₁..Aₙ",   "Join group ID, call it G and add accounts A₁..Aₙ",    n_tm),
                       ("/group add G A₁..Aₙ",       "Add accounts A₁..Aₙ to group G",                      n_tm),
                       ("/group rm G A₁..Aₙ",        "Remove accounts A₁..Aₙ from group G",                 n_tm),
                       ("/group rm G",               "Remove group G",                                      n_tm)]

    terminal_width = get_terminal_width()

    clear_screen()

    print(textwrap.fill("List of commands:", width=terminal_width))
    print('')
    help_printer(common_commands)
    print(terminal_width * '─')

    if settings.traffic_masking:
        print('')
    else:
        print(textwrap.fill("Group management:", width=terminal_width))
        print('')
        help_printer(group_commands)
        print(terminal_width * '─' + '\n')


def print_recipients(contact_list: 'ContactList', group_list: 'GroupList') -> None:
    """Print the list of contacts and groups."""
    contact_list.print_contacts()
    group_list.print_groups()


def change_master_key(user_input:    'UserInput',
                      contact_list:  'ContactList',
                      group_list:    'GroupList',
                      settings:      'Settings',
                      queues:        'QueueDict',
                      master_key:    'MasterKey',
                      onion_service: 'OnionService'
                      ) -> None:
    """Change the master key on Transmitter/Receiver Program."""
    if settings.traffic_masking:
        raise SoftError("Error: Command is disabled during traffic masking.", head_clear=True)

    try:
        device = user_input.plaintext.split()[1].lower()
    except IndexError:
        raise SoftError(f"Error: No target-system ('{TX}' or '{RX}') specified.", head_clear=True)

    if device not in [TX, RX]:
        raise SoftError(f"Error: Invalid target system '{device}'.", head_clear=True)

    if device == RX:
        queue_command(CH_MASTER_KEY, settings, queues)
        return None

    authenticated = master_key.authenticate_action()

    if authenticated:
        # Halt `sender_loop` for the duration of database re-encryption.
        queues[KEY_MANAGEMENT_QUEUE].put((KDB_M_KEY_CHANGE_HALT_HEADER,))
        wait_for_key_db_halt(queues)

        # Load old key_list from database file as it's not used on input_loop side.
        key_list = KeyList(master_key, settings)

        # Cache old master key to allow log file re-encryption.
        old_master_key = master_key.master_key[:]

        # Create new master key but do not store new master key data into any database.
        new_master_key = master_key.master_key = master_key.new_master_key(replace=False)
        phase("Re-encrypting databases")

        # Update encryption keys for databases
        contact_list.database.database_key  = new_master_key
        key_list.database.database_key      = new_master_key
        group_list.database.database_key    = new_master_key
        settings.database.database_key      = new_master_key
        onion_service.database.database_key = new_master_key

        # Create temp databases for each database, do not replace original.
        with ignored(SoftError):
            change_log_db_key(old_master_key, new_master_key, settings)
        contact_list.store_contacts(replace=False)
        key_list.store_keys(replace=False)
        group_list.store_groups(replace=False)
        settings.store_settings(replace=False)
        onion_service.store_onion_service_private_key(replace=False)

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
        onion_service.database.replace_database()

        # Now all databases have been updated. It's time to let
        # the key database know what the new master key is.
        queues[KEY_MANAGEMENT_QUEUE].put(new_master_key)

        wait_for_key_db_ack(new_master_key, queues)

        phase(DONE)
        m_print("Master key successfully changed.", bold=True, tail_clear=True, delay=1, head=1)


def wait_for_key_db_halt(queues: 'QueueDict') -> None:
    """Wait for the key database to acknowledge it has halted output of packets."""
    while not queues[KEY_MGMT_ACK_QUEUE].qsize():
        time.sleep(0.001)
    if queues[KEY_MGMT_ACK_QUEUE].get() != KDB_HALT_ACK_HEADER:
        raise SoftError("Error: Key database returned wrong signal.")


def wait_for_key_db_ack(new_master_key: bytes, queues: 'QueueDict') -> None:
    """Wait for the key database to acknowledge it has replaced the master key."""
    while not queues[KEY_MGMT_ACK_QUEUE].qsize():
        time.sleep(0.001)
    if queues[KEY_MGMT_ACK_QUEUE].get() != new_master_key:
        raise CriticalError("Key database failed to install new master key.")


def remove_log(user_input:   'UserInput',
               contact_list: 'ContactList',
               group_list:   'GroupList',
               settings:     'Settings',
               queues:       'QueueDict',
               master_key:   'MasterKey'
               ) -> None:
    """Remove log entries for contact or group."""
    try:
        selection = user_input.plaintext.split()[1]
    except IndexError:
        raise SoftError("Error: No contact/group specified.", head_clear=True)

    if not yes(f"Remove logs for {selection}?", abort=False, head=1):
        raise SoftError("Log file removal aborted.", tail_clear=True, delay=1, head=0)

    selector = determine_selector(selection, contact_list, group_list)

    # Remove logs that match the selector
    command = LOG_REMOVE + selector
    queue_command(command, settings, queues)

    remove_logs(contact_list, group_list, settings, master_key, selector)


def determine_selector(selection:    str,
                       contact_list: 'ContactList',
                       group_list:   'GroupList'
                       ) -> bytes:
    """Determine selector (group ID or Onion Service public key)."""
    if selection in contact_list.contact_selectors():
        selector = contact_list.get_contact_by_address_or_nick(selection).onion_pub_key

    elif selection in group_list.get_list_of_group_names():
        selector = group_list.get_group(selection).group_id

    elif len(selection) == ONION_ADDRESS_LENGTH:
        if validate_onion_addr(selection):
            raise SoftError("Error: Invalid account.", head_clear=True)
        selector = onion_address_to_pub_key(selection)

    elif len(selection) == GROUP_ID_ENC_LENGTH:
        try:
            selector = b58decode(selection)
        except ValueError:
            raise SoftError("Error: Invalid group ID.", head_clear=True)

    else:
        raise SoftError("Error: Unknown selector.", head_clear=True)

    return selector


def change_setting(user_input:   'UserInput',
                   window:       'TxWindow',
                   contact_list: 'ContactList',
                   group_list:   'GroupList',
                   settings:     'Settings',
                   queues:       'QueueDict',
                   master_key:   'MasterKey',
                   gateway:      'Gateway'
                   ) -> None:
    """Change setting on Transmitter and Receiver Program."""
    # Validate the KV-pair
    try:
        setting = user_input.plaintext.split()[1]
    except IndexError:
        raise SoftError("Error: No setting specified.", head_clear=True)

    if setting not in (settings.key_list + gateway.settings.key_list):
        raise SoftError(f"Error: Invalid setting '{setting}'.", head_clear=True)

    try:
        value = user_input.plaintext.split()[2]
    except IndexError:
        raise SoftError("Error: No value for setting specified.", head_clear=True)

    relay_settings = dict(serial_error_correction=UNENCRYPTED_EC_RATIO,
                          serial_baudrate        =UNENCRYPTED_BAUDRATE,
                          allow_contact_requests =UNENCRYPTED_MANAGE_CONTACT_REQ)  # type: Dict[str, bytes]

    check_setting_change_conditions(setting, settings, relay_settings, master_key)

    change_setting_value(setting, value, relay_settings, queues, contact_list, group_list, settings, gateway)

    propagate_setting_effects(setting, queues, contact_list, group_list, settings, window)


def check_setting_change_conditions(setting:        str,
                                    settings:       'Settings',
                                    relay_settings: Dict[str, bytes],
                                    master_key:     'MasterKey'
                                    ) -> None:
    """Check if the setting can be changed."""
    if settings.traffic_masking and (setting in relay_settings or setting == "max_number_of_contacts"):
        raise SoftError("Error: Can't change this setting during traffic masking.", head_clear=True)

    if setting in ["use_serial_usb_adapter", "built_in_serial_interface"]:
        raise SoftError("Error: Serial interface setting can only be changed manually.", head_clear=True)

    if setting == "ask_password_for_log_access":
        if not master_key.authenticate_action():
            raise SoftError("Error: No permission to change setting.", head_clear=True)


def change_setting_value(setting:        str,
                         value:          str,
                         relay_settings: Dict[str, bytes],
                         queues:         'QueueDict',
                         contact_list:   'ContactList',
                         group_list:     'GroupList',
                         settings:       'Settings',
                         gateway:        'Gateway'
                         ) -> None:
    """Change setting value in setting databases."""
    if setting in gateway.settings.key_list:
        gateway.settings.change_setting(setting, value)
    else:
        settings.change_setting(setting, value, contact_list, group_list)

    receiver_command = CH_SETTING + setting.encode() + US_BYTE + value.encode()

    queue_command(receiver_command, settings, queues)

    if setting in relay_settings:
        if setting == 'allow_contact_requests':
            value = bool_to_bytes(settings.allow_contact_requests).decode()
        relay_command = UNENCRYPTED_DATAGRAM_HEADER + relay_settings[setting] + value.encode()
        queue_to_nc(relay_command, queues[RELAY_PACKET_QUEUE])


def propagate_setting_effects(setting:      str,
                              queues:       'QueueDict',
                              contact_list: 'ContactList',
                              group_list:   'GroupList',
                              settings:     'Settings',
                              window:       'TxWindow'
                              ) -> None:
    """Propagate the effects of the setting."""
    if setting == "max_number_of_contacts":
        contact_list.store_contacts()
        queues[KEY_MANAGEMENT_QUEUE].put((KDB_UPDATE_SIZE_HEADER, settings))

    if setting in ['max_number_of_group_members', 'max_number_of_groups']:
        group_list.store_groups()

    if setting == 'traffic_masking':
        queues[SENDER_MODE_QUEUE].put(settings)
        queues[TRAFFIC_MASKING_QUEUE].put(settings.traffic_masking)
        window.deselect()

    if setting == 'log_file_masking':
        queues[LOGFILE_MASKING_QUEUE].put(settings.log_file_masking)


def print_settings(settings: 'Settings', gateway: 'Gateway') -> None:
    """Print settings and gateway settings."""
    settings.print_settings()
    gateway.settings.print_settings()


def rxp_display_unread(settings: 'Settings', queues: 'QueueDict') -> None:
    """\
    Display the list of windows that contain unread messages on Receiver
    Program.
    """
    queue_command(WIN_ACTIVITY, settings, queues)


def verify(window: 'TxWindow', contact_list: 'ContactList') -> None:
    """Verify fingerprints with contact."""
    if window.type == WIN_TYPE_GROUP or window.contact is None:
        raise SoftError("Error: A group is selected.", head_clear=True)

    if window.contact.uses_psk():
        raise SoftError("Pre-shared keys have no fingerprints.", head_clear=True)

    try:
        verified = verify_fingerprints(window.contact.tx_fingerprint,
                                       window.contact.rx_fingerprint)
    except (EOFError, KeyboardInterrupt):
        raise SoftError("Fingerprint verification aborted.", delay=1, head=2, tail_clear=True)

    status_hr, status = {True:  ("Verified",   KEX_STATUS_VERIFIED),
                         False: ("Unverified", KEX_STATUS_UNVERIFIED)}[verified]

    window.contact.kex_status = status
    contact_list.store_contacts()
    m_print(f"Marked fingerprints with {window.name} as '{status_hr}'.", bold=True, tail_clear=True, delay=1, tail=1)


def whisper(user_input: 'UserInput',
            window:     'TxWindow',
            settings:   'Settings',
            queues:     'QueueDict',
            ) -> None:
    """\
    Send a message to the contact that overrides their enabled logging
    setting for that message.

    The functionality of this feature is impossible to enforce, but if
    the recipient can be trusted and they do not modify their client,
    this feature can be used to send the message off-the-record.
    """
    try:
        message = user_input.plaintext.strip().split(' ', 1)[1]
    except IndexError:
        raise SoftError("Error: No whisper message specified.", head_clear=True)

    queue_message(user_input=UserInput(message, MESSAGE),
                  window=window,
                  settings=settings,
                  queues=queues,
                  whisper=True,
                  log_as_ph=True)


def whois(user_input:   'UserInput',
          contact_list: 'ContactList',
          group_list:   'GroupList'
          ) -> None:
    """Do a lookup for a contact or group selector."""
    try:
        selector = user_input.plaintext.split()[1]
    except IndexError:
        raise SoftError("Error: No account or nick specified.", head_clear=True)

    # Contacts
    if selector in contact_list.get_list_of_addresses():
        m_print([f"Nick of '{selector}' is ",
                 f"{contact_list.get_contact_by_address_or_nick(selector).nick}"], bold=True)

    elif selector in contact_list.get_list_of_nicks():
        m_print([f"Account of '{selector}' is",
                 f"{contact_list.get_contact_by_address_or_nick(selector).onion_address}"], bold=True)

    # Groups
    elif selector in group_list.get_list_of_group_names():
        m_print([f"Group ID of group '{selector}' is",
                 f"{b58encode(group_list.get_group(selector).group_id)}"], bold=True)

    elif selector in group_list.get_list_of_hr_group_ids():
        m_print([f"Name of group with ID '{selector}' is",
                 f"{group_list.get_group_by_id(b58decode(selector)).name}"], bold=True)

    else:
        raise SoftError("Error: Unknown selector.", head_clear=True)


def wipe(settings: 'Settings',
         queues:   'QueueDict',
         gateway:  'Gateway'
         ) -> None:
    """\
    Reset terminals, wipe all TFC user data from Source, Networked, and
    Destination Computer, and power all three systems off.

    The purpose of the wipe command is to provide additional protection
    against physical attackers, e.g. in situation where a dissident gets
    a knock on their door. By overwriting and deleting user data the
    program prevents access to encrypted databases. Additional security
    should be sought with full disk encryption (FDE).

    Unfortunately, no effective tool for overwriting RAM currently exists.
    However, as long as Source and Destination Computers use FDE and
    DDR3 memory, recovery of sensitive data becomes impossible very fast:
        https://www1.cs.fau.de/filepool/projects/coldboot/fares_coldboot.pdf
    """
    if not yes("Wipe all user data and power off systems?", abort=False):
        raise SoftError("Wipe command aborted.", head_clear=True)

    clear_screen()

    for q in [COMMAND_PACKET_QUEUE, RELAY_PACKET_QUEUE]:
        while queues[q].qsize() != 0:
            queues[q].get()

    queue_command(WIPE_USR_DATA, settings, queues)

    if not settings.traffic_masking:
        if settings.local_testing_mode:
            time.sleep(0.8)
            time.sleep(gateway.settings.data_diode_sockets * 2.2)
        else:
            time.sleep(gateway.settings.race_condition_delay)

    relay_command = UNENCRYPTED_DATAGRAM_HEADER + UNENCRYPTED_WIPE_COMMAND
    queue_to_nc(relay_command, queues[RELAY_PACKET_QUEUE])

    reset_terminal()
