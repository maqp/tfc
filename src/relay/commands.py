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

import serial
import time
import typing

from typing import Any, Dict

from src.common.encoding   import bytes_to_bool, bytes_to_int
from src.common.exceptions import SoftError
from src.common.misc       import ignored, reset_terminal, separate_header, separate_headers, split_byte_string
from src.common.output     import clear_screen, m_print
from src.common.statics    import (ACCOUNT_CHECK_QUEUE, CONFIRM_CODE_LENGTH, CONTACT_MGMT_QUEUE, C_REQ_MGMT_QUEUE,
                                   C_REQ_STATE_QUEUE, ENCODED_BOOLEAN_LENGTH, ENCODED_INTEGER_LENGTH, EXIT,
                                   GROUP_MGMT_QUEUE, LOCAL_TESTING_PACKET_DELAY, MAX_INT, ONION_CLOSE_QUEUE,
                                   ONION_KEY_QUEUE, ONION_SERVICE_PRIVATE_KEY_LENGTH, ONION_SERVICE_PUBLIC_KEY_LENGTH,
                                   PUB_KEY_CHECK_QUEUE, RP_ADD_CONTACT_HEADER, RP_REMOVE_CONTACT_HEADER,
                                   SRC_TO_RELAY_QUEUE, UNENCRYPTED_ACCOUNT_CHECK, UNENCRYPTED_ADD_EXISTING_CONTACT,
                                   UNENCRYPTED_ADD_NEW_CONTACT, UNENCRYPTED_BAUDRATE, UNENCRYPTED_COMMAND_HEADER_LENGTH,
                                   UNENCRYPTED_EC_RATIO, UNENCRYPTED_EXIT_COMMAND, UNENCRYPTED_MANAGE_CONTACT_REQ,
                                   UNENCRYPTED_ONION_SERVICE_DATA, UNENCRYPTED_PUBKEY_CHECK, UNENCRYPTED_REM_CONTACT,
                                   UNENCRYPTED_SCREEN_CLEAR, UNENCRYPTED_SCREEN_RESET, UNENCRYPTED_WIPE_COMMAND, WIPE)

if typing.TYPE_CHECKING:
    from multiprocessing    import Queue
    from src.common.gateway import Gateway
    QueueDict = Dict[bytes, Queue[Any]]


def relay_command(queues:    'QueueDict',
                  gateway:   'Gateway',
                  unit_test: bool = False
                  ) -> None:
    """Process Relay Program commands."""
    queue_from_src = queues[SRC_TO_RELAY_QUEUE]

    while True:
        with ignored(EOFError, KeyboardInterrupt, SoftError):
            while queue_from_src.qsize() == 0:
                time.sleep(0.01)

            command = queue_from_src.get()
            process_command(command, gateway, queues)

            if unit_test:
                break


def process_command(command:  bytes,
                    gateway:  'Gateway',
                    queues:   'QueueDict'
                    ) -> None:
    """Select function for received Relay Program command."""
    header, command = separate_header(command, UNENCRYPTED_COMMAND_HEADER_LENGTH)

    #             Keyword                            Function to run    (       Parameters        )
    #             ---------------------------------------------------------------------------------
    function_d = {UNENCRYPTED_SCREEN_CLEAR:         (clear_windows,               gateway,        ),
                  UNENCRYPTED_SCREEN_RESET:         (reset_windows,               gateway,        ),
                  UNENCRYPTED_EXIT_COMMAND:         (exit_tfc,                    gateway,  queues),
                  UNENCRYPTED_WIPE_COMMAND:         (wipe,                        gateway,  queues),
                  UNENCRYPTED_EC_RATIO:             (change_ec_ratio,    command, gateway,        ),
                  UNENCRYPTED_BAUDRATE:             (change_baudrate,    command, gateway,        ),
                  UNENCRYPTED_MANAGE_CONTACT_REQ:   (manage_contact_req, command,           queues),
                  UNENCRYPTED_ADD_NEW_CONTACT:      (add_contact,        command, False,    queues),
                  UNENCRYPTED_ADD_EXISTING_CONTACT: (add_contact,        command, True,     queues),
                  UNENCRYPTED_REM_CONTACT:          (remove_contact,     command,           queues),
                  UNENCRYPTED_ONION_SERVICE_DATA:   (add_onion_data,     command,           queues),
                  UNENCRYPTED_ACCOUNT_CHECK:        (compare_accounts,   command,           queues),
                  UNENCRYPTED_PUBKEY_CHECK:         (compare_pub_keys,   command,           queues)
                  }  # type: Dict[bytes, Any]

    if header not in function_d:
        raise SoftError("Error: Received an invalid command.")

    from_dict  = function_d[header]
    func       = from_dict[0]
    parameters = from_dict[1:]
    func(*parameters)


def race_condition_delay(gateway: 'Gateway') -> None:
    """Prevent race condition with Receiver command."""
    if gateway.settings.local_testing_mode:
        time.sleep(LOCAL_TESTING_PACKET_DELAY)
        time.sleep(gateway.settings.data_diode_sockets * 1.0)


def clear_windows(gateway: 'Gateway') -> None:
    """Clear Relay Program screen."""
    race_condition_delay(gateway)
    clear_screen()


def reset_windows(gateway: 'Gateway') -> None:
    """Reset Relay Program screen."""
    race_condition_delay(gateway)
    reset_terminal()


def exit_tfc(gateway: 'Gateway', queues: 'QueueDict') -> None:
    """Exit TFC.

    The queue is read by
        relay.onion.onion_service()
    """
    race_condition_delay(gateway)
    queues[ONION_CLOSE_QUEUE].put(EXIT)


def wipe(gateway: 'Gateway', queues: 'QueueDict') -> None:
    """Reset terminal, wipe all user data and power off the system.

    No effective RAM overwriting tool currently exists, so as long as Source and
    Destination Computers use FDE and DDR3 memory, recovery of user data becomes
    impossible very fast:
        https://www1.cs.fau.de/filepool/projects/coldboot/fares_coldboot.pdf

    The queue is read by
        relay.onion.onion_service()
    """
    reset_terminal()
    race_condition_delay(gateway)
    queues[ONION_CLOSE_QUEUE].put(WIPE)


def change_ec_ratio(command: bytes, gateway: 'Gateway') -> None:
    """Change Relay Program's Reed-Solomon error correction ratio."""
    try:
        value = int(command)
        if value < 0 or value > MAX_INT:
            raise ValueError
    except ValueError:
        raise SoftError("Error: Received invalid EC ratio value from Transmitter Program.")

    m_print("Error correction ratio will change on restart.", head=1, tail=1)

    gateway.settings.serial_error_correction = value
    gateway.settings.store_settings()


def change_baudrate(command: bytes, gateway: 'Gateway') -> None:
    """Change Relay Program's serial interface baud rate setting."""
    try:
        value = int(command)
        if value not in serial.Serial.BAUDRATES:
            raise ValueError
    except ValueError:
        raise SoftError("Error: Received invalid baud rate value from Transmitter Program.")

    m_print("Baud rate will change on restart.", head=1, tail=1)

    gateway.settings.serial_baudrate = value
    gateway.settings.store_settings()


def manage_contact_req(command: bytes,
                       queues:  'QueueDict',
                       notify:  bool = True
                       ) -> None:
    """Control whether contact requests are accepted."""
    enabled = bytes_to_bool(command)
    if notify:
        m_print(f"Contact requests are have been {('enabled' if enabled else 'disabled')}.", head=1, tail=1)
    queues[C_REQ_STATE_QUEUE].put(enabled)


def add_contact(command:  bytes,
                existing: bool,
                queues:   'QueueDict'
                ) -> None:
    """Add clients to Relay Program.

    The queues are read by
        relay.client.client_scheduler()
        relay.client.g_msg_manager() and
        relay.client.c_req_manager()
    """
    queues[CONTACT_MGMT_QUEUE].put((RP_ADD_CONTACT_HEADER, command, existing))
    queues[GROUP_MGMT_QUEUE].put((RP_ADD_CONTACT_HEADER, command))
    queues[C_REQ_MGMT_QUEUE].put((RP_ADD_CONTACT_HEADER, command))


def remove_contact(command: bytes, queues: 'QueueDict') -> None:
    """Remove clients from Relay Program.

    The queues are read by
        relay.client.client_scheduler()
        relay.client.g_msg_manager() and
        relay.client.c_req_manager()
    """
    queues[CONTACT_MGMT_QUEUE].put((RP_REMOVE_CONTACT_HEADER, command, False))
    queues[GROUP_MGMT_QUEUE].put((RP_REMOVE_CONTACT_HEADER, command))
    queues[C_REQ_MGMT_QUEUE].put((RP_REMOVE_CONTACT_HEADER, command))


def add_onion_data(command: bytes, queues: 'QueueDict') -> None:
    """Add Onion Service data.

    Separate onion service private key and public keys for
    pending/existing contacts and add them as contacts.

    The ONION_KEY_QUEUE is read by
        relay.onion.onion_service()
    """
    os_private_key, confirmation_code, allow_req_byte, no_pending_bytes, ser_pub_keys \
        = separate_headers(command, [ONION_SERVICE_PRIVATE_KEY_LENGTH, CONFIRM_CODE_LENGTH,
                                     ENCODED_BOOLEAN_LENGTH, ENCODED_INTEGER_LENGTH])

    no_pending           = bytes_to_int(no_pending_bytes)
    public_key_list      = split_byte_string(ser_pub_keys, ONION_SERVICE_PUBLIC_KEY_LENGTH)
    pending_public_keys  = public_key_list[:no_pending]
    existing_public_keys = public_key_list[no_pending:]

    for onion_pub_key in pending_public_keys:
        add_contact(onion_pub_key, False, queues)
    for onion_pub_key in existing_public_keys:
        add_contact(onion_pub_key, True, queues)

    manage_contact_req(allow_req_byte, queues, notify=False)
    queues[ONION_KEY_QUEUE].put((os_private_key, confirmation_code))


def compare_accounts(command: bytes, queues: 'QueueDict') -> None:
    """\
    Compare incorrectly typed account to what's available on Relay
    Program.
    """
    queues[ACCOUNT_CHECK_QUEUE].put(command.decode())


def compare_pub_keys(command: bytes, queues: 'QueueDict') -> None:
    """\
    Compare incorrectly typed public key to what's available on Relay
    Program.
    """
    account, incorrect_pub_key = separate_header(command, ONION_SERVICE_PUBLIC_KEY_LENGTH)
    queues[PUB_KEY_CHECK_QUEUE].put((account, incorrect_pub_key))
