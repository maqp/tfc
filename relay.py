#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
TFC - Onion-routed, endpoint secure messaging system
Copyright (C) 2013-2024  Markus Ottela

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

import os
import sys

from multiprocessing import Process, Queue
from typing          import Any, Dict

from src.common.crypto  import X448
from src.common.gateway import Gateway, gateway_loop
from src.common.misc    import ensure_dir, monitor_processes, platform_is_tails, process_arguments
from src.common.output  import print_title
from src.common.statics import (ACCOUNT_CHECK_QUEUE, ACCOUNT_SEND_QUEUE, CONTACT_MGMT_QUEUE, CONTACT_REQ_QUEUE,
                                C_REQ_MGMT_QUEUE, C_REQ_STATE_QUEUE, DIR_TAILS_PERS, DIR_TFC, DST_COMMAND_QUEUE,
                                DST_MESSAGE_QUEUE, EXIT_QUEUE, GATEWAY_QUEUE, GUI_INPUT_QUEUE, GROUP_MGMT_QUEUE,
                                GROUP_MSG_QUEUE, NC, ONION_CLOSE_QUEUE, PUB_KEY_CHECK_QUEUE, PUB_KEY_SEND_QUEUE,
                                ONION_KEY_QUEUE, SRC_TO_RELAY_QUEUE, RX_BUF_KEY_QUEUE, TOR_DATA_QUEUE, TX_BUF_KEY_QUEUE,
                                URL_TOKEN_QUEUE, USER_ACCOUNT_QUEUE)

from src.relay.client   import c_req_manager, client_scheduler, g_msg_manager
from src.relay.commands import relay_command
from src.relay.diffs    import account_checker, pub_key_checker
from src.relay.onion    import onion_service
from src.relay.server   import flask_server
from src.relay.tcb      import dst_outgoing, src_incoming


def main() -> None:
    """Load persistent settings and launch the Relay Program.

    This function loads settings from the settings database and launches
    processes for the Relay Program. It then monitors the EXIT_QUEUE for
    EXIT/WIPE signals and each process in case one of them dies.

    If you're reading this code to get the big picture on how TFC works,
    start by looking at `tfc.py` for Transmitter Program functionality.
    After you have reviewed the Transmitter Program's code, revisit the
    code of this program.

    The Relay Program operates multiple processes to enable real time IO
    between multiple data sources and destinations.

    Symbols:
        process_name    denotes the name of the process

        ─>, <─, ↑, ↓    denotes the direction of data passed from one
                        process to another

        (Description)   denotes the description of data passed from one
                        process to another

        ┈, ┊            denotes the link between a description and path
                        of data matching the description

        ▶|, |◀          denotes the gateways where the direction of data
                        flow is enforced with hardware data diodes


                                         Relay Program (Networked Computer)
                    ┏━━  ━━  ━━  ━━  ━━  ━━  ━━  ━━  ━━  ━━  ━━  ━━  ━━  ━━  ━━  ━━  ━━  ━━  ━━┓
                    ┃                  (1: Onion Service private key)                          ┃
                                       (2: Contact management commands)
                    ┃  ┌──────────────────────────────┬────────────────────────┬────────────┐  ┃
                       │                              │                        ↓┈2          │
                    ┃  │                    ┌─────> relay_command  ┌───> c_req_manager      │  ┃
                       │                    │                  │   │                        │
                    ┃  │     (Relay Program┈│   (Onion Service┈│   │                        │  ┃
                       │      commands)     │    public key)   │   │┈(In: Contact requests) │
                    ┃  │                    │                  ↓   │       ┊              1┈↓  ┃
      Source ───▶|─────(── gateway_loop ─> src_incoming ─> flask_server <─────> onion_service <───> client on contact's
    Computer        ┃  │                            │              ↑       ┊                   ┃     Networked Computer
                       │   (Local keys, commands,   │              │ (Out: msg/file/pubkey/
                    ┃  │    and copies of messages)┄│              │  group mgmt message)      ┃
                       │                            │              │
                    ┃  │                            ↓              │                           ┃
 Destination <──|◀─────(────────────────────── dst_outgoing        │
    Computer        ┃  │                    ┊       ↑              │                           ┃
                       ├──> g_msg_manager   ┊       │              │
                    ┃  │               ↑    ┊       │              │                           ┃
                       │        (Group┈│  (Incoming┈│  (URL token)┈│
                    ┃  │    management │  messages) │              │                           ┃
                       │     messages) │            │              │
                    ┃  ↓┈1,2           │            │              │                           ┃
                      client_scheduler │            │              │
                    ┃         └──> client ──────────┴──────────────┘                           ┃
                                     ↑
                    ┃                │                                                         ┃
                                     └───────────────────────────────────────────────────────────> flask_server on
                    ┃                                        ┊                                 ┃   contact's Networked
                                (In: message/file/public key/group management message              Computer
                    ┃            Out: contact request)                                         ┃
                    ┗━━  ━━  ━━  ━━  ━━  ━━  ━━  ━━  ━━  ━━  ━━  ━━  ━━  ━━  ━━  ━━  ━━  ━━  ━━┛


    The diagram above gives a rough overview of the structure of the
    Relay Program. The Relay Program acts as a protocol converter that
    reads datagrams from the Source Computer. Outgoing
    message/file/public key datagrams are made available in the user's
    Tor v3 Onion Service. Copies of sent message datagrams as well as
    datagrams from contacts' Onion Services are forwarded to the
    Destination Computer. The Relay-to-Relay encrypted datagrams from
    contacts such as contact requests, public keys and group management
    messages are displayed by the Relay Program.

    Outgoing message datagrams are loaded by contacts from the user's
    Flask web server. To request messages intended for them, each
    contact uses a contact-specific URL token to load the messages.
    The URL token is the X448 shared secret derived from the per-session
    ephemeral X448 values of the two conversing parties. The private
    value stays on the Relay Program -- the public value is obtained by
    connecting to the root domain of contact's Onion Service.
    """
    if platform_is_tails():
        working_dir = f'{os.getenv("HOME")}/{DIR_TAILS_PERS}{DIR_TFC}'
    else:
        working_dir = f'{os.getenv("HOME")}/{DIR_TFC}'

    ensure_dir(working_dir)
    os.chdir(working_dir)

    _, local_test, data_diode_sockets, qubes, test_run = process_arguments()

    gateway = Gateway(NC, local_test, data_diode_sockets, qubes, test_run)

    print_title(NC)

    url_token_private_key = X448.generate_private_key()
    url_token_public_key  = X448.derive_public_key(url_token_private_key).hex()

    queues = \
        {GATEWAY_QUEUE:       Queue(),  # All     datagrams           from `gateway_loop`          to `src_incoming`
         DST_MESSAGE_QUEUE:   Queue(),  # Message datagrams           from `src_incoming`/`client` to `dst_outgoing`
         TX_BUF_KEY_QUEUE:    Queue(),  # Datagram buffer key         from `onion_service`         to `src_incoming`
         RX_BUF_KEY_QUEUE:    Queue(),  # Datagram buffer key         from `onion_service`         to `flask_server`
         SRC_TO_RELAY_QUEUE:  Queue(),  # Command datagrams           from `src_incoming`          to `relay_command`
         DST_COMMAND_QUEUE:   Queue(),  # Command datagrams           from `src_incoming`          to `dst_outgoing`
         CONTACT_MGMT_QUEUE:  Queue(),  # Contact management commands from `relay_command`         to `client_scheduler`
         C_REQ_STATE_QUEUE:   Queue(),  # Contact req. notify setting from `relay_command`         to `c_req_manager`
         URL_TOKEN_QUEUE:     Queue(),  # URL tokens                  from `client`                to `flask_server`
         GROUP_MSG_QUEUE:     Queue(),  # Group management messages   from `client`                to `g_msg_manager`
         CONTACT_REQ_QUEUE:   Queue(),  # Contact requests            from `flask_server`          to `c_req_manager`
         C_REQ_MGMT_QUEUE:    Queue(),  # Contact list management     from `relay_command`         to `c_req_manager`
         GROUP_MGMT_QUEUE:    Queue(),  # Contact list management     from `relay_command`         to `g_msg_manager`
         ONION_CLOSE_QUEUE:   Queue(),  # Onion Service close command from `relay_command`         to `onion_service`
         ONION_KEY_QUEUE:     Queue(),  # Onion Service private key   from `relay_command`         to `onion_service`
         TOR_DATA_QUEUE:      Queue(),  # Open port for Tor           from `onion_service`         to `client_scheduler`
         EXIT_QUEUE:          Queue(),  # EXIT/WIPE signal            from `relay_command`         to `main`
         ACCOUNT_CHECK_QUEUE: Queue(),  # Incorrectly typed accounts  from `src_incoming`          to `account_checker`
         ACCOUNT_SEND_QUEUE:  Queue(),  # Contact requests            from `flask_server`          to `account_checker`
         USER_ACCOUNT_QUEUE:  Queue(),  # User's public key           from `onion_service`         to `account_checker`
         PUB_KEY_CHECK_QUEUE: Queue(),  # Typed public keys           from `src_incoming`          to `pub_key_checker`
         PUB_KEY_SEND_QUEUE:  Queue(),  # Received public keys        from `client`                to `pub_key_checker`
         GUI_INPUT_QUEUE:     Queue()   # User inputs                 from `GUI prompt`            to `account_checker`
         }  # type: Dict[bytes, Queue[Any]]

    process_list = [Process(target=gateway_loop,     args=(queues, gateway                       )),
                    Process(target=src_incoming,     args=(queues, gateway                       )),
                    Process(target=dst_outgoing,     args=(queues, gateway                       )),
                    Process(target=client_scheduler, args=(queues, gateway, url_token_private_key)),
                    Process(target=g_msg_manager,    args=(queues,                               )),
                    Process(target=c_req_manager,    args=(queues,                               )),
                    Process(target=flask_server,     args=(queues,          url_token_public_key )),
                    Process(target=onion_service,    args=(queues,          test_run             )),
                    Process(target=relay_command,    args=(queues, gateway,                      )),
                    Process(target=account_checker,  args=(queues,          sys.stdin.fileno()   )),
                    Process(target=pub_key_checker,  args=(queues,          local_test           ))]

    for p in process_list:
        p.start()

    monitor_processes(process_list, NC, queues)


if __name__ == '__main__':
    main()
