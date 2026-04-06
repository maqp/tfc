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

import sys

from multiprocessing import Process

from src.common.types_custom import IntStdInFD
from src.common.utils.io import setup_working_dir
from src.common.queues import RelayQueue
from src.common.statics import ProgramID
from src.common.crypto.algorithms.x448 import X448
from src.common.crypto.keys.x448_keys import X448PrivKey
from src.common.gateway import Gateway
from src.common.process import configure_multiprocessing_start_method, process_gateway_reader, monitor_processes
from src.common.launch_args import process_arguments_relay

from src.relay.process_client_scheduler import process_client_scheduler
from src.relay.process_gateway_dispatcher import process_gateway_dispatcher
from src.relay.process_group_msg_manager import process_group_msg_manager
from src.relay.process_contact_request_manager import process_contact_request_manager
from src.relay.process_diff_check_accounts import process_account_diff_checker
from src.relay.process_diff_check_pub_keys import process_pub_key_diff_checker
from src.relay.process_onion_service import Tor, process_onion_service
from src.relay.process_server_flask import process_flask_server
from src.relay.process_server_proxy import process_server_proxy
from src.relay.process_dst_outgoing import process_dst_outgoing
from src.relay.process_traffic_masking_void import process_traffic_masking_void
from src.ui.common.output.print_title import print_title


def relay_program() -> None:
    """TFC Relay Program.

    Relay program facilitates the connection between TFC users. The
    outbound data is made available through `Flask` web-server that
    operates behind a Tor v3 Onion Service. Contacts connect to the
    server through a `requests web-client that fetches inbound data
    from the server.
    """
    setup_working_dir()
    configure_multiprocessing_start_method()
    launch_arguments = process_arguments_relay()
    print_title(launch_arguments.program_name)

    queues   = RelayQueue()
    stdin_fn = IntStdInFD(sys.stdin.fileno())
    gateway  = Gateway(launch_arguments)

    # Ephemeral key-pair for agreeing on secret routes.
    url_token_private_key = X448PrivKey(X448.generate_private_key())
    url_token_public_key  = url_token_private_key.x448_pub_key
    flask_port            = Tor.get_available_local_port()

    process_list = [Process(target=process_gateway_reader,           args=(queues, gateway                              )),
                    Process(target=process_gateway_dispatcher,       args=(queues, gateway                              )),
                    Process(target=process_dst_outgoing,             args=(queues, gateway                              )),
                    Process(target=process_client_scheduler,         args=(queues, gateway, url_token_private_key       )),
                    Process(target=process_traffic_masking_void,     args=(queues,                                      )),
                    Process(target=process_group_msg_manager,        args=(queues,                                      )),
                    Process(target=process_contact_request_manager,  args=(queues,                                      )),
                    Process(target=process_server_proxy,             args=(queues,                                      )),
                    Process(target=process_flask_server,             args=(queues, url_token_public_key,      flask_port)),
                    Process(target=process_onion_service,            args=(queues, launch_arguments.test_run, flask_port)),
                    Process(target=process_account_diff_checker,     args=(queues, stdin_fn                             )),
                    Process(target=process_pub_key_diff_checker,     args=(queues, launch_arguments.local_test          ))]

    for p in process_list:
        p.start()

    monitor_processes(process_list, ProgramID.NC, queues)


if __name__ == '__main__':
    relay_program()
