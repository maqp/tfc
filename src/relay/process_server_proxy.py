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

import time

from typing import TYPE_CHECKING

from src.common.exceptions import ignored
from src.common.types_custom import BoolUnitTesting
from src.datagrams.relay.group_management.group_msg import DatagramGroupMessage
from src.relay.server.write_to_server_buffer_file import write_to_server_buffer_file

if TYPE_CHECKING:
    from src.common.queues import RelayQueue
    from src.common.crypto.keys.symmetric_key import BufferKey
    from src.datagrams.receiver.message import DatagramOutgoingMessage
    from src.datagrams.receiver.public_key import DatagramPublicKey
    from src.datagrams.receiver.file_multicast import DatagramFileMulticast


def process_server_proxy(queues    : 'RelayQueue',
                         unit_test : BoolUnitTesting = BoolUnitTesting(False)
                         ) -> None:
    """Process that forwards outgoing datagrams from their queues to server in priority."""
    public_key_queue        = queues.from_txp_to_sxy_outgoing_x448_public_keys
    group_mgmt_invite_queue = queues.from_txp_to_srv_datagram_group_mgmt_invite
    group_mgmt_join_queue   = queues.from_txp_to_srv_datagram_group_mgmt_join
    group_mgmt_add_queue    = queues.from_txp_to_srv_datagram_group_mgmt_add
    group_mgmt_rem_queue    = queues.from_txp_to_srv_datagram_group_mgmt_rem
    group_mgmt_exit_queue   = queues.from_txp_to_srv_datagram_group_mgmt_exit
    message_queue           = queues.from_txp_to_sxy_datagram_messages
    file_mcast_queue        = queues.from_txp_to_sxy_datagram_file_mcast

    while queues.from_txp_to_sxy_buffer_key.qsize() == 0:
        time.sleep(0.01)
    buffer_key = queues.from_txp_to_sxy_buffer_key.get()

    while True:
        with ignored(EOFError, KeyboardInterrupt):
            if public_key_queue.qsize() > 0:
                handle_outgoing_public_key_datagram(buffer_key, public_key_queue.get())
                continue

            elif group_mgmt_invite_queue.qsize() > 0:
                handle_outgoing_group_mgmt_datagram(buffer_key, group_mgmt_invite_queue.get())
                continue

            elif group_mgmt_join_queue.qsize() > 0:
                handle_outgoing_group_mgmt_datagram(buffer_key, group_mgmt_join_queue.get())
                continue

            elif group_mgmt_add_queue.qsize() > 0:
                handle_outgoing_group_mgmt_datagram(buffer_key, group_mgmt_add_queue.get())
                continue

            elif group_mgmt_rem_queue.qsize() > 0:
                handle_outgoing_group_mgmt_datagram(buffer_key, group_mgmt_rem_queue.get())
                continue

            elif group_mgmt_exit_queue.qsize() > 0:
                handle_outgoing_group_mgmt_datagram(buffer_key, group_mgmt_exit_queue.get())
                continue

            elif message_queue.qsize() > 0:
                handle_outgoing_message_datagram(buffer_key, message_queue.get(), queues)
                continue

            elif file_mcast_queue.qsize() > 0:
                handle_outgoing_mc_file_datagram(buffer_key, file_mcast_queue.get())
                continue

            time.sleep(0.01)
            if unit_test:
                break


def handle_outgoing_public_key_datagram(buffer_key : 'BufferKey',
                                        datagram   : 'DatagramPublicKey',
                                        ) -> None:
    """Store an outgoing public-key line for the contact."""
    write_to_server_buffer_file(datagram, datagram.pub_key_contact, buffer_key)


def handle_outgoing_group_mgmt_datagram(buffer_key : 'BufferKey',
                                        datagram   : 'DatagramGroupMessage',
                                        ) -> None:
    """Handle outgoing group management message datagrams."""
    write_to_server_buffer_file(datagram, datagram.pub_key_contact, buffer_key)


def handle_outgoing_message_datagram(buffer_key : 'BufferKey',
                                     datagram   : 'DatagramOutgoingMessage',
                                     queues     : 'RelayQueue',
                                     ) -> None:
    """Store an outgoing message line and forward the copy to Receiver."""
    write_to_server_buffer_file(datagram, datagram.pub_key_contact, buffer_key)
    queues.from_sxy_to_rxp_datagram_messages.put(datagram)


def handle_outgoing_mc_file_datagram(buffer_key : 'BufferKey',
                                     datagram   : 'DatagramFileMulticast',
                                     ) -> None:
    """Store the outgoing multicast file once for each intended recipient."""
    for onion_pub_key in datagram.recipient_pub_keys:
        write_to_server_buffer_file(datagram, onion_pub_key, buffer_key)
