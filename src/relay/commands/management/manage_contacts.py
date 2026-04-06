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

from typing import TYPE_CHECKING

from src.common.statics import QueueSignal
from src.common.types_custom import BoolIsPending
from src.datagrams.relay.command.replay import DatagramRelayResendFile, DatagramRelayResendPackets
from src.datagrams.relay.command.contact_add import DatagramRelayAddContact
from src.datagrams.relay.command.contact_remove import DatagramRelayRemoveContact
from src.datagrams.relay.diff_comparison.diff_comparison_account import DatagramRelayDiffComparisonAccount
from src.datagrams.relay.diff_comparison.diff_comparison_public_key import DatagramRelayDiffComparisonPublicKey
from src.datagrams.relay.command.setup_onion_service import DatagramRelaySetupOnionService

if TYPE_CHECKING:
    from src.common.queues import RelayQueue


def add_existing_contact(queues   : 'RelayQueue',
                         datagram : DatagramRelayAddContact,
                         ) -> None:
    """Add existing clients to Relay Program.

    The queues are read by
        relay.client.client_scheduler()
        relay.client.g_msg_manager() and
        relay.client.c_req_manager()
    """
    onion_pub_key = datagram.onion_pub_key

    queues.from_rec_to_sch_client_contact_mgmt_commands.put(( QueueSignal.RP_ADD_CONTACT_HEADER, [onion_pub_key], BoolIsPending(False) ))
    queues.from_rec_to_gmm_group_mgmt                  .put(( QueueSignal.RP_ADD_CONTACT_HEADER,  onion_pub_key                        ))
    queues.from_rec_to_crm_contact_list_mgmt           .put(( QueueSignal.RP_ADD_CONTACT_HEADER, [onion_pub_key]                       ))


def add_pending_contact(queues   : 'RelayQueue',
                        datagram : DatagramRelayAddContact
                        ) -> None:
    """Add pending clients to Relay Program.

    The queues are read by
        relay.client.client_scheduler()
        relay.client.g_msg_manager() and
        relay.client.c_req_manager()
    """
    onion_pub_key = datagram.onion_pub_key

    queues.from_rec_to_sch_client_contact_mgmt_commands.put(( QueueSignal.RP_ADD_CONTACT_HEADER, [onion_pub_key], BoolIsPending(True) ))
    queues.from_rec_to_gmm_group_mgmt                  .put(( QueueSignal.RP_ADD_CONTACT_HEADER,  onion_pub_key                       ))
    queues.from_rec_to_crm_contact_list_mgmt           .put(( QueueSignal.RP_ADD_CONTACT_HEADER, [onion_pub_key]                      ))



def remove_contact(queues   : 'RelayQueue',
                   datagram : DatagramRelayRemoveContact
                   ) -> None:
    """Remove clients from Relay Program.

    The queues are read by
        relay.client.client_scheduler()
        relay.client.g_msg_manager() and
        relay.client.c_req_manager()
    """
    onion_pub_key = datagram.onion_pub_key

    queues.from_rec_to_sch_client_contact_mgmt_commands.put(( QueueSignal.RP_REMOVE_CONTACT_HEADER, [onion_pub_key], BoolIsPending(False) ))
    queues.from_rec_to_gmm_group_mgmt                  .put(( QueueSignal.RP_REMOVE_CONTACT_HEADER,  onion_pub_key                        ))
    queues.from_rec_to_crm_contact_list_mgmt           .put(( QueueSignal.RP_REMOVE_CONTACT_HEADER, [onion_pub_key]                       ))


def add_onion_data(queues   : 'RelayQueue',
                   datagram : DatagramRelaySetupOnionService,
                   ) -> None:
    """Add Onion Service data.

    Separate onion service private key and public keys for
    pending/existing contacts and add them as contacts.

    The ONION_KEY_QUEUE is read by
        relay.onion.onion_service()
    """
    setup_fields = datagram

    for pending_public_key in setup_fields.pending_pub_keys:
        add_existing_contact(queues, DatagramRelayAddContact(pending_public_key))

    for existing_onion_pub_key in setup_fields.existing_pub_keys:
        add_pending_contact(queues, DatagramRelayAddContact(existing_onion_pub_key))

    # Print contact request status
    state = 'enabled' if setup_fields.allow_contact_requests else 'disabled'
    queues.relay_status_messages.put(f'Contact requests are currently {state}.')

    queues.from_rec_to_crm_accept_requests_setting           .put(setup_fields.allow_contact_requests)
    queues.from_rec_to_onion_service_process_onion_setup_data.put(setup_fields)


def compare_accounts(queues   : 'RelayQueue',
                     datagram : DatagramRelayDiffComparisonAccount
                     ) -> None:
    """\
    Compare incorrectly typed account to
    what's available on Relay Program.
    """
    queues.from_rec_to_diff_comp_purported_accounts.put(datagram.invalid_onion_address)


def compare_pub_keys(queues   : 'RelayQueue',
                     datagram : DatagramRelayDiffComparisonPublicKey
                     ) -> None:
    """\
    Compare incorrectly typed public key to
    what's available on Relay Program.
    """
    queues.from_rec_to_diff_comp_user_input_x448_public_keys.put((datagram.onion_pub_key_contact,
                                                                  datagram.invalid_key.decode()))

def resend_to_receiver(queues  : 'RelayQueue',
                      datagram : DatagramRelayResendPackets
                     ) -> None:
    """Resend datagram to Receiver Program."""
    queues.from_txp_to_dst_resend_packet_numbers.put(datagram.packet_numbers)


def resend_file_to_receiver(queues   : 'RelayQueue',
                            datagram : DatagramRelayResendFile
                            ) -> None:
    """Resend file to Receiver Program."""
    queues.from_txp_to_dst_resend_file_ids.put(datagram.file_id)
