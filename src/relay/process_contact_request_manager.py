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

from collections import deque
from typing import TYPE_CHECKING

from src.common.exceptions import ValidationError, ignored
from src.common.crypto.keys.onion_service_keys import OnionPublicKeyContact
from src.common.statics import RelayLimits
from src.common.types_custom import BoolUnitTesting
from src.ui.common.output.print_message import print_message
from src.common.utils.validators import validate_onion_addr
from src.relay.process_group_msg_manager import update_list_of_existing_contacts
from src.common.utils.date_time import get_log_ts

if TYPE_CHECKING:
    from src.common.queues import RelayQueue


def process_contact_request_manager(queues       : 'RelayQueue',
                                    unit_testing : BoolUnitTesting = BoolUnitTesting(False)
                                    ) -> None:
    """Process that handles received contact requests."""
    existing_contacts     : list[OnionPublicKeyContact]  = []
    displayed_requests    : deque[OnionPublicKeyContact] = deque()
    displayed_request_set : set[OnionPublicKeyContact]   = set()

    address_queue = queues.from_srv_to_crm_contact_request_addresses
    setting_queue = queues.from_rec_to_crm_accept_requests_setting
    account_queue = queues.from_crm_to_diff_comp_received_accounts
    show_requests = True

    while True:
        with ignored(EOFError, KeyboardInterrupt):

            while address_queue.qsize() == 0:
                time.sleep(0.1)

                # Update the `show contact requests` setting when provided
                if setting_queue.qsize() != 0:
                    show_requests = setting_queue.get()

                # Update existing contacts when provided
                existing_contacts = update_list_of_existing_contacts(queues, existing_contacts)


            # Address becomes available
            purp_onion_address = address_queue.get()

            # ┌────────────┐
            # │ Validation │
            # └────────────┘

            # Ignore if feature is disabled
            if not show_requests:
                continue

            # Ignore invalid
            try:
                validate_onion_addr(purp_onion_address)
                onion_pub_key = OnionPublicKeyContact.from_onion_address(purp_onion_address)
            except ValidationError:
                continue

            # Ignore from existing contacts
            if onion_pub_key in existing_contacts:
                continue

            # Ignore duplicate requests during a session
            if onion_pub_key in displayed_request_set:
                continue

            # ┌────────────────────────┐
            # │ Show and store request │
            # └────────────────────────┘

            print_message([f'{get_log_ts()} - New contact request from an unknown TFC account:', purp_onion_address], box=True)

            account_queue.put(onion_pub_key)
            if len(displayed_requests) == RelayLimits.CONTACT_REQUEST_CACHE_SIZE:
                expired_key = displayed_requests.popleft()
                displayed_request_set.discard(expired_key)

            displayed_requests.append(onion_pub_key)
            displayed_request_set.add(onion_pub_key)

            # ---

            if unit_testing and queues.unit_test.qsize() != 0:
                break
