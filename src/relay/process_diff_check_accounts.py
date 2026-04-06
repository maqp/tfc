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

import difflib
import os
import sys
import time

from typing import Optional as O, TYPE_CHECKING

from src.common.exceptions import ignored
from src.common.crypto.keys.onion_service_keys import OnionPublicKeyContact
from src.common.statics import RemoteInputLiterals
from src.common.crypto.keys.onion_service_keys import OnionPublicKeyUser
from src.common.types_custom import IntStdInFD, BoolUnitTesting
from src.ui.common.input.get_onion_addr_from_user_zenity import GetAccountFromUser
from src.ui.common.output.print_key_diffs import print_key_diffs

if TYPE_CHECKING:
    from src.common.queues import RelayQueue


def process_account_diff_checker(queues       : 'RelayQueue',
                                 stdin_fd     : IntStdInFD,
                                 unit_testing : BoolUnitTesting = BoolUnitTesting(False)
                                 ) -> None:
    """\
    Display diffs between received TFC accounts and accounts
    manually imported to Source Computer."""
    if not unit_testing:  # pragma: no cover
        sys.stdin = os.fdopen(stdin_fd)

    onion_pub_keys : set[OnionPublicKeyContact] = set()

    cache_queue = queues.from_crm_to_diff_comp_received_accounts
    purp_queue  = queues.from_rec_to_diff_comp_purported_accounts

    while queues.from_rec_to_diff_comp_public_keys.qsize() == 0:
        time.sleep(0.01)
    onion_pub_key_user = queues.from_rec_to_diff_comp_public_keys.get()  # type: OnionPublicKeyUser

    while True:
        with ignored(EOFError, KeyboardInterrupt):

            # Cache received contact requests' accounts
            if cache_queue.qsize() != 0:
                pub_key = cache_queue.get()
                onion_pub_keys.add(pub_key)
                continue

            if purp_queue.qsize() != 0:
                purp_pub_key = OnionPublicKeyContact.from_onion_address(purp_queue.get())

                real_pub_key : OnionPublicKeyContact

                # Determine correct account pub key
                for real_pub_key in onion_pub_keys:

                    # Check if accounts are similar enough:
                    ratio = difflib.SequenceMatcher(a=purp_pub_key.public_bytes_raw,
                                                    b=real_pub_key.public_bytes_raw).ratio()
                    if ratio >= RemoteInputLiterals.ACCOUNT_SIMILARITY_MIN_PERCENTAGE.value / 100.0:
                        break

                else:
                    # We ask user to input the correct public key from terminal backlog.
                    pub_key_from_user = get_account_from_user(queues, onion_pub_keys, onion_pub_key_user)

                    if pub_key_from_user is None:
                        continue

                print_key_diffs('account', purp_pub_key.onion_address, real_pub_key.onion_address, local_test=True)

                continue
            time.sleep(0.01)

            if unit_testing:
                break


def get_account_from_user(queues             : 'RelayQueue',
                          accounts           : set[OnionPublicKeyContact],
                          onion_pub_key_user : OnionPublicKeyUser,
                          ) -> O[OnionPublicKeyContact]:
    """Get account from user."""
    queue = queues.from_gui_to_diff_comp_user_selected_account

    GetAccountFromUser(queues, onion_pub_key_user)
    account = queue.get()

    if account is not None and account not in accounts:
        accounts.add(account)
    return account
