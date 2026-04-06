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
from src.common.crypto.keys.x448_keys import X448PubKey
from src.common.types_custom import BoolUnitTesting, BoolLocalTest
from src.common.utils.encoding import b58encode
from src.ui.common.output.print_key_diffs import print_key_diffs

if TYPE_CHECKING:
    from src.common.queues import RelayQueue
    from src.common.crypto.keys.onion_service_keys import OnionPublicKeyContact


def process_pub_key_diff_checker(queues     : 'RelayQueue',
                                 local_test : BoolLocalTest,
                                 unit_test  : BoolUnitTesting = BoolUnitTesting(False)
                                 ) -> None:
    """\
    Display diffs between received X448 public keys and
    public keys manually imported to Source Computer.
    """
    queue_purp_public_keys = queues.from_rec_to_diff_comp_user_input_x448_public_keys
    queue_real_public_keys = queues.from_cli_to_diff_comp_received_x448_public_keys

    pub_key_dictionary : 'dict[OnionPublicKeyContact, X448PubKey]' = dict()

    while True:
        with ignored(EOFError, KeyboardInterrupt):
            if queue_real_public_keys.qsize() != 0:
                account, pub_key            = queue_real_public_keys.get()
                pub_key_dictionary[account] = pub_key
                continue

            if queue_purp_public_keys.qsize() != 0:
                account, purp_pub_key = queue_purp_public_keys.get()

                if account in pub_key_dictionary:
                    real_x448_pub_key = pub_key_dictionary[account]
                    real_b58_pub_key  = b58encode(real_x448_pub_key.x448_public_key.public_bytes_raw())

                    print_key_diffs('public key', purp_pub_key, real_b58_pub_key, local_test)

            time.sleep(0.01)

            if unit_test:
                break
