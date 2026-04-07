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

import secrets

from typing import TYPE_CHECKING

from src.common.types_custom import FloatTMDelay, StrURLToken
from src.transmitter.sender.sender_traffic_masking import HideRunTime

if TYPE_CHECKING:
    from src.common.queues import RelayQueue
    from src.relay.process_server_flask import PubKeyDict


def validate_url_token(purp_url_token : StrURLToken,
                       queues         : 'RelayQueue',
                       pub_key_dict   : 'PubKeyDict'
                       ) -> bool:
    """Validate URL token using constant time comparison."""
    # This context manager hides the duration of URL_TOKEN_QUEUE check as
    # well as the number of accounts in pub_key_dict when iterating over keys.
    with HideRunTime(duration=FloatTMDelay(0.01)):

        # Check if the client has derived new URL token for contact(s).
        # If yes, add the url tokens to pub_key_dict to have up-to-date
        # information about whether the purported URL tokens are valid.
        while queues.from_cli_to_srv_url_tokens.qsize() > 0:
            onion_pub_key, url_token = queues.from_cli_to_srv_url_tokens.get()

            # To keep dictionary compact, delete old key when new
            # one with matching value (onion_pub_key) is received.
            for ut in list(pub_key_dict.keys()):
                if pub_key_dict[ut] == onion_pub_key:
                    del pub_key_dict[ut]

            pub_key_dict[url_token] = onion_pub_key

        # Here we OR the result of constant time comparison with initial
        # False. ORing is also a constant time operation that returns
        # True if a matching shared secret was found in pub_key_dict.
        valid_url_token = False

        for url_token in pub_key_dict:
            try:
                valid_url_token |= secrets.compare_digest(purp_url_token, url_token)
            except TypeError:
                valid_url_token |= False

        return valid_url_token
