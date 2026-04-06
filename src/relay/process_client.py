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

import random
import time

from typing import Optional as O, TYPE_CHECKING

# noinspection PyPackageRequirements
import requests

from src.common.exceptions import SoftError, ignored
from src.common.crypto.keys.x448_keys import X448PrivKey, X448PubKey
from src.common.statics import Delay, NetworkLiterals
from src.common.types_custom import BoolUnitTesting, FloatCheckDelay, BoolIsOnline, IntPortNumberTor, StrURLToken
from src.relay.client.show_contact_status import show_contact_status
from src.ui.common.output.print_log_message import print_log_message
from src.relay.client.get_messages import load_message_batch
from src.relay.client.send_contact_request import send_contact_request
from src.relay.client.url_token import load_url_token_public_key, update_url_token

if TYPE_CHECKING:
    from src.common.gateway import Gateway
    from src.common.queues import RelayQueue
    from src.common.crypto.keys.onion_service_keys import OnionPublicKeyContact, OnionPublicKeyUser


def process_client(queues                : 'RelayQueue',
                   gateway               : 'Gateway',
                   onion_pub_key_user    : O['OnionPublicKeyUser'],
                   onion_pub_key_contact : 'OnionPublicKeyContact',
                   url_token_private_key : X448PrivKey,
                   tor_port              : IntPortNumberTor,
                   unit_test             : BoolUnitTesting = BoolUnitTesting(False)
                   ) -> None:
    """Process that loads packets from contact's Onion Service."""
    cached_url_token : O[StrURLToken] = None
    cached_pub_key   : O[X448PubKey]  = None

    check_delay = FloatCheckDelay(Delay.RELAY_CLIENT_MIN_DELAY.value)
    is_online   = BoolIsOnline(False)

    session         = requests.session()
    session.proxies = {'http'  : f'socks5h://{NetworkLiterals.LOCALHOST_IP}:{tor_port}',
                       'https' : f'socks5h://{NetworkLiterals.LOCALHOST_IP}:{tor_port}'}

    print_log_message(f'Connecting to {onion_pub_key_contact.short_address}...', bold=True)

    # When Transmitter Program sends contact under UNENCRYPTED_ADD_EXISTING_CONTACT, this function
    # receives user's own Onion address: That way it knows to request the contact to add them:
    if onion_pub_key_user is not None:
        send_contact_request(session, onion_pub_key_user, onion_pub_key_contact)

    rng = random.SystemRandom()

    while True:
        with ignored(EOFError, KeyboardInterrupt, SoftError):
            time.sleep(check_delay)

            url_token_public_key   = load_url_token_public_key(session, onion_pub_key_contact)
            is_online, check_delay = show_contact_status(onion_pub_key_contact, url_token_public_key, check_delay, is_online)

            if not is_online:
                continue
            if url_token_public_key is None:
                continue

            try:
                cached_url_token, cached_pub_key = update_url_token(queues,
                                                                    url_token_private_key,
                                                                    url_token_public_key,
                                                                    cached_pub_key, cached_url_token,
                                                                    onion_pub_key_contact)

                if cached_url_token is None:
                    continue

                load_message_batch(queues, gateway, session, onion_pub_key_contact, cached_url_token)

                # Normal-distributed random wait
                min_delay  = Delay.RELAY_CLIENT_MIN_RANDOM_DELAY.value
                max_delay  = Delay.RELAY_CLIENT_MAX_RANDOM_DELAY.value
                mean       = (min_delay + max_delay) / 2
                std_dev    = (max_delay - min_delay) / 6
                delay_time = max(0, min(max_delay, round(rng.normalvariate(mean, std_dev))))
                time.sleep(delay_time)

            except SoftError:
                continue

            if unit_test:
                break
