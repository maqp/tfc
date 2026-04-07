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

from typing import Optional as O

from src.common.crypto.keys.onion_service_keys import OnionPublicKeyContact
from src.common.crypto.keys.x448_keys import X448PubKey
from src.common.statics import Delay
from src.common.types_custom import BoolIsOnline, FloatCheckDelay
from src.ui.common.output.print_log_message import print_log_message


def show_contact_status(onion_pub_key_contact : 'OnionPublicKeyContact',
                        url_token_public_key  : O[X448PubKey],
                        check_delay           : FloatCheckDelay,
                        is_online             : BoolIsOnline,
                        ) -> tuple[BoolIsOnline, FloatCheckDelay]:
    """Manage online status of contact based on availability of URL token's public key."""
    if url_token_public_key is None:
        if check_delay < Delay.RELAY_CLIENT_MAX_DELAY.value:
            check_delay = FloatCheckDelay(check_delay * 2)
        if check_delay > Delay.CLIENT_OFFLINE_THRESHOLD.value and is_online:
            is_online = BoolIsOnline(False)
            print_log_message(f'{onion_pub_key_contact.short_address} is now offline', bold=True)

    else:
        check_delay = FloatCheckDelay(Delay.RELAY_CLIENT_MIN_DELAY.value)
        if not is_online:
            is_online = BoolIsOnline(True)
            print_log_message(f'{onion_pub_key_contact.short_address} is now online', bold=True)

    return is_online, check_delay
