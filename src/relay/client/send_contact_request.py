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

from typing import Optional as O

# noinspection PyPackageRequirements
import requests

# noinspection PyPackageRequirements
from requests import Session

from src.common.crypto.keys.onion_service_keys import OnionPublicKeyUser, OnionPublicKeyContact
from src.common.statics import Delay


def send_contact_request(session               : 'Session',
                         onion_pub_key_user    : 'OnionPublicKeyUser',
                         onion_pub_key_contact : 'OnionPublicKeyContact',
                         ) -> None:
    """Send contact request."""
    while True:
        response : O[requests.Response] = None
        try:
            # noinspection HttpUrlsUsage
            response = session.get(f'http://{onion_pub_key_contact.onion_address}.onion'
                                   f'/contact_request/{onion_pub_key_user.onion_address}', timeout=5)

            reply = response.text
            if reply == 'OK':
                break
        except requests.exceptions.RequestException:
            pass
        finally:
            if response is not None:
                response.close()

        time.sleep(Delay.RELAY_CLIENT_MIN_DELAY.value)
