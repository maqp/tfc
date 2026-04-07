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

from typing import Optional as O, TYPE_CHECKING

# noinspection PyPackageRequirements
import requests

# noinspection PyPackageRequirements
from requests import Session

from cryptography.hazmat.primitives.asymmetric.x448 import X448PublicKey

from src.common.exceptions import SoftError
from src.common.crypto.algorithms.x448 import X448
from src.common.crypto.keys.x448_keys import X448PrivKey, X448PubKey
from src.common.statics import CryptoVarLength
from src.common.types_custom import StrURLToken

if TYPE_CHECKING:
    from src.common.crypto.keys.onion_service_keys import OnionPublicKeyContact
    from src.common.queues import RelayQueue


def load_url_token_public_key(session               : Session,
                              onion_pub_key_contact : 'OnionPublicKeyContact',
                              ) -> O[X448PubKey]:
    """Load URL token for contact."""
    response = None  # type: O[requests.Response]
    try:
        # HTTPS check disabled as Tor Onion Services always use its
        # own end-to-end encryption layer instead of certificates.

        # noinspection HttpUrlsUsage
        response = session.get(f'http://{onion_pub_key_contact.onion_address}.onion/', timeout=5)

        ut_pubkey_hex = str(response.text)
    except requests.exceptions.RequestException:
        return None
    finally:
        if response is not None:
            response.close()

    if len(ut_pubkey_hex) != 2 * CryptoVarLength.X448_PUBLIC_KEY.value:
        return None

    try:
        public_bytes = bytes.fromhex(ut_pubkey_hex)
    except ValueError:
        return None

    if all(byte == 0 for byte in public_bytes):
        return None

    try:
        return X448PubKey(X448PublicKey.from_public_bytes(public_bytes))
    except ValueError:
        return None


def update_url_token(queues                : 'RelayQueue',
                     url_token_private_key : X448PrivKey,
                     url_token_public_key  : X448PubKey,
                     cached_pub_key        : O[X448PubKey],
                     cached_url_token      : O[StrURLToken],
                     onion_pub_key_contact : 'OnionPublicKeyContact',
                     ) -> tuple[StrURLToken, X448PubKey]:
    """Update URL token for contact.

    When contact's URL token public key changes, update URL token.
    """
    if cached_pub_key is not None and cached_url_token is not None and url_token_public_key == cached_pub_key:
        return StrURLToken(cached_url_token), url_token_public_key

    try:
        url_token_hex = X448.shared_key(url_token_private_key.x448_private_key,
                                        url_token_public_key.x448_public_key).raw_bytes.hex()

        queues.from_cli_to_srv_url_tokens.put((onion_pub_key_contact, url_token_hex))  # Update Flask server's URL token for contact

        return StrURLToken(url_token_hex), url_token_public_key

    except (TypeError, ValueError):
        raise SoftError('URL token derivation failed.', output=False)
