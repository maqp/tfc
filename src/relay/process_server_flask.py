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

import logging
import sys
import time

from queue import Full
from typing import Any, Optional as O, TYPE_CHECKING

# noinspection PyPackageRequirements
from flask import Flask

from src.common.crypto.keys.x448_keys import X448PubKey
from src.common.statics import OnionAddress, FieldLength
from src.common.types_custom import BoolUnitTesting, IntPortNumberFlask, StrURLToken
from src.relay.server.read_from_server_buffer_file import load_messages_from_server_buffer_file, load_file_from_server_buffer_file

if TYPE_CHECKING:
    from src.common.queues import RelayQueue
    from src.common.crypto.keys.onion_service_keys import OnionPublicKeyContact
    PubKeyDict  = dict[str, OnionPublicKeyContact]
    MessageDict = dict[bytes, list[str]]
    FileDict    = dict[bytes, list[bytes]]


def process_flask_server(queues               : 'RelayQueue',
                         url_token_public_key : X448PubKey,
                         flask_port           : IntPortNumberFlask,
                         unit_testing         : BoolUnitTesting = BoolUnitTesting(False)
                         ) -> O[Flask]:
    """Run Flask web server for outgoing messages.

    This process runs Flask web server from where clients of contacts
    can load messages sent to them. Making such requests requires the
    clients know the secret path (i.e. URL token), that is, the X448
    shared secret derived from Relay Program's private key, and the
    public key obtained from the Onion Service of the contact.

    Note that this private key is not part of E2EE of messages, it only
    manages E2EE sessions between Relay Programs of conversing parties.
    It prevents anyone without the Relay Program's ephemeral private key
    from requesting ciphertexts from contact that do not belong to the
    user.

    The connection between the requests client and Flask server is
    end-to-end encrypted by the Tor Onion Service protocol: No Tor relay
    between them can see the content of the traffic; With Onion
    Services, there is no exit node. The connection is strongly
    authenticated by the Onion Service domain name, that is, the TFC
    account pinned by the user.
    """

    # ┌───────────────────────────────────┐
    # │ Wait until BufferKey is available │
    # └───────────────────────────────────┘
    while queues.from_txp_to_srv_buffer_key.qsize() == 0:
        time.sleep(0.01)
    buffer_key = queues.from_txp_to_srv_buffer_key.get()

    # ┌───────────────┐
    # │ Launch Server │
    # └───────────────┘
    app          = Flask(__name__)
    pub_key_dict = dict()  # type: PubKeyDict

    @app.route('/')
    def index() -> str:
        """Return the URL token public key to contacts that know the .onion address."""
        return url_token_public_key.x448_public_key.public_bytes_raw().hex()

    @app.route('/contact_request/<string:purp_onion_address>')
    def contact_request(purp_onion_address: str) -> tuple[str, int]:
        """Pass contact request to `c_req_manager`."""
        # Quick validation to limit what gets queued
        if (len(purp_onion_address) != FieldLength.ONION_ADDRESS.value
                or any(c not in OnionAddress.CHARSET for c in purp_onion_address)):
            return '', 400
        try:
            queues.from_srv_to_crm_contact_request_addresses.put_nowait(purp_onion_address)
        except Full:
            return '', 400
        return 'OK', 200

    @app.route('/<purp_url_token>/files/')
    def file_get(purp_url_token: str) -> Any:
        """Validate the URL token and return a queued file."""
        return load_file_from_server_buffer_file(StrURLToken(purp_url_token),
                                                 queues,
                                                 pub_key_dict,
                                                 buffer_key)

    @app.route('/<purp_url_token>/messages/')
    def message_get(purp_url_token: str) -> Any:
        """Validate the URL token and return queued messages."""
        return load_messages_from_server_buffer_file(StrURLToken(purp_url_token),
                                                     queues,
                                                     pub_key_dict,
                                                     buffer_key)

    # --------------------------------------------------------------------------

    cli = sys.modules.get('flask.cli')

    def hide_flask_banner(*_: object) -> None:
        """Silence Flask's startup banner."""
        return None

    cli_module: Any = cli
    cli_module.show_server_banner = hide_flask_banner

    log = logging.getLogger('werkzeug')
    log.setLevel(logging.ERROR)

    if unit_testing:
        return app
    else:  # pragma: no cover
        app.run(host='127.0.0.1', port=flask_port, use_reloader=False)
        return None
