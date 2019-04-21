#!/usr/bin/env python3.7
# -*- coding: utf-8 -*-

"""
TFC - Onion-routed, endpoint secure messaging system
Copyright (C) 2013-2019  Markus Ottela

This file is part of TFC.

TFC is free software: you can redistribute it and/or modify it under the terms
of the GNU General Public License as published by the Free Software Foundation,
either version 3 of the License, or (at your option) any later version.

TFC is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with TFC. If not, see <https://www.gnu.org/licenses/>.
"""

import hmac
import logging
import threading
import time
import typing

from io              import BytesIO
from multiprocessing import Queue
from typing          import Any, Dict, List, Optional

from flask import Flask, send_file

from src.common.statics import *

if typing.TYPE_CHECKING:
    QueueDict = Dict[bytes, Queue]


def flask_server(queues:               'QueueDict',
                 url_token_public_key: str,
                 unittest:             bool = False
                 ) -> Optional[Flask]:
    """Run Flask web server for outgoing messages.

    This process runs Flask web server from where clients of contacts
    can load messages sent to them. Making such requests requires the
    clients know the secret path, that is, the X448 shared secret
    derived from Relay Program's private key, and the public key
    obtained from the Onion Service of the contact.

    Note that this private key does not handle E2EE of messages, it only
    manages E2EE sessions between Relay Programs of conversing parties.
    It prevents anyone without the Relay Program's ephemeral private key
    from requesting ciphertexts from the user.

    The connection between the requests client and Flask server is
    end-to-end encrypted: No Tor relay between them can see the content
    of the traffic; With Onion Services, there is no exit node. The
    connection is strongly authenticated by the Onion Service domain
    name, that is, the TFC account pinned by the user.
    """
    app          = Flask(__name__)
    pub_key_dict = dict()  # type: Dict[str, bytes]
    message_dict = dict()  # type: Dict[bytes, List[str]]
    file_dict    = dict()  # type: Dict[bytes, List[bytes]]

    class HideRunTime(object):
        """Context manager that hides function runtime.

        By joining a thread that sleeps for a longer time than it takes
        for the function to run, this context manager hides the actual
        running time of the function.
        """

        def __init__(self, length: float = 0.0) -> None:
            self.length = length

        def __enter__(self) -> None:
            self.timer = threading.Thread(target=time.sleep, args=(self.length,))
            self.timer.start()

        def __exit__(self, exc_type: Any, exc_value: Any, traceback: Any) -> None:
            self.timer.join()

    def validate_url_token(purp_url_token: str) -> bool:
        """Validate URL token using constant time comparison."""

        # This context manager hides the duration of URL_TOKEN_QUEUE check as
        # well as the number of accounts in pub_key_dict when iterating over keys.
        with HideRunTime(0.01):

            # Check if the client has derived new URL token for contact(s).
            # If yes, add the url tokens to pub_key_dict to have up-to-date
            # information about whether the purported URL tokens are valid.
            while queues[URL_TOKEN_QUEUE].qsize() > 0:
                onion_pub_key, url_token = queues[URL_TOKEN_QUEUE].get()

                # Delete old URL token for contact when their URL token pub key changes.
                for ut in list(pub_key_dict.keys()):
                    if pub_key_dict[ut] == onion_pub_key:
                        del pub_key_dict[ut]

                pub_key_dict[url_token] = onion_pub_key

            # Here we OR the result of constant time comparison with initial
            # False. ORing is also a constant time operation that returns
            # True if a matching shared secret was found in pub_key_dict.
            valid_url_token = False
            for url_token in pub_key_dict:
                valid_url_token |= hmac.compare_digest(purp_url_token, url_token)

        return valid_url_token

    @app.route('/')
    def index() -> str:
        """Return the URL token public key to contacts that know the .onion address."""
        return url_token_public_key

    @app.route('/contact_request/<string:purp_onion_address>')
    def contact_request(purp_onion_address: str) -> str:
        """Pass contact request to `c_req_manager`."""
        queues[CONTACT_REQ_QUEUE].put(purp_onion_address)
        return 'OK'

    @app.route('/<purp_url_token>/files/')
    def file_get(purp_url_token: str) -> Any:
        """Validate the URL token and return a queued file."""
        if not validate_url_token(purp_url_token):
            return ''

        identified_onion_pub_key = pub_key_dict[purp_url_token]

        while queues[F_TO_FLASK_QUEUE].qsize() != 0:
            packet, onion_pub_key = queues[F_TO_FLASK_QUEUE].get()
            file_dict.setdefault(onion_pub_key, []).append(packet)

        if identified_onion_pub_key in file_dict and file_dict[identified_onion_pub_key]:
            mem = BytesIO()
            mem.write(file_dict[identified_onion_pub_key].pop(0))
            mem.seek(0)
            return send_file(mem, mimetype='application/octet-stream')
        else:
            return ''

    @app.route('/<purp_url_token>/messages/')
    def contacts_url(purp_url_token: str) -> str:
        """Validate the URL token and return queued messages."""
        if not validate_url_token(purp_url_token):
            return ''

        identified_onion_pub_key = pub_key_dict[purp_url_token]

        # Load outgoing messages for all contacts,
        # return the oldest message for contact
        while queues[M_TO_FLASK_QUEUE].qsize() != 0:
            packet, onion_pub_key = queues[M_TO_FLASK_QUEUE].get()
            message_dict.setdefault(onion_pub_key, []).append(packet)

        if identified_onion_pub_key in message_dict and message_dict[identified_onion_pub_key]:
            packets = '\n'.join(message_dict[identified_onion_pub_key])  # All messages for contact
            message_dict[identified_onion_pub_key] = []
            return packets
        else:
            return ''

    # --------------------------------------------------------------------------

    log = logging.getLogger('werkzeug')
    log.setLevel(logging.ERROR)

    if unittest:
        return app
    else:  # not unittest
        app.run()
        return None
