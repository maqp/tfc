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

import base64

from datetime import datetime
from typing import Optional as O, TYPE_CHECKING

# noinspection PyPackageRequirements
import requests

# noinspection PyPackageRequirements
from requests import Session

from src.common.exceptions import ValidationError, SoftError
from src.common.statics import DatagramHeader, FieldLength
from src.common.types_custom import BytesServerB85Payload, StrURLToken
from src.ui.common.output.print_key import print_key
from src.ui.common.output.print_log_message import print_log_message
from src.common.utils.strings import separate_header
from src.datagrams.receiver.message import DatagramIncomingMessage, DatagramIncomingNoiseMessage
from src.datagrams.receiver.public_key import DatagramPublicKey
from src.relay.client.get_files import check_for_files

if TYPE_CHECKING:
    from src.common.crypto.keys.onion_service_keys import OnionPublicKeyContact
    from src.common.gateway import Gateway
    from src.common.queues import RelayQueue


def load_message_batch(queues                : 'RelayQueue',
                       gateway               : 'Gateway',
                       session               : Session,
                       onion_pub_key_contact : 'OnionPublicKeyContact',
                       url_token             : StrURLToken,
                       ) -> None:
    """Load one batch of TFC data from contact's Onion Service using a valid URL token."""
    response : O[Session | requests.Response] = None
    accepted_datagram_headers = (DatagramHeader.MESSAGE,
                                 DatagramHeader.FILE,
                                 DatagramHeader.PUBLIC_KEY,
                                 DatagramHeader.GROUP_INVITE,
                                 DatagramHeader.GROUP_JOIN,
                                 DatagramHeader.GROUP_ADD_MEMBER,
                                 DatagramHeader.GROUP_REM_MEMBER,
                                 DatagramHeader.GROUP_EXIT_GROUP,
                                 DatagramHeader.TRAFFIC_MASKING)

    try:
        check_for_files(queues, session, onion_pub_key_contact, url_token)

        # noinspection HttpUrlsUsage
        response = session.get(f'http://{onion_pub_key_contact.onion_address}.onion/{url_token}/messages', stream=True)

        if not hasattr(response, 'iter_lines'):
            return None

        # noinspection PyUnresolvedReferences
        for line in response.iter_lines():  # Iterate over newline-separated datagrams

            if not line:
                continue

            try:
                header_bytes, payload_b85_bytes = separate_header(line, FieldLength.DATAGRAM_HEADER.value)

                if header_bytes not in DatagramHeader:
                    raise SoftError('Invalid datagram header', output=False)

                header = DatagramHeader(header_bytes)
                if header not in accepted_datagram_headers:
                    raise SoftError('Disallowed datagram header', output=False)

                payload_b85 = BytesServerB85Payload(payload_b85_bytes)

            except (SoftError, UnicodeError, ValueError):
                continue

            ts = datetime.now()

            process_received_packet(queues, gateway, ts, header, payload_b85, onion_pub_key_contact)

    except requests.exceptions.RequestException:
        return None

    finally:
        if response is not None and hasattr(response, 'close'):
            response.close()


def process_received_packet(queues        : 'RelayQueue',
                            gateway       : 'Gateway',
                            ts            : datetime,
                            header        : DatagramHeader | DatagramHeader,
                            payload_b85   : BytesServerB85Payload,
                            onion_pub_key : 'OnionPublicKeyContact'
                            ) -> None:
    """Process received packet."""
    if header == DatagramHeader.PUBLIC_KEY:
        try:
            datagram_pub_key = DatagramPublicKey.from_server_b85(ts, payload_b85)
        except (ValidationError, ValueError):
            print_log_message(f'Received invalid packet from {onion_pub_key.short_address}', ts, bold=True)
            return

        msg = (f"Received public key from {onion_pub_key.short_address} "
               f"on {ts.strftime('%b %d - %H:%M:%S.%f')[:-4]}:")
        print_key(msg, datagram_pub_key.x448_public_key, gateway.settings, public_key=True)
        queues.from_cli_to_diff_comp_received_x448_public_keys.put((onion_pub_key, datagram_pub_key.x448_public_key))

    elif header in {DatagramHeader.MESSAGE, DatagramHeader.TRAFFIC_MASKING}:

        if header == DatagramHeader.MESSAGE:
            try:
                datagram_msg = DatagramIncomingMessage.from_server_b85(ts, payload_b85)
                datagram     = DatagramIncomingMessage(onion_pub_key, datagram_msg.ct_header, datagram_msg.ct_packet, ts)
                queues.from_cli_to_rxp_datagram_messages.put(datagram)
                print_log_message(f'Message   from contact {onion_pub_key.short_address}', ts)
            except (ValidationError, ValueError):
                print_log_message(f'Received invalid packet from {onion_pub_key.short_address}', ts, bold=True)
                return
        else:
            try:
                datagram_msg = DatagramIncomingNoiseMessage.from_server_b85(ts, payload_b85)
                datagram     = DatagramIncomingNoiseMessage(onion_pub_key, datagram_msg.ct_header, datagram_msg.ct_packet, ts)
                queues.from_cli_to_npv_datagram_messages.put(datagram)
            except (ValidationError, ValueError):
                print_log_message(f'Received invalid packet from {onion_pub_key.short_address}', ts, bold=True)
                return

    elif header in [DatagramHeader.GROUP_INVITE,
                    DatagramHeader.GROUP_JOIN,
                    DatagramHeader.GROUP_ADD_MEMBER,
                    DatagramHeader.GROUP_REM_MEMBER,
                    DatagramHeader.GROUP_EXIT_GROUP]:
        try:
            payload_bytes = base64.b85decode(payload_b85)
        except ValueError:
            print_log_message(f'Received invalid packet from {onion_pub_key.short_address}', ts, bold=True)
            return

        queues.from_cli_to_gmm_group_mgmt_messages.put((header, payload_bytes, onion_pub_key))

    else:
        print_log_message(f'Received invalid packet from {onion_pub_key.short_address}', ts, bold=True)
