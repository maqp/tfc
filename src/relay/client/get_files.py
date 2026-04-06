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

from datetime import datetime

from typing import Any, TYPE_CHECKING

# noinspection PyPackageRequirements
import requests

# noinspection PyPackageRequirements
from requests import Session

from src.common.exceptions import SoftError, ValidationError
from src.common.replay import cache_received_file
from src.common.statics import DatagramHeader, DatagramTypeHR, FieldLength, ProgramID, RelayLimits
from src.common.types_custom import StrURLToken
from src.common.utils.strings import separate_header
from src.datagrams.receiver.file_multicast import DatagramFileMulticast
from src.ui.common.output.print_log_message import print_log_message

if TYPE_CHECKING:
    from src.common.crypto.keys.onion_service_keys import OnionPublicKeyContact
    from src.common.queues import RelayQueue


def check_for_files(queues                : 'RelayQueue',
                    session               : Session,
                    onion_pub_key_contact : 'OnionPublicKeyContact',
                    url_token             : StrURLToken,
                    ) -> None:
    """See if a file is available from contact."""
    response: Any = None
    try:
        # noinspection HttpUrlsUsage
        response = session.get(f'http://{onion_pub_key_contact.onion_address}.onion/{url_token}/files', stream=True)
        packet   = load_bounded_response_bytes(response)

        if not packet:
            return

        header_bytes, payload_b85 = separate_header(packet, FieldLength.DATAGRAM_HEADER.value)
        if header_bytes != DatagramHeader.FILE.value:
            raise SoftError('Received invalid file packet', output=False)

        ts              = datetime.now()
        server_datagram = DatagramFileMulticast.from_server_b85(ts, payload_b85)
        datagram        = DatagramFileMulticast(server_datagram.file_ct,
                                                pub_key_contact=onion_pub_key_contact,
                                                timestamp=ts)

        file_id = cache_received_file(ProgramID.NC.value, datagram.to_rep_rxp_bytes())
        queues.from_cli_to_rxp_datagram_file_mcast.put(datagram)
        print_log_message(f'{DatagramTypeHR.FILE:<9}      from contact {onion_pub_key_contact.short_address} cached as {file_id}', ts)

    except SoftError as exc:
        print_log_message(f'{exc.message} from {onion_pub_key_contact.short_address}', bold=True)
    except (ValidationError, ValueError):
        print_log_message(f'Received invalid file packet from {onion_pub_key_contact.short_address}', bold=True)
    except requests.exceptions.RequestException:
        pass
    finally:
        if response is not None and hasattr(response, 'close'):
            response.close()


def load_bounded_response_bytes(response: Any) -> bytes:
    """Read the server response with a hard size cap."""
    content_length = response.headers.get('Content-Length') if hasattr(response, 'headers') else None
    if content_length is not None:
        try:
            if int(content_length) > RelayLimits.MAX_FILE_SIZE.value:
                raise SoftError('Discarded oversized file', output=False)
        except ValueError:
            pass

    file_data = bytearray()

    for chunk in response.iter_content(chunk_size=RelayLimits.FILE_FETCH_CHUNK_SIZE):
        if not chunk:
            continue

        file_data.extend(chunk)
        if len(file_data) > RelayLimits.MAX_FILE_SIZE.value:
            raise SoftError('Discarded oversized file', output=False)

    return bytes(file_data)
