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

import base64
import hashlib
import time
import typing

from datetime import datetime
from multiprocessing import Process, Queue
from typing import Any, Dict, List, Tuple

import requests

from cryptography.hazmat.primitives.asymmetric.x448 import X448PublicKey, X448PrivateKey

from src.common.encoding import (
    b58encode,
    int_to_bytes,
    onion_address_to_pub_key,
    pub_key_to_onion_address,
)
from src.common.encoding import pub_key_to_short_address
from src.common.exceptions import SoftError
from src.common.misc import (
    ignored,
    separate_header,
    split_byte_string,
    validate_onion_addr,
)
from src.common.output import m_print, print_key, rp_print
from src.common.statics import (
    CLIENT_OFFLINE_THRESHOLD,
    CONTACT_MGMT_QUEUE,
    CONTACT_REQ_QUEUE,
    C_REQ_MGMT_QUEUE,
    C_REQ_STATE_QUEUE,
    DATAGRAM_HEADER_LENGTH,
    DST_MESSAGE_QUEUE,
    FILE_DATAGRAM_HEADER,
    GROUP_ID_LENGTH,
    GROUP_MGMT_QUEUE,
    GROUP_MSG_EXIT_GROUP_HEADER,
    GROUP_MSG_INVITE_HEADER,
    GROUP_MSG_JOIN_HEADER,
    GROUP_MSG_MEMBER_ADD_HEADER,
    GROUP_MSG_MEMBER_REM_HEADER,
    GROUP_MSG_QUEUE,
    MESSAGE_DATAGRAM_HEADER,
    ONION_SERVICE_PUBLIC_KEY_LENGTH,
    ORIGIN_CONTACT_HEADER,
    PUBLIC_KEY_DATAGRAM_HEADER,
    RELAY_CLIENT_MAX_DELAY,
    RELAY_CLIENT_MIN_DELAY,
    RP_ADD_CONTACT_HEADER,
    RP_REMOVE_CONTACT_HEADER,
    TFC_PUBLIC_KEY_LENGTH,
    TOR_DATA_QUEUE,
    UNIT_TEST_QUEUE,
    URL_TOKEN_LENGTH,
    URL_TOKEN_QUEUE,
)

if typing.TYPE_CHECKING:
    from src.common.gateway import Gateway
    from requests.sessions import Session

    QueueDict = Dict[bytes, Queue[Any]]


def client_scheduler(
    queues: "QueueDict",
    gateway: "Gateway",
    ut_private_key: X448PrivateKey,
    unit_test: bool = False,
) -> None:
    """Manage `client` processes."""
    proc_dict = dict()  # type: Dict[bytes, Process]

    # Wait for Tor port from `onion_service` process.
    while True:
        with ignored(EOFError, KeyboardInterrupt):
            while not queues[TOR_DATA_QUEUE].qsize():
                time.sleep(0.1)
            tor_port, onion_addr_user = queues[TOR_DATA_QUEUE].get()
            break

    while True:
        with ignored(EOFError, KeyboardInterrupt):

            while not queues[CONTACT_MGMT_QUEUE].qsize():
                time.sleep(0.1)

            command, ser_public_keys, is_existing_contact = queues[
                CONTACT_MGMT_QUEUE
            ].get()  # type: str, bytes, bool

            onion_pub_keys = split_byte_string(
                ser_public_keys, ONION_SERVICE_PUBLIC_KEY_LENGTH
            )

            if command == RP_ADD_CONTACT_HEADER:
                add_new_client_process(
                    gateway,
                    is_existing_contact,
                    onion_addr_user,
                    onion_pub_keys,
                    proc_dict,
                    queues,
                    tor_port,
                    ut_private_key,
                )

            elif command == RP_REMOVE_CONTACT_HEADER:
                remove_client_process(onion_pub_keys, proc_dict)

            if unit_test and queues[UNIT_TEST_QUEUE].qsize() != 0:
                break


def add_new_client_process(
    gateway: "Gateway",
    is_existing_contact: bool,
    onion_addr_user: str,
    onion_pub_keys: List[bytes],
    proc_dict: Dict[bytes, Process],
    queues: "QueueDict",
    tor_port: int,
    url_token_private_key: X448PrivateKey,
) -> None:
    """Add new client process."""
    for onion_pub_key in onion_pub_keys:
        if onion_pub_key not in proc_dict:
            onion_addr_user = "" if is_existing_contact else onion_addr_user
            proc_dict[onion_pub_key] = Process(
                target=client,
                args=(
                    onion_pub_key,
                    queues,
                    url_token_private_key,
                    tor_port,
                    gateway,
                    onion_addr_user,
                ),
            )
            proc_dict[onion_pub_key].start()


def remove_client_process(
    onion_pub_keys: List[bytes], proc_dict: Dict[bytes, Process]
) -> None:
    """Remove client process."""
    for onion_pub_key in onion_pub_keys:
        if onion_pub_key in proc_dict:
            process = proc_dict[onion_pub_key]  # type: Process
            process.terminate()
            proc_dict.pop(onion_pub_key)
            rp_print(f"Removed {pub_key_to_short_address(onion_pub_key)}", bold=True)


def client(
    onion_pub_key: bytes,
    queues: "QueueDict",
    url_token_private_key: X448PrivateKey,
    tor_port: str,
    gateway: "Gateway",
    onion_addr_user: str,
    unit_test: bool = False,
) -> None:
    """Load packets from contact's Onion Service."""
    cached_pk = ""
    short_addr = pub_key_to_short_address(onion_pub_key)
    onion_addr = pub_key_to_onion_address(onion_pub_key)
    check_delay = RELAY_CLIENT_MIN_DELAY
    is_online = False

    session = requests.session()
    session.proxies = {
        "http": f"socks5h://127.0.0.1:{tor_port}",
        "https": f"socks5h://127.0.0.1:{tor_port}",
    }

    rp_print(f"Connecting to {short_addr}...", bold=True)

    # When Transmitter Program sends contact under UNENCRYPTED_ADD_EXISTING_CONTACT, this function
    # receives user's own Onion address: That way it knows to request the contact to add them:
    if onion_addr_user:
        send_contact_request(onion_addr, onion_addr_user, session)

    while True:
        with ignored(EOFError, KeyboardInterrupt, SoftError):
            time.sleep(check_delay)

            url_token_public_key_hex = load_url_token(onion_addr, session)
            is_online, check_delay = manage_contact_status(
                url_token_public_key_hex, check_delay, is_online, short_addr
            )

            if not is_online:
                continue

            url_token, cached_pk = update_url_token(
                url_token_private_key,
                url_token_public_key_hex,
                cached_pk,
                onion_pub_key,
                queues,
            )

            get_data_loop(
                onion_addr,
                url_token,
                short_addr,
                onion_pub_key,
                queues,
                session,
                gateway,
            )

            if unit_test:
                break


def update_url_token(
    ut_private_key: "X448PrivateKey",
    ut_pubkey_hex: str,
    cached_pk: str,
    onion_pub_key: bytes,
    queues: "QueueDict",
) -> Tuple[str, str]:
    """Update URL token for contact.

    When contact's URL token public key changes, update URL token.
    """
    if ut_pubkey_hex == cached_pk:
        raise SoftError("URL token public key has not changed.", output=False)

    try:
        public_key = bytes.fromhex(ut_pubkey_hex)

        if len(public_key) != TFC_PUBLIC_KEY_LENGTH or public_key == bytes(
            TFC_PUBLIC_KEY_LENGTH
        ):
            raise ValueError

        shared_secret = ut_private_key.exchange(
            X448PublicKey.from_public_bytes(public_key)
        )
        url_token = hashlib.blake2b(
            shared_secret, digest_size=URL_TOKEN_LENGTH
        ).hexdigest()

        queues[URL_TOKEN_QUEUE].put(
            (onion_pub_key, url_token)
        )  # Update Flask server's URL token for contact

        return url_token, ut_pubkey_hex

    except (TypeError, ValueError):
        raise SoftError("URL token derivation failed.", output=False)


def manage_contact_status(
    ut_pubkey_hex: str, check_delay: float, is_online: bool, short_addr: str
) -> Tuple[bool, float]:
    """Manage online status of contact based on availability of URL token's public key."""
    if ut_pubkey_hex == "":
        if check_delay < RELAY_CLIENT_MAX_DELAY:
            check_delay *= 2
        if check_delay > CLIENT_OFFLINE_THRESHOLD and is_online:
            is_online = False
            rp_print(f"{short_addr} is now offline", bold=True)

    else:
        check_delay = RELAY_CLIENT_MIN_DELAY
        if not is_online:
            is_online = True
            rp_print(f"{short_addr} is now online", bold=True)

    return is_online, check_delay


def load_url_token(onion_addr: str, session: "Session") -> str:
    """Load URL token for contact."""
    try:
        ut_pubkey_hex = session.get(f"http://{onion_addr}.onion/", timeout=5).text
    except requests.exceptions.RequestException:
        ut_pubkey_hex = ""

    return ut_pubkey_hex


def send_contact_request(
    onion_addr: str, onion_addr_user: str, session: "Session"
) -> None:
    """Send contact request."""
    while True:
        try:
            reply = session.get(
                f"http://{onion_addr}.onion/contact_request/{onion_addr_user}",
                timeout=5,
            ).text
            if reply == "OK":
                break
        except requests.exceptions.RequestException:
            time.sleep(RELAY_CLIENT_MIN_DELAY)


def get_data_loop(
    onion_addr: str,
    url_token: str,
    short_addr: str,
    onion_pub_key: bytes,
    queues: "QueueDict",
    session: "Session",
    gateway: "Gateway",
) -> None:
    """Load TFC data from contact's Onion Service using valid URL token."""
    while True:
        try:
            check_files(
                url_token, onion_pub_key, onion_addr, short_addr, session, queues
            )

            try:
                r = session.get(
                    f"http://{onion_addr}.onion/{url_token}/messages", stream=True
                )
            except requests.exceptions.RequestException:
                return None

            for line in r.iter_lines():  # Iterate over newline-separated datagrams

                if not line:
                    continue

                try:
                    header, payload = separate_header(
                        line, DATAGRAM_HEADER_LENGTH
                    )  # type: bytes, bytes
                    payload_bytes = base64.b85decode(payload)
                except (UnicodeError, ValueError):
                    continue

                ts = datetime.now()
                ts_bytes = int_to_bytes(int(ts.strftime("%Y%m%d%H%M%S%f")[:-4]))

                process_received_packet(
                    ts,
                    ts_bytes,
                    header,
                    payload_bytes,
                    onion_pub_key,
                    short_addr,
                    queues,
                    gateway,
                )

        except requests.exceptions.RequestException:
            break


def check_files(
    url_token: str,
    onion_pub_key: bytes,
    onion_addr: str,
    short_addr: str,
    session: "Session",
    queues: "QueueDict",
) -> None:
    """See if a file is available from contact.."""
    try:
        file_data = session.get(
            f"http://{onion_addr}.onion/{url_token}/files", stream=True
        ).content
        if file_data:
            ts = datetime.now()
            ts_bytes = int_to_bytes(int(ts.strftime("%Y%m%d%H%M%S%f")[:-4]))
            packet = (
                FILE_DATAGRAM_HEADER
                + ts_bytes
                + onion_pub_key
                + ORIGIN_CONTACT_HEADER
                + file_data
            )
            queues[DST_MESSAGE_QUEUE].put(packet)
            rp_print(f"File      from contact {short_addr}", ts)

    except requests.exceptions.RequestException:
        pass


def process_received_packet(
    ts: "datetime",
    ts_bytes: bytes,
    header: bytes,
    payload_bytes: bytes,
    onion_pub_key: bytes,
    short_addr: str,
    queues: "QueueDict",
    gateway: "Gateway",
) -> None:
    """Process received packet."""
    if header == PUBLIC_KEY_DATAGRAM_HEADER:
        if len(payload_bytes) == TFC_PUBLIC_KEY_LENGTH:
            msg = f"Received public key from {short_addr} at {ts.strftime('%b %d - %H:%M:%S.%f')[:-4]}:"
            print_key(msg, payload_bytes, gateway.settings, public_key=True)

    elif header == MESSAGE_DATAGRAM_HEADER:
        queues[DST_MESSAGE_QUEUE].put(
            header + ts_bytes + onion_pub_key + ORIGIN_CONTACT_HEADER + payload_bytes
        )
        rp_print(f"Message   from contact {short_addr}", ts)

    elif header in [
        GROUP_MSG_INVITE_HEADER,
        GROUP_MSG_JOIN_HEADER,
        GROUP_MSG_MEMBER_ADD_HEADER,
        GROUP_MSG_MEMBER_REM_HEADER,
        GROUP_MSG_EXIT_GROUP_HEADER,
    ]:
        queues[GROUP_MSG_QUEUE].put((header, payload_bytes, short_addr))

    else:
        rp_print(f"Received invalid packet from {short_addr}", ts, bold=True)


def g_msg_manager(queues: "QueueDict", unit_test: bool = False) -> None:
    """Show group management messages according to contact list state.

    This process keeps track of existing contacts for whom there's a
    `client` process. When a group management message from a contact
    is received, existing contacts are displayed under "known contacts",
    and non-existing contacts are displayed under "unknown contacts".
    """
    existing_contacts = []  # type: List[bytes]
    group_management_queue = queues[GROUP_MGMT_QUEUE]

    while True:
        with ignored(EOFError, KeyboardInterrupt):
            while not queues[GROUP_MSG_QUEUE].qsize():
                time.sleep(0.01)

            header, payload, trunc_addr = queues[GROUP_MSG_QUEUE].get()
            group_id, data = separate_header(payload, GROUP_ID_LENGTH)

            if len(group_id) != GROUP_ID_LENGTH:
                continue
            group_id_hr = b58encode(group_id)

            existing_contacts = update_list_of_existing_contacts(
                group_management_queue, existing_contacts
            )

            # Handle group management messages
            process_group_management_message(
                data, existing_contacts, group_id_hr, header, trunc_addr
            )

            if unit_test and queues[UNIT_TEST_QUEUE].qsize() != 0:
                break


def process_group_management_message(
    data: bytes,
    existing_contacts: List[bytes],
    group_id_hr: str,
    header: bytes,
    trunc_addr: str,
) -> None:
    """Process group management message."""
    if header in [
        GROUP_MSG_INVITE_HEADER,
        GROUP_MSG_JOIN_HEADER,
        GROUP_MSG_MEMBER_ADD_HEADER,
        GROUP_MSG_MEMBER_REM_HEADER,
    ]:

        pub_keys = split_byte_string(data, ONION_SERVICE_PUBLIC_KEY_LENGTH)
        pub_key_length = ONION_SERVICE_PUBLIC_KEY_LENGTH

        members = [k for k in pub_keys if len(k) == pub_key_length]
        known = [
            f"  * {pub_key_to_onion_address(m)}"
            for m in members
            if m in existing_contacts
        ]
        unknown = [
            f"  * {pub_key_to_onion_address(m)}"
            for m in members
            if m not in existing_contacts
        ]

        line_list = []
        if known:
            line_list.extend(["Known contacts"] + known)
        if unknown:
            line_list.extend(["Unknown contacts"] + unknown)

        if header in [GROUP_MSG_INVITE_HEADER, GROUP_MSG_JOIN_HEADER]:
            action = "invited you to" if header == GROUP_MSG_INVITE_HEADER else "joined"
            postfix = " with" if members else ""
            m_print(
                [f"{trunc_addr} has {action} group {group_id_hr}{postfix}"] + line_list,
                box=True,
            )

        elif header in [GROUP_MSG_MEMBER_ADD_HEADER, GROUP_MSG_MEMBER_REM_HEADER]:
            if members:
                action, p = (
                    ("added", "to")
                    if header == GROUP_MSG_MEMBER_ADD_HEADER
                    else ("removed", "from")
                )
                m_print(
                    [
                        f"{trunc_addr} has {action} following members {p} group {group_id_hr}"
                    ]
                    + line_list,
                    box=True,
                )

    elif header == GROUP_MSG_EXIT_GROUP_HEADER:
        m_print(
            [
                f"{trunc_addr} has left group {group_id_hr}",
                "",
                "Warning",
                "Unless you remove the contact from the group, they",
                "can still read messages you send to the group.",
            ],
            box=True,
        )


def c_req_manager(queues: "QueueDict", unit_test: bool = False) -> None:
    """Manage incoming contact requests."""
    existing_contacts = []  # type: List[bytes]
    contact_requests = []  # type: List[bytes]

    request_queue = queues[CONTACT_REQ_QUEUE]
    contact_queue = queues[C_REQ_MGMT_QUEUE]
    setting_queue = queues[C_REQ_STATE_QUEUE]
    show_requests = True

    while True:
        with ignored(EOFError, KeyboardInterrupt):
            while not request_queue.qsize():
                time.sleep(0.1)
            purp_onion_address = request_queue.get()

            while setting_queue.qsize():
                show_requests = setting_queue.get()

            # Update list of existing contacts
            existing_contacts = update_list_of_existing_contacts(
                contact_queue, existing_contacts
            )

            if validate_onion_addr(purp_onion_address) == "":
                onion_pub_key = onion_address_to_pub_key(purp_onion_address)
                if onion_pub_key in existing_contacts:
                    continue
                if onion_pub_key in contact_requests:
                    continue

                if show_requests:
                    ts_fmt = datetime.now().strftime("%b %d - %H:%M:%S.%f")[:-4]
                    m_print(
                        [
                            f"{ts_fmt} - New contact request from an unknown TFC account:",
                            purp_onion_address,
                        ],
                        box=True,
                    )
                contact_requests.append(onion_pub_key)

            if unit_test and queues[UNIT_TEST_QUEUE].qsize() != 0:
                break


def update_list_of_existing_contacts(
    contact_queue: "Queue[Any]", existing_contacts: List[bytes]
) -> List[bytes]:
    """Update list of existing contacts."""
    while contact_queue.qsize() > 0:
        command, ser_onion_pub_keys = contact_queue.get()
        onion_pub_key_list = split_byte_string(
            ser_onion_pub_keys, ONION_SERVICE_PUBLIC_KEY_LENGTH
        )

        if command == RP_ADD_CONTACT_HEADER:
            existing_contacts = list(set(existing_contacts) | set(onion_pub_key_list))
        elif command == RP_REMOVE_CONTACT_HEADER:
            existing_contacts = list(set(existing_contacts) - set(onion_pub_key_list))

    return existing_contacts
