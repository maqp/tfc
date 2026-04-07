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

from typing import TYPE_CHECKING, Iterator

from src.common.entities.payload import MessagePayload, FilePayload, CommandPayload

if TYPE_CHECKING:
    from src.common.crypto.keys.onion_service_keys import OnionPublicKeyContact


class PayloadBuffer:
    """PayloadBuffer stores the incomplete payload from contacts until they're ready to be displayed."""

    def __init__(self) -> None:
        self.__command_payload = CommandPayload()

        self._payload_dict_message_origin_user    : 'dict[OnionPublicKeyContact, MessagePayload]' = dict()
        self._payload_dict_message_origin_contact : 'dict[OnionPublicKeyContact, MessagePayload]' = dict()
        self._payload_dict_file_origin_user       : 'dict[OnionPublicKeyContact, FilePayload]'    = dict()
        self._payload_dict_file_origin_contact    : 'dict[OnionPublicKeyContact, FilePayload]'    = dict()

    def get_command_payload(self) -> CommandPayload:
        """Get the command payload."""
        return self.__command_payload

    def get_message_payload_from_user(self, onion_pub_key: 'OnionPublicKeyContact') -> MessagePayload:
        """Get message payload from user."""
        return self._payload_dict_message_origin_user.setdefault(onion_pub_key, MessagePayload())

    def get_message_payload_from_contact(self, onion_pub_key: 'OnionPublicKeyContact') -> MessagePayload:
        """Get message payload from contact."""
        return self._payload_dict_message_origin_contact.setdefault(onion_pub_key, MessagePayload())

    def get_file_payload_from_user(self, onion_pub_key: 'OnionPublicKeyContact') -> FilePayload:
        """Get file payload from user."""
        return self._payload_dict_file_origin_user.setdefault(onion_pub_key, FilePayload())

    def get_file_payload_from_contact(self, onion_pub_key: 'OnionPublicKeyContact') -> FilePayload:
        """Get file payload from contact."""
        return self._payload_dict_file_origin_contact.setdefault(onion_pub_key, FilePayload())

    def iter_contact_file_payloads(self) -> Iterator[tuple['OnionPublicKeyContact', FilePayload]]:
        """Iterate over in-progress file payloads from contacts."""
        for onion_pub_key, payload in self._payload_dict_file_origin_contact.items():
            if payload.has_packets:
                yield onion_pub_key, payload
