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

from typing import TYPE_CHECKING

from src.common.entities.nick_name import Nick
from src.common.crypto.keys.onion_service_keys import OnionPublicKeyContact
from src.common.exceptions import SoftError, raise_if_traffic_masking
from src.common.statics import FieldLength, KexType
from src.ui.common.input.get_input import get_input
from src.ui.common.output.print_message import print_message
from src.common.utils.validators import validate_nick, validate_key_exchange
from src.datagrams.relay.command.contact_add import DatagramRelayAddContact
from src.transmitter.key_exchanges.pre_shared_key import create_pre_shared_key
from src.transmitter.key_exchanges.x448 import start_key_exchange
from src.ui.common.input.get_onion_addr_from_user import get_onion_address_from_user

if TYPE_CHECKING:
    from src.common.queues import TxQueue
    from src.database.db_contacts import ContactList
    from src.database.db_groups import GroupList
    from src.database.db_local_key import LocalKeyDB
    from src.database.db_masterkey import MasterKey
    from src.database.db_onion import OnionService
    from src.database.db_settings import Settings


def add_new_contact(settings      : 'Settings',
                    queues        : 'TxQueue',
                    contact_list  : 'ContactList',
                    group_list    : 'GroupList',
                    master_key    : 'MasterKey',
                    local_key_db  : 'LocalKeyDB',
                    onion_service : 'OnionService',
                    ) -> None:
    """Prompt for contact account details and initialize desired key exchange.

    This function requests the minimum amount of data about the
    recipient as possible. The TFC account of contact is the same as the
    Onion URL of contact's v3 Tor Onion Service. Since the accounts are
    random and hard to remember, the user has to choose a nickname for
    their contact. Finally, the user must select the key exchange method:
    ECDHE for convenience in a pre-quantum world, or PSK for situations
    where physical key exchange is possible, and ciphertext must remain
    secure even after sufficient QTMs are available to adversaries.

    Before starting the key exchange, Transmitter Program exports the
    public key of contact's Onion Service to Relay Program on their
    Networked Computer so that a connection to the contact can be
    established.
    """
    try:
        raise_if_traffic_masking(settings)

        if len(contact_list) >= settings.max_number_of_contacts:
            raise SoftError(f'Error: TFC settings only allow {settings.max_number_of_contacts} accounts.',
                            clear_before=True)

        print_message('Add new contact', padding_top=1, bold=True, clear_before=True)

        print_message(['Your TFC account is',
                       onion_service.onion_addr_user,
                 '', 'Warning!',
                 'Anyone who knows this account',
                 'can see when your TFC is online'], box=True)

        contact_address       = get_onion_address_from_user(queues, onion_service.onion_addr_user)
        onion_pub_key_contact = OnionPublicKeyContact.from_onion_address(contact_address)

        contact_nick = Nick(get_input('Contact nick',
                                      expected_len   = FieldLength.ONION_ADDRESS.value,  # Limited to 255 but such long nick is unpractical.
                                      validator      = validate_nick,
                                      validator_args = (contact_list, group_list, onion_pub_key_contact)).strip())

        key_exchange = KexType(get_input(f'Key exchange ([{KexType.ECDHE}],PSK) ',
                                         default      = KexType.ECDHE.value,
                                         expected_len = 28,
                                         validator    = validate_key_exchange).strip())

        queues.relay_packet.put( DatagramRelayAddContact(onion_pub_key_contact) )

        if key_exchange == KexType.ECDHE:
            start_key_exchange(onion_pub_key_contact, contact_nick, contact_list, settings, local_key_db, master_key, queues)

        elif key_exchange == KexType.PSK:
            create_pre_shared_key(onion_pub_key_contact, contact_nick, contact_list, settings, onion_service, queues)

    except (EOFError, KeyboardInterrupt):
        raise SoftError('Contact creation aborted.', padding_top=2, clear_delay=1, clear_after=True)

