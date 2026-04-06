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

from src.ui.common.input.get_confirmation_code import get_confirmation_code
from src.ui.common.output.print_message import print_message
from src.datagrams.relay.command.setup_onion_service import DatagramRelaySetupOnionService
from src.ui.common.output.vt100_utils import clear_screen, clear_previous_lines
from src.ui.common.output.phase import phase

if TYPE_CHECKING:
    from src.common.gateway import Gateway
    from src.database.db_contacts import ContactList
    from src.database.db_onion import OnionService
    from src.database.db_settings import Settings


def export_onion_service_data(settings      : 'Settings',
                              contact_list  : 'ContactList',
                              onion_service : 'OnionService',
                              gateway       : 'Gateway',
                              ) -> None:
    """\
    Send the Tor Onion Service's private key and list of Onion Service
    public keys of contacts to Relay Program on Networked Computer.

    This private key is not intended to be used by the Transmitter
    Program. Because the Networked Computer we are exporting it to
    might not store data (e.g. Tails OS without persistence), we use
    the trusted Source Computer to generate the private key and store
    it safely. The private key is needed by Tor on Networked Computer
    to start the Onion Service.

    Exporting this private key does not endanger message confidentiality
    because TFC uses a separate key exchange with separate private key
    to create the symmetric keys that protect the messages. Those secret
    keys are never exported to the Networked Computer.

    Access to this key does not give to any user any information other
    than the v3 Onion Address. However, if they have compromised Relay
    Program to gain access to the key, they can see its public part
    anyway.

    This key is used by Tor to sign Diffie-Hellman public keys used when
    clients of contacts connect to the Onion Service. Thus, this key
    can't be used to decrypt traffic retrospectively.

    The worst possible case in the situation of Onion Service key compromise
    is, the key allows the attacker to start their own copy of the user's
    Onion Service.

    This does not allow impersonating as the user however, because the
    attacker is not in possession of keys that allow them to create
    valid ciphertexts. Even if they inject TFC public keys to conduct a
    MITM attack, that attack will be detected during fingerprint
    comparison.

    In addition to the private key, the Onion Service data packet also
    transmits the list of Onion Service public keys of existing and
    pending contacts to the Relay Program, as well as the setting that
    determines whether contact requests are allowed. Bundling everything
    in single packet minimizes the confirmation code overhead.
    """
    print_message('Onion Service setup', bold=True, clear_before=True, padding_top=1, padding_bottom=1)

    datagram = DatagramRelaySetupOnionService(onion_service_private_key = onion_service.onion_private_key,
                                              buffer_key                = onion_service.buffer_key,
                                              confirmation_code         = onion_service.confirmation_code,
                                              pending_pub_keys          = contact_list.get_list_of_pending_pub_keys(),
                                              existing_pub_keys         = contact_list.get_list_of_existing_pub_keys(),
                                              allow_contact_requests    = settings.allow_contact_requests)

    gateway.write(datagram)

    while True:
        purp_code = get_confirmation_code(code_displayed_on='Relay')

        if purp_code == onion_service.confirmation_code:
            onion_service.mark_delivered()
            clear_screen()
            break

        elif purp_code.is_resend_request:
            with phase('Resending Onion Service data', padding_top=2):
                gateway.write(datagram)
            clear_previous_lines(no_lines=5)

        else:
            print_message(['Incorrect confirmation code. If Relay Program did not',
                     'receive Onion Service data, resend it by pressing <Enter>.'], padding_top=1)
            clear_previous_lines(no_lines=5, delay=2.0)
