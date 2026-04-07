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

from src.common.exceptions import SoftError
from src.ui.common.input.get_yes import get_yes
from src.ui.common.output.print_message import print_message
from src.transmitter.key_exchanges.onion_service import export_onion_service_data

if TYPE_CHECKING:
    from src.common.gateway import Gateway
    from src.database.db_contacts import ContactList
    from src.database.db_onion import OnionService
    from src.database.db_settings import Settings


def send_onion_service_key(settings      : 'Settings',
                           contact_list  : 'ContactList',
                           onion_service : 'OnionService',
                           gateway       : 'Gateway'
                           ) -> None:
    """Resend Onion Service data to Relay Program on Networked Computer.

    This command is used in cases where Relay Program had to be
    restarted for some reason (e.g. due to system updates).
    """
    try:
        if settings.traffic_masking:
            print_message(['Warning!',
                     'Exporting Onion Service data to Networked Computer ',
                     'during traffic masking can reveal to an adversary ',
                     'TFC is being used at the moment. You should only do ',
                     "this if you've had to restart the Relay Program."],
                          bold=True, padding_top=1, padding_bottom=1)

            if not get_yes('Proceed with the Onion Service data export?', abort=False):
                raise SoftError('Onion Service data export canceled.', clear_after=True, clear_delay=1, padding_top=0)

        export_onion_service_data(settings, contact_list, onion_service, gateway)
    except (EOFError, KeyboardInterrupt):
        raise SoftError('Onion Service data export canceled.', clear_after=True, clear_delay=1, padding_top=2)
