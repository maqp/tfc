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

from src.common.entities.serialized_command import SerializedCommand
from src.ui.common.input.get_confirmation_code import get_confirmation_code
from src.transmitter.queue_packet.queue_packet import queue_command
from src.ui.common.output.print_message import print_message
from src.ui.common.output.vt100_utils import clear_previous_lines
from src.ui.common.output.phase import phase

if TYPE_CHECKING:
    from src.common.crypto.keys.onion_service_keys import OnionPublicKeyContact
    from src.common.crypto.keys.symmetric_key import HeaderKeyContact, HeaderKeyUser, MessageKeyContact, MessageKeyUser
    from src.common.entities.nick_name import Nick
    from src.common.queues import TxQueue
    from src.common.statics import RxCommand
    from src.database.db_settings import Settings


def deliver_contact_data(header   : 'RxCommand',
                         nick     : 'Nick',
                         pub_key  : 'OnionPublicKeyContact',
                         tx_hk    : 'HeaderKeyUser',
                         tx_mk    : 'MessageKeyUser',
                         rx_hk    : 'HeaderKeyContact',
                         rx_mk    : 'MessageKeyContact',
                         queues   : 'TxQueue',
                         settings : 'Settings',
                         ) -> None:
    """Deliver contact data to Destination Computer."""
    serialized_fields = (pub_key.serialize()
                         + tx_hk.raw_bytes
                         + tx_mk.raw_bytes
                         + rx_hk.raw_bytes
                         + rx_mk.raw_bytes
                         + nick.nick_bytes)

    queue_command(settings, queues, SerializedCommand(header, serialized_fields))

    while True:
        purp_code = get_confirmation_code(code_displayed_on='Receiver')

        if purp_code == pub_key.c_code:
            break

        elif purp_code.is_resend_request:
            with phase('Resending contact data', padding_top=2):
                queue_command(settings, queues, SerializedCommand(header, serialized_fields))
            clear_previous_lines(no_lines=5)

        else:
            print_message('Incorrect confirmation code.', padding_top=1)
            clear_previous_lines(no_lines=4, delay=2)
