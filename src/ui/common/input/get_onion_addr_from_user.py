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

from src.common.exceptions import ValidationError, CheckInputError
from src.common.statics import FieldLength
from src.common.types_custom import StrOnionAddressContact, StrOnionAddressUser
from src.ui.common.input.get_input import get_input
from src.common.utils.validators import validate_onion_addr
from src.datagrams.relay.diff_comparison.diff_comparison_account import DatagramRelayDiffComparisonAccount
from src.ui.common.output.print_message import print_message
from src.ui.common.output.vt100_utils import clear_previous_lines

if TYPE_CHECKING:
    from src.common.queues import TxQueue


def get_onion_address_from_user(queues             : 'TxQueue',
                                onion_address_user : StrOnionAddressUser
                                ) -> StrOnionAddressContact:
    """Get contact's Onion Address from user."""
    while True:
        onion_address_contact = get_input('Contact account', expected_len=FieldLength.ONION_ADDRESS.value)

        try:
            validate_onion_addr(onion_address_contact, onion_address_user)
        except ValidationError as e:
            print_message(str(e), padding_top=1)
            clear_previous_lines(no_lines=5, delay=1)
            continue
        except CheckInputError as e:
            queues.relay_packet.put( DatagramRelayDiffComparisonAccount(onion_address_contact) )
            print_message(str(e), padding_top=1)
            clear_previous_lines(no_lines=5, delay=1)
            continue

        return StrOnionAddressContact(onion_address_contact)

    raise RuntimeError('Broke out of loop')
