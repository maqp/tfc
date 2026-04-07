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

from src.common.exceptions import CriticalError
from src.common.statics import B58KeyType, KexType, CryptoVarLength
from src.common.utils.encoding import b58decode
from src.ui.common.input.get_input import get_input
from src.ui.common.output.print_message import print_message
from src.ui.common.output.vt100_utils import clear_screen, clear_previous_lines

if TYPE_CHECKING:
    from src.database.db_settings import Settings


def get_b58_key(key_type      : str,         # The type of Base58 key to be entered
                settings      : 'Settings',  # Settings object
                short_address : str = ''     # The contact's short Onion address
                ) -> bytes:                  # The Base58 decoded key
    """Ask the user to input a Base58 encoded key."""
    if key_type == B58KeyType.B58_PUBLIC_KEY:
        clear_screen()
        print_message(f'{KexType.ECDHE} key exchange', padding_top=1, padding_bottom=1, bold=True)
        print_message('If needed, resend your public key to the contact by pressing <Enter>', padding_bottom=1)

        box_msg = f'Enter public key of {short_address} (from Relay)'
    elif key_type == B58KeyType.B58_LOCAL_KEY:
        box_msg = 'Enter local key decryption key (from Transmitter)'
    else:
        raise CriticalError('Invalid key type')

    while True:
        rx_pk = get_input(box_msg, key_type=key_type, guide=not (settings.local_testing_mode or settings.qubes))
        rx_pk = ''.join(rx_pk.split())

        if key_type == B58KeyType.B58_PUBLIC_KEY and rx_pk == '':
            return rx_pk.encode()

        try:
            return b58decode(rx_pk, public_key=(key_type == B58KeyType.B58_PUBLIC_KEY))
        except ValueError:
            print_message('Checksum error - Check that the entered key is correct.')
            clear_previous_lines(no_lines=(4 if settings.local_testing_mode else 5), delay=1)

            if key_type == B58KeyType.B58_PUBLIC_KEY and len(rx_pk) == CryptoVarLength.ENCODED_B58_PUB_KEY:
                raise ValueError(rx_pk)
