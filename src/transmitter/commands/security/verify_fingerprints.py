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
from src.common.statics import WindowType, KexStatus
from src.transmitter.key_exchanges.x448 import verify_fingerprints
from src.ui.common.output.print_message import print_message

if TYPE_CHECKING:
    from src.database.db_contacts import ContactList
    from src.ui.transmitter.window_tx import TxWindow


def verify(window: 'TxWindow', contact_list: 'ContactList') -> None:
    """Verify fingerprints with contact."""
    if window.window_type == WindowType.GROUP or window.contact is None:
        raise SoftError('Error: A group is selected.', clear_before=True)

    if window.contact.uses_psk():
        raise SoftError('Pre-shared keys have no fingerprints.', clear_before=True)

    try:
        verified = verify_fingerprints(window.contact.tx_fingerprint,
                                       window.contact.rx_fingerprint)
    except (EOFError, KeyboardInterrupt):
        raise SoftError('Fingerprint verification aborted.', clear_delay=1, padding_top=2, clear_after=True)

    status_hr, status = {True:  ('Verified',   KexStatus.KEX_STATUS_VERIFIED),
                         False: ('Unverified', KexStatus.KEX_STATUS_UNVERIFIED)}[verified]

    window.contact.kex_status = status
    contact_list.store_contacts()
    print_message(f"Marked fingerprints with {window.window_name} as '{status_hr}'.",
                  bold=True, clear_after=True, clear_delay=1, padding_bottom=1)
