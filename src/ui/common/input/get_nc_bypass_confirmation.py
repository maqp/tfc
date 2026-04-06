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

from src.common.statics import NCBypassState
from src.ui.common.output.print_message import print_message

if TYPE_CHECKING:
    from src.database.db_settings import Settings


def get_nc_bypass_confirmation(key: NCBypassState, settings: 'Settings') -> None:
    """Get confirmation from user about bypassing and reconnecting Networked Computer.

    During ciphertext delivery of local key exchange, these bypass
    messages tell the user when to bypass and remove bypass of Networked
    Computer. Bypass of Networked Computer makes initial bootstrap more
    secure by denying remote attacker the access to the encrypted local
    key. Without the ciphertext, e.g. a visually collected local key
    decryption key is useless.
    """
    m = {NCBypassState.NC_BYPASS_START: 'Bypass the Networked Computer if needed. Press <Enter> to send local key.',
         NCBypassState.NC_BYPASS_STOP:  'Remove bypass of the Networked Computer. Press <Enter> to continue.'}

    if settings.nc_bypass_messages:
        print_message(m[NCBypassState(key)], manual_proceed=True, box=True, padding_top=(1 if key == NCBypassState.NC_BYPASS_STOP else 0))
