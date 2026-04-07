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

from src.common.types_custom import BoolUnitTesting
from src.transmitter.sender.sender_traffic_masking import traffic_masking_sender
from src.transmitter.sender.sender_normal import normal_sender

if TYPE_CHECKING:
    from src.common.gateway import Gateway
    from src.common.queues import TxQueue
    from src.common.types_compound import NormalSenderMsgBuffer
    from src.database.db_keys import KeyStore
    from src.database.db_local_key import LocalKeyDB
    from src.database.db_settings import Settings


def process_sender(queues       : 'TxQueue',
                   settings     : 'Settings',
                   gateway      : 'Gateway',
                   key_store    : 'KeyStore',
                   local_key_db : 'LocalKeyDB',
                   unit_test    : BoolUnitTesting = BoolUnitTesting(False)
                   ) -> None:
    """Process that outputs packets from queues based on queue priority.

    Depending on traffic masking setting adjusted by the user, enable
    either traffic masking or standard sender loop for packet output.
    """
    m_buffer : 'NormalSenderMsgBuffer' = dict()

    while True:
        if settings.traffic_masking:
            settings = traffic_masking_sender(queues, settings, gateway, key_store, local_key_db)
        else:
            settings, m_buffer = normal_sender(queues, settings, gateway, key_store, local_key_db, m_buffer)
        if unit_test:
            break
