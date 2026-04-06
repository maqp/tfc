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

import os

from typing import TYPE_CHECKING

from src.common.statics import BufferFileName, BufferFileDir
from src.datagrams.receiver.file_multicast import DatagramFileMulticast
from src.ui.common.output.print_log_message import print_log_message
from src.common.utils.io import store_unique, get_working_dir

if TYPE_CHECKING:
    from src.datagrams.datagram import DatagramShared
    from src.common.crypto.keys.symmetric_key import BufferKey
    from src.common.crypto.keys.onion_service_keys import OnionPublicKeyContact


def write_to_server_buffer_file(datagram        : 'DatagramShared',
                                pub_key_contact : 'OnionPublicKeyContact',
                                buffer_key      : 'BufferKey',
                                ) -> None:
    """Write an outgoing packet to server's buffer directory.

    Caching the ciphertexts on disk massively reduces packet drops if
    user closers TFC while there is still packets to be delivered to
    contacts.
    """
    file_name  = (BufferFileName.RELAY_BUF_OUTGOING_FILE
                  if isinstance(datagram, DatagramFileMulticast)
                  else BufferFileName.RELAY_BUF_OUTGOING_MESSAGE)
    file_dir   = (BufferFileDir.RELAY_BUF_OUTGOING_FILES
                  if isinstance(datagram, DatagramFileMulticast)
                  else BufferFileDir.RELAY_BUF_OUTGOING_MESSAGES)
    sub_dir    = pub_key_contact.derive_relay_buffer_sub_dir(buffer_key)
    buffer_dir = os.path.join(get_working_dir(), file_dir, sub_dir)

    if isinstance(datagram, DatagramFileMulticast):
        file_datagram = DatagramFileMulticast(datagram.file_ct, pub_key_contact=pub_key_contact, timestamp=datagram.ts)
        packet        = file_datagram.to_server_b85()
    else:
        packet = datagram.to_server_b85()

    store_unique(file_dir  = buffer_dir,
                 file_name = file_name,
                 file_data = buffer_key.encrypt_and_sign(packet))

    print_log_message(f"{datagram.DATAGRAM_TYPE_HR:<9} {'to':<4} contact {pub_key_contact.short_address}", datagram.ts)
