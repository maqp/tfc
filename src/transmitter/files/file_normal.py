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

import base64
import os
import zlib

from pathlib import Path
from typing import TYPE_CHECKING

from src.common.entities.window_uid import WindowUID
from src.common.crypto.pt_ct import MulticastFilePT
from src.common.crypto.keys.symmetric_key import MulticastFileKey
from src.common.types_custom import BoolLogAsPlaceHolder, StrPlaintextMessage
from src.common.utils.encoding import str_to_padded_bytes
from src.common.exceptions import SoftError, raise_if_traffic_masking
from src.common.statics import (PayloadType, CompressionLiterals, MessageHeader)

from src.datagrams.receiver.file_multicast import DatagramFileMulticast
from src.ui.common.output.print_message import print_message
from src.ui.common.output.vt100_utils import clear_previous_lines
from src.ui.common.output.phase import phase

from src.ui.transmitter.user_input import UserInput

if TYPE_CHECKING:
    from src.common.queues import TxQueue
    from src.database.db_settings import Settings
    from src.ui.transmitter.window_tx import TxWindow



def queue_normal_file(path     : Path,
                      settings : 'Settings',
                      queues   : 'TxQueue',
                      window   : 'TxWindow'
                      ) -> None:
    """Send file to window members in a single transmission.

    This is the default mode for file transmission, used when traffic
    masking is not enabled. The file is loaded and compressed before it
    is encrypted. The encrypted file is then exported to Networked
    Computer along with a list of Onion Service public keys (members in
    window) of all recipients to whom the Relay Program will multicast
    the file to.

    Once the file ciphertext has been exported, this function will
    multicast the file decryption key to each recipient inside an
    automated key delivery message that uses a special FILE_KEY_HEADER
    in place of standard PRIVATE_MESSAGE_HEADER. To know for which file
    ciphertext the key is for, an identifier must be added to the key
    delivery message. The identifier in this case is the BLAKE2b digest
    of the ciphertext itself. The reason of using the digest as the
    identifier is, it authenticates both the ciphertext and its origin.
    To understand this, consider the following attack scenario:

    Let the file ciphertext identifier be just a random 32-byte value 'ID'.

    1) Alice sends Bob and Chuck (a malicious common peer) a file
       ciphertext and identifier CT|ID (where | denotes concatenation).

    2) Chuck who has compromised Bob's Networked Computer interdicts the
       CT|ID from Alice.

    3) Chuck decrypts CT in his end, makes edits to the plaintext PT to
       create PT'.

    4) Chuck re-encrypts PT' with the same symmetric key to produce CT'.

    5) Chuck re-uses the ID and produces CT'|ID.

    6) Chuck uploads the CT'|ID to Bob's Networked Computer and replaces
       the interdicted CT|ID with it.

    7) When Bob's Receiver Program receives the automated key delivery
       message from Alice, his Receiver program uses the bundled ID to
       identify the key is for CT'.

    8) Bob's Receiver decrypts CT' using the newly received key and
       obtains Chuck's PT', that appears to come from Alice.

    Now, consider a situation where the ID is instead calculated
    ID = BLAKE2b(CT), if Chuck edits the PT, the CT' will by definition
    be different from CT, and the BLAKE2b digest will also be different.
    In order to make Bob decrypt CT', Chuck needs to also change the
    hash in Alice's key delivery message, which means Chuck needs to
    create an existential forgery of the TFC message. Since the Poly1305
    tag prevents this, the calculated ID is enough to authenticate the
    ciphertext.

    If Chuck attempts to send their own key delivery message, Chuck's
    own Onion Service public key used to identify the TFC message key
    (decryption key for the key delivery message) will be permanently
    associated with the file hash, so if they inject a file CT, and Bob
    has decided to enable file reception for Chuck, the file CT will
    appear to come from Chuck, and not from Alice. From the perspective
    of Bob, it's as if Chuck had dropped Alice's file and sent him
    another file instead.

    This function makes an exception to key encapsulation as the security
    of the key isn't being protected in ways other than delivering it in
    the last assembly packet -- again for sender-based control over
    partial transmission.
    """
    from src.transmitter.queue_packet.queue_packet import queue_message
    from src.ui.transmitter.window_tx import MockWindow

    raise_if_traffic_masking(settings)

    name = os.path.basename(path)
    data = bytearray()
    data.extend(str_to_padded_bytes(name))

    if not os.path.isfile(path):
        raise SoftError('Error: File not found.', clear_before=True)

    if os.path.getsize(path) == 0:
        raise SoftError('Error: Target file is empty.', clear_before=True)

    with phase('Reading data'):
        with open(path, 'rb') as f:
            data.extend(f.read())
    clear_previous_lines(no_lines=1, flush=True)

    with phase('Compressing data'):
        file_pt = MulticastFilePT(bytes(zlib.compress(bytes(data), level=CompressionLiterals.COMPRESSION_LEVEL)))
    clear_previous_lines(no_lines=1, flush=True)

    with phase('Encrypting data'):
        file_key = MulticastFileKey()
        file_ct  = file_key.encrypt_and_sign(file_pt)

    clear_previous_lines(no_lines=1, flush=True)

    recipient_pub_keys = [contact.onion_pub_key for contact in window.window_contacts]

    with phase('Exporting file'):
        queues.relay_packet.put(DatagramFileMulticast(file_ct, recipient_pub_keys))

    clear_previous_lines(no_lines=1, flush=True)

    with phase('Sending decryption keys'):
        key_delivery_msg = StrPlaintextMessage(base64.b85encode(file_ct.ct_hash + file_key.raw_bytes).decode())
        for contact in window:
            queue_message(user_input = UserInput(key_delivery_msg, PayloadType.MESSAGE),
                          window     = MockWindow(WindowUID.for_contact(contact), [contact]),
                          settings   = settings,
                          queues     = queues,
                          msg_header = MessageHeader.FILE_KEY,
                          log_as_ph  = BoolLogAsPlaceHolder(True))
    clear_previous_lines(no_lines=1, flush=True)
    print_message(f"Sent file '{name}' to {window.window_type_hr} {window.window_name}.")
