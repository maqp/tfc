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

from src.common.crypto.keys.symmetric_key import LocalKeyEncryptionKey
from src.common.crypto.keys.x448_keys import X448PubKey
from src.common.exceptions import CriticalError
from src.common.statics import B58Guide
from src.common.utils.encoding import b58encode
from src.common.utils.strings import split_string
from src.ui.common.output.print_message import print_message

if TYPE_CHECKING:
    from src.database.db_settings_gateway import GatewaySettings
    from src.database.db_settings import Settings


def print_key(message    : str,
              key        : 'LocalKeyEncryptionKey|X448PubKey',
              settings   : 'Settings|GatewaySettings',
              public_key : bool = False
              ) -> None:
    """Print a symmetric key in WIF format.

    If serial-interface based platform is used, this function adds
    spacing in the middle of the key, as well as guide letters to help
    the user keep track of typing progress:

    Local key encryption keys:

         A   B   C   D   E   F   G   H   I   J   K   L   M   N   O   P   Q
        5Ka 52G yNz vjF nM4 2jw Duu rWo 7di zgi Y8g iiy yGd 78L cCx mwQ mWV

    X448 public keys:

           A       B       C       D       E       F       H       H       I       J       K       L
        4EcuqaD ddsdsuc gBX2PY2 qR8hReA aeSN2oh JB9w5Cv q6BQjDa PPgzSvW 932aHio sT42SKJ Gu2PpS1 Za3Xrao
    """
    if   isinstance(key, X448PubKey):            key_bytes = key.x448_public_key.public_bytes_raw()
    elif isinstance(key, LocalKeyEncryptionKey): key_bytes = key.raw_bytes
    else: raise CriticalError(f"Invalid key type '{type(key)}'")

    b58key = b58encode(key_bytes, public_key)
    if settings.local_testing_mode or settings.qubes:
        print_message([message, b58key], box=True)
    else:
        guide, chunk_length = (B58Guide.B58_PUBLIC_KEY_GUIDE, 7) if public_key else (B58Guide.B58_LOCAL_KEY_GUIDE, 3)

        key_str = ' '.join(split_string(b58key, item_len=chunk_length))
        print_message([message, guide, key_str], box=True)
