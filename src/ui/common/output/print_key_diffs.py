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

from src.common.statics import CryptoVarLength, B58Guide
from src.common.utils.strings import split_string
from src.ui.common.output.print_message import print_message


def print_key_diffs(value_type : str,
                    purp_value : str,
                    true_value : str,
                    local_test : bool
                    ) -> None:
    """Show differences between purported value and correct value."""
    # Pad with underscores to denote missing chars
    while len(purp_value) < CryptoVarLength.ENCODED_B58_PUB_KEY:
        purp_value += '_'

    rep_arrows = ''
    purported  = ''

    for c1, c2 in zip(purp_value, true_value):
        rep_arrows += ' ' if c1 == c2 else '↓'
        purported  += c1

    message_list = [f'Source Computer received an invalid {value_type}.',
                    'See arrows below that point to correct characters.']

    if local_test:
        print_message(message_list + ['', purported, rep_arrows, true_value], box=True)
    else:
        purported  = ' '.join(split_string(purported,  item_len=7))
        rep_arrows = ' '.join(split_string(rep_arrows, item_len=7))
        true_value = ' '.join(split_string(true_value, item_len=7))

        print_message(message_list + ['',
                                      B58Guide.B58_PUBLIC_KEY_GUIDE,
                                      purported,
                                      rep_arrows,
                                      true_value,
                                      B58Guide.B58_PUBLIC_KEY_GUIDE], box=True)
