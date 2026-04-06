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

from typing import TYPE_CHECKING, Optional as O

from src.common.exceptions import SoftError
from src.common.statics import Origin, HashRatchet
from src.ui.common.input.get_yes import get_yes
from src.ui.common.output.print_message import print_message

if TYPE_CHECKING:
    from src.common.entities.nick_name import Nick
    from src.ui.receiver.window_rx import RxWindow


def process_offset(offset : int,
                   origin : Origin,
                   nick   : O['Nick'],
                   window : 'RxWindow',
                   p_type : str
                   ) -> None:
    """Display warnings about increased offsets.

    If the offset has increased over the threshold, ask the user to
    confirm hash ratchet catch up.
    """
    direction = 'from' if origin == Origin.CONTACT else 'sent to'

    if offset < 0:
        # Output is disabled to not litter Receiver Program with false positives when autoreplaying older packets.
        raise SoftError(f'Error: Received {p_type} {direction} {nick} had an expired hash ratchet counter.', output=False)

    if offset > HashRatchet.CATCHUP_WARN_THRESHOLD and origin in [Origin.CONTACT, Origin.CONTACT]:
        print_message([f'Warning! {offset} packets from {nick} were not received.',
                 f'This might indicate that {offset} most recent packets were ',
                  'lost during transmission, or that the contact is attempting ',
                  'a DoS attack. You can wait for TFC to attempt to decrypt the ',
                  'packet, but it might take a very long time or even forever.'])

        if not get_yes('Proceed with the decryption?', abort=False, tail=1):
            raise SoftError(f'Dropped packet from {nick}.', window=window)

    elif offset:
        print_message(f'Warning! {offset} packet{'s' if offset > 1 else ''} {direction} {nick} were not received.')
