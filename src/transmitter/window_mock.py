#!/usr/bin/env python3.7
# -*- coding: utf-8 -*-

"""
TFC - Onion-routed, endpoint secure messaging system
Copyright (C) 2013-2020  Markus Ottela

This file is part of TFC.

TFC is free software: you can redistribute it and/or modify it under the terms
of the GNU General Public License as published by the Free Software Foundation,
either version 3 of the License, or (at your option) any later version.

TFC is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with TFC. If not, see <https://www.gnu.org/licenses/>.
"""

import typing

from typing import Iterable, Iterator, List, Optional

from src.common.db_contacts import Contact
from src.common.statics     import WIN_TYPE_CONTACT

if typing.TYPE_CHECKING:
    from src.common.db_groups import Group


class MockWindow(Iterable[Contact]):
    """\
    Mock window simplifies queueing of message assembly packets for
    automatically generated group management and key delivery messages.
    """

    def __init__(self, uid: bytes, contacts: List['Contact']) -> None:
        """Create a new MockWindow object."""
        self.window_contacts = contacts
        self.type            = WIN_TYPE_CONTACT
        self.group           = None  # type: Optional[Group]
        self.name            = None  # type: Optional[str]
        self.uid             = uid
        self.log_messages    = self.window_contacts[0].log_messages

    def __iter__(self) -> Iterator[Contact]:
        """Iterate over contact objects in the window."""
        yield from self.window_contacts
