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

from typing import Any, Optional as O

from src.common.statics import VT100


def split_byte_string(bytestring : bytes,  # Bytestring to split
                      item_len   : int     # Length of each substring
                      ) -> list[bytes]:    # List of substrings
    """Split a bytestring into a list of specific length substrings."""
    return [bytestring[i:i + item_len] for i in range(0, len(bytestring), item_len)]


def split_string(string   : str,  # String to split
                 item_len : int   # Length of each substring
                 ) -> list[str]:  # List of substrings
    """Split a string into a list of specific length substrings."""
    return [string[i:i + item_len] for i in range(0, len(string), item_len)]


def separate_header(bytestring    : bytes,     # Bytestring to slice
                    header_length : int        # Number of header bytes to separate
                    ) -> tuple[bytes, bytes]:  # Header and payload
    """Separate `header_length` first bytes from a bytestring."""
    return bytestring[:header_length], bytestring[header_length:]


def separate_headers(bytestring         : bytes,      # Bytestring to slice
                     header_length_list : list[int],  # List of header lengths
                     ) -> list[bytes]:                # Header and payload
    """Separate a list of headers from bytestring.

    Length of each header is determined in the `header_length_list`.
    """
    fields = []
    for header_length in header_length_list:
        field, bytestring = separate_header(bytestring, header_length)
        fields.append(field)
    fields.append(bytestring)

    return fields


def separate_trailer(bytestring     : bytes,    # Bytestring to slice
                     trailer_length : int       # Number of trailer bytes to separate
                     ) -> tuple[bytes, bytes]:  # Payload and trailer
    """Separate `trailer_length` last bytes from a bytestring.

    This saves space and makes trailer separation more readable.
    """
    return bytestring[:-trailer_length], bytestring[-trailer_length:]


def split_to_substrings(bytestring: bytes, length: int) -> list[bytes]:
    """Split byte string into all it's possible `length` long substrings."""
    substrings = []
    for i in range(0, len(bytestring) - length + 1):
        substrings.append(bytestring[i:length + i])

    return substrings


def bold(text: str, bold_first_n: O[int] = None) -> str:
    """Return text wrapped in VT100 bold style."""
    if bold_first_n is None:
        return VT100.BOLD_ON.value + text + VT100.NORMAL_TEXT.value
    else:
        return (  VT100.BOLD_ON    .value + text[:bold_first_n]
                + VT100.NORMAL_TEXT.value + text[bold_first_n:])


def s(lst: bool|int|list[Any]) -> str:
    """Return '' when the list has one item else 's'.

    Used to add a plural 's' to a string when the list has zero, or more than one item.
    """
    if isinstance(lst, bool):
        return '' if lst else 's'
    elif isinstance(lst, int):
        return '' if lst == 1 else 's'
    elif isinstance(lst, list):
        return '' if len(lst) == 1 else 's'
    else:
        return ''
