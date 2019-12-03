#!/usr/bin/env python3.7
# -*- coding: utf-8 -*-

"""
TFC - Onion-routed, endpoint secure messaging system
Copyright (C) 2013-2019  Markus Ottela

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

import unittest

import src.common.statics

from src.common.encoding import onion_address_to_pub_key
from src.common.misc import validate_onion_addr


class TestStatics(unittest.TestCase):
    def test_uniqueness(self) -> None:
        variable_list = [
            getattr(src.common.statics, i)
            for i in dir(src.common.statics)
            if not i.startswith("__")
        ]
        variable_list = [v for v in variable_list if (isinstance(v, (bytes, str)))]

        # Debugger
        for unique_variable in list(set(variable_list)):
            repeats = 0
            for variable in variable_list:
                if variable == unique_variable:
                    repeats += 1
            if repeats > 1:
                spacing = (3 - len(unique_variable)) * " "
                print(
                    f"Setting value '{unique_variable}'{spacing} appeared in {repeats} variables: ",
                    end="",
                )
                items = [
                    i
                    for i in dir(src.common.statics)
                    if not i.startswith("__")
                    and getattr(src.common.statics, i) == unique_variable
                ]
                print(", ".join(items))

        self.assertEqual(len(list(set(variable_list))), len(variable_list))

    def test_group_id_length_is_not_same_as_onion_service_pub_key_length(self) -> None:
        """\
        In current implementation, `src.common.db_logs.remove_logs`
        determines the type of data to be removed from the length of
        provided `selector` parameter. If group ID length is set to same
        length as Onion Service public keys, the function is no longer
        able to distinguish what type of entries (contacts or group
        logs) should be removed from the database.
        """
        self.assertNotEqual(
            src.common.statics.ONION_SERVICE_PUBLIC_KEY_LENGTH,
            src.common.statics.GROUP_ID_LENGTH,
        )

    def test_reserved_accounts_are_valid(self) -> None:
        """\
        Each used account placeholder should be a valid, but reserved
        account.
        """
        reserved_accounts = [
            src.common.statics.LOCAL_ID,
            src.common.statics.DUMMY_CONTACT,
            src.common.statics.DUMMY_MEMBER,
        ]

        for account in reserved_accounts:
            self.assertEqual(
                validate_onion_addr(account), "Error: Can not add reserved account."
            )

        # Test each account is unique.
        self.assertEqual(len(reserved_accounts), len(set(reserved_accounts)))

    def test_local_pubkey(self) -> None:
        """Test that local key's reserved public key is valid."""
        self.assertEqual(
            src.common.statics.LOCAL_PUBKEY,
            onion_address_to_pub_key(src.common.statics.LOCAL_ID),
        )

    def test_group_management_header_length_matches_datagram_header_length(
        self,
    ) -> None:
        """
        As group management messages are handled as messages available
        to Relay Program, the header should be the same as any datagrams
        handled by the Relay program.
        """
        self.assertEqual(
            src.common.statics.GROUP_MGMT_HEADER_LENGTH,
            src.common.statics.DATAGRAM_HEADER_LENGTH,
        )

    def test_key_exchanges_start_with_different_letter(self) -> None:
        """
        Key exchange can be selected by entering just X to represent
        X448 or P to represent X448. This test detects if selection
        names would ever be set to something like PUBLIC and PSK
        that both start with P.
        """
        self.assertNotEqual(src.common.statics.ECDHE[:1], src.common.statics.PSK[:1])


if __name__ == "__main__":
    unittest.main(exit=False)
