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
import binascii
import hashlib

from typing import Any, Optional as O, TYPE_CHECKING

from src.common.exceptions import ValidationError, CheckInputError, SoftError
from src.common.statics import (CryptoVarLength, DummyID, KexType, SpecialHandle, OnionLiterals, FieldLength, OnionAddress)
from src.common.types_custom import StrOnionAddressContact, StrOnionAddressUser
from src.common.utils.strings import separate_headers

if TYPE_CHECKING:
    from src.ui.transmitter.user_input import UserInput
    from src.database.db_contacts import ContactList
    from src.database.db_groups import GroupList
    from src.common.crypto.keys.onion_service_keys import OnionPublicKeyContact


def validate_second_field(user_input: 'UserInput|str', key: str) -> str:
    """Validate the second field of user input.

    This is generally the main parameter for commands after command. E.g.:

    /nick Alice
          -----
    """
    from src.ui.transmitter.user_input import UserInput

    string_input = user_input.plaintext if isinstance(user_input, UserInput) else user_input

    try:
        first_field = string_input.split()[1]
    except IndexError:
        raise SoftError(f'Error: No {key} specified.', clear_before=True)
    return first_field


def validate_type(key            : str,
                  purported_type : Any,
                  expected_type  : type
                  ) -> None:
    """Validate the type of value."""
    if not isinstance(purported_type, expected_type):
        raise ValidationError(f"Expected {expected_type}, "
                              f"but type of '{key}' was {type(purported_type)}")


def validate_bytes(value         : bytes,
                   *,
                   empty_allowed : bool   = False,
                   key           : O[str] = None,
                   min_length    : O[int] = None,
                   max_length    : O[int] = None,
                   is_length     : O[int] = None,
                   len_is_mul_of : O[int] = None,
                   not_all_zeros : bool   = False,
                   ) -> None:
    """Validate a value is a string."""
    if key is not None:
        validate_type('key', key, str)
    validate_type(key if key is not None else 'value', value, bytes)

    specifier = f"'{key}' " if key is not None else ''

    if min_length is not None and len(value) < min_length:
        raise ValidationError(f'Expected bytestring {specifier}to contain at least {min_length} bytes but received {len(value)} bytes.')
    if max_length is not None and len(value) > max_length:
        raise ValidationError(f'Expected bytestring {specifier}to contain at most {max_length} bytes but received {len(value)} bytes.')
    if is_length is not None and len(value) != is_length:
        raise ValidationError(f'Expected bytestring {specifier}to contain exactly {is_length} bytes but received {len(value)} bytes.')
    if not empty_allowed and value == b'':
        raise ValidationError(f'Expected bytestring {specifier}to contain bytes but it was empty.')
    if not_all_zeros and all(byte == 0 for byte in value):
        raise ValidationError(f'Expected bytestring {specifier}to not be all zeroes but it was.')
    if len_is_mul_of is not None and (remainder := len(value) % len_is_mul_of) != 0:
        raise ValidationError(f'Expected bytestring {specifier}to be multiple of {len_is_mul_of} but remainder was {remainder}.')


def validate_int(value            : int,
                 key              : O[str] = None,
                 negative_allowed : bool   = False,
                 min_value        : O[int] = None,
                 max_value        : O[int] = None,
                 ) -> None:
    """Validate a value is an integer."""
    if key is not None:
        validate_type('key', key, str)

    specifier = f"for '{key}'" if key is not None else ''

    validate_type(key if key is not None else 'value', value, int)

    if not negative_allowed and value < 0:
        raise ValidationError(f"Expected a positive value {specifier}, but value was '{value}'")
    if min_value is not None and value < min_value:
        raise ValidationError(f'Expected the value {specifier} to be at least {min_value} but was {value}.')
    if max_value is not None and value > max_value:
        raise ValidationError(f'Expected the value {specifier} to be at most {max_value} but was {value}.')


def validate_onion_addr(onion_address_contact : str,
                        onion_address_user    : 'str | O[StrOnionAddressUser]' = None
                        ) -> None:
    """Validate a v3 Onion Service address."""
    onion_address_contact = str(onion_address_contact)

    if len(onion_address_contact) != FieldLength.ONION_ADDRESS:
        raise ValidationError('Error: Invalid account length.')

    # Together with length check this should make accidental export local key decryption keys hard enough.
    if any(c.isupper() for c in onion_address_contact):
        raise ValidationError('Error: Account must be in lower case.')

    invalid_chars = set([c for c in onion_address_contact if c not in OnionAddress.CHARSET])
    if invalid_chars:
        raise ValidationError(f"Error: Invalid characters {', '.join(invalid_chars)} in account.")

    try:
        decoded = base64.b32decode(onion_address_contact.upper())

        public_key, checksum, version \
            = separate_headers(decoded, [CryptoVarLength.ONION_SERVICE_PUBLIC_KEY.value,
                                         FieldLength.ONION_ADDRESS_CHECKSUM.value])

        if checksum != hashlib.sha3_256(OnionLiterals.ONION_ADDRESS_CHECKSUM_ID.value
                                        + public_key
                                        + version
                                        ).digest()[:FieldLength.ONION_ADDRESS_CHECKSUM.value]:

            # CheckInputError is used to detect inputs that are checked on Relay Program side.
            raise CheckInputError('Checksum error - Check that the entered account is correct.')

    except (binascii.Error, ValueError):
        raise CheckInputError('Error: Invalid account format.')

    if onion_address_contact in (DummyID.DUMMY_CONTACT, DummyID.DUMMY_MEMBER):
        raise ValidationError('Error: Can not add reserved account.')

    if onion_address_user is not None and onion_address_contact == onion_address_user:
        raise ValidationError('Error: Can not add own account.')

    return None


def validate_group_name(group_name_str : str,
                        contact_list   : 'ContactList',
                        group_list     : 'GroupList'
                        ) -> None:
    """Validate the specified group name."""
    from src.common.crypto.keys.onion_service_keys import OnionPublicKeyContact

    # Avoids collision with delimiters
    if not group_name_str.isprintable():
        raise ValidationError('Error: Group name must be printable.')

    # Length is limited by database's Unicode padding
    if len(group_name_str) >= CryptoVarLength.PADDING.value:
        raise ValidationError(f'Error: Group name must be less than {CryptoVarLength.PADDING} chars long.')

    if group_name_str == DummyID.DUMMY_GROUP:
        raise ValidationError('Error: Group name cannot use the name reserved for database padding.')

    try:
        OnionPublicKeyContact.from_onion_address(group_name_str)
    except (CheckInputError, ValidationError):
        pass
    else:
        raise ValidationError('Error: Group name cannot have the format of an account.')

    if group_name_str in [nick.value for nick in contact_list.get_list_of_nicks()]:
        raise ValidationError('Error: Group name cannot be a nick of contact.')

    if group_name_str in group_list.get_list_of_group_names():
        raise ValidationError(f"Error: Group with name '{group_name_str}' already exists.")


def validate_key_exchange(key_ex : str,  # Key exchange selection to validate
                          *_     : Any   # Unused arguments
                          ) -> None:
    """Validate the specified key exchange."""
    if key_ex.upper() not in [KexType.ECDHE, KexType.ECDHE.value[:1],
                              KexType.PSK,   KexType.PSK  .value[:1]]:
        raise ValidationError('Invalid key exchange selection.')

    return None


def validate_nick(nick          : str,
                  contact_list  : 'ContactList',
                  group_list    : 'GroupList',
                  onion_pub_key : 'OnionPublicKeyContact'
                  ) -> None:
    """Validate the specified nickname."""

    # Length is limited by database's Unicode padding
    if len(nick) >= CryptoVarLength.PADDING.value:
        raise ValidationError(f'Error: Nick must be shorter than {CryptoVarLength.PADDING.value} chars.')

    # Avoid delimiter char collision in output packets
    if not nick.isprintable():
        raise ValidationError('Error: Nick must be printable.')

    if nick == '':
        raise ValidationError('Error: Nick cannot be empty.')

    # Receiver displays sent messages under 'Me'
    if nick.lower() == SpecialHandle.USER.value.lower():
        raise ValidationError(f"Error: '{SpecialHandle.USER.value}' is a reserved nick.")

    # Receiver displays system notifications under reserved notification symbol
    if nick == SpecialHandle.SYSTEM_MESSAGE.value:
        raise ValidationError(f"Error: '{SpecialHandle.SYSTEM_MESSAGE.value}' is a reserved nick.")

    # Ensure that nicks, accounts and group names are UIDs in recipient selection
    try:
        validate_onion_addr(StrOnionAddressContact(nick))
    except (CheckInputError, ValidationError):
        pass
    else:
        raise ValidationError('Error: Nick cannot have the format of an account.')

    if nick in (DummyID.DUMMY_CONTACT, DummyID.DUMMY_MEMBER.value):
        raise ValidationError('Error: Nick cannot have the format of an account.')

    if nick in [nick.value for nick in contact_list.get_list_of_nicks(exclude_onion_pub_key=onion_pub_key)]:
        raise ValidationError('Error: Nick already in use.')

    if nick in group_list.get_list_of_group_names():
        raise ValidationError('Error: Nick cannot be a group name.')
