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

from typing import Any, Optional as O, TYPE_CHECKING

from src.common.crypto.keys.x448_keys import X448PrivKey
from src.common.statics import KexStatus
from src.common.utils.encoding import bool_to_bytes, str_to_padded_bytes
from src.common.utils.validators import validate_bytes

if TYPE_CHECKING:
    from src.common.entities.nick_name import Nick
    from src.common.crypto.keys.onion_service_keys import OnionPublicKeyContact
    from src.common.crypto.fingerprint import FingerprintUser, FingerprintContact
    from src.common.types_custom import BoolFileReception, BoolLogMessages, BoolShowNotifications


class Contact:
    """\
    Contact object contains contact data not related to key management
    and hash ratchet state:

      onion_pub_key: The public key of the contact's v3 Tor
                     Onion Service. The Relay Program on user's Networked
                     Computer uses this public key to anonymously
                     discover the Onion Service and to authenticate the
                     end-to-end encryption used between Relay Computers.
                     Since Relay Program might run on an amnesic distro
                     like Tails, the Transmitter and Receiver Programs
                     handle long-term storage of the contact's Onion
                     Service public key.

               nick: As per Zooko's triangle and Stiegler's Petname
                     Systems, .onion names (i.e., TFC accounts) cannot
                     be global, secure and memorable at the same time*.
                     To deal with hard to remember accounts, in TFC
                     contacts (and groups) are managed mostly with
                     nicknames assigned by the user. The nickname must
                     be unique among both contacts and groups so that
                     single command `/msg <selection>` can select a
                     specific contact or group. Some nicknames are
                     reserved so that messages from contacts cannot be
                     confused with system messages of Receiver Program.
                     Nicknames also have a length limit of 254 chars.

    * https://gitlab.torproject.org/legacy/trac/-/wikis/doc/HiddenServiceNames#why-are-onion-names-created-that-way

    TFC stores the 32-byte public key fingerprints of the ECDHE key
    exchange into the contact database. These values allow the user to
    verify at any time no MITM attack took place during the key
    exchange. When PSKs are used, a null-byte string is used as a
    placeholder value.

     tx_fingerprint: The user's fingerprint. This fingerprint is derived
                     from the user's public key which means it's
                     automatically authentic. During verification over
                     an authenticated channel, the user reads this value
                     to the contact out loud.

     rx_fingerprint: The purported fingerprint for the contact. This
                     fingerprint depends on the public key received from
                     the insecure network and therefore, it shouldn't be
                     trusted implicitly. During verification over an
                     authenticated channel, the contact reads their
                     `tx_fingerprint` to the user out loud, and the user
                     then compares it to this purported value.

         kex_status: This byte remembers the key exchange status of the
                     contact.

    TFC stores the contact-specific settings to the contact database:

       log_messages: This setting defines whether the Receiver Program
                     on Destination Computer writes the assembly packets
                     of a successfully received message into a log file.
                     When logging is enabled, Transmitter Program will
                     also log assembly packets of sent messages to its
                     log file.

     file_reception: This setting defines whether the Receiver Program
                     accepts files sent by the contact. The setting has
                     no effect on user's Transmitter Program.

      notifications: This setting defines whether, in situations where
                     some other window is active, the Receiver Program
                     displays a notification about the contact sending
                     a new message to their window. The setting has no
                     effect on user's Transmitter Program.

    tfc_private_key: This value is an ephemerally stored private key
                     for situations where the user interrupts the key
                     exchange. The purpose of the value is to prevent
                     the user from generating different ECDHE values
                     when re-selecting the contact to continue the key
                     exchange. Note that once a shared key is derived
                     from this private key (and contact's public key),
                     it is discarded. New private key will thus be
                     generated if the users decide to exchange new keys
                     with each other.
    """

    def __init__(self,
                 onion_pub_key  : 'OnionPublicKeyContact',
                 nick           : 'Nick',
                 tx_fingerprint : 'FingerprintUser',
                 rx_fingerprint : 'FingerprintContact',
                 kex_status     : KexStatus,
                 log_messages   : 'BoolLogMessages',
                 file_reception : 'BoolFileReception',
                 notifications  : 'BoolShowNotifications'
                 ) -> None:
        """Create a new Contact object.

        `self.short_address` is the truncated version of the Onion
        address used to identify the contact in printed messages.
        """
        self.__onion_pub_key = onion_pub_key
        self.nick            = nick
        self.tx_fingerprint  = tx_fingerprint
        self.rx_fingerprint  = rx_fingerprint
        self.kex_status      = kex_status
        self.log_messages    = log_messages
        self.file_reception  = file_reception
        self.notifications   = notifications
        self.__cached_x448_private_key = None  # type: O[X448PrivKey]

    def __eq__(self, other: Any) -> bool:
        """Return True if two contact objects are equal."""
        if not isinstance(other, Contact):
            return False
        return self.onion_pub_key == other.onion_pub_key

    @property
    def onion_address(self) -> str:
        """Return the onion address of the contact."""
        return self.__onion_pub_key.onion_address

    @property
    def short_address(self) -> str:
        """Return the short address of the contact."""
        return self.__onion_pub_key.short_address

    @property
    def onion_pub_key(self) -> 'OnionPublicKeyContact':
        """Return onion public key."""
        return self.__onion_pub_key

    @property
    def cached_x448_private_key(self) -> O['X448PrivKey']:
        """Return the cached x448 private key, if one exists."""
        return self.__cached_x448_private_key

    @cached_x448_private_key.setter
    def cached_x448_private_key(self, private_key: O['X448PrivKey']) -> None:
        """Cache or clear the x448 private key."""
        self.__cached_x448_private_key = private_key

    def serialize(self) -> bytes:
        """Return contact data as a constant length byte string.

        This function serializes the contact's data into a byte string
        that has the exact length of
              56         The v3 Onion Service address, encoded with UTF-8
            + 2*32       The two 32-byte fingerprints
            + 1          The key exchange status
            + 3*1        The three per-contact settings
            + 1024       The PKCS #7 padded, UTF-32 encoded nickname
            = 1148 bytes

        The length is guaranteed regardless of nickname.

        The purpose of the constant length serialization is to hide any
        metadata about the contact the ciphertext length of the contact
        database would reveal.
        """
        serialized = (self.__onion_pub_key.serialize()
                      + self.tx_fingerprint.to_bytes()
                      + self.rx_fingerprint.to_bytes()
                      + self.kex_status
                      + bool_to_bytes(self.log_messages)
                      + bool_to_bytes(self.file_reception)
                      + bool_to_bytes(self.notifications)
                      + str_to_padded_bytes(str(self.nick)))

        validate_bytes(serialized, is_length=1148)
        return serialized

    def uses_psk(self) -> bool:
        """\
        Return True if the user and the contact are using pre-shared
        keys (PSKs), else False.

        When the user sets up pre-shared keys with the contact, the key
        exchange status can only have two specific values (that remember
        whether the PSK of the contact has been imported). That fact can
        be used to determine whether the keys with contact were
        pre-shared.
        """
        return self.kex_status in [KexStatus.KEX_STATUS_NO_RX_PSK, KexStatus.KEX_STATUS_HAS_RX_PSK]

    @property
    def can_be_group_member(self) -> bool:
        """Return True when the contact's key-exchange status allows group membership."""
        return self.kex_status in [KexStatus.KEX_STATUS_UNVERIFIED,
                                   KexStatus.KEX_STATUS_VERIFIED,
                                   KexStatus.KEX_STATUS_HAS_RX_PSK]
