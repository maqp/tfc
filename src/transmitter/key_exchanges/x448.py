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

from cryptography.hazmat.primitives.asymmetric.x448 import X448PublicKey

from src.common.exceptions import SoftError
from src.common.crypto.algorithms.blake2b import blake2b
from src.common.crypto.algorithms.x448 import X448
from src.common.crypto.fingerprint import FingerprintUser, FingerprintContact
from src.common.crypto.keys.x448_keys import X448PrivKey, X448PubKey
from src.common.crypto.keys.symmetric_key import MessageKeyContact, HeaderKeyContact
from src.common.statics import CryptoVarLength, KexStatus, RxCommand, KeyDBMgmt, B58KeyType
from src.ui.common.input.get_yes import get_yes
from src.ui.common.input.get_b58_key import get_b58_key
from src.common.utils.strings import split_to_substrings
from src.database.db_local_key import LocalKeyDB
from src.datagrams.receiver.public_key import DatagramPublicKey
from src.datagrams.relay.diff_comparison.diff_comparison_public_key import DatagramRelayDiffComparisonPublicKey
from src.transmitter.key_exchanges.deliver_contact_data import deliver_contact_data
from src.ui.common.output.print_message import print_message
from src.ui.common.output.print_fingerprint import print_fingerprint

if TYPE_CHECKING:
    from src.common.entities.contact import Contact
    from src.common.entities.nick_name import Nick
    from src.common.crypto.keys.onion_service_keys import OnionPublicKeyContact
    from src.common.queues import TxQueue
    from src.common.crypto.keys.kek_hash import KEKHash
    from src.database.db_contacts import ContactList
    from src.database.db_masterkey import MasterKey
    from src.database.db_settings import Settings


def start_key_exchange(pub_key_contact : 'OnionPublicKeyContact',
                       nick            : 'Nick',
                       contact_list    : 'ContactList',
                       settings        : 'Settings',
                       local_key_db    : LocalKeyDB,
                       master_key      : 'MasterKey',
                       queues          : 'TxQueue'
                       ) -> None:
    """Start X448 key exchange with the recipient.

    This function first creates the X448 key pair. It then outputs the
    public key to Relay Program on Networked Computer, that passes the
    public key to contact's Relay Program where it is displayed. When
    the contact's public key reaches the user's Relay Program, the user
    will manually type the key into their Transmitter Program.

    The X448 shared secret is used to create unidirectional message and
    header keys, that will be used in forward secret communication. This
    is followed by the fingerprint verification where the user manually
    authenticates the public key.

    Once the fingerprint has been accepted, this function will add the
    contact/key data to contact/key databases, and export that data to
    the Receiver Program on Destination Computer. The transmission is
    encrypted with the local key.

    ---

    TFC provides proactive security by making fingerprint verification
    part of the key exchange. This prevents the situation where the
    users don't know about the feature, and thus helps minimize the risk
    of MITM attack.

    The fingerprints can be skipped by pressing Ctrl+C. This feature is
    not advertised however, because verifying fingerprints the only
    strong way to be sure TFC is not under MITM attack. When
    verification is skipped, TFC marks the contact's X448 keys as
    'Unverified'. The fingerprints can later be verified with the
    `/verify` command: answering `yes` to the question on whether the
    fingerprints match, marks the X448 keys as 'Verified'.

    Variable naming:
        tx = user's key     rx = contact's key
        hk = header key     mk = message key
        fp = fingerprint
    """
    if not contact_list.has_onion_pub_key(pub_key_contact):
        contact_list.add_contact(pub_key_contact, nick,
                                 FingerprintUser   (bytes(CryptoVarLength.FINGERPRINT)),
                                 FingerprintContact(bytes(CryptoVarLength.FINGERPRINT)),
                                 KexStatus.KEX_STATUS_PENDING,
                                 settings.log_messages_by_default,
                                 settings.accept_files_by_default,
                                 settings.show_notifications_by_default)

    contact = contact_list.get_contact_by_pub_key(pub_key_contact)

    LocalKeyDB(master_key, settings)

    # Generate new private key or load cached private key
    x448_private_key_user = contact.cached_x448_private_key
    if x448_private_key_user is None:
        x448_private_key_user = X448PrivKey(X448.generate_private_key())

    try:
        tfc_public_key_user    = x448_private_key_user.x448_pub_key
        tfc_public_key_contact = exchange_public_keys(pub_key_contact,
                                                      tfc_public_key_user,
                                                      local_key_db.kek_hash,
                                                      contact,
                                                      settings,
                                                      queues)

        validate_contact_public_key(tfc_public_key_contact)

        dh_shared_key = X448.shared_key(x448_private_key_user.x448_private_key,
                                        tfc_public_key_contact.x448_public_key)

        tx_hk, tx_mk, rx_hk, rx_mk, tx_fp, rx_fp = X448.derive_subkeys(dh_shared_key,
                                                                       tfc_public_key_user.x448_public_key,
                                                                       tfc_public_key_contact.x448_public_key)

        kex_status = validate_contact_fingerprint(tx_fp, rx_fp)

        deliver_contact_data(RxCommand.KEY_EX_ECDHE,
                             nick, pub_key_contact,
                             tx_hk, tx_mk,
                             rx_hk, rx_mk,
                             queues, settings)

        # Store contact data into databases
        contact.cached_x448_private_key = None
        contact.tx_fingerprint          = tx_fp
        contact.rx_fingerprint          = rx_fp
        contact.kex_status              = kex_status
        contact_list.store_contacts()

        rx_mk = MessageKeyContact()
        rx_hk = HeaderKeyContact()

        queues.key_store_mgmt.put((KeyDBMgmt.INSERT_ROW,
                                   pub_key_contact,
                                   tx_hk, tx_mk,
                                   rx_hk, rx_mk ))

        print_message(f'Successfully added {nick}.', bold=True, clear_after=True, clear_delay=1, padding_top=1)

    except (EOFError, KeyboardInterrupt):
        contact.cached_x448_private_key = x448_private_key_user
        raise SoftError('Key exchange interrupted.', clear_after=True, clear_delay=1, padding_top=2)


def exchange_public_keys(onion_pub_key_contact : 'OnionPublicKeyContact',
                         x448_public_key_user  : X448PubKey,
                         kek_hash              : 'KEKHash',
                         contact               : 'Contact',
                         settings              : 'Settings',
                         queues                : 'TxQueue',
                         ) -> X448PubKey:
    """Exchange public keys with contact.

    This function outputs the user's public key and waits for user to
    enter the public key of the contact. If the User presses <Enter>,
    the function will resend the users' public key to contact.
    """
    public_key_datagram = DatagramPublicKey(onion_pub_key_contact, x448_public_key_user)

    queues.relay_packet.put( public_key_datagram )

    while True:
        try:
            tfc_public_key_contact_bytes = get_b58_key(B58KeyType.B58_PUBLIC_KEY.value, settings, contact.short_address)
        except ValueError as invalid_pub_key:
            invalid_key = str(invalid_pub_key).encode()

            # Do not send packet to Relay Program if the user has for some reason
            # managed to embed the local key decryption key inside the public key.
            substrings  = split_to_substrings(invalid_key, CryptoVarLength.ENCODED_B58_KEK.value)
            safe_string = not any(blake2b(substring) == kek_hash.kek_bytes for substring in substrings)

            if safe_string:
                queues.relay_packet.put( DatagramRelayDiffComparisonPublicKey(onion_pub_key_contact, invalid_key) )
            continue

        if tfc_public_key_contact_bytes == b'':
            queues.relay_packet.put( public_key_datagram )
            continue

        return X448PubKey(X448PublicKey.from_public_bytes(tfc_public_key_contact_bytes))

    raise RuntimeError('Broke out of loop')


def validate_contact_public_key(x448_public_key_contact: X448PubKey) -> None:
    """This function validates the public key from contact.

    The validation takes into account key state, and it will detect if
    the public key is zero, but it can't predict whether the shared key
    will be zero. Further validation of the public key is done by the
    `src.common.crypto` module.
    """
    public_key_bytes = x448_public_key_contact.x448_public_key.public_bytes_raw()

    if len(public_key_bytes) != CryptoVarLength.X448_PUBLIC_KEY:
        print_message(['Warning!',
                 'Received invalid size public key.',
                 'Aborting key exchange for your safety.'],
                      bold=True, padding_bottom=1)
        raise SoftError('Error: Invalid public key length', output=False)

    if public_key_bytes == bytes(CryptoVarLength.X448_PUBLIC_KEY):
        # The public key of contact is zero with negligible probability,
        # therefore we assume such key is malicious and attempts to set
        # the shared key to zero.
        print_message(['Warning!',
                 'Received a malicious zero-public key.',
                 'Aborting key exchange for your safety.'],
                      bold=True, padding_bottom=1)
        raise SoftError('Error: Zero public key', output=False)


def validate_contact_fingerprint(tx_fp: FingerprintUser,
                                 rx_fp: FingerprintContact
                                 ) -> KexStatus:
    """Validate or skip validation of contact fingerprint.

    This function prompts the user to verify the fingerprint of the contact.
    If the user issues Ctrl+{C,D} command, this function will set the key
    exchange status as unverified.
    """
    try:
        if not verify_fingerprints(tx_fp, rx_fp):
            print_message(['Warning!',
                     'Possible man-in-the-middle attack detected.',
                     'Aborting key exchange for your safety.'], bold=True, padding_bottom=1)
            raise SoftError('Error: Fingerprint mismatch', clear_delay=2.5, output=False)
        kex_status = KexStatus.KEX_STATUS_VERIFIED

    except (EOFError, KeyboardInterrupt):
        print_message(['Skipping fingerprint verification.',
                 '', 'Warning!',
                 'Man-in-the-middle attacks can not be detected',
                 'unless fingerprints are verified! To re-verify',
                 "the contact, use the command '/verify'.",
                 '', 'Press <enter> to continue.'],
                      manual_proceed=True, box=True, padding_top=2, padding_bottom=1)
        kex_status = KexStatus.KEX_STATUS_UNVERIFIED

    return kex_status


def verify_fingerprints(tx_fp : FingerprintUser,
                        rx_fp : FingerprintContact
                        ) -> bool:
    """\
    Verify fingerprints over an authenticated out-of-band channel to
    detect MITM attacks against TFC's key exchange.

    MITM or man-in-the-middle attack is an attack against an inherent
    problem in cryptography:

    Cryptography is math, nothing more. During key exchange public keys
    are just very large numbers. There is no way to tell by looking if a
    number (received from an untrusted network / Networked Computer) is
    the same number the contact generated.

    Public key fingerprints are values designed to be compared by humans
    either visually or audibly (or sometimes by using semi-automatic
    means such as QR-codes). By comparing the fingerprint over an
    authenticated channel it's possible to verify that the correct key
    was received from the network.
    """
    print_message('To verify received public key was not replaced by an attacker, '
            'call the contact over an end-to-end encrypted line, preferably Signal '
            "(https://signal.org/). Make sure Signal's safety numbers have been "
            'verified, and then verbally compare the key fingerprints below.',
                  clear_before=True, max_width=49, padding_top=1, padding_bottom=1)

    print_fingerprint(tx_fp, '         Your fingerprint (you read)         ')
    print_fingerprint(rx_fp, 'Purported fingerprint for contact (they read)')

    return get_yes("Is the contact's fingerprint correct?")
