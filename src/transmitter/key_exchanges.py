#!/usr/bin/env python3.6
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

import os
import time
import typing

from typing import Dict

from src.common.crypto       import argon2_kdf, blake2b, csprng, encrypt_and_sign, X448
from src.common.db_masterkey import MasterKey
from src.common.encoding     import bool_to_bytes, int_to_bytes, pub_key_to_short_address, str_to_bytes
from src.common.exceptions   import FunctionReturn
from src.common.input        import ask_confirmation_code, get_b58_key, nc_bypass_msg, yes
from src.common.output       import m_print, phase, print_fingerprint, print_key, print_on_previous_line
from src.common.path         import ask_path_gui
from src.common.statics      import *

from src.transmitter.packet import queue_command, queue_to_nc

if typing.TYPE_CHECKING:
    from multiprocessing         import Queue
    from src.common.db_contacts  import ContactList
    from src.common.db_onion     import OnionService
    from src.common.db_settings  import Settings
    from src.common.gateway      import Gateway
    from src.transmitter.windows import TxWindow
    QueueDict = Dict[bytes, Queue]


def export_onion_service_data(contact_list:  'ContactList',
                              settings:      'Settings',
                              onion_service: 'OnionService',
                              gateway:       'Gateway'
                              ) -> None:
    """\
    Send the Tor Onion Service's private key and list of Onion Service
    public keys of contacts to Relay Program on Networked Computer.

    This private key is not intended to be used by the Transmitter
    Program. Because the Networked Computer we are exporting it to
    might not store data, we use the trusted Source Computer to generate
    the private key and store it safely. The private key is needed by
    Tor on Networked Computer to start the Onion Service.

    Exporting this private key does not endanger message confidentiality
    because TFC uses a separate key exchange with separate private key
    to create the symmetric keys that protect the messages. That private
    key is never exported to the Networked Computer.

    Access to this key does not give any to user any information other
    than the v3 Onion Address. However, if they have compromised Relay
    Program to gain access to the key, they can see its public part
    anyway.

    This key is used by Tor to sign Diffie-Hellman public keys used when
    clients of contacts establish a secure connection to the Onion
    Service. This key can't be used to decrypt traffic retrospectively.

    The worst possible case in the situation of key compromise is, the
    key allows the attacker to start their own copy of the user's Onion
    Service.

    This does not allow impersonating as the user however, because the
    attacker is not in possession of keys that allow them to create
    valid ciphertexts. Even if they inject TFC public keys to conduct a
    MITM attack, that attack will be detected during fingerprint
    comparison.

    In addition to the private key, the Onion Service data packet also
    transmits the list of Onion Service public keys of existing and
    pending contacts to the Relay Program, as well as the setting that
    determines whether contact requests are allowed. Bundling all this
    data in a single packet is great in the sense a single confirmation
    code can be used to ensure that Relay Program has all the
    information necessary to perform its duties.
    """
    m_print("Onion Service setup", bold=True, head_clear=True, head=1, tail=1)

    pending_contacts  = b''.join(contact_list.get_list_of_pending_pub_keys())
    existing_contacts = b''.join(contact_list.get_list_of_existing_pub_keys())
    no_pending        = int_to_bytes(len(contact_list.get_list_of_pending_pub_keys()))
    contact_data      = no_pending + pending_contacts + existing_contacts

    relay_command = (UNENCRYPTED_DATAGRAM_HEADER
                     + UNENCRYPTED_ONION_SERVICE_DATA
                     + onion_service.onion_private_key
                     + onion_service.conf_code
                     + bool_to_bytes(settings.allow_contact_requests)
                     + contact_data)

    gateway.write(relay_command)

    while True:
        purp_code = ask_confirmation_code('Relay')

        if purp_code == onion_service.conf_code.hex():
            onion_service.is_delivered = True
            onion_service.new_confirmation_code()
            break

        elif purp_code == '':
            phase("Resending Onion Service data", head=2)
            gateway.write(relay_command)
            phase(DONE)
            print_on_previous_line(reps=5)

        else:
            m_print(["Incorrect confirmation code. If Relay Program did not",
                     "receive Onion Service data, resend it by pressing <Enter>."], head=1)
            print_on_previous_line(reps=5, delay=2)


def new_local_key(contact_list: 'ContactList',
                  settings:     'Settings',
                  queues:       'QueueDict'
                  ) -> None:
    """Run local key exchange protocol.

    Local key encrypts commands and data sent from Source Computer to
    user's Destination Computer. The key is delivered to Destination
    Computer in packet encrypted with an ephemeral, symmetric, key
    encryption key.

    The check-summed Base58 format key decryption key is typed to
    Receiver Program manually. This prevents local key leak in following
    scenarios:

        1. CT is intercepted by an adversary on compromised Networked
           Computer, but no visual eavesdropping takes place.

        2. CT is not intercepted by an adversary on Networked Computer,
           but visual eavesdropping records key decryption key.

        3. CT is delivered from Source Computer to Destination Computer
           directly (bypassing compromised Networked Computer), and
           visual eavesdropping records key decryption key.

    Once the correct key decryption key is entered to Receiver Program,
    it will display the 2-hexadecimal confirmation code generated by
    the Transmitter Program. The code will be entered back to
    Transmitter Program to confirm the user has successfully delivered
    the key decryption key.

    The protocol is completed with Transmitter Program sending
    LOCAL_KEY_RDY signal to the Receiver Program, that then moves to
    wait for public keys from contact.
    """
    try:
        if settings.traffic_masking and contact_list.has_local_contact():
            raise FunctionReturn("Error: Command is disabled during traffic masking.", head_clear=True)

        m_print("Local key setup", bold=True, head_clear=True, head=1, tail=1)

        if not contact_list.has_local_contact():
            time.sleep(0.5)

        key    = csprng()
        hek    = csprng()
        kek    = csprng()
        c_code = os.urandom(CONFIRM_CODE_LENGTH)

        local_key_packet = LOCAL_KEY_DATAGRAM_HEADER + encrypt_and_sign(plaintext=key + hek + c_code, key=kek)

        # Deliver local key to Destination computer
        nc_bypass_msg(NC_BYPASS_START, settings)
        queue_to_nc(local_key_packet, queues[RELAY_PACKET_QUEUE])
        while True:
            print_key("Local key decryption key (to Receiver)", kek, settings)
            purp_code = ask_confirmation_code('Receiver')
            if purp_code == c_code.hex():
                nc_bypass_msg(NC_BYPASS_STOP, settings)
                break
            elif purp_code == '':
                phase("Resending local key", head=2)
                queue_to_nc(local_key_packet, queues[RELAY_PACKET_QUEUE])
                phase(DONE)
                print_on_previous_line(reps=(9 if settings.local_testing_mode else 10))
            else:
                m_print(["Incorrect confirmation code. If Receiver did not receive",
                         "the encrypted local key, resend it by pressing <Enter>."], head=1)
                print_on_previous_line(reps=(9 if settings.local_testing_mode else 10), delay=2)

        # Add local contact to contact list database
        contact_list.add_contact(LOCAL_PUBKEY,
                                 LOCAL_NICK,
                                 bytes(FINGERPRINT_LENGTH),
                                 bytes(FINGERPRINT_LENGTH),
                                 KEX_STATUS_LOCAL_KEY,
                                 False, False, False)

        # Add local contact to keyset database
        queues[KEY_MANAGEMENT_QUEUE].put((KDB_ADD_ENTRY_HEADER,
                                          LOCAL_PUBKEY,
                                          key, csprng(),
                                          hek, csprng()))

        # Notify Receiver that confirmation code was successfully entered
        queue_command(LOCAL_KEY_RDY, settings, queues)

        m_print("Successfully completed the local key exchange.", bold=True, tail_clear=True, delay=1, head=1)
        os.system(RESET)

    except (EOFError, KeyboardInterrupt):
        raise FunctionReturn("Local key setup aborted.", tail_clear=True, delay=1, head=2)


def verify_fingerprints(tx_fp: bytes,  # User's fingerprint
                        rx_fp: bytes   # Contact's fingerprint
                        ) -> bool:     # True if fingerprints match, else False
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
    m_print("To verify received public key was not replaced by an attacker "
            "call the contact over an end-to-end encrypted line, preferably Signal "
            "(https://signal.org/). Make sure Signal's safety numbers have been "
            "verified, and then verbally compare the key fingerprints below.",
            head_clear=True, max_width=49, head=1, tail=1)

    print_fingerprint(tx_fp, "         Your fingerprint (you read)         ")
    print_fingerprint(rx_fp, "Purported fingerprint for contact (they read)")

    return yes("Is the contact's fingerprint correct?")


def start_key_exchange(onion_pub_key: bytes,          # Public key of contact's v3 Onion Service
                       nick:          str,            # Contact's nickname
                       contact_list:  'ContactList',  # Contact list object
                       settings:      'Settings',     # Settings object
                       queues:        'QueueDict'     # Dictionary of multiprocessing queues
                       ) -> None:
    """Start X448 key exchange with the recipient.

    This function first creates the X448 key pair. It then outputs the
    public key to Relay Program on Networked Computer, that passes the
    public key to contact's Relay Program. When Contact's public key
    reaches the user's Relay Program, the user will manually copy the
    key into their Transmitter Program.

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
    "Unverified". The fingerprints can later be verified with the
    `/verify` command: answering `yes` to the question on whether the
    fingerprints match, marks the X448 keys as "Verified".

    Variable naming:
        tx = user's key     rx = contact's key    fp = fingerprint
        mk = message key    hk = header key
    """
    if not contact_list.has_pub_key(onion_pub_key):
        contact_list.add_contact(onion_pub_key, nick,
                                 bytes(FINGERPRINT_LENGTH), bytes(FINGERPRINT_LENGTH),
                                 KEX_STATUS_PENDING,
                                 settings.log_messages_by_default,
                                 settings.accept_files_by_default,
                                 settings.show_notifications_by_default)
    contact = contact_list.get_contact_by_pub_key(onion_pub_key)

    # Generate new private key or load cached private key
    if contact.tfc_private_key is None:
        tfc_private_key_user = X448.generate_private_key()
    else:
        tfc_private_key_user = contact.tfc_private_key

    try:
        tfc_public_key_user = X448.derive_public_key(tfc_private_key_user)

        # Import public key of contact
        while True:
            public_key_packet = PUBLIC_KEY_DATAGRAM_HEADER + onion_pub_key + tfc_public_key_user
            queue_to_nc(public_key_packet, queues[RELAY_PACKET_QUEUE])

            tfc_public_key_contact = get_b58_key(B58_PUBLIC_KEY, settings, contact.short_address)
            if tfc_public_key_contact != b'':
                break

        # Validate public key of contact
        if len(tfc_public_key_contact) != TFC_PUBLIC_KEY_LENGTH:
            m_print(["Warning!",
                     "Received invalid size public key.",
                     "Aborting key exchange for your safety."], bold=True, tail=1)
            raise FunctionReturn("Error: Invalid public key length", output=False)

        if tfc_public_key_contact == bytes(TFC_PUBLIC_KEY_LENGTH):
            # The public key of contact is zero with negligible probability,
            # therefore we assume such key is malicious and attempts to set
            # the shared key to zero.
            m_print(["Warning!",
                     "Received a malicious zero-public key.",
                     "Aborting key exchange for your safety."], bold=True, tail=1)
            raise FunctionReturn("Error: Zero public key", output=False)

        # Derive shared key
        dh_shared_key = X448.shared_key(tfc_private_key_user, tfc_public_key_contact)

        # Domain separate unidirectional keys from shared key by using public
        # keys as message and the context variable as personalization string.
        tx_mk = blake2b(tfc_public_key_contact, dh_shared_key, person=b'message_key', digest_size=SYMMETRIC_KEY_LENGTH)
        rx_mk = blake2b(tfc_public_key_user,    dh_shared_key, person=b'message_key', digest_size=SYMMETRIC_KEY_LENGTH)
        tx_hk = blake2b(tfc_public_key_contact, dh_shared_key, person=b'header_key',  digest_size=SYMMETRIC_KEY_LENGTH)
        rx_hk = blake2b(tfc_public_key_user,    dh_shared_key, person=b'header_key',  digest_size=SYMMETRIC_KEY_LENGTH)

        # Domain separate fingerprints of public keys by using the
        # shared secret as key and the context variable as
        # personalization string. This way entities who might monitor
        # fingerprint verification channel are unable to correlate
        # spoken values with public keys that they might see on RAM or
        # screen of Networked Computer: Public keys can not be derived
        # from the fingerprints due to preimage resistance of BLAKE2b,
        # and fingerprints can not be derived from public key without
        # the X448 shared secret. Using the context variable ensures
        # fingerprints are distinct from derived message and header keys.
        tx_fp = blake2b(tfc_public_key_user,    dh_shared_key, person=b'fingerprint', digest_size=FINGERPRINT_LENGTH)
        rx_fp = blake2b(tfc_public_key_contact, dh_shared_key, person=b'fingerprint', digest_size=FINGERPRINT_LENGTH)

        # Verify fingerprints
        try:
            if not verify_fingerprints(tx_fp, rx_fp):
                m_print(["Warning!",
                         "Possible man-in-the-middle attack detected.",
                         "Aborting key exchange for your safety."], bold=True, tail=1)
                raise FunctionReturn("Error: Fingerprint mismatch", delay=2.5, output=False)
            kex_status = KEX_STATUS_VERIFIED

        except (EOFError, KeyboardInterrupt):
            m_print(["Skipping fingerprint verification.",
                     '', "Warning!",
                     "Man-in-the-middle attacks can not be detected",
                     "unless fingerprints are verified! To re-verify",
                     "the contact, use the command '/verify'.",
                     '', "Press <enter> to continue."],
                    manual_proceed=True, box=True, head=2)
            kex_status = KEX_STATUS_UNVERIFIED

        # Send keys to the Receiver Program
        c_code  = blake2b(onion_pub_key, digest_size=CONFIRM_CODE_LENGTH)
        command = (KEY_EX_ECDHE
                   + onion_pub_key
                   + tx_mk + rx_mk
                   + tx_hk + rx_hk
                   + str_to_bytes(nick))

        queue_command(command, settings, queues)

        while True:
            purp_code = ask_confirmation_code('Receiver')
            if purp_code == c_code.hex():
                break

            elif purp_code == '':
                phase("Resending contact data", head=2)
                queue_command(command, settings, queues)
                phase(DONE)
                print_on_previous_line(reps=5)

            else:
                m_print("Incorrect confirmation code.", head=1)
                print_on_previous_line(reps=4, delay=2)

        # Store contact data into databases
        contact.tfc_private_key = None
        contact.tx_fingerprint  = tx_fp
        contact.rx_fingerprint  = rx_fp
        contact.kex_status      = kex_status
        contact_list.store_contacts()

        queues[KEY_MANAGEMENT_QUEUE].put((KDB_ADD_ENTRY_HEADER,
                                          onion_pub_key,
                                          tx_mk, csprng(),
                                          tx_hk, csprng()))

        m_print(f"Successfully added {nick}.", bold=True, tail_clear=True, delay=1, head=1)

    except (EOFError, KeyboardInterrupt):
        contact.tfc_private_key = tfc_private_key_user
        raise FunctionReturn("Key exchange interrupted.", tail_clear=True, delay=1, head=2)


def create_pre_shared_key(onion_pub_key: bytes,           # Public key of contact's v3 Onion Service
                          nick:          str,             # Nick of contact
                          contact_list:  'ContactList',   # Contact list object
                          settings:      'Settings',      # Settings object
                          onion_service: 'OnionService',  # OnionService object
                          queues:        'QueueDict'      # Dictionary of multiprocessing queues
                          ) -> None:
    """Generate a new pre-shared key for manual key delivery.

    Pre-shared keys offer a low-tech solution against the slowly
    emerging threat of quantum computers. PSKs are less convenient and
    not usable in every scenario, but until a quantum-safe key exchange
    algorithm with reasonably short keys is standardized, TFC can't
    provide a better alternative against quantum computers.

    The generated keys are protected by a key encryption key, derived
    from a 256-bit salt and a password (that is to be shared with the
    recipient) using Argon2d key derivation function.

    The encrypted message and header keys are stored together with salt
    on a removable media. This media must be a never-before-used device
    from sealed packaging. Re-using an old device might infect Source
    Computer, and the malware could either copy sensitive data on that
    removable media, or Source Computer might start transmitting the
    sensitive data covertly over the serial interface to malware on
    Networked Computer.

    Once the key has been exported to the clean drive, contact data and
    keys are exported to the Receiver Program on Destination computer.
    The transmission is encrypted with the local key.
    """
    try:
        tx_mk = csprng()
        tx_hk = csprng()
        salt  = csprng()

        password = MasterKey.new_password("password for PSK")

        phase("Deriving key encryption key", head=2)
        kek = argon2_kdf(password, salt, rounds=ARGON2_ROUNDS, memory=ARGON2_MIN_MEMORY)
        phase(DONE)

        ct_tag = encrypt_and_sign(tx_mk + tx_hk, key=kek)

        while True:
            trunc_addr = pub_key_to_short_address(onion_pub_key)
            store_d    = ask_path_gui(f"Select removable media for {nick}", settings)
            f_name     = f"{store_d}/{onion_service.user_short_address}.psk - Give to {trunc_addr}"
            try:
                with open(f_name, 'wb+') as f:
                    f.write(salt + ct_tag)
                break
            except PermissionError:
                m_print("Error: Did not have permission to write to the directory.", delay=0.5)
                continue

        command = (KEY_EX_PSK_TX
                   + onion_pub_key
                   + tx_mk + csprng()
                   + tx_hk + csprng()
                   + str_to_bytes(nick))

        queue_command(command, settings, queues)

        contact_list.add_contact(onion_pub_key, nick,
                                 bytes(FINGERPRINT_LENGTH), bytes(FINGERPRINT_LENGTH),
                                 KEX_STATUS_NO_RX_PSK,
                                 settings.log_messages_by_default,
                                 settings.accept_files_by_default,
                                 settings.show_notifications_by_default)

        queues[KEY_MANAGEMENT_QUEUE].put((KDB_ADD_ENTRY_HEADER,
                                          onion_pub_key,
                                          tx_mk, csprng(),
                                          tx_hk, csprng()))

        m_print(f"Successfully added {nick}.", bold=True, tail_clear=True, delay=1, head=1)

    except (EOFError, KeyboardInterrupt):
        raise FunctionReturn("PSK generation aborted.", tail_clear=True, delay=1, head=2)


def rxp_load_psk(window:       'TxWindow',
                 contact_list: 'ContactList',
                 settings:     'Settings',
                 queues:       'QueueDict',
                 ) -> None:
    """Send command to Receiver Program to load PSK for active contact."""
    if settings.traffic_masking:
        raise FunctionReturn("Error: Command is disabled during traffic masking.", head_clear=True)

    if window.type == WIN_TYPE_GROUP or window.contact is None:
        raise FunctionReturn("Error: Group is selected.", head_clear=True)

    if not contact_list.get_contact_by_pub_key(window.uid).uses_psk():
        raise FunctionReturn(f"Error: The current key was exchanged with {ECDHE}.", head_clear=True)

    c_code  = blake2b(window.uid, digest_size=CONFIRM_CODE_LENGTH)
    command = KEY_EX_PSK_RX + c_code + window.uid
    queue_command(command, settings, queues)

    while True:
        try:
            purp_code = ask_confirmation_code('Receiver')
            if purp_code == c_code.hex():
                window.contact.kex_status = KEX_STATUS_HAS_RX_PSK
                contact_list.store_contacts()
                raise FunctionReturn(f"Removed PSK reminder for {window.name}.", tail_clear=True, delay=1)
            else:
                m_print("Incorrect confirmation code.", head=1)
                print_on_previous_line(reps=4, delay=2)
        except (EOFError, KeyboardInterrupt):
            raise FunctionReturn("PSK verification aborted.", tail_clear=True, delay=1, head=2)
