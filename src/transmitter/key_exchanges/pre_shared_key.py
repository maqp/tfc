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

import os

from typing import TYPE_CHECKING

from src.common.crypto.algorithms.argon2 import argon2_kdf
from src.common.crypto.argon2_salt import Argon2Salt
from src.common.crypto.fingerprint import FingerprintUser, FingerprintContact
from src.common.crypto.keys.symmetric_key import (MessageKeyUser, HeaderKeyContact, HeaderKeyUser, MessageKeyContact,
                                                  PSKEncryptionKey)
from src.common.crypto.pt_ct import PSKPT
from src.common.entities.serialized_command import SerializedCommand
from src.common.exceptions import SoftError, raise_if_traffic_masking
from src.common.statics import Argon2Literals, RxCommand, KexStatus, KeyDBMgmt, WindowType, KexType
from src.common.types_custom import IntArgon2MemoryCost, IntArgon2TimeCost, IntArgon2Parallelism
from src.common.utils.encoding import int_to_bytes
from src.database.db_masterkey import MasterKey
from src.transmitter.key_exchanges.deliver_contact_data import deliver_contact_data
from src.transmitter.queue_packet.queue_packet import queue_command
from src.ui.common.input.get_confirmation_code import get_confirmation_code
from src.ui.common.input.path.get_path import get_path
from src.ui.common.output.phase import phase
from src.ui.common.output.print_message import print_message
from src.ui.common.output.vt100_utils import clear_previous_lines

if TYPE_CHECKING:
    from src.common.entities.nick_name import Nick
    from src.common.crypto.keys.onion_service_keys import OnionPublicKeyContact
    from src.common.queues import TxQueue
    from src.common.crypto.pt_ct import PSKCT
    from src.database.db_contacts import ContactList
    from src.database.db_onion import OnionService
    from src.database.db_settings import Settings
    from src.ui.transmitter.window_tx import TxWindow


def create_pre_shared_key(pub_key_contact : 'OnionPublicKeyContact',
                          nick            : 'Nick',
                          contact_list    : 'ContactList',
                          settings        : 'Settings',
                          onion_service   : 'OnionService',
                          queues          : 'TxQueue'
                          ) -> None:
    """Generate a new pre-shared key for manual key delivery.

    Pre-shared keys offer a low-tech solution against the slowly
    emerging threat of quantum computers. PSKs are less convenient and
    not usable in every scenario, but until a quantum-safe key exchange
    algorithm with reasonably short keys is standardized, TFC can't
    provide a better alternative against quantum computers.

    The generated keys are protected by a key encryption key, derived
    from a 256-bit salt and a password (that is to be shared with the
    recipient) using Argon2id key derivation function.

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
        tx_mk = MessageKeyUser()
        rx_hk = HeaderKeyContact()
        tx_hk = HeaderKeyUser()
        rx_mk = MessageKeyContact()
        salt  = Argon2Salt()

        password = MasterKey.new_password('password for PSK')

        time_cost   = IntArgon2TimeCost(Argon2Literals.ARGON2_PSK_TIME_COST)
        memory_cost = IntArgon2MemoryCost(Argon2Literals.ARGON2_PSK_MEMORY_COST)
        parallelism = IntArgon2Parallelism(Argon2Literals.ARGON2_PSK_PARALLELISM)

        with phase('Deriving key encryption key', padding_top=2):
            kek = PSKEncryptionKey(argon2_kdf(password, salt, time_cost, memory_cost, parallelism))

        ct_tag = kek.encrypt_and_sign(PSKPT(  tx_hk.raw_bytes
                                            + tx_mk.raw_bytes))

        store_keys_on_removable_drive(salt,
                                      time_cost,
                                      memory_cost,
                                      parallelism,
                                      ct_tag,
                                      nick,
                                      pub_key_contact,
                                      onion_service,
                                      settings)

        deliver_contact_data(RxCommand.KEY_EX_PSK_TX, nick, pub_key_contact,
                             tx_hk, tx_mk,
                             rx_hk, rx_mk,
                             queues, settings)

        contact_list.add_contact(pub_key_contact, nick,
                                 FingerprintUser   .generate_zero_fp(),
                                 FingerprintContact.generate_zero_fp(),
                                 KexStatus.KEX_STATUS_NO_RX_PSK,
                                 settings.log_messages_by_default,
                                 settings.accept_files_by_default,
                                 settings.show_notifications_by_default)

        queues.key_store_mgmt.put((KeyDBMgmt.INSERT_ROW,
                                   pub_key_contact,
                                   tx_hk, tx_mk,
                                   rx_hk, rx_mk))

        print_message(f'Successfully added {nick}.', bold=True, clear_after=True, clear_delay=1, padding_top=1)

    except (EOFError, KeyboardInterrupt):
        raise SoftError('PSK generation aborted.', clear_after=True, clear_delay=1, padding_top=2)


def store_keys_on_removable_drive(salt            : Argon2Salt,
                                  time_cost       : IntArgon2TimeCost,
                                  memory_cost     : IntArgon2MemoryCost,
                                  parallelism     : IntArgon2Parallelism,
                                  psk_ct          : 'PSKCT',
                                  nick            : 'Nick',
                                  pub_key_contact : 'OnionPublicKeyContact',
                                  onion_service   : 'OnionService',
                                  settings        : 'Settings',
                                  ) -> None:
    """Store keys for contact on a removable media."""
    while True:
        store_d = get_path(f'Select removable media for {nick}', settings)
        f_name  = f'{store_d}/{onion_service.short_addr_user}.psk - Give to {pub_key_contact.short_address}'

        try:
            with open(f_name, 'wb+') as f:
                f.write(salt.salt_bytes
                        + int_to_bytes(time_cost)
                        + int_to_bytes(memory_cost)
                        + int_to_bytes(parallelism)
                        + psk_ct.ct_bytes)
                f.flush()
                os.fsync(f.fileno())
            break
        except PermissionError:
            print_message('Error: Did not have permission to write to the directory.', clear_delay=0.5)
            continue


def rxp_load_psk(settings     : 'Settings',
                 queues       : 'TxQueue',
                 window       : 'TxWindow',
                 contact_list : 'ContactList',
                 ) -> None:
    """Send command to Receiver Program to load PSK for active contact."""
    raise_if_traffic_masking(settings)

    if window.window_type == WindowType.GROUP or window.contact is None:
        raise SoftError('Error: Group is selected.', clear_before=True)

    if not contact_list.get_contact_by_pub_key(window.contact.onion_pub_key).uses_psk():
        raise SoftError(f'Error: The current key was exchanged with {KexType.ECDHE}.', clear_before=True)

    contact_pub_key = window.contact.onion_pub_key

    command = SerializedCommand(RxCommand.KEY_EX_PSK_RX, contact_pub_key.serialize())
    queue_command(settings, queues, command)

    while True:
        try:
            purp_code = get_confirmation_code(code_displayed_on='Receiver')

            if purp_code == contact_pub_key.c_code:
                window.contact.kex_status = KexStatus.KEX_STATUS_HAS_RX_PSK
                contact_list.store_contacts()
                raise SoftError(f'Removed PSK reminder for {window.window_name}.', clear_after=True, clear_delay=1)

            elif purp_code.is_resend_request:
                with phase('PSK import command', padding_top=2):
                    queue_command(settings, queues, command)
                clear_previous_lines(no_lines=5)

            else:
                print_message('Incorrect confirmation code.', padding_top=1)
                clear_previous_lines(no_lines=4, delay=2)

        except (EOFError, KeyboardInterrupt):
            raise SoftError('PSK install verification aborted.', clear_after=True, clear_delay=1, padding_top=2)
