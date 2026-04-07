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

from datetime import datetime
from typing import TYPE_CHECKING

from src.common.exceptions import SoftError
from src.common.statics import FieldLength, RelayCommand
from src.common.types_custom import BytesRelayCommand
from src.common.utils.strings import separate_header
from src.datagrams.relay.command.change_setting import DatagramRelayChangeSetting
from src.datagrams.relay.command.replay import DatagramRelayResendFile, DatagramRelayResendPackets
from src.datagrams.relay.command.contact_add import DatagramRelayAddContact
from src.datagrams.relay.command.contact_remove import DatagramRelayRemoveContact
from src.datagrams.relay.diff_comparison.diff_comparison_account import DatagramRelayDiffComparisonAccount
from src.datagrams.relay.diff_comparison.diff_comparison_public_key import DatagramRelayDiffComparisonPublicKey
from src.datagrams.relay.command.setup_onion_service import DatagramRelaySetupOnionService
from src.relay.commands.management.manage_contacts import (add_existing_contact, add_onion_data, compare_accounts,
                                                           compare_pub_keys, remove_contact, resend_to_receiver,
                                                           resend_file_to_receiver, add_pending_contact)
from src.relay.commands.management.manage_settings_system import (change_autoreplay_loop, change_autoreplay_times,
                                                                 change_baudrate, change_contact_requests,
                                                                 change_ec_ratio, change_require_resends)
from src.relay.commands.security.security import clear_windows, clear_ciphertext_cache, reset_windows, exit_tfc, wipe

if TYPE_CHECKING:
    from src.common.gateway import Gateway
    from src.common.queues import RelayQueue


def dispatch_relay_command(queues   : 'RelayQueue',
                           gateway  : 'Gateway',
                           ts       : datetime,
                           command  : BytesRelayCommand,
                           ) -> None:
    """Separate header and run correct command."""
    header, payload = separate_header(command, FieldLength.RELAY_COMMAND_HEADER.value)

    if   header == RelayCommand.CLEAR_SCREEN.value:             clear_windows           (gateway)
    elif header == RelayCommand.CLEAR_CIPHERTEXT_CACHE.value:   clear_ciphertext_cache  (gateway, queues)
    elif header == RelayCommand.RESET_SCREEN.value:             reset_windows           (gateway)
    elif header == RelayCommand.EXIT_TFC.value:                 exit_tfc                (gateway, queues)
    elif header == RelayCommand.WIPE_SYSTEM.value:              wipe                    (gateway, queues)
    elif header == RelayCommand.SET_ERROR_CORRECTION.value:     change_ec_ratio         (gateway, queues, DatagramRelayChangeSetting          .from_txp_rep_bytes(ts, payload))
    elif header == RelayCommand.SET_BAUDRATE.value:             change_baudrate         (gateway, queues, DatagramRelayChangeSetting          .from_txp_rep_bytes(ts, payload))
    elif header == RelayCommand.MANAGE_CONTACT_REQUESTS.value:  change_contact_requests (queues,  DatagramRelayChangeSetting          .from_txp_rep_bytes(ts, payload))
    elif header == RelayCommand.SET_REQUIRE_RESENDS.value:      change_require_resends  (queues,  DatagramRelayChangeSetting          .from_txp_rep_bytes(ts, payload))
    elif header == RelayCommand.SET_AUTOREPLAY_TIMES.value:     change_autoreplay_times (queues,  DatagramRelayChangeSetting          .from_txp_rep_bytes(ts, payload))
    elif header == RelayCommand.SET_AUTOREPLAY_LOOP.value:      change_autoreplay_loop  (queues,  DatagramRelayChangeSetting          .from_txp_rep_bytes(ts, payload))
    elif header == RelayCommand.ADD_NEW_CONTACT.value:          add_pending_contact     (queues,  DatagramRelayAddContact             .from_txp_rep_bytes(ts, payload))
    elif header == RelayCommand.ADD_EXISTING_CONTACT.value:     add_existing_contact    (queues,  DatagramRelayAddContact             .from_txp_rep_bytes(ts, payload))
    elif header == RelayCommand.REMOVE_CONTACT.value:           remove_contact          (queues,  DatagramRelayRemoveContact          .from_txp_rep_bytes(ts, payload))
    elif header == RelayCommand.ONION_SERVICE_SETUP_DATA.value: add_onion_data          (queues,  DatagramRelaySetupOnionService      .from_txp_rep_bytes(ts, payload))
    elif header == RelayCommand.CHECK_ACCOUNT_INPUT.value:      compare_accounts        (queues,  DatagramRelayDiffComparisonAccount  .from_txp_rep_bytes(ts, payload))
    elif header == RelayCommand.CHECK_PUBLIC_KEY_INPUT.value:   compare_pub_keys        (queues,  DatagramRelayDiffComparisonPublicKey.from_txp_rep_bytes(ts, payload))
    elif header == RelayCommand.RESEND_TO_RECEIVER.value:       resend_to_receiver      (queues,  DatagramRelayResendPackets          .from_txp_rep_bytes(ts, payload))
    elif header == RelayCommand.RESEND_FILE_TO_RECEIVER.value:  resend_file_to_receiver (queues,  DatagramRelayResendFile             .from_txp_rep_bytes(ts, payload))
    else: raise SoftError('Error: Received an invalid command.')
