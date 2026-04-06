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

from src.common.entities.serialized_command import SerializedCommand
from src.common.exceptions import SoftError
from src.common.statics import (Separator, RxCommand, RelaySettingKey, KeyDBMgmt, TrafficMaskingOmittedSettings,
                                TFCSettingKey)
from src.common.types_custom import StrSettingValue
from src.common.utils.encoding import bool_to_bytes
from src.common.utils.validators import validate_second_field
from src.datagrams.relay.command.change_setting import DatagramRelayChangeSetting
from src.transmitter.queue_packet.queue_packet import queue_command

if TYPE_CHECKING:
    from src.common.gateway import Gateway
    from src.common.queues import TxQueue
    from src.database.db_contacts import ContactList
    from src.database.db_groups import GroupList
    from src.database.db_masterkey import MasterKey
    from src.database.db_settings import Settings
    from src.ui.transmitter.user_input import UserInput
    from src.ui.transmitter.window_tx import TxWindow


def change_system_setting(settings     : 'Settings',
                          queues       : 'TxQueue',
                          window       : 'TxWindow',
                          contact_list : 'ContactList',
                          group_list   : 'GroupList',
                          user_input   : 'UserInput',
                          master_key   : 'MasterKey',
                          gateway      : 'Gateway'
                          ) -> None:
    """Change a system setting on Transmitter and Receiver Program."""
    # ┌──────────────────────────────┐
    # │ Validate the setting KV-pair │
    # └──────────────────────────────┘
    setting_k_str = validate_second_field(user_input, key='setting')

    try:
        setting_k = TFCSettingKey(setting_k_str)
    except ValueError:
        raise SoftError(f"Error: Invalid setting '{setting_k_str}'.", clear_before=True)

    try:
        setting_v = StrSettingValue(user_input.plaintext.split()[2])
    except IndexError:
        raise SoftError('Error: No value for setting specified.', clear_before=True)

    # ┌─────────────────────┐
    # │ Validate Conditions │
    # └─────────────────────┘
    check_setting_change_conditions(setting_k, settings, master_key)

    # ┌───────────────┐
    # │ Apply Setting │
    # └───────────────┘
    # Route the traffic-masking toggle through the currently active sender
    # mode so the Receiver sees the setting change before the sender flips
    # to the new command queues.
    if setting_k == TFCSettingKey.TRAFFIC_MASKING:
        change_setting_value_on_receiver(setting_k, setting_v, queues, settings)

    change_setting_value_locally (setting_k, setting_v,         contact_list, group_list, settings, gateway)
    change_setting_value_on_relay(setting_k, setting_v, queues,                           settings         )

    if setting_k != TFCSettingKey.TRAFFIC_MASKING:
        change_setting_value_on_receiver(setting_k, setting_v, queues, settings)

    propagate_setting_effects(setting_k, queues, contact_list, group_list, settings, window )


def check_setting_change_conditions(setting_key : TFCSettingKey,
                                    settings    : 'Settings',
                                    master_key  : 'MasterKey'
                                    ) -> None:
    """Check if the setting can be changed."""
    if settings.traffic_masking and setting_key in TrafficMaskingOmittedSettings:
        raise SoftError("Error: Can't change this setting during traffic masking.", clear_before=True)

    if setting_key == TFCSettingKey.ASK_PASSWORD_FOR_LOG_ACCESS:
        if not master_key.authenticate_action():
            raise SoftError('Error: No permission to change setting.', clear_before=True)


def change_setting_value_locally(setting_k    : TFCSettingKey,
                                 setting_v    : StrSettingValue,
                                 contact_list : 'ContactList',
                                 group_list   : 'GroupList',
                                 settings     : 'Settings',
                                 gateway      : 'Gateway'
                                 ) -> None:
    """Change setting value in setting databases."""
    if setting_k in gateway.settings.key_list:
        gateway.settings.change_setting(setting_k, setting_v)
    else:
        settings.change_setting(setting_k, setting_v, contact_list, group_list)


def change_setting_value_on_relay(setting_k : TFCSettingKey,
                                  setting_v : StrSettingValue,
                                  queues    : 'TxQueue',
                                  settings  : 'Settings',
                                  ) -> None:
    """Change setting value in setting databases."""
    if setting_k not in RelaySettingKey:
        return

    if   setting_k == TFCSettingKey.ALLOW_CONTACT_REQUESTS: setting_v = StrSettingValue(bool_to_bytes(settings.allow_contact_requests).decode())
    elif setting_k == TFCSettingKey.REQUIRE_RESENDS:        setting_v = StrSettingValue(bool_to_bytes(settings.require_resends       ).decode())
    elif setting_k == TFCSettingKey.AUTOREPLAY_TIMES:       setting_v = StrSettingValue(str          (settings.autoreplay_times      )         )
    elif setting_k == TFCSettingKey.AUTOREPLAY_LOOP:        setting_v = StrSettingValue(bool_to_bytes(settings.autoreplay_loop       ).decode())

    queues.relay_packet.put( DatagramRelayChangeSetting(setting_k, setting_v) )


def change_setting_value_on_receiver(setting_k  : TFCSettingKey,
                                     setting_v  : StrSettingValue,
                                     queues     : 'TxQueue',
                                     settings   : 'Settings',
                                     ) -> None:
    """Change setting value in setting databases."""
    serialized_fields = (setting_k.encode()
                         + Separator.US_BYTE.value
                         + setting_v.encode())

    queue_command(settings, queues, SerializedCommand(RxCommand.CH_SETTING, serialized_fields))


def propagate_setting_effects(setting_k    : TFCSettingKey,
                              queues       : 'TxQueue',
                              contact_list : 'ContactList',
                              group_list   : 'GroupList',
                              settings     : 'Settings',
                              window       : 'TxWindow'
                              ) -> None:
    """Propagate the effects of the setting."""
    if setting_k == 'max_number_of_contacts':
        contact_list.store_contacts()
        queues.key_store_mgmt.put((KeyDBMgmt.UPDATE_ROW_COUNT, settings))

    if setting_k in [TFCSettingKey.MAX_NUMBER_OF_GROUPS,
                     TFCSettingKey.MAX_NUMBER_OF_GROUP_MEMBERS]:
        group_list.store_groups()

    if setting_k == TFCSettingKey.TRAFFIC_MASKING:
        queues.sender_mode.put(settings)
        queues.traffic_masking.put(settings.traffic_masking)
        window.deselect()

    if setting_k == TFCSettingKey.REQUIRE_RESENDS:  queues.sender_setting_update.put( (setting_k, settings.require_resends ))
    if setting_k == TFCSettingKey.AUTOREPLAY_TIMES: queues.sender_setting_update.put( (setting_k, settings.autoreplay_times))
    if setting_k == TFCSettingKey.AUTOREPLAY_LOOP:  queues.sender_setting_update.put( (setting_k, settings.autoreplay_loop ))
    if setting_k == TFCSettingKey.LOG_FILE_MASKING: queues.logfile_masking      .put(             settings.log_file_masking)


def enqueue_initial_relay_runtime_settings(settings: 'Settings',
                                           queues  : 'TxQueue',
                                           ) -> None:
    """Queue relay runtime settings that must be restored each session."""
    for setting_key in [TFCSettingKey.REQUIRE_RESENDS,
                        TFCSettingKey.AUTOREPLAY_TIMES,
                        TFCSettingKey.AUTOREPLAY_LOOP]:
        change_setting_value_on_relay(setting_key,
                                      StrSettingValue(str(settings.get_setting_value(setting_key))),
                                      queues,
                                      settings)
