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

import serial

from src.common.exceptions import SoftError
from src.common.statics import SettingLimitsInt, TFCSettingKey
from src.common.types_custom import BoolAutoreplayLoop, BoolRequireResends, IntAutoreplayTimes, \
    IntSerialErrorCorrection, IntSerialBaudrate
from src.common.utils.encoding import bytes_to_bool

if TYPE_CHECKING:
    from src.common.gateway import Gateway
    from src.common.queues import RelayQueue
    from src.datagrams.relay.command.change_setting import DatagramRelayChangeSetting


def queue_relay_status_message(queues   : 'RelayQueue',
                               message  : str
                               ) -> None:
    """Queue Relay setting status message for bundled printing."""
    queues.relay_status_messages.put(message)


def change_ec_ratio(gateway  : 'Gateway',
                    queues   : 'RelayQueue',
                    datagram : 'DatagramRelayChangeSetting'
                    ) -> None:
    """Change Relay Program's Reed-Solomon error correction ratio."""
    try:
        value = int(datagram.setting_value)
        if (value < SettingLimitsInt.SERIAL_ERROR_CORRECTION_MIN.value
                or value > SettingLimitsInt.SERIAL_ERROR_CORRECTION_MAX.value):
            raise ValueError
    except ValueError:
        raise SoftError('Error: Received invalid EC ratio value from Transmitter Program.')

    queue_relay_status_message(queues, 'Error correction ratio will change on restart.')

    gateway.settings.serial_error_correction = IntSerialErrorCorrection(value)
    gateway.settings.store_settings()


def change_baudrate(gateway  : 'Gateway',
                    queues   : 'RelayQueue',
                    datagram : 'DatagramRelayChangeSetting'
                    ) -> None:
    """Change Relay Program's serial interface baud rate setting."""
    try:
        value = int(datagram.setting_value)
        if value not in serial.Serial.BAUDRATES:
            raise ValueError
    except ValueError:
        raise SoftError('Error: Received invalid baud rate value from Transmitter Program.')

    queue_relay_status_message(queues, 'Baud rate will change on restart.')

    gateway.settings.serial_baudrate = IntSerialBaudrate(value)
    gateway.settings.store_settings()


def change_contact_requests(queues   : 'RelayQueue',
                            datagram : 'DatagramRelayChangeSetting'
                            ) -> None:
    """Control whether contact requests are accepted."""
    allow_contact_requests = bytes_to_bool(datagram.setting_value)

    state = 'enabled' if allow_contact_requests else 'disabled'
    queue_relay_status_message(queues, f'Contact requests have been {state}.')
    queues.from_rec_to_crm_accept_requests_setting.put(allow_contact_requests)


def change_require_resends(queues   : 'RelayQueue',
                           datagram : 'DatagramRelayChangeSetting'
                           ) -> None:
    """Control whether Relay tracks missing gateway packets."""
    require_resends = BoolRequireResends(bytes_to_bool(datagram.setting_value))

    state = 'enabled' if require_resends else 'disabled'
    queue_relay_status_message(queues, f'Resend tracking has been {state}.')
    queues.from_gwr_to_rpe_relay_runtime_settings.put((TFCSettingKey.REQUIRE_RESENDS, require_resends))
    queues.relay_runtime_settings_to_dst         .put((TFCSettingKey.REQUIRE_RESENDS, require_resends))


def change_autoreplay_times(queues   : 'RelayQueue',
                            datagram : 'DatagramRelayChangeSetting'
                            ) -> None:
    """Control how many times Relay retransmits every sent packet."""
    try:
        value = int(datagram.setting_value)
        if (value < SettingLimitsInt.AUTOREPLAY_TIMES_MIN.value
                or value > SettingLimitsInt.AUTOREPLAY_TIMES_MAX.value):
            raise ValueError
    except ValueError:
        raise SoftError('Error: Received invalid autoreplay count from Transmitter Program.')

    queue_relay_status_message(queues, f'Relay autoreplay count set to {value}.')
    queues.relay_runtime_settings_to_dst.put((TFCSettingKey.AUTOREPLAY_TIMES, IntAutoreplayTimes(value)))


def change_autoreplay_loop(queues   : 'RelayQueue',
                           datagram : 'DatagramRelayChangeSetting'
                           ) -> None:
    """Control whether Relay idly replays recent packets."""
    autoreplay_loop = BoolAutoreplayLoop(bytes_to_bool(datagram.setting_value))

    state = 'enabled' if autoreplay_loop else 'disabled'
    queue_relay_status_message(queues, f'Relay idle autoreplay has been {state}.')
    queues.from_gwr_to_rpe_relay_runtime_settings.put((TFCSettingKey.AUTOREPLAY_LOOP, autoreplay_loop))
    queues.relay_runtime_settings_to_dst.put((TFCSettingKey.AUTOREPLAY_LOOP, autoreplay_loop))
