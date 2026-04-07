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

import time

from multiprocessing import Queue
from typing import TYPE_CHECKING

from src.common.exceptions import SoftError
from src.common.replay import iter_recent_cached_packets, resend_cached_packets, should_cache_gateway_packets
from src.common.types_custom import IntAutoreplayTimes, BoolCachePacket, IntIdleReplayIndex
from src.transmitter.sender.shared import monitor_proxy, send_message, send_command

if TYPE_CHECKING:
    from src.common.gateway import Gateway
    from src.common.queues import TxQueue
    from src.common.types_compound import NormalSenderMsgBuffer, ReplaySettingUpdate
    from src.database.db_keys import KeyStore
    from src.database.db_local_key import LocalKeyDB
    from src.database.db_settings import Settings


def normal_sender(queues       : 'TxQueue',
                  settings     : 'Settings',
                  gateway      : 'Gateway',
                  key_store    : 'KeyStore',
                  local_key_db : 'LocalKeyDB',
                  m_buffer     : 'NormalSenderMsgBuffer'
                  ) -> tuple['Settings', 'NormalSenderMsgBuffer']:
    """Run Transmitter program in standard send mode.

    The standard sender loop loads assembly packets from a set of queues.
    As Python's multiprocessing lacks priority queues, several queues are
    prioritized based on their status:

    KEY_MANAGEMENT_QUEUE has the highest priority. This is to ensure the
    no queued message/command is encrypted with expired keyset.

    COMMAND_PACKET_QUEUE has the second-highest priority, to ensure
    commands are issued swiftly to Receiver program. Some commands like
    screen clearing might need to be issued quickly.

    RELAY_PACKET_QUEUE has third-highest priority. These are still
    commands but since Relay Program does not handle sensitive data,
    issuing commands to that devices does not take priority.

    Buffered messages have fourth-highest priority. This ensures that if
    for whatever reason the keyset is removed, buffered messages do not
    get lost. Packets are loaded from the buffer in FIFO basis ensuring
    packets arrive to the recipient in order.

    MESSAGE_PACKET_QUEUE has fifth-highest priority. Any buffered
    messages need to arrive earlier, thus new messages must be
    prioritized after the buffered ones.

    SENDER_MODE_QUEUE has sixth-highest priority. This prevents outgoing
    packets from being left in the queues used by this loop. This queue
    returns an up-to-date settings object for `process_sender()`,
    which then switches to `traffic_masking_sender()`.

    Along with settings, this function returns the m_buffer status so that
    assembly packets that could not have been sent due to missing key
    can be output later, if the user resumes standard sender mode and
    adds new keys for the contact.
    """
    km_queue = queues.key_store_mgmt
    lm_queue = queues.local_key_mgmt
    c_queue  = queues.command_packet
    rp_queue = queues.relay_packet
    sm_queue = queues.sender_mode
    rs_queue = queues.resend_packet_numbers
    su_queue = queues.sender_setting_update
    m_queue  = queues.message_packet

    idle_replay_index = IntIdleReplayIndex(0)

    while True:
        try:
            process_sender_setting_updates(    settings, su_queue)

            cache_packet = should_cache_gateway_packets(settings.require_resends, settings.autoreplay_times, settings.autoreplay_loop)

            process_key_mgmt_command(           queues, key_store, local_key_db)
            process_command(                    queues,            local_key_db, gateway, settings.autoreplay_times, cache_packet)
            process_relay_packets(              queues,                          gateway, settings.autoreplay_times, cache_packet)
            process_resend_packets(             rs_queue,                        gateway)
            process_buffered_messages(m_buffer, queues, key_store,               gateway, settings.autoreplay_times, cache_packet)
            process_new_message(      m_buffer, queues, key_store,               gateway, settings.autoreplay_times, cache_packet)

            idle_replay_index = process_idle_replay(settings, queues, gateway, idle_replay_index)

            # If traffic masking has been enabled, switch send mode when all queues are empty.
            if sm_queue.qsize() != 0 and all(q.qsize() == 0 for q in (km_queue, lm_queue, c_queue, rp_queue, m_queue)):
                settings = sm_queue.get()
                return settings, m_buffer

            time.sleep(0.01)

        except (EOFError, KeyboardInterrupt, SoftError):
            pass


def process_key_mgmt_command(queues       : 'TxQueue',
                             key_store    : 'KeyStore',
                             local_key_db : 'LocalKeyDB'
                             ) -> None:
    """Process key management command."""
    km_queue = queues.key_store_mgmt
    lm_queue = queues.local_key_mgmt

    processed = False

    if km_queue.qsize():
        key_store.manage(queues, *km_queue.get())
        processed = True

    if lm_queue.qsize():
        local_key_db.manage(queues, *lm_queue.get())
        processed = True

    if processed:
        raise SoftError('Key management command processing complete.', output=False)


def process_sender_setting_updates(settings     : 'Settings',
                                   update_queue : 'Queue[ReplaySettingUpdate]'
                                   ) -> None:
    """Apply runtime sender setting updates."""
    while update_queue.qsize():
        key, value = update_queue.get()
        settings.set_setting_value(key, value)


def process_command(queues           : 'TxQueue',
                    local_key_db     : 'LocalKeyDB',
                    gateway          : 'Gateway',
                    autoreplay_times : 'IntAutoreplayTimes',
                    cache_packet     : BoolCachePacket,
                    ) -> None:
    """Process command."""
    c_queue = queues.command_packet

    if c_queue.qsize():
        command = c_queue.get()

        if local_key_db.has_keyset:
            send_command(local_key_db, gateway, command, autoreplay_times, cache_packet=cache_packet)
        raise SoftError('Command processing complete.', output=False)


def process_relay_packets(queues           : 'TxQueue',
                          gateway          : 'Gateway',
                          autoreplay_times : 'IntAutoreplayTimes',
                          cache_packet     : BoolCachePacket,
                          ) -> None:
    """Process packet to Relay Program on Networked Computer."""
    rp_queue = queues.relay_packet

    if rp_queue.qsize():
        datagram      = rp_queue.get()
        cache_packet  = BoolCachePacket(cache_packet or autoreplay_times > 1)
        packet_number = gateway.write(datagram, cache_packet=cache_packet)
        for _ in range(max(0, autoreplay_times - 1)):
            gateway.resend_cached_packet(packet_number)
        monitor_proxy(queues, gateway)
        raise SoftError('Relay packet processing complete.', output=False)


def process_resend_packets(resend_queue : 'Queue[list[int]]',
                           gateway      : 'Gateway'
                           ) -> None:
    """Resend cached packet numbers requested by the user."""
    if resend_queue.qsize():
        resend_cached_packets(gateway, resend_queue.get())
        raise SoftError('Packet resend processing complete.', output=False)


def process_buffered_messages(m_buffer         : 'NormalSenderMsgBuffer',
                              queues           : 'TxQueue',
                              key_store        : 'KeyStore',
                              gateway          : 'Gateway',
                              autoreplay_times : 'IntAutoreplayTimes',
                              cache_packet     : BoolCachePacket,
                              ) -> None:
    """Process messages cached in `m_buffer`."""
    log_queue = queues.log_packet

    for pub_key in m_buffer:
        if key_store.has_keyset_for_pub_key(pub_key) and m_buffer[pub_key]:
            assembly_packet, queued_account, log_messages, log_as_ph, _ = m_buffer[pub_key].pop(0)
            send_message(key_store,
                         gateway,
                         log_queue,
                         assembly_packet,
                         queued_account,
                         log_messages,
                         log_as_ph,
                         autoreplay_times,
                         cache_packet=cache_packet)
            raise SoftError('Buffered message processing complete.', output=False)


def process_new_message(m_buffer         : 'NormalSenderMsgBuffer',
                        queues           : 'TxQueue',
                        key_store        : 'KeyStore',
                        gateway          : 'Gateway',
                        autoreplay_times : 'IntAutoreplayTimes',
                        cache_packet     : BoolCachePacket,
                        ) -> None:
    """Process new message in message queue."""
    m_queue   = queues.message_packet
    log_queue = queues.log_packet

    if m_queue.qsize():
        queue_data = m_queue.get()
        pub_key    = queue_data[1]

        if key_store.has_keyset_for_pub_key(pub_key):
            assembly_packet, queued_account, log_messages, log_as_ph, _ = queue_data
            send_message(key_store,
                         gateway,
                         log_queue,
                         assembly_packet,
                         queued_account,
                         log_messages,
                         log_as_ph,
                         autoreplay_times,
                         cache_packet=cache_packet)
        else:
            m_buffer.setdefault(pub_key, []).append(queue_data)

        raise SoftError('New message processing complete.', output=False)


def process_idle_replay(settings          : 'Settings',
                        queues            : 'TxQueue',
                        gateway           : 'Gateway',
                        idle_replay_index : IntIdleReplayIndex,
                        ) -> IntIdleReplayIndex:
    """Replay recent cached datagrams when the sender has no other work."""
    if not settings.autoreplay_loop:
        return IntIdleReplayIndex(0)

    if (queues.key_store_mgmt.qsize()
            or queues.local_key_mgmt.qsize()
            or queues.command_packet.qsize()
            or queues.relay_packet.qsize()
            or queues.message_packet.qsize()
            or queues.resend_packet_numbers.qsize()):
        return idle_replay_index

    replay_packets = iter_recent_cached_packets(gateway.settings.program_id)
    if not replay_packets:
        return IntIdleReplayIndex(0)

    packet = replay_packets[idle_replay_index % len(replay_packets)]
    gateway.send_numbered_packet(packet)
    return IntIdleReplayIndex(idle_replay_index + 1)
