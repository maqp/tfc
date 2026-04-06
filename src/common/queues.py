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
from multiprocessing import Queue
from typing import Optional as O, TYPE_CHECKING

from src.common.statics import RelayLimits
from src.datagrams.relay.group_management.group_msg_add_rem import DatagramGroupAddMember, DatagramGroupRemMember
from src.datagrams.relay.group_management.group_msg_flat import (DatagramGroupInvite, DatagramGroupJoin,
                                                                 DatagramGroupExit)

if TYPE_CHECKING:
    from src.datagrams.datagram import Datagram, DatagramRelayCommand
    from src.datagrams.receiver.command import DatagramReceiverCommand
    from src.datagrams.receiver.local_key import DatagramReceiverLocalKey
    from src.datagrams.receiver.message import DatagramIncomingMessage, DatagramOutgoingMessage, \
    DatagramIncomingNoiseMessage
    from src.datagrams.receiver.public_key import DatagramPublicKey
    from src.datagrams.receiver.file_multicast import DatagramFileMulticast
    from src.datagrams.relay.command.setup_onion_service import DatagramRelaySetupOnionService
    from src.common.entities.assembly_packet import CommandAssemblyPacket
    from src.common.entities.contact import Contact
    from src.common.crypto.keys.onion_service_keys import OnionPublicKeyContact, OnionPublicKeyUser
    from src.common.crypto.keys.symmetric_key import BufferKey
    from src.common.crypto.keys.x448_keys import X448PubKey
    from src.common.statics import LogWriterMgmt, MonitorQueueSignal
    from src.common.types_compound import (StandardPacketQueueData, TrafficMaskingMessageQueueData,
                                           BoolLogThisAssemblyPacket, LogQueueData,
                                           KeyDBAckQueueData, KeyStoreMgmt, LocalKeyMgmt, LogWriterQueueData,
                                           DispatcherSettingUpdate, ReplaySettingUpdate, TorDataTuple,
                                           ClientMgmtCommandTuple, GroupMgmtMessageTuple, ContactListMgmtTuple,
                                           GroupMgmtTuple)
    from src.common.types_custom import BoolLogFileMasking, BoolTrafficMasking, BoolUnitTesting
    from src.database.db_settings import Settings


class TxQueue:
    """TxQueue is a wrapper-object for Transmitter Program's multiprocessing queues."""

    def __init__(self) -> None:
        """Initializes a new TxQueue object."""
        self.message_packet                                     : 'Queue[StandardPacketQueueData]'                         = Queue()
        self.command_packet                                     : 'Queue[CommandAssemblyPacket]'                           = Queue()
        self.tm_message_packet                                  : 'Queue[TrafficMaskingMessageQueueData]'                  = Queue()
        self.tm_file_packet                                     : 'Queue[TrafficMaskingMessageQueueData]'                  = Queue()
        self.tm_noise_packet                                    : 'Queue[TrafficMaskingMessageQueueData]'                  = Queue()
        self.tm_command_packet                                  : 'Queue[CommandAssemblyPacket]'                           = Queue()
        self.tm_noise_command                                   : 'Queue[CommandAssemblyPacket]'                           = Queue()
        self.relay_packet                                       : 'Queue[Datagram]'                                        = Queue()
        self.log_packet                                         : 'Queue[LogQueueData]'                                    = Queue()
        self.log_setting                                        : 'Queue[BoolLogThisAssemblyPacket]'                       = Queue()
        self.traffic_masking                                    : 'Queue[BoolTrafficMasking]'                              = Queue()
        self.logfile_masking                                    : 'Queue[BoolLogFileMasking]'                              = Queue()
        self.log_writer_mgmt                                    : 'Queue[LogWriterQueueData]'                              = Queue()
        self.log_writer_ack                                     : 'Queue[LogWriterMgmt]'                                   = Queue()
        self.key_store_mgmt                                     : 'Queue[KeyStoreMgmt]'                                    = Queue()
        self.local_key_mgmt                                     : 'Queue[LocalKeyMgmt]'                                    = Queue()
        self.key_mgmt_ack                                       : 'Queue[KeyDBAckQueueData]'                               = Queue()
        self.sender_mode                                        : 'Queue[Settings]'                                        = Queue()
        self.sender_setting_update                              : 'Queue[ReplaySettingUpdate]'                             = Queue()
        self.resend_packet_numbers                              : 'Queue[list[int]]'                                       = Queue()
        self.tm_recipient_list                                  : 'Queue[list[Contact]]'                                   = Queue()
        self.to_monitor_proxy                                   : 'Queue[MonitorQueueSignal]'                              = Queue()
        self.to_process_monitor                                 : 'Queue[MonitorQueueSignal]'                              = Queue()
        self.unit_test                                          : 'Queue[BoolUnitTesting]'                                 = Queue()


class RxQueue:
    """RxQueue is a wrapper-object for Receiver Program's multiprocessing queues."""
    def __init__(self) -> None:
        """Initializes a new RxQueue object."""
        self.from_gwr_to_dispatcher_datagrams                   : 'Queue[tuple[datetime, bytes]]'                          = Queue()
        self.datagram_local_keys                                : 'Queue[DatagramReceiverLocalKey]'                        = Queue()
        self.datagram_messages                                  : 'Queue[DatagramIncomingMessage|DatagramOutgoingMessage]' = Queue()
        self.datagram_mc_files                                  : 'Queue[DatagramFileMulticast]' = Queue()
        self.datagram_commands                                  : 'Queue[DatagramReceiverCommand]'                         = Queue()
        self.dispatcher_setting_updates                         : 'Queue[DispatcherSettingUpdate]'                         = Queue()
        self.replay_cache_clear                                 : 'Queue[bool]'                                            = Queue()
        self.exit                                               : 'Queue[MonitorQueueSignal]'                              = Queue()
        self.unit_test                                          : 'Queue[BoolUnitTesting]'                                 = Queue()
        self.to_process_monitor                                 : 'Queue[MonitorQueueSignal]'                              = Queue()


class RelayQueue:
    """RelayQueue is a wrapper-object for Relay Program's multiprocessing queues."""

    def __init__(self) -> None:
        """Initializes a new RelayQueue object."""
        # Gateway
        self.from_gwr_to_dispatcher_datagrams                   : 'Queue[tuple[datetime, bytes]]'                          = Queue()
        self.from_gwr_to_rpe_relay_runtime_settings             : 'Queue[DispatcherSettingUpdate]'                         = Queue()
        self.replay_cache_clear                                 : 'Queue[bool]'                                            = Queue()

        # ┌────────────────┐
        # │ Endpoint Setup │
        # └────────────────┘
        self.from_txp_to_sxy_buffer_key                         : 'Queue[BufferKey]'                                       = Queue()
        self.from_txp_to_srv_buffer_key                         : 'Queue[BufferKey]'                                       = Queue()
        self.from_rec_to_onion_service_process_onion_setup_data : 'Queue[DatagramRelaySetupOnionService]'                  = Queue()
        self.from_txp_to_rxp_datagram_local_key                 : 'Queue[DatagramReceiverLocalKey]'                        = Queue()
        self.relay_status_messages                              : 'Queue[str]'                                             = Queue()

        # ┌───────────────────┐
        # │ Contact Discovery │
        # └───────────────────┘
        self.from_srv_to_crm_contact_request_addresses          : 'Queue[str]'                                             = Queue(maxsize=RelayLimits.CONTACT_REQUEST_QUEUE_SIZE)
        self.from_cli_to_srv_url_tokens                         : 'Queue[tuple[OnionPublicKeyContact, str]]'               = Queue()

        # ┌───────┐
        # │ Comms │
        # └───────┘

        # Accounts
        self.from_crm_to_diff_comp_received_accounts            : 'Queue[OnionPublicKeyContact]'                           = Queue()
        self.from_rec_to_diff_comp_purported_accounts           : 'Queue[str]'                                             = Queue()
        self.from_gui_to_diff_comp_user_selected_account        : 'Queue[O[OnionPublicKeyContact]]'                        = Queue()

        # X448 public keys
        self.from_txp_to_sxy_outgoing_x448_public_keys          : 'Queue[DatagramPublicKey]'                               = Queue()
        self.from_rec_to_diff_comp_user_input_x448_public_keys  : 'Queue[tuple[OnionPublicKeyContact, str       ]]'        = Queue()
        self.from_cli_to_diff_comp_received_x448_public_keys    : 'Queue[tuple[OnionPublicKeyContact, X448PubKey]]'        = Queue()
        self.from_rec_to_diff_comp_public_keys                  : 'Queue[OnionPublicKeyUser]'                              = Queue()

        # ---

        # Outgoing messages
        self.from_txp_to_sxy_datagram_messages                  : 'Queue[DatagramOutgoingMessage]'                         = Queue()
        self.from_sxy_to_rxp_datagram_messages                  : 'Queue[DatagramOutgoingMessage]'                         = Queue()
        # Incoming messages
        self.from_cli_to_rxp_datagram_messages                  : 'Queue[DatagramIncomingMessage]'                         = Queue()
        self.from_cli_to_npv_datagram_messages                  : 'Queue[DatagramIncomingNoiseMessage]'                    = Queue()

        # Outgoing files
        self.from_txp_to_sxy_datagram_file_mcast                : 'Queue[DatagramFileMulticast]' = Queue()
        # Incoming files
        self.from_cli_to_rxp_datagram_file_mcast                : 'Queue[DatagramFileMulticast]' = Queue()
        self.from_txp_to_dst_resend_packet_numbers              : 'Queue[list[int]]'                                       = Queue()
        self.from_txp_to_dst_resend_file_ids                    : 'Queue[str]'                                             = Queue()
        self.relay_runtime_settings_to_dst                      : 'Queue[ReplaySettingUpdate]'                             = Queue()

        # Commands
        self.from_txp_to_rep_datagram_command                   : 'Queue[DatagramRelayCommand]'                            = Queue()
        self.from_txp_to_rxp_datagram_command                   : 'Queue[DatagramReceiverCommand]'                         = Queue()
        self.from_txp_to_cli_buffer_key                         : 'Queue[BufferKey]'                                       = Queue()

        # Outgoing group management messages
        self.from_txp_to_srv_datagram_group_mgmt_invite         : 'Queue[DatagramGroupInvite]'                             = Queue()
        self.from_txp_to_srv_datagram_group_mgmt_join           : 'Queue[DatagramGroupJoin]'                               = Queue()
        self.from_txp_to_srv_datagram_group_mgmt_add            : 'Queue[DatagramGroupAddMember]'                          = Queue()
        self.from_txp_to_srv_datagram_group_mgmt_rem            : 'Queue[DatagramGroupRemMember]'                          = Queue()
        self.from_txp_to_srv_datagram_group_mgmt_exit           : 'Queue[DatagramGroupExit]'                               = Queue()

        # Incoming group management messages
        self.from_cli_to_rpe_datagram_group_mgmt_invite         : 'Queue[DatagramGroupInvite]'                             = Queue()
        self.from_cli_to_rpe_datagram_group_mgmt_join           : 'Queue[DatagramGroupJoin]'                               = Queue()
        self.from_cli_to_rpe_datagram_group_mgmt_add            : 'Queue[DatagramGroupAddMember]'                          = Queue()
        self.from_cli_to_rpe_datagram_group_mgmt_rem            : 'Queue[DatagramGroupRemMember]'                          = Queue()
        self.from_cli_to_rpe_datagram_group_mgmt_exit           : 'Queue[DatagramGroupExit]'                               = Queue()

        self.from_tor_to_sch_client_tor_data                    : 'Queue[TorDataTuple]'                                    = Queue()
        self.from_rec_to_crm_accept_requests_setting            : 'Queue[bool]'                                            = Queue()
        self.from_rec_to_sch_client_contact_mgmt_commands       : 'Queue[ClientMgmtCommandTuple]'                          = Queue()
        self.from_cli_to_gmm_group_mgmt_messages                : 'Queue[GroupMgmtMessageTuple]'                           = Queue()
        self.from_rec_to_crm_contact_list_mgmt                  : 'Queue[ContactListMgmtTuple]'                            = Queue()
        self.from_rec_to_gmm_group_mgmt                         : 'Queue[GroupMgmtTuple]'                                  = Queue()

        # Relay teardown related
        self.close_onion_service_signal                         : 'Queue[MonitorQueueSignal]'                              = Queue()
        self.to_process_monitor                                 : 'Queue[MonitorQueueSignal]'                              = Queue()
        self.exit                                               : 'Queue[MonitorQueueSignal]'                              = Queue()
        self.unit_test                                          : 'Queue[BoolUnitTesting]'                                 = Queue()


class DataDiodeQueue:
    """RelayQueue is a wrapper-object for Data Diode Simulator's multiprocessing queues."""

    def __init__(self) -> None:
        """Initializes a new RelayQueue object."""
        self.exit                                               : 'Queue[MonitorQueueSignal]'                              = Queue()
        self.io_queue                                           : 'Queue[bytes]'                                           = Queue()
        self.to_process_monitor                                 : 'Queue[MonitorQueueSignal]'                              = Queue()
