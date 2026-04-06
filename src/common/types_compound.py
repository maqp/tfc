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
from typing import Literal, Optional as O, TypeAlias, TYPE_CHECKING

from src.common.statics import (KeyDBMgmt,
                                LocalKeyDBMgmt,
                                LogWriterMgmt,
                                SettingLimitsBool,
                                SettingLimitsFloat,
                                SettingLimitsInt,
                                TFCSettingKey, QueueSignal, DatagramHeader)

from src.common.types_custom import (BoolAutoreplayLoop,
                                     BoolAskPasswordForLogAccess,
                                     BoolConfirmTMFiles,
                                     BoolDisableGuiDialog,
                                     BoolFileReception,
                                     BoolAllowContactRequests,
                                     BoolLogAsPlaceHolder,
                                     BoolLogFileMasking,
                                     BoolLogMessages,
                                     BoolRequireResends,
                                     BoolNcBypassMessages,
                                     BoolNewMessageNotifyPreview,
                                     BoolShowNotifications,
                                     BoolTrafficMasking,
                                     BoolDoubleSpaceExits,
                                     BoolUseSerialUSBAdapter,
                                     BytesWindowUID,
                                     FloatNewMessageNotifyDuration,
                                     FloatTMRandomDelay,
                                     FloatTMStaticDelay,
                                     IntAutoreplayTimes,
                                     IntMaxDecompressSizeMB,
                                     IntMaxNumberOfContacts,
                                     IntMaxNumberOfGroupMembers,
                                     IntMaxNumberOfGroups,
                                     IntPortNumberTor,
                                     IntSerialBaudrate,
                                     IntSerialErrorCorrection,
                                     StrBuiltInSerialInterface, BoolIsPending)

if TYPE_CHECKING:
    from src.common.entities.assembly_packet import CommandAssemblyPacket, AssemblyPacket, MessageAssemblyPacket
    from src.common.crypto.keys.onion_service_keys import OnionPublicKeyContact, OnionPublicKeyUser
    from src.common.crypto.keys.kek_hash import KEKHash
    from src.common.crypto.pt_ct import LocalKeySetCT, MulticastFileCT
    from src.common.crypto.keys.symmetric_key import (MessageKeyUser, HeaderKeyUser, MessageKeyContact, HeaderKeyContact,
                                                      MasterKeyRekeying, LocalHeaderKey, LocalMessageKey, MulticastFileKey)
    from src.database.db_settings import Settings
    from src.datagrams.receiver.file_multicast import DatagramFileMulticastFragment
    from src.datagrams.receiver.message import DatagramIncomingMessage, DatagramOutgoingMessage
    from src.ui.transmitter.window_tx import TxWindow, MockWindow


# ┌───────────────────────────────────────────────────────────────────────────┐
# │                               Compound Types                              │
# └───────────────────────────────────────────────────────────────────────────┘

KeyDBAddKeysetTuple              : TypeAlias = tuple[KeyDBMgmt, 'OnionPublicKeyContact', 'HeaderKeyUser', 'MessageKeyUser', 'HeaderKeyContact', 'MessageKeyContact']
KeyDBDeleteKeysetTuple           : TypeAlias = tuple[KeyDBMgmt, 'OnionPublicKeyContact']
KeyDBUpdateRowsTuple             : TypeAlias = tuple[KeyDBMgmt, 'Settings']
KeyDBUpdateMasterKeyTuple        : TypeAlias = tuple[KeyDBMgmt, 'MasterKeyRekeying']
KeyDBWaitForSyncTuple            : TypeAlias = tuple[KeyDBMgmt]
KeyDBReleaseWaitTuple            : TypeAlias = tuple[Literal[KeyDBMgmt.RELEASE_WAIT]]
LocalKeyDBUpsertLocalKeysetTuple : TypeAlias = tuple[LocalKeyDBMgmt, 'LocalHeaderKey', 'LocalMessageKey', 'KEKHash']
LocalKeyDBUpdateMasterKeyTuple   : TypeAlias = tuple[LocalKeyDBMgmt, 'MasterKeyRekeying']
LocalKeyDBWaitForSyncTuple       : TypeAlias = tuple[LocalKeyDBMgmt]
LogWriterUpdateMasterKeyTuple    : TypeAlias = tuple[Literal[LogWriterMgmt.UPDATE_MASTER_KEY], 'MasterKeyRekeying']
LogWriterWaitForSyncTuple        : TypeAlias = tuple[Literal[LogWriterMgmt.WAIT_FOR_SYNC]]
TorDataTuple                     : TypeAlias = tuple[IntPortNumberTor, 'OnionPublicKeyUser']
ClientMgmtCommandTuple           : TypeAlias = tuple[QueueSignal, list['OnionPublicKeyContact'], BoolIsPending]
GroupMgmtMessageTuple            : TypeAlias = tuple[DatagramHeader, bytes, 'OnionPublicKeyContact']
GroupMgmtTuple                   : TypeAlias = tuple[QueueSignal, 'OnionPublicKeyContact']
ContactListMgmtTuple             : TypeAlias = tuple[QueueSignal, list['OnionPublicKeyContact']]
BoolLogThisAssemblyPacket        : TypeAlias = BoolLogMessages
MulticastFileFragmentDict        : TypeAlias = dict['OnionPublicKeyContact', list['DatagramFileMulticastFragment']]

KeyStoreMgmt : TypeAlias = (KeyDBAddKeysetTuple
                            | KeyDBDeleteKeysetTuple
                            | KeyDBUpdateRowsTuple
                            | KeyDBUpdateMasterKeyTuple
                            | KeyDBWaitForSyncTuple)

KeyDBAckQueueData : TypeAlias = (KeyDBReleaseWaitTuple
                                 | KeyDBUpdateRowsTuple
                                 | KeyDBUpdateMasterKeyTuple)

LocalKeyMgmt : TypeAlias = (LocalKeyDBUpsertLocalKeysetTuple
                            | LocalKeyDBUpdateMasterKeyTuple
                            | LocalKeyDBWaitForSyncTuple)

LogWriterQueueData : TypeAlias = (LogWriterUpdateMasterKeyTuple
                                  | LogWriterWaitForSyncTuple)

ContactSetting : TypeAlias = BoolLogMessages | BoolFileReception | BoolShowNotifications

BoolSettingValue : TypeAlias = (BoolDisableGuiDialog
                                | BoolLogMessages
                                | BoolFileReception
                                | BoolShowNotifications
                                | BoolLogFileMasking
                                | BoolAskPasswordForLogAccess
                                | BoolNcBypassMessages
                                | BoolConfirmTMFiles
                                | BoolDoubleSpaceExits
                                | BoolTrafficMasking
                                | BoolRequireResends
                                | BoolAutoreplayLoop
                                | BoolAllowContactRequests
                                | BoolNewMessageNotifyPreview
                                | BoolUseSerialUSBAdapter)

IntSettingValue : TypeAlias = (IntMaxNumberOfGroupMembers
                               | IntMaxNumberOfGroups
                               | IntMaxNumberOfContacts
                               | IntAutoreplayTimes
                               | IntMaxDecompressSizeMB
                               | IntSerialBaudrate
                               | IntSerialErrorCorrection)

FloatSettingValue   : TypeAlias = FloatTMStaticDelay | FloatTMRandomDelay | FloatNewMessageNotifyDuration
StrSettingValueDB   : TypeAlias = StrBuiltInSerialInterface
TFCSettingValue     : TypeAlias = BoolSettingValue | IntSettingValue | FloatSettingValue
GatewaySettingValue : TypeAlias = BoolUseSerialUSBAdapter | IntSerialBaudrate | IntSerialErrorCorrection | StrSettingValueDB
AnySettingValue     : TypeAlias = TFCSettingValue | GatewaySettingValue

BoolSettingLimits  : TypeAlias = tuple[SettingLimitsBool, SettingLimitsBool]
IntSettingLimits   : TypeAlias = tuple[SettingLimitsInt, SettingLimitsInt]
FloatSettingLimits : TypeAlias = tuple[SettingLimitsFloat, SettingLimitsFloat]

DispatcherSettingUpdate : TypeAlias = (tuple[Literal[TFCSettingKey.REQUIRE_RESENDS], BoolRequireResends]
                                       | tuple[Literal[TFCSettingKey.AUTOREPLAY_LOOP], BoolAutoreplayLoop])

ReplaySettingUpdate : TypeAlias = (tuple[Literal[TFCSettingKey.REQUIRE_RESENDS], BoolRequireResends]
                                   | tuple[Literal[TFCSettingKey.AUTOREPLAY_TIMES], IntAutoreplayTimes]
                                   | tuple[Literal[TFCSettingKey.AUTOREPLAY_LOOP], BoolAutoreplayLoop])

StandardPacketQueueData : TypeAlias = tuple['MessageAssemblyPacket',
                                            'OnionPublicKeyContact',
                                            BoolLogMessages,
                                            BoolLogAsPlaceHolder,
                                            BytesWindowUID]

TrafficMaskingCommandQueueData : TypeAlias = tuple['CommandAssemblyPacket',
                                                   BoolLogMessages,
                                                   BoolLogAsPlaceHolder]

TrafficMaskingMessageQueueData : TypeAlias = tuple['MessageAssemblyPacket',
                                                   BoolLogMessages,
                                                   BoolLogAsPlaceHolder]

LogQueueData : TypeAlias = tuple[O['OnionPublicKeyContact'],
                                   'AssemblyPacket',
                                    BoolLogMessages,
                                    BoolLogAsPlaceHolder]

LocalKeyQueueData : TypeAlias = tuple[datetime,
                                      'LocalKeySetCT']

NormalSenderMsgBuffer : TypeAlias = dict['OnionPublicKeyContact', list[StandardPacketQueueData]]

TxWindows : TypeAlias = 'MockWindow|TxWindow'

DatagramBufferDict : TypeAlias = dict['OnionPublicKeyContact', list['DatagramIncomingMessage|DatagramOutgoingMessage']]
FileBufferDict     : TypeAlias = dict['OnionPublicKeyContact', tuple[datetime, 'MulticastFileCT']]

# Note: the dict keys are concatenations of
# serialized contact onion addresses, and
# file ciphertexts
FileKeyDict : TypeAlias = dict[bytes, 'MulticastFileKey']

