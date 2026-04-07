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

from typing import NewType

BoolAuthenticate               = NewType('BoolAuthenticate',             bool)
BoolCachePacket                = NewType('BoolCachePacket',              bool)
BoolDatagramDompleted          = NewType('BoolDatagramDompleted',        bool)
BoolExportLog                  = NewType('BoolExportLog',                bool)
BoolFileReception              = NewType('BoolFileReception',            bool)
BoolIsFileCommand              = NewType('BoolIsFileCommand',            bool)
BoolIsOnline                   = NewType('BoolIsOnline',                 bool)
BoolIsPending                  = NewType('BoolIsPending',                bool)
BoolIsWhisperedMessage         = NewType('BoolIsWhisperedMessage',       bool)
BoolLogAsPlaceHolder           = NewType('BoolLogAsPlaceHolder',         bool)
BoolLogMessages                = NewType('BoolLogMessages',              bool)
BoolRekeyDB                    = NewType('BoolRekeyDB',                  bool)
BoolReplaceDB                  = NewType('BoolReplaceDB',                bool)
BoolSelectWinByCmd             = NewType('BoolSelectWinByCmd',           bool)
BoolSettingValue               = NewType('BoolSettingValue',             bool)
BoolShowNotifications          = NewType('BoolShowNotifications',        bool)
BoolUnitTesting                = NewType('BoolUnitTesting',              bool)
BytesActiveSetup               = NewType('BytesActiveSetup',            bytes)
BytesAssembledFile             = NewType('BytesAssembledFile',          bytes)
BytesAssembledMessage          = NewType('BytesAssembledMessage',       bytes)
BytesFile                      = NewType('BytesFile',                   bytes)
BytesGroupMsgData              = NewType('BytesGroupMsgData',           bytes)
BytesMessage                   = NewType('BytesMessage',                bytes)
BytesRawMasterKey              = NewType('BytesRawMasterKey',           bytes)
BytesRelayCommand              = NewType('BytesRelayCommand',           bytes)
BytesServerB85Payload          = NewType('BytesServerB85Payload',       bytes)
BytesWindowUID                 = NewType('BytesWindowUID',              bytes)
FloatCheckDelay                = NewType('FloatCheckDelay',             float)
FloatRxReceiveTimeout          = NewType('FloatRxReceiveTimeout',       float)
FloatTxInterPacketDelay        = NewType('FloatTxInterPacketDelay',     float)
IntArgon2MemoryCost            = NewType('IntArgon2MemoryCost',           int)
IntArgon2Parallelism           = NewType('IntArgon2Parallelism',          int)
IntArgon2TimeCost              = NewType('IntArgon2TimeCost',             int)
IntIdleReplayIndex             = NewType('IntIdleReplayIndex',            int)
IntMsgToLoad                   = NewType('IntMsgToLoad',                  int)
IntPortNumberFlask             = NewType('IntPortNumberFlask',            int)
IntPortNumberTor               = NewType('IntPortNumberTor',              int)
IntRatchetOffset               = NewType('IntRatchetOffset',              int)
IntRatchetOffsetLocalKey       = NewType('IntRatchetOffsetLocalKey',      int)
IntStdInFD                     = NewType('IntStdInFD',                    int)
StrContactBufferFileDir        = NewType('StrContactBufferFileDir',       str)
StrOnionAddressContact         = NewType('StrOnionAddressContact',        str)
StrOnionAddressUser            = NewType('StrOnionAddressUser',           str)
StrPlaintextMessage            = NewType('StrPlaintextMessage',           str)
StrSelection                   = NewType('StrSelection',                  str)
StrSettingValue                = NewType('StrSettingValue',               str)
StrTorPathToBinary             = NewType('StrTorPathToBinary',            str)
StrTorPathToControlSocketFile  = NewType('StrTorPathToControlSocketFile', str)
StrUniqueBufferedFileName      = NewType('StrUniqueBufferedFileName',     str)
StrURLToken                    = NewType('StrURLToken',                   str)
StrWindowName                  = NewType('StrWindowName',                 str)

# Launch args
BoolLocalTest                  = NewType('BoolLocalTest',                 bool)
BoolDataDiodeSockets           = NewType('BoolDataDiodeSockets',          bool)
BoolQubes                      = NewType('BoolQubes',                     bool)
BoolTestRun                    = NewType('BoolTestRun',                   bool)

# Settings
BoolDisableGuiDialog           = NewType('BoolDisableGuiDialog',          bool)
IntMaxNumberOfGroupMembers     = NewType('IntMaxNumberOfGroupMembers',    int)
IntMaxNumberOfGroups           = NewType('IntMaxNumberOfGroups',          int)
IntMaxNumberOfContacts         = NewType('IntMaxNumberOfContacts',        int)
BoolLogMessagesByDefault       = NewType('BoolLogMessagesByDefault',      bool)
BoolAcceptFilesByDefault       = NewType('BoolAcceptFilesByDefault',      bool)
BoolShowNotificationsByDefault = NewType('BoolShowNotificationsByDefault',bool)
BoolLogFileMasking             = NewType('BoolLogFileMasking',            bool)
BoolAskPasswordForLogAccess    = NewType('BoolAskPasswordForLogAccess',   bool)
BoolNcBypassMessages           = NewType('BoolNcBypassMessages',          bool)
BoolConfirmTMFiles             = NewType('BoolConfirmTMFiles',            bool)
BoolDoubleSpaceExits           = NewType('BoolDoubleSpaceExits',          bool)
BoolTrafficMasking             = NewType('BoolTrafficMasking',            bool)
BoolRequireResends             = NewType('BoolRequireResends',            bool)
FloatTMDelay                   = NewType('FloatTMDelay',                  float)
FloatTMStaticDelay             = NewType('FloatTMStaticDelay',            float)
FloatTMRandomDelay             = NewType('FloatTMRandomDelay',            float)
IntAutoreplayTimes             = NewType('IntAutoreplayTimes',            int)
BoolAutoreplayLoop             = NewType('BoolAutoreplayLoop',            bool)
BoolAllowContactRequests       = NewType('BoolAllowContactRequests',      bool)
BoolNewMessageNotifyPreview    = NewType('BoolNewMessageNotifyPreview',   bool)
FloatNewMessageNotifyDuration  = NewType('FloatNewMessageNotifyDuration', float)
IntMaxDecompressSizeMB         = NewType('IntMaxDecompressSizeMB',        int)

# Gateway Settings
IntSerialBaudrate              = NewType('IntSerialBaudrate',             int)
IntSerialErrorCorrection       = NewType('IntSerialErrorCorrection',      int)
BoolUseSerialUSBAdapter        = NewType('BoolUseSerialUSBAdapter',      bool)
StrBuiltInSerialInterface      = NewType('StrBuiltInSerialInterface',     str)
