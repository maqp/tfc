#!/usr/bin/env python3.6
# -*- coding: utf-8 -*-

"""
Copyright (C) 2013-2017  Markus Ottela

This file is part of TFC.

TFC is free software: you can redistribute it and/or modify it under the terms
of the GNU General Public License as published by the Free Software Foundation,
either version 3 of the License, or (at your option) any later version.

TFC is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with TFC. If not, see <http://www.gnu.org/licenses/>.
"""


"""VT100 codes

VT100 codes are used to control printing to terminals. These
make building functions like text box drawers possible.
"""
CURSOR_UP_ONE_LINE      = '\x1b[1A'
CURSOR_RIGHT_ONE_COLUMN = '\x1b[1C'
CLEAR_ENTIRE_LINE       = '\x1b[2K'
CLEAR_ENTIRE_SCREEN     = '\x1b[2J'
CURSOR_LEFT_UP_CORNER   = '\x1b[H'
BOLD_ON                 = '\033[1m'
BOLD_OFF                = '\033[0m'


"""Separators

Separator byte/char is a non-printable byte used
to separate fields in serialized data structures.
"""
US_BYTE = b'\x1f'
US_STR  =  '\x1f'


"""Datagram headers

These headers are prepended to transmissions that are transmitted over
Serial or over the network. They tell receiving device what type of
packet is in question.

Local key packets are only accepted by NH from local TxM. Even if NH is
compromised, the worst case scenario is a denial of service attack where
RxM receives new local keys user has to cancel when they do not know the
key decryption key for.

Public keys are delivered from contact all the way to RxM provided they
are of correct format.

Message and command packet headers tell RxM whether to parse trailing
fields that determine which decryption keys for XSalsa20-Poly1305 it
should load. Contacts can alter their packets to deliver C header, but
NH will by design drop them and even if it somehow couldn't, RxM would
drop the packet after MAC verification of encrypted harac fails.

Unencrypted packet headers are intended to notify NH that the packet
is intended for it: Trailing the header follows a command for the NH.
These commands are not delivered to RxM, but a standard encrypted
command is sent to RxM before any unencrypted command is sent to NH.
During trickle connection, unencrypted commands are disabled to hide
the quantity and schedule of communication even if NH is compromised and
monitoring user. Unencrypted commands do not cause issues in security
because if adversary can compromise NH to the point it can issue
commands to NH, they could DoS NH anyway.

File CT headers are for faster non-trickle file export from TxM to NH
and in receiving end, import from NH to RxM.
"""
LOCAL_KEY_PACKET_HEADER   = b'L'
PUBLIC_KEY_PACKET_HEADER  = b'P'
MESSAGE_PACKET_HEADER     = b'M'
COMMAND_PACKET_HEADER     = b'C'
UNENCRYPTED_PACKET_HEADER = b'U'
EXPORTED_FILE_CT_HEADER   = b'E'
IMPORTED_FILE_CT_HEADER   = b'I'


"""Assembly packet headers

These one byte assembly packet headers are not part of the padded
message parsed from assembly packets. They are however the very first
plaintext byte, prepended to every padded assembly packet delivered to
recipient or local RxM. They deliver information about if and when to
process the packet and when to drop previously collected assembly packets.
"""
M_S_HEADER = b'a'  # Short message packet
M_L_HEADER = b'b'  # First packet of multi-packet message
M_A_HEADER = b'c'  # Appended packet of multi-packet message
M_E_HEADER = b'd'  # Last packet of multi-packet message
M_C_HEADER = b'e'  # Cancelled multi-packet message
P_N_HEADER = b'f'  # Noise message packet (no separate packet for files is needed)

F_S_HEADER = b'A'  # Short file packet
F_L_HEADER = b'B'  # First packet of multi-packet file
F_A_HEADER = b'C'  # Appended packet for multi-packet file
F_E_HEADER = b'D'  # Last packet of multi-packet file
F_C_HEADER = b'E'  # Cancelled multi-packet file

C_S_HEADER = b'0'  # Short command packet
C_L_HEADER = b'1'  # First packet of multi-packet command
C_A_HEADER = b'2'  # Appended packet of multi-packet command
C_E_HEADER = b'3'  # Last packet of multi-packet command
C_C_HEADER = b'4'  # Cancelled multi-packet command (not implemented)
C_N_HEADER = b'5'  # Noise command packet


"""Unencrypted command headers

These two-byte headers are only used to control NH. These commands will
not be used during trickle connection to hide when TFC is being used.
These commands are not encrypted because if attacker is able to inject
commands from within NH, it could also access any keys stored on NH.
"""
UNENCRYPTED_SCREEN_CLEAR   = b'SC'
UNENCRYPTED_SCREEN_RESET   = b'SR'
UNENCRYPTED_EXIT_COMMAND   = b'EX'
UNENCRYPTED_IMPORT_COMMAND = b'IF'
UNENCRYPTED_EC_RATIO       = b'EC'
UNENCRYPTED_BAUDRATE       = b'BR'
UNENCRYPTED_GUI_DIALOG     = b'GD'


"""Encrypted command headers

These two-byte headers are prepended to each command delivered to local
RxM. The header is evaluated after RxM has received all assembly packets
of one transmission. These headers tell RxM to what function the command
must be redirected to.
"""
LOCAL_KEY_INSTALLED_HEADER  = b'LI'
SHOW_WINDOW_ACTIVITY_HEADER = b'SA'
WINDOW_CHANGE_HEADER        = b'WS'
CLEAR_SCREEN_HEADER         = b'SC'
RESET_SCREEN_HEADER         = b'SR'
EXIT_PROGRAM_HEADER         = b'EX'
LOG_DISPLAY_HEADER          = b'LD'
LOG_EXPORT_HEADER           = b'LE'
CHANGE_MASTER_K_HEADER      = b'MK'
CHANGE_NICK_HEADER          = b'NC'
CHANGE_SETTING_HEADER       = b'CS'
CHANGE_LOGGING_HEADER       = b'CL'
CHANGE_FILE_R_HEADER        = b'CF'
CHANGE_NOTIFY_HEADER        = b'CN'
GROUP_CREATE_HEADER         = b'GC'
GROUP_ADD_HEADER            = b'GA'
GROUP_REMOVE_M_HEADER       = b'GR'
GROUP_DELETE_HEADER         = b'GD'
KEY_EX_ECDHE_HEADER         = b'KE'
KEY_EX_PSK_TX_HEADER        = b'KT'
KEY_EX_PSK_RX_HEADER        = b'KR'
CONTACT_REMOVE_HEADER       = b'CR'


"""Origin headers

This one byte header notifies RxM whether the account delivered with
packet is from user to that account or from the account to user.
"""
ORIGIN_USER_HEADER    = b'u'
ORIGIN_CONTACT_HEADER = b'c'


"""Message headers

This one byte header will be prepended to each plaintext message prior
to padding and splitting the message. It will be evaluated once RxM
has received all assembly packets. It allows RxM to detect whether
the message should be displayed on private or group window. This does
not allow spoofing of messages in unauthorized group windows, because
the group configuration managed personally by the recipient white lists
accounts who are authorized to display the message under the window.
"""
PRIVATE_MESSAGE_HEADER = b'P'
GROUP_MESSAGE_HEADER   = b'G'


"""Group management headers

Group messages are automatically parsed messages that TxM recommends user
to send when they make changes to group members or add/remove groups.
These messages are displayed temporarily on whatever active window and
later in command window.
"""
GROUP_MSG_INVITATION_HEADER = b'I'
GROUP_MSG_ADD_NOTIFY_HEADER = b'A'
GROUP_MSG_MEMBER_RM_HEADER  = b'R'
GROUP_MSG_EXIT_GROUP_HEADER = b'E'


"""Delays

Trickle packet queue check delay ensures that the lookup time for packet
queue is obfuscated.

Serial packet output delay ensures that receiving device will timeout
between datagrams.
"""
TRICKLE_QUEUE_CHECK_DELAY  = 0.1


"""Default folders"""
DIR_USER_DATA = 'user_data'
DIR_RX_FILES  = 'received_files'
DIR_IMPORTED  = 'imported_files'


"""Static identifiers"""
LOCAL_WIN_ID_BYTES  = b'local'
FILE_R_WIN_ID_BYTES = b'file_window'


"""Regular expressions

These are used to specify exact format of some inputs.
"""
ACCOUNT_FORMAT = "(^.[^/:,]*@.[^/:,]*\.[^/:,]*.$)"  # <something>@<something>.<something>


"""Queue dictionary keys"""

MESSAGE_PACKET_QUEUE = b'm'
FILE_PACKET_QUEUE    = b'f'
COMMAND_PACKET_QUEUE = b'c'
LOG_PACKET_QUEUE     = b'l'
NOISE_PACKET_QUEUE   = b'np'
NOISE_COMMAND_QUEUE  = b'nc'
KEY_MANAGEMENT_QUEUE = b'km'
WINDOW_SELECT_QUEUE  = b'ws'  # For trickle connection
GATEWAY_QUEUE        = b'gw'
