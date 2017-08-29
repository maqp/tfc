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

"""Program details"""
TFC     = 'TFC'
VERSION = '1.17.08'


"""Identifiers"""
LOCAL_ID      = 'local_id'
DUMMY_CONTACT = 'dummy_contact'
DUMMY_USER    = 'dummy_user'
DUMMY_STR     = 'dummy_str'
DUMMY_MEMBER  = 'dummy_member'
DUMMY_GROUP   = 'dummy_group'
TX            = 'tx'
RX            = 'rx'
NH            = 'nh'
TAILS         = b'Tails'


"""Window identifiers (string)"""
WIN_TYPE_COMMAND = 'win_type_command'
WIN_TYPE_FILE    = 'win_type_file'
WIN_TYPE_CONTACT = 'win_type_contact'
WIN_TYPE_GROUP   = 'win_type_group'


"""Packet types"""
COMMAND = 'command'
FILE    = 'file'
MESSAGE = 'message'


"""Group message IDs"""
NEW_GROUP        = 'new_group'
ADDED_MEMBERS    = 'added_members'
ALREADY_MEMBER   = 'already_member'
REMOVED_MEMBERS  = 'removed_members'
NOT_IN_GROUP     = 'not_in_group'
UNKNOWN_ACCOUNTS = 'unknown_accounts'


"""Base58 key types"""
B58_PUB_KEY   = 'b58_pub_key'
B58_LOCAL_KEY = 'b58_local_key'
B58_FILE_KEY  = 'b58_file_key'


"""Key exchange types"""
X25519 = 'x25519'
PSK    = 'psk'


"""Contact setting types"""
LOGGING = 'logging'
STORE   = 'store'
NOTIFY  = 'notify'


"""Command identifiers"""
CLEAR = 'clear'
RESET = 'reset'


"""Contact setting management"""
ENABLE  = b'es'
DISABLE = b'ds'
ALL     = 'all'


"""NH bypass states"""
NH_BYPASS_START = 'nh_bypass_start'
NH_BYPASS_STOP  = 'nh_bypass_stop'
RESEND          = 'resend'


"""Phase messages"""
DONE = 'DONE'


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
NORMAL_TEXT             = '\033[0m'


"""Separators

Separator byte/char is a non-printable byte used
to separate fields in serialized data structures.
"""
US_BYTE = b'\x1f'
US_STR  =  '\x1f'


"""Datagram headers

These headers are prepended to datagrams that are transmitted over
Serial or over the network. They tell receiving device what type of
packet is in question.

Local key packets are only accepted by NH from local TxM. Even if NH is
compromised, the worst case scenario is a denial of service attack 
where RxM receives new local keys. As user does not know the correct 
decryption key, they would have to manually cancel packets.

Public keys are delivered from contact all the way to RxM provided they
are of correct format.

Message and command packet headers tell RxM whether to parse trailing
fields that determine which XSalsa20-Poly1305 decryption keys it should 
load. Contacts can alter their packets to deliver COMMAND_PACKET_HEADER 
header, but NH will by design drop them and even if it somehow couldn't, 
RxM would drop the packet after MAC verification of encrypted harac 
fails.

Unencrypted packet headers are intended to notify NH that the packet
is intended for it. These commands are not delivered to RxM, but a 
standard encrypted command is sent to RxM before any unencrypted command 
is sent to NH. During traffic masking connection, unencrypted commands 
are disabled to hide the quantity and schedule of communication even if 
NH is compromised and monitoring the user. Unencrypted commands do not 
cause issues in security because if adversary can compromise NH to the 
point it can issue commands to NH, they could DoS NH anyway.

File CT headers are for file export from TxM to NH and in receiving end,
import from NH to RxM.
"""
LOCAL_KEY_PACKET_HEADER   = b'L'
PUBLIC_KEY_PACKET_HEADER  = b'P'
MESSAGE_PACKET_HEADER     = b'M'
COMMAND_PACKET_HEADER     = b'Y'
UNENCRYPTED_PACKET_HEADER = b'U'
EXPORTED_FILE_HEADER      = b'O'
IMPORTED_FILE_HEADER      = b'I'


"""Assembly packet headers

These one byte assembly packet headers are not part of the padded 
message parsed from assembly packets. They are however the very first
plaintext byte, prepended to every padded assembly packet delivered to
recipient or local RxM. They deliver information about if and when to
process the packet and when to drop previously collected assembly 
packets.
"""
M_S_HEADER = b'a'  # Short message packet
M_L_HEADER = b'b'  # First packet of multi-packet message
M_A_HEADER = b'c'  # Appended packet of multi-packet message
M_E_HEADER = b'd'  # Last packet of multi-packet message
M_C_HEADER = b'e'  # Cancelled multi-packet message
P_N_HEADER = b'f'  # Noise message packet

F_S_HEADER = b'A'  # Short file packet
F_L_HEADER = b'B'  # First packet of multi-packet file
F_A_HEADER = b'C'  # Appended packet of multi-packet file
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
not be used during traffic masking to hide when TFC is being used. These 
commands are not encrypted because if attacker is able to inject 
commands from within NH, they could also access any keys stored on NH.
"""
UNENCRYPTED_SCREEN_CLEAR   = b'UC'
UNENCRYPTED_SCREEN_RESET   = b'UR'
UNENCRYPTED_EXIT_COMMAND   = b'UX'
UNENCRYPTED_IMPORT_COMMAND = b'UI'
UNENCRYPTED_EC_RATIO       = b'UE'
UNENCRYPTED_BAUDRATE       = b'UB'
UNENCRYPTED_GUI_DIALOG     = b'UD'
UNENCRYPTED_WIPE_COMMAND   = b'UW'


"""Encrypted command headers

These two-byte headers are prepended to each command delivered to local
RxM. The header is evaluated after RxM has received all assembly packets
of one transmission. These headers tell RxM to what function the command
must be redirected to.
"""
LOCAL_KEY_INSTALLED_HEADER  = b'LI'
SHOW_WINDOW_ACTIVITY_HEADER = b'SA'
WINDOW_SELECT_HEADER        = b'WS'
CLEAR_SCREEN_HEADER         = b'SC'
RESET_SCREEN_HEADER         = b'SR'
EXIT_PROGRAM_HEADER         = b'EX'
LOG_DISPLAY_HEADER          = b'LD'
LOG_EXPORT_HEADER           = b'LE'
LOG_REMOVE_HEADER           = b'LR'
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
KEY_EX_X25519_HEADER        = b'KE'
KEY_EX_PSK_TX_HEADER        = b'KT'
KEY_EX_PSK_RX_HEADER        = b'KR'
CONTACT_REMOVE_HEADER       = b'CR'
WIPE_USER_DATA_HEADER       = b'WD'


"""Origin headers

This one byte header notifies RxM whether the account 
included in the packet is the source or destination.
"""
ORIGIN_USER_HEADER    = b'o'
ORIGIN_CONTACT_HEADER = b'i'


"""Message headers

This one byte header will be prepended to each plaintext message prior 
to padding and splitting the message. It will be evaluated once RxM has 
received all assembly packets. It allows RxM to detect whether the 
message should be displayed on private or group window. This does not 
allow spoofing of messages in unauthorized group windows, because the 
(group configuration managed personally by the recipient) white lists 
accounts who are authorized to display the message under the group 
window.

Whisper message header is message with "sender based control". Unless
contact is malicious, these messages are not logged.
"""
PRIVATE_MESSAGE_HEADER = b'p'
GROUP_MESSAGE_HEADER   = b'g'
WHISPER_MESSAGE_HEADER = b'w'


"""Group management headers

Group messages are automatically parsed messages that TxM recommends 
user to send when they make changes to group members or add/remove 
groups. These messages are displayed temporarily on whatever active 
window and later in command window.
"""
GROUP_MSG_INVITEJOIN_HEADER = b'T'
GROUP_MSG_MEMBER_ADD_HEADER = b'N'
GROUP_MSG_MEMBER_REM_HEADER = b'R'
GROUP_MSG_EXIT_GROUP_HEADER = b'X'


"""Delays

Traffic masking packet queue check delay ensures that 
the lookup time for packet queue is obfuscated.
"""
TRAFFIC_MASKING_QUEUE_CHECK_DELAY = 0.1


"""Constant time delay types"""
STATIC          = 'static'
TRAFFIC_MASKING = 'traffic_masking'


"""Default folders"""
DIR_USER_DATA = 'user_data/'
DIR_RX_FILES  = 'received_files/'
DIR_IMPORTED  = 'imported_files/'


"""Regular expressions

These are used to specify exact format of some inputs.
"""
ACCOUNT_FORMAT = '(^.[^/:,]*@.[^/:,]*\.[^/:,]*.$)'  # <something>@<something>.<something>


"""Queue dictionary keys"""

# Common
EXIT_QUEUE     = b'exit'
GATEWAY_QUEUE  = b'gateway'
UNITTEST_QUEUE = b'unittest_queue'

# Transmitter
MESSAGE_PACKET_QUEUE = b'message_packet'
FILE_PACKET_QUEUE    = b'file_packet'
COMMAND_PACKET_QUEUE = b'command_packet'
NH_PACKET_QUEUE      = b'nh_packet'
LOG_PACKET_QUEUE     = b'log_packet'
NOISE_PACKET_QUEUE   = b'noise_packet'
NOISE_COMMAND_QUEUE  = b'noise_command'
KEY_MANAGEMENT_QUEUE = b'key_management'
WINDOW_SELECT_QUEUE  = b'window_select'

# NH
TXM_INCOMING_QUEUE = b'txm_incoming'
RXM_OUTGOING_QUEUE = b'rxm_outgoing'
TXM_TO_IM_QUEUE    = b'txm_to_im'
TXM_TO_NH_QUEUE    = b'txm_to_nh'
TXM_TO_RXM_QUEUE   = b'txm_to_rxm'
NH_TO_IM_QUEUE     = b'nh_to_im'


"""Queue signals"""
KDB_ADD_ENTRY_HEADER         = 'ADD'
KDB_REMOVE_ENTRY_HEADER      = 'REM'
KDB_CHANGE_MASTER_KEY_HEADER = 'KEY'
EXIT                         = 'EXIT'
WIPE                         = 'WIPE'


"""Static values

These values are not settings but descriptive integer values.
"""

# Misc
BAUDS_PER_BYTE    = 10
COMPRESSION_LEVEL = 9
ENTROPY_THRESHOLD = 512

# Forward secrecy
INITIAL_HARAC        = 0
HARAC_WARN_THRESHOLD = 1000

# CLI indents
CONTACT_LIST_INDENT = 4
SETTINGS_INDENT     = 2

# Local testing
TXM_DD_LISTEN_SOCKET       = 5000
NH_LISTEN_SOCKET           = 5001
RXM_DD_LISTEN_SOCKET       = 5002
RXM_LISTEN_SOCKET          = 5003
LOCAL_TESTING_PACKET_DELAY = 0.1

# Field lengths
BOOLEAN_SETTING_LEN  = 1
ORIGIN_HEADER_LEN    = 1
TIMESTAMP_LEN        = 4
INTEGER_SETTING_LEN  = 8
FLOAT_SETTING_LEN    = 8
FILE_PACKET_CTR_LEN  = 8
FILE_ETA_FIELD_LEN   = 8
FILE_SIZE_FIELD_LEN  = 8
GROUP_MSG_ID_LEN     = 16
GROUP_DB_HEADER_LEN  = 32
PADDED_UTF32_STR_LEN = 1024

ARGON2_SALT_LEN    = 32
ARGON2_ROUNDS      = 25
ARGON2_MIN_MEMORY  = 64000
XSALSA20_NONCE_LEN = 24
POLY1305_TAG_LEN   = 16

FINGERPRINT_LEN = 32
KEY_LENGTH      = 32
HARAC_LEN       = 8
B58_CHKSUM_LEN  = 4

PADDING_LEN         = 255
ASSEMBLY_PACKET_LEN = 256

# Special messages
PLACEHOLDER_DATA = P_N_HEADER + bytes(PADDING_LEN)


# Field lengths
MESSAGE_LENGTH = (XSALSA20_NONCE_LEN
                  + HARAC_LEN
                  + POLY1305_TAG_LEN

                  + XSALSA20_NONCE_LEN
                  + ASSEMBLY_PACKET_LEN
                  + POLY1305_TAG_LEN)

PACKET_LENGTH  = (len(MESSAGE_PACKET_HEADER)
                  + MESSAGE_LENGTH
                  + ORIGIN_HEADER_LEN)

CONTACT_LENGTH = (3*PADDED_UTF32_STR_LEN
                  + 2*FINGERPRINT_LEN
                  + 3*BOOLEAN_SETTING_LEN)

KEYSET_LENGTH = (PADDED_UTF32_STR_LEN
                 + 4*KEY_LENGTH
                 + 2*HARAC_LEN)

PSK_FILE_SIZE = (XSALSA20_NONCE_LEN
                 + ARGON2_SALT_LEN
                 + 2*KEY_LENGTH
                 + POLY1305_TAG_LEN)

LOG_ENTRY_LENGTH = (XSALSA20_NONCE_LEN
                    + PADDED_UTF32_STR_LEN
                    + TIMESTAMP_LEN
                    + ORIGIN_HEADER_LEN
                    + ASSEMBLY_PACKET_LEN
                    + POLY1305_TAG_LEN)

SETTING_LENGTH = (XSALSA20_NONCE_LEN
                  + 5*INTEGER_SETTING_LEN
                  + 4*FLOAT_SETTING_LEN
                  + 13*BOOLEAN_SETTING_LEN
                  + POLY1305_TAG_LEN)
