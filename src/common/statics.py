#!/usr/bin/env python3.7
# -*- coding: utf-8 -*-

"""
TFC - Onion-routed, endpoint secure messaging system
Copyright (C) 2013-2020  Markus Ottela

This file is part of TFC.

TFC is free software: you can redistribute it and/or modify it under the terms
of the GNU General Public License as published by the Free Software Foundation,
either version 3 of the License, or (at your option) any later version.

TFC is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with TFC. If not, see <https://www.gnu.org/licenses/>.
"""

"""Program details"""
TFC         = 'TFC'
VERSION     = '1.20.04'
TRANSMITTER = 'Transmitter'
RECEIVER    = 'Receiver'
RELAY       = 'Relay'


"""Identifiers

Placeholder accounts for databases need to be valid v3 Onion addresses.
"""
LOCAL_ID      = 'localidlocalidlocalidlocalidlocalidlocalidlocalidloj7uyd'
LOCAL_PUBKEY  = b'[\x84\x05\xa0kp\x80\xb4\rn\x10\x16\x81\xad\xc2\x02\xd05\xb8@Z\x06\xb7\x08\x0b@\xd6\xe1\x01h\x1a\xdc'
LOCAL_NICK    = 'local Source Computer'
DUMMY_CONTACT = 'dummycontactdummycontactdummycontactdummycontactdumhsiid'
DUMMY_MEMBER  = 'dummymemberdummymemberdummymemberdummymemberdummymedakad'
DUMMY_NICK    = 'dummy_nick'
DUMMY_GROUP   = 'dummy_group'
TX            = 'tx'
RX            = 'rx'
NC            = 'nc'
TAILS         = 'TAILS_PRODUCT_NAME="Tails"'


"""Window identifiers"""
WIN_TYPE_COMMAND = 'system messages'
WIN_TYPE_FILE    = 'incoming files'
WIN_TYPE_CONTACT = 'contact'
WIN_TYPE_GROUP   = 'group'


"""Window UIDs"""
WIN_UID_COMMAND = b"win_uid_command"
WIN_UID_FILE    = b'win_uid_file'


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


"""Base58 encoding"""
B58_ALPHABET   = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
MAINNET_HEADER = b'\x80'
TESTNET_HEADER = b'\xef'


"""Base58 key types"""
B58_PUBLIC_KEY = 'b58_public_key'
B58_LOCAL_KEY  = 'b58_local_key'


"""Base58 key input guides"""
B58_PUBLIC_KEY_GUIDE = '   A       B       C       D       E       F       G       H       I       J       K       L   '
B58_LOCAL_KEY_GUIDE  = ' A   B   C   D   E   F   G   H   I   J   K   L   M   N   O   P   Q '


"""Key exchange types"""
ECDHE = 'X448'
PSK   = 'PSK'


"""Contact setting types"""
LOGGING = 'logging'
STORE   = 'store'
NOTIFY  = 'notify'


"""Command identifiers"""
CLEAR    = 'clear'
RESET    = 'reset'
POWEROFF = 'systemctl poweroff'
GENERATE = 'generate'


"""Contact setting management"""
CONTACT_SETTING_HEADER_LENGTH = 2
ENABLE                        = b'es'
DISABLE                       = b'ds'
ALL                           = 'all'


"""Networked Computer bypass states"""
NC_BYPASS_START = 'nc_bypass_start'
NC_BYPASS_STOP  = 'nc_bypass_stop'


"""Status messages"""
DONE  = 'DONE'
EVENT = '-!-'
ME    = 'Me'


"""Data diode simulator identifiers"""
IDLE      = 'Idle'
DATA_FLOW = 'Data flow'
SCNCLR    = 'scnclr'
SCNCRL    = 'scncrl'
NCDCLR    = 'ncdclr'
NCDCRL    = 'ncdcrl'


"""VT100 codes

VT100 codes are used to control printing to the terminal. These make
building functions like textbox drawers possible.
"""
CURSOR_UP_ONE_LINE      = '\x1b[1A'
CURSOR_RIGHT_ONE_COLUMN = '\x1b[1C'
CLEAR_ENTIRE_LINE       = '\x1b[2K'
CLEAR_ENTIRE_SCREEN     = '\x1b[2J'
CURSOR_LEFT_UP_CORNER   = '\x1b[H'
BOLD_ON                 = '\033[1m'
NORMAL_TEXT             = '\033[0m'


"""Separators

Separator byte is a non-printable byte used to separate fields in
serialized data structures.
"""
US_BYTE = b'\x1f'


"""Datagram headers

These headers are prepended to datagrams that are transmitted over
serial or over the network. They tell the receiving device what type of
datagram is in question.

Datagrams with local key header contain the encrypted local key, used to
encrypt commands and data transferred between local Source and
Destination computers. Packets with the header are only accepted by the
Relay Program when they originate from the user's Source Computer. Even
if the Networked Computer is compromised and the local key datagram is
injected to the Destination Computer, the injected key could not be
accepted by the user as they don't know the decryption key for it. The
worst case scenario is a DoS attack where the Receiver Program receives
new local keys continuously. Such an attack would, however, reveal the
user they are under a sophisticated attack, and that their Networked
Computer has been compromised.

Datagrams with Public key header contain TCB-level public keys that
originate from the sender's Source Computer, and are displayed by the
recipient's Networked Computer, from where they are manually typed to
recipient's Destination Computer.

Message and command type datagrams tell the Receiver Program whether to
parse the trailing fields that determine which XChaCha20-Poly1305
decryption keys it should load. Contacts can of course try to alter
their datagrams to contain a COMMAND_DATAGRAM_HEADER header, but Relay
Program will by design drop them. Even if a compromised Networked
Computer injects such a datagram to Destination Computer, the Receiver
Program will drop the datagram when the MAC verification of the
encrypted hash ratchet counter value fails.

File type datagram contains an encrypted file that the Receiver Program
caches until its decryption key arrives from the sender inside a
special, automated key delivery message.

Unencrypted type datagrams contain commands intended for the Relay
Program. These commands are in some cases preceded by an encrypted
version of the command, that the Relay Program forwards to Receiver
Program on Destination Computer. The unencrypted Relay commands are
disabled during traffic masking to hide the quantity and schedule of
communication even from the Networked Computer (in case it's compromised
and monitoring the user). The fact these commands are unencrypted, do
not cause security issues because if an adversary can compromise the
Networked Computer to the point it can issue commands to the Relay
Program, they could DoS the Relay Program, and thus TFC, anyway.
"""
DATAGRAM_TIMESTAMP_LENGTH   = 8
DATAGRAM_HEADER_LENGTH      = 1
LOCAL_KEY_DATAGRAM_HEADER   = b'L'
PUBLIC_KEY_DATAGRAM_HEADER  = b'P'
MESSAGE_DATAGRAM_HEADER     = b'M'
COMMAND_DATAGRAM_HEADER     = b'K'
FILE_DATAGRAM_HEADER        = b'F'
UNENCRYPTED_DATAGRAM_HEADER = b'U'


"""Group management headers

Group management datagrams are are automatic messages that the
Transmitter Program recommends the user to send when they make changes
to the member list of a group, or when they add or remove groups. These
messages are displayed by the Relay Program.
"""
GROUP_ID_LENGTH             = 4
GROUP_ID_ENC_LENGTH         = 13
GROUP_MSG_ID_LENGTH         = 16
GROUP_MGMT_HEADER_LENGTH    = 1
GROUP_MSG_INVITE_HEADER     = b'I'
GROUP_MSG_JOIN_HEADER       = b'J'
GROUP_MSG_MEMBER_ADD_HEADER = b'N'
GROUP_MSG_MEMBER_REM_HEADER = b'R'
GROUP_MSG_EXIT_GROUP_HEADER = b'X'


"""Assembly packet headers

These one-byte assembly packet headers are not part of the padded
message parsed from assembly packets. They are however the very first
plaintext byte, prepended to every padded assembly packet that is
delivered to the recipient/local Destination Computer. The header
delivers the information about if and when to assemble the packet,
as well as when to drop any previously collected assembly packets.
"""
FILE_PACKET_CTR_LENGTH        = 8
ASSEMBLY_PACKET_HEADER_LENGTH = 1

M_S_HEADER = b'a'  # Short message packet
M_L_HEADER = b'b'  # First    packet of multi-packet message
M_A_HEADER = b'c'  # Appended packet of multi-packet message
M_E_HEADER = b'd'  # Last     packet of multi-packet message
M_C_HEADER = b'e'  # Cancelled          multi-packet message
P_N_HEADER = b'f'  # Noise message packet

F_S_HEADER = b'A'  # Short file packet
F_L_HEADER = b'B'  # First    packet of multi-packet file
F_A_HEADER = b'C'  # Appended packet of multi-packet file
F_E_HEADER = b'D'  # Last     packet of multi-packet file
F_C_HEADER = b'E'  # Cancelled          multi-packet file

C_S_HEADER = b'0'  # Short command packet
C_L_HEADER = b'1'  # First    packet of multi-packet command
C_A_HEADER = b'2'  # Appended packet of multi-packet command
C_E_HEADER = b'3'  # Last     packet of multi-packet command
C_C_HEADER = b'4'  # Cancelled          multi-packet command (reserved but not in use)
C_N_HEADER = b'5'  # Noise command packet


"""Unencrypted command headers

These two-byte headers are only used to control the Relay Program on
Networked Computer. These commands will not be used during traffic
masking, as they would reveal when TFC is being used. These commands do
not require encryption, because if an attacker can compromise the
Networked Computer to the point it could inject commands to Relay
Program, it could most likely also access any decryption keys used by
the Relay Program.
"""
UNENCRYPTED_COMMAND_HEADER_LENGTH = 2

UNENCRYPTED_SCREEN_CLEAR         = b'UC'
UNENCRYPTED_SCREEN_RESET         = b'UR'
UNENCRYPTED_EXIT_COMMAND         = b'UX'
UNENCRYPTED_EC_RATIO             = b'UE'
UNENCRYPTED_BAUDRATE             = b'UB'
UNENCRYPTED_WIPE_COMMAND         = b'UW'
UNENCRYPTED_ADD_NEW_CONTACT      = b'UN'
UNENCRYPTED_ADD_EXISTING_CONTACT = b'UA'
UNENCRYPTED_REM_CONTACT          = b'UD'
UNENCRYPTED_ONION_SERVICE_DATA   = b'UO'
UNENCRYPTED_MANAGE_CONTACT_REQ   = b'UM'
UNENCRYPTED_PUBKEY_CHECK         = b'UP'
UNENCRYPTED_ACCOUNT_CHECK        = b'UT'


"""Encrypted command headers

These two-byte headers determine the type of command for Receiver
Program on local Destination Computer. The header is evaluated after the
Receiver Program has received all assembly packets and assembled the
command. These headers tell the Receiver Program to which function the
provided parameters (if any) must be redirected.
"""
ENCRYPTED_COMMAND_HEADER_LENGTH = 2

LOCAL_KEY_RDY = b'LI'
WIN_ACTIVITY  = b'SA'
WIN_SELECT    = b'WS'
CLEAR_SCREEN  = b'SC'
RESET_SCREEN  = b'SR'
EXIT_PROGRAM  = b'EX'
LOG_DISPLAY   = b'LD'
LOG_EXPORT    = b'LE'
LOG_REMOVE    = b'LR'
CH_MASTER_KEY = b'MK'
CH_NICKNAME   = b'NC'
CH_SETTING    = b'CS'
CH_LOGGING    = b'CL'
CH_FILE_RECV  = b'CF'
CH_NOTIFY     = b'CN'
GROUP_CREATE  = b'GC'
GROUP_ADD     = b'GA'
GROUP_REMOVE  = b'GR'
GROUP_DELETE  = b'GD'
GROUP_RENAME  = b'GN'
KEY_EX_ECDHE  = b'KE'
KEY_EX_PSK_TX = b'KT'
KEY_EX_PSK_RX = b'KR'
CONTACT_REM   = b'CR'
WIPE_USR_DATA = b'WD'


"""Origin headers

This one-byte header tells the Relay and Receiver Programs whether the
account included in the packet is the source or the destination of the
transmission. The user origin header is used when the Relay Program
forwards the message packets from user's Source Computer to user's
Destination Computer. The contact origin header is used when the program
forwards packets that are loaded from servers of contacts to the user's
Destination Computer.

On Destination Computer, the Receiver Program uses the origin header to
determine which unidirectional keys it should load to decrypt the
datagram payload.
"""
ORIGIN_HEADER_LENGTH  = 1
ORIGIN_USER_HEADER    = b'o'
ORIGIN_CONTACT_HEADER = b'i'


"""Message headers

This one-byte header will be prepended to each plaintext message before
padding and splitting the message. It will be evaluated once the Relay
Program has received all assembly packets and assembled the message.

The private and group message headers allow the Receiver Program to
determine whether the message should be displayed in a private or in a
group window. This does not allow re-direction of messages to
unauthorized group windows, because TFC's manually managed group
configuration is also a whitelist for accounts that are authorized to
display messages under the group's window.

Messages with the whisper message header have "sender-based control".
Unless the contact maliciously alters their Receiver Program's behavior,
whispered messages are not logged regardless of in-program controlled
settings.

Messages with file key header contain the hash of the file ciphertext
that was sent to the user earlier. It also contains the symmetric
decryption key for that file.
"""
MESSAGE_HEADER_LENGTH  = 1
WHISPER_FIELD_LENGTH   = 1
PRIVATE_MESSAGE_HEADER = b'p'
GROUP_MESSAGE_HEADER   = b'g'
FILE_KEY_HEADER        = b'k'


"""Delays

Traffic masking packet queue check delay ensures that the lookup time
for the packet queue is obfuscated.

The local testing packet delay is an arbitrary delay that simulates the
slight delay caused by data transmission over a serial interface.

The Relay client delays are values that determine the delays between
checking the online status of the contact (and the state of their
ephemeral URL token public key).
"""
TRAFFIC_MASKING_QUEUE_CHECK_DELAY = 0.1
TRAFFIC_MASKING_MIN_STATIC_DELAY  = 0.1
TRAFFIC_MASKING_MIN_RANDOM_DELAY  = 0.1
LOCAL_TESTING_PACKET_DELAY        = 0.1
RELAY_CLIENT_MAX_DELAY            = 8
RELAY_CLIENT_MIN_DELAY            = 0.125
CLIENT_OFFLINE_THRESHOLD          = 4.0


"""Constant time delay types"""
STATIC          = 'static'
TRAFFIC_MASKING = 'traffic_masking'


"""Default directories"""
DIR_USER_DATA  = 'user_data/'
DIR_RECV_FILES = 'received_files/'
DIR_TFC        = 'tfc/'
TEMP_POSTFIX   = '_temp'


"""Key exchange status states"""
KEX_STATUS_LENGTH     = 1
KEX_STATUS_NONE       = b'\xa0'
KEX_STATUS_PENDING    = b'\xa1'
KEX_STATUS_UNVERIFIED = b'\xa2'
KEX_STATUS_VERIFIED   = b'\xa3'
KEX_STATUS_NO_RX_PSK  = b'\xa4'
KEX_STATUS_HAS_RX_PSK = b'\xa5'
KEX_STATUS_LOCAL_KEY  = b'\xa6'


"""Queue dictionary keys"""
# Common
EXIT_QUEUE      = b'exit'
GATEWAY_QUEUE   = b'gateway'
UNIT_TEST_QUEUE = b'unit_test'

# Transmitter
MESSAGE_PACKET_QUEUE    = b'message_packet'
COMMAND_PACKET_QUEUE    = b'command_packet'
TM_MESSAGE_PACKET_QUEUE = b'tm_message_packet'
TM_FILE_PACKET_QUEUE    = b'tm_file_packet'
TM_COMMAND_PACKET_QUEUE = b'tm_command_packet'
TM_NOISE_PACKET_QUEUE   = b'tm_noise_packet'
TM_NOISE_COMMAND_QUEUE  = b'tm_noise_command'
RELAY_PACKET_QUEUE      = b'relay_packet'
LOG_PACKET_QUEUE        = b'log_packet'
LOG_SETTING_QUEUE       = b'log_setting'
TRAFFIC_MASKING_QUEUE   = b'traffic_masking'
LOGFILE_MASKING_QUEUE   = b'logfile_masking'
KEY_MANAGEMENT_QUEUE    = b'key_management'
KEY_MGMT_ACK_QUEUE      = b'key_mgmt_ack'
SENDER_MODE_QUEUE       = b'sender_mode'
WINDOW_SELECT_QUEUE     = b'window_select'

# Relay
DST_COMMAND_QUEUE   = b'dst_command'
DST_MESSAGE_QUEUE   = b'dst_message'
M_TO_FLASK_QUEUE    = b'm_to_flask'
F_TO_FLASK_QUEUE    = b'f_to_flask'
SRC_TO_RELAY_QUEUE  = b'src_to_relay'
URL_TOKEN_QUEUE     = b'url_token'
GROUP_MGMT_QUEUE    = b'group_mgmt'
GROUP_MSG_QUEUE     = b'group_msg'
CONTACT_REQ_QUEUE   = b'contact_req'
C_REQ_MGMT_QUEUE    = b'c_req_mgmt'
CONTACT_MGMT_QUEUE  = b'contact_mgmt'
C_REQ_STATE_QUEUE   = b'c_req_state'
ONION_KEY_QUEUE     = b'onion_key'
ONION_CLOSE_QUEUE   = b'close_onion'
TOR_DATA_QUEUE      = b'tor_data'
PUB_KEY_CHECK_QUEUE = b'pubkey_check'
PUB_KEY_SEND_QUEUE  = b'pubkey_send'
ACCOUNT_CHECK_QUEUE = b'account_check'
ACCOUNT_SEND_QUEUE  = b'account_send'
USER_ACCOUNT_QUEUE  = b'user_account'
GUI_INPUT_QUEUE     = b'gui_input'


"""Queue signals"""
KDB_ADD_ENTRY_HEADER         = 'ADD'
KDB_REMOVE_ENTRY_HEADER      = 'REM'
KDB_M_KEY_CHANGE_HALT_HEADER = 'HALT'
KDB_HALT_ACK_HEADER          = 'HALT_ACK'
KDB_UPDATE_SIZE_HEADER       = 'STO'
RP_ADD_CONTACT_HEADER        = 'RAC'
RP_REMOVE_CONTACT_HEADER     = 'RRC'
EXIT                         = 'EXIT'
WIPE                         = 'WIPE'


# Serial interface
BAUDS_PER_BYTE        = 10
SERIAL_RX_MIN_TIMEOUT = 0.05

# CLI indents
CONTACT_LIST_INDENT  = 4
FILE_TRANSFER_INDENT = 4
SETTINGS_INDENT      = 2

# Compression
COMPRESSION_LEVEL = 9
MAX_MESSAGE_SIZE  = 100_000  # bytes

# Traffic masking
NOISE_PACKET_BUFFER = 100

# Local testing
LOCALHOST             = 'localhost'
SRC_DD_LISTEN_SOCKET  = 5005
RP_LISTEN_SOCKET      = 5006
DST_DD_LISTEN_SOCKET  = 5007
DST_LISTEN_SOCKET     = 5008
DD_ANIMATION_LENGTH   = 16
DD_OFFSET_FROM_CENTER = 4

# Qubes related
QUBES_SRC_LISTEN_SOCKET = 2063
QUBES_DST_LISTEN_SOCKET = 2064
SOCKET_BUFFER_SIZE      = 4096
QUBES_RX_IP_ADDR_FILE   = 'rx_ip_addr'

# Field lengths
ENCODED_BOOLEAN_LENGTH  = 1
ENCODED_BYTE_LENGTH     = 1
TIMESTAMP_LENGTH        = 4
ENCODED_INTEGER_LENGTH  = 8
ENCODED_FLOAT_LENGTH    = 8
FILE_ETA_FIELD_LENGTH   = 8
FILE_SIZE_FIELD_LENGTH  = 8
GROUP_DB_HEADER_LENGTH  = 32
PADDED_UTF32_STR_LENGTH = 1024
CONFIRM_CODE_LENGTH     = 1
PACKET_CHECKSUM_LENGTH  = 16

# Onion address format
ONION_ADDRESS_CHECKSUM_ID     = b'.onion checksum'
ONION_SERVICE_VERSION         = b'\x03'
ONION_SERVICE_VERSION_LENGTH  = 1
ONION_ADDRESS_CHECKSUM_LENGTH = 2
ONION_ADDRESS_LENGTH          = 56

# Misc
BITS_PER_BYTE        = 8
MAX_INT              = 2 ** 64 - 1
B58_CHECKSUM_LENGTH  = 4
TRUNC_ADDRESS_LENGTH = 5
TOR_CONTROL_PORT     = 9051
TOR_SOCKS_PORT       = 9050
DB_WRITE_RETRY_LIMIT = 10
ACCOUNT_RATIO_LIMIT  = 0.75

# Key derivation
ARGON2_MIN_TIME_COST      = 1
ARGON2_MIN_MEMORY_COST    = 8
ARGON2_MIN_PARALLELISM    = 1
ARGON2_SALT_LENGTH        = 32
ARGON2_PSK_TIME_COST      = 25
ARGON2_PSK_MEMORY_COST    = 512 * 1024  # kibibytes
ARGON2_PSK_PARALLELISM    = 2
MIN_KEY_DERIVATION_TIME   = 3.0         # seconds
MAX_KEY_DERIVATION_TIME   = 4.0         # seconds
PASSWORD_MIN_BIT_STRENGTH = 128

# Cryptographic field sizes
TFC_PRIVATE_KEY_LENGTH           = 56
TFC_PUBLIC_KEY_LENGTH            = 56
X448_SHARED_SECRET_LENGTH        = 56
FINGERPRINT_LENGTH               = 32
ONION_SERVICE_PRIVATE_KEY_LENGTH = 32
ONION_SERVICE_PUBLIC_KEY_LENGTH  = 32
URL_TOKEN_LENGTH                 = 32
XCHACHA20_NONCE_LENGTH           = 24
SYMMETRIC_KEY_LENGTH             = 32
POLY1305_TAG_LENGTH              = 16
BLAKE2_DIGEST_LENGTH             = 32
BLAKE2_DIGEST_LENGTH_MIN         = 1
BLAKE2_DIGEST_LENGTH_MAX         = 64
BLAKE2_KEY_LENGTH_MAX            = 64
BLAKE2_SALT_LENGTH_MAX           = 16
BLAKE2_PERSON_LENGTH_MAX         = 16
HARAC_LENGTH                     = 8
PADDING_LENGTH                   = 255
ENCODED_B58_PUB_KEY_LENGTH       = 84
ENCODED_B58_KDK_LENGTH           = 51

# Domain separation
MESSAGE_KEY = b'message_key'
HEADER_KEY  = b'header_key'
FINGERPRINT = b'fingerprint'

# Forward secrecy
INITIAL_HARAC        = 0
HARAC_WARN_THRESHOLD = 100_000

# Special messages
PLACEHOLDER_DATA = P_N_HEADER + bytes(PADDING_LENGTH)

# Field lengths
ASSEMBLY_PACKET_LENGTH = ASSEMBLY_PACKET_HEADER_LENGTH + PADDING_LENGTH

HARAC_CT_LENGTH = (XCHACHA20_NONCE_LENGTH
                   + HARAC_LENGTH
                   + POLY1305_TAG_LENGTH)

ASSEMBLY_PACKET_CT_LENGTH = (XCHACHA20_NONCE_LENGTH
                             + ASSEMBLY_PACKET_LENGTH
                             + POLY1305_TAG_LENGTH)

MESSAGE_LENGTH = HARAC_CT_LENGTH + ASSEMBLY_PACKET_CT_LENGTH

COMMAND_LENGTH = (DATAGRAM_HEADER_LENGTH
                  + MESSAGE_LENGTH)

PACKET_LENGTH = (DATAGRAM_HEADER_LENGTH
                 + MESSAGE_LENGTH
                 + ORIGIN_HEADER_LENGTH)

GROUP_STATIC_LENGTH = (PADDED_UTF32_STR_LENGTH
                       + GROUP_ID_LENGTH
                       + 2 * ENCODED_BOOLEAN_LENGTH)

CONTACT_LENGTH = (ONION_SERVICE_PUBLIC_KEY_LENGTH
                  + 2 * FINGERPRINT_LENGTH
                  + 4 * ENCODED_BOOLEAN_LENGTH
                  + PADDED_UTF32_STR_LENGTH)

KEYSET_LENGTH = (ONION_SERVICE_PUBLIC_KEY_LENGTH
                 + 4 * SYMMETRIC_KEY_LENGTH
                 + 2 * HARAC_LENGTH)

PSK_FILE_SIZE = (XCHACHA20_NONCE_LENGTH
                 + ARGON2_SALT_LENGTH
                 + 2 * SYMMETRIC_KEY_LENGTH
                 + POLY1305_TAG_LENGTH)

LOG_ENTRY_LENGTH = (ONION_SERVICE_PUBLIC_KEY_LENGTH
                    + TIMESTAMP_LENGTH
                    + ORIGIN_HEADER_LENGTH
                    + ASSEMBLY_PACKET_LENGTH)

MASTERKEY_DB_SIZE = (ARGON2_SALT_LENGTH
                     + BLAKE2_DIGEST_LENGTH
                     + 3 * ENCODED_INTEGER_LENGTH)

SETTING_LENGTH = (XCHACHA20_NONCE_LENGTH
                  + 4 * ENCODED_INTEGER_LENGTH
                  + 3 * ENCODED_FLOAT_LENGTH
                  + 12 * ENCODED_BOOLEAN_LENGTH
                  + POLY1305_TAG_LENGTH)
