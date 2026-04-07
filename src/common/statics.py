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

import enum
import os

from enum import Enum, IntEnum, StrEnum


@enum.unique
class ProgramLiterals(StrEnum):
    """Program literals"""
    NAME       = 'TFC'
    FULL_NAME  = 'Tinfoil Chat'
    VERSION    = '2.26.04'
    AUTHOR     = 'Markus Ottela'
    START_YEAR = '2013'


# ┌───────────────────────────────────────────────────────────────────────────┐
# │                          Low Level Packet Headers                         │
# └───────────────────────────────────────────────────────────────────────────┘

@enum.unique
class Origin(bytes, Enum):
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
    USER    = b'o'
    CONTACT = b'i'


@enum.unique
class DatagramHeader(bytes, Enum):
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

    Group management datagrams are are automatic messages that the
    Transmitter Program recommends the user to send when they make changes
    to the member list of a group, or when they add or remove groups. These
    messages are displayed by the Relay Program.

    Traffic masking header is for noise data the server sends whenever
    it has no real data to send to someone requesting data. The client
    ignores these packets. This hides when communication takes place from
    all adversaries except those that compromise the Networked Computer of
    the user to see what the server is actually doing. Note that this is
    completely separate from the user-controlled traffic masking that
    makes the Transmitter Program output noise messages to selected window.
    """
    # Receiver Program
    LOCAL_KEY        = b'K'
    COMMAND          = b'C'
    MESSAGE          = b'M'
    FILE             = b'F'

    # Relay Program
    PUBLIC_KEY       = b'P'
    RELAY_COMMAND    = b'U'

    # Group management
    GROUP_INVITE     = b'I'
    GROUP_JOIN       = b'J'
    GROUP_ADD_MEMBER = b'N'
    GROUP_REM_MEMBER = b'R'
    GROUP_EXIT_GROUP = b'X'

    # Traffic masking
    TRAFFIC_MASKING  = b'T'


@enum.unique
class AsmPacket(bytes, Enum):
    """Assembly packet headers

    These one-byte assembly packet headers are not part of the padded
    message parsed from assembly packets. They are however the very first
    plaintext byte, prepended to every padded assembly packet that is
    delivered to the recipient/local Destination Computer. The header
    delivers the information about if and when to assemble the packet,
    as well as when to drop any previously collected assembly packets.
    """
    M_S_HEADER = b'a'  #                   single-packet message
    M_L_HEADER = b'b'  # First    packet of multi-packet message
    M_A_HEADER = b'c'  # Appended packet of multi-packet message
    M_E_HEADER = b'd'  # Last     packet of multi-packet message
    M_C_HEADER = b'e'  # Cancelled          multi-packet message
    P_N_HEADER = b'f'  # Noise message packet

    F_S_HEADER = b'A'  #                   single-packet file
    F_L_HEADER = b'B'  # First    packet of multi-packet file
    F_A_HEADER = b'C'  # Appended packet of multi-packet file
    F_E_HEADER = b'D'  # Last     packet of multi-packet file
    F_C_HEADER = b'E'  # Cancelled          multi-packet file

    C_S_HEADER = b'0'  #                   single-packet command
    C_L_HEADER = b'1'  # First    packet of multi-packet command
    C_A_HEADER = b'2'  # Appended packet of multi-packet command
    C_E_HEADER = b'3'  # Last     packet of multi-packet command
    C_C_HEADER = b'4'  # Cancelled          multi-packet command (reserved but not in use)
    C_N_HEADER = b'5'  # Noise command packet


@enum.unique
class RelayCommand(bytes, Enum):
    """Unencrypted command headers that control Relay Program.

    These two-byte headers are only used to control the Relay Program on
    Networked Computer. These commands will not be used during traffic
    masking, as they would reveal when TFC is being used. These commands do
    not require encryption, because if an attacker can compromise the
    Networked Computer to the point it could inject commands to Relay
    Program, it could most likely also access any decryption keys used by
    the Relay Program.
    """
    ONION_SERVICE_SETUP_DATA = b'UO'
    CLEAR_SCREEN             = b'UC'
    CLEAR_CIPHERTEXT_CACHE   = b'UZ'
    RESET_SCREEN             = b'UR'
    EXIT_TFC                 = b'UX'
    WIPE_SYSTEM              = b'UW'

    SET_BAUDRATE             = b'UB'
    SET_ERROR_CORRECTION     = b'UE'
    SET_REQUIRE_RESENDS      = b'UH'
    SET_AUTOREPLAY_TIMES     = b'UY'
    SET_AUTOREPLAY_LOOP      = b'UL'

    ADD_NEW_CONTACT          = b'UN'
    ADD_EXISTING_CONTACT     = b'UA'
    REMOVE_CONTACT           = b'UD'
    MANAGE_CONTACT_REQUESTS  = b'UM'
    RESEND_TO_RECEIVER       = b'UV'
    RESEND_FILE_TO_RECEIVER  = b'UF'

    CHECK_PUBLIC_KEY_INPUT   = b'UP'
    CHECK_ACCOUNT_INPUT      = b'UT'


@enum.unique
class RxCommand(bytes, Enum):
    """Encrypted command headers that control Receiver Program.

    These two-byte headers determine the type of command for Receiver
    Program on local Destination Computer. The header is evaluated after the
    Receiver Program has received all assembly packets and assembled the
    command. These headers tell the Receiver Program to which function the
    provided parameters (if any) must be redirected.
    """
    LOCAL_KEY_RDY  = b'LI'
    WIN_ACTIVITY   = b'SA'
    WIN_SELECT     = b'WS'
    CLEAR_CT_CACHE = b'CC'
    CLEAR_SCREEN   = b'SC'
    RESET_SCREEN   = b'SR'
    EXIT_PROGRAM   = b'EX'
    LOG_DISPLAY    = b'LD'
    LOG_EXPORT     = b'LE'
    LOG_REMOVE     = b'LR'
    CH_MASTER_KEY  = b'MK'
    CH_NICKNAME    = b'NC'
    CH_SETTING     = b'CS'
    CH_LOGGING     = b'CL'
    CH_FILE_RECV   = b'CF'
    CH_NOTIFY      = b'CN'
    GROUP_CREATE   = b'GC'
    GROUP_ADD      = b'GA'
    GROUP_REMOVE   = b'GR'
    GROUP_DELETE   = b'GD'
    GROUP_RENAME   = b'GN'
    KEY_EX_ECDHE   = b'KE'
    KEY_EX_PSK_TX  = b'KT'
    KEY_EX_PSK_RX  = b'KR'
    REMOVE_CONTACT = b'CR'
    WIPE_SYSTEM    = b'WD'


@enum.unique
class MessageHeader(bytes, Enum):
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

    Messages with the whisper message header have 'sender-based control'.
    Unless the contact maliciously alters their Receiver Program's behavior,
    whispered messages are not logged regardless of in-program controlled
    settings.

    Messages with file key header contain the hash of the file ciphertext
    that was sent to the user earlier. It also contains the symmetric
    decryption key for that file.
    """
    PRIVATE_MESSAGE = b'p'
    GROUP_MESSAGE   = b'g'
    FILE_KEY        = b'k'


@enum.unique
class WinSelectHeader(bytes, Enum):
    """Window Selection header"""
    SYSTEM_MESSAGES = b'win_uid_sys_msg'
    FILE_TRANSFERS  = b'win_uid_file'


@enum.unique
class ContactSettingValueHeader(bytes, Enum):
    """Contact setting controller"""
    ENABLE      = b'es'
    DISABLE     = b'ds'
    ENABLE_ALL  = b'ea'
    DISABLE_ALL = b'da'


@enum.unique
class Separator(bytes, Enum):
    """Separators

    Separator byte is a non-printable byte used to
    separate fields in serialized data structures.
    """
    US_BYTE = b'\x1f'


@enum.unique
class KexStatus(bytes, Enum):
    """Key exchange status states"""
    KEX_STATUS_NONE       = b'\xa0'
    KEX_STATUS_PENDING    = b'\xa1'
    KEX_STATUS_UNVERIFIED = b'\xa2'
    KEX_STATUS_VERIFIED   = b'\xa3'
    KEX_STATUS_NO_RX_PSK  = b'\xa4'
    KEX_STATUS_HAS_RX_PSK = b'\xa5'


# ┌───────────────────────────────────────────────────────────────────────────┐
# │                           High Level Identifiers                          │
# └───────────────────────────────────────────────────────────────────────────┘

@enum.unique
class ProgramName(StrEnum):
    """Program names."""
    TRANSMITTER = 'Transmitter'
    RECEIVER    = 'Receiver'
    RELAY       = 'Relay'


@enum.unique
class ProgramID(StrEnum):
    """Program identifiers."""
    TX = 'tx'
    RX = 'rx'
    NC = 'nc'


@enum.unique
class OSIdentifier(StrEnum):
    """OS identifiers"""
    TAILS = 'NAME="Tails"'


@enum.unique
class DummyID(StrEnum):
    """Dummy identifiers.

    Placeholder accounts for databases need to be valid v3 Onion addresses.
    """
    DUMMY_CONTACT = 'dummycontactdummycontactdummycontactdummycontactdumhsiid'
    DUMMY_MEMBER  = 'dummymemberdummymemberdummymemberdummymemberdummymedakad'
    DUMMY_NICK    = 'dummy_nick'
    DUMMY_GROUP   = 'dummy_group'


@enum.unique
class WindowType(StrEnum):
    """Window types."""
    SYSTEM_MESSAGES = 'system messages'
    FILE_TRANSFERS  = 'file transfers'
    CONTACT         = 'contact'
    GROUP           = 'group'

@enum.unique
class PayloadType(StrEnum):
    """Payload types."""
    COMMAND = 'command'
    FILE    = 'file'
    MESSAGE = 'message'


@enum.unique
class DatagramTypeHR(StrEnum):
    """Human readable datagram types."""
    LOCAL_KEY        = 'Local Key'
    COMMAND          = 'Command'
    PUBLIC_KEY       = 'Pub key'
    MESSAGE          = 'Message'
    FILE             = 'File'
    GROUP_INVITE     = 'G Invite'
    GROUP_JOIN       = 'G Join'
    GROUP_ADD_MEMBER = 'G Add'
    GROUP_REM_MEMBER = 'G Remove'
    GROUP_EXIT       = 'G Exit'


@enum.unique
class GroupMsgID(StrEnum):
    """Group message IDs"""
    NEW_GROUP        = 'new_group'
    ADDED_MEMBERS    = 'added_members'
    ALREADY_MEMBER   = 'already_member'
    REMOVED_MEMBERS  = 'removed_members'
    NOT_IN_GROUP     = 'not_in_group'
    INVALID_KEX      = 'invalid_kex'
    UNKNOWN_ACCOUNTS = 'unknown_accounts'


@enum.unique
class KexType(StrEnum):
    """Key exchange types"""
    ECDHE = 'X448'
    PSK   = 'PSK'


@enum.unique
class ShellCommand(StrEnum):
    """Shell commands."""
    CLEAR    = 'clear'
    RESET    = 'reset'
    POWEROFF = 'systemctl poweroff'


@enum.unique
class NCBypassState(StrEnum):
    """Networked Computer bypass states"""
    NC_BYPASS_START = 'nc_bypass_start'
    NC_BYPASS_STOP  = 'nc_bypass_stop'


@enum.unique
class ContactSettingKey(StrEnum):
    """Contact setting keys"""
    LOGGING = 'logging'
    STORE   = 'store'
    NOTIFY  = 'notify'


@enum.unique
class GroupMgmtCommand(StrEnum):
    """Group management commands"""
    CREATE = 'create'
    JOIN   = 'join'
    ADD    = 'add'
    RM     = 'rm'


@enum.unique
class ContactSettingValue(StrEnum):
    """Contact setting values"""
    ON  = 'on'
    OFF = 'off'


@enum.unique
class DataDiodeSimState(StrEnum):
    """Data diode simulator state"""
    IDLE      = 'Idle'
    DATA_FLOW = 'Data flow'


@enum.unique
class DataDiodeLaunchArguments(StrEnum):
    """Data diode simulator launch arguments."""
    SCNCLR = 'scnclr'
    SCNCRL = 'scncrl'
    NCDCLR = 'ncdclr'
    NCDCRL = 'ncdcrl'


# ┌───────────────────────────────────────────────────────────────────────────┐
# │                            Transmitter Commands                           │
# └───────────────────────────────────────────────────────────────────────────┘

@enum.unique
class TxCommand(StrEnum):
    """Transmitter commands."""
    ABOUT    = 'about'
    ADD      = 'add'
    CC       = 'cc'
    CF       = 'cf'
    CM       = 'cm'
    CLEAR    = 'clear'
    CMD      = 'cmd'
    CONNECT  = 'connect'
    EXIT     = 'exit'
    EXPORT   = 'export'
    FW       = 'fw'
    GROUP    = 'group'
    HELP     = 'help'
    HISTORY  = 'history'
    LOCALKEY = 'localkey'
    LOGGING  = 'logging'
    MSG      = 'msg'
    NAMES    = 'names'
    NICK     = 'nick'
    NOTIFY   = 'notify'
    PASSWD   = 'passwd'
    PSK      = 'psk'
    RESET    = 'reset'
    RM       = 'rm'
    RF       = 'rf'
    RMLOGS   = 'rmlogs'
    RR       = 'rr'
    RT       = 'rt'
    SET      = 'set'
    SETTINGS = 'settings'
    STORE    = 'store'
    UNREAD   = 'unread'
    VERIFY   = 'verify'
    WHISPER  = 'whisper'
    WHOIS    = 'whois'
    WIPE     = 'wipe'


# ┌───────────────────────────────────────────────────────────────────────────┐
# │                                  Settings                                 │
# └───────────────────────────────────────────────────────────────────────────┘

class SettingKey(StrEnum):
    """Setting keys."""

    # Shared settings
    disable_gui_dialog            = 'disable_gui_dialog'
    max_number_of_group_members   = 'max_number_of_group_members'
    max_number_of_groups          = 'max_number_of_groups'
    max_number_of_contacts        = 'max_number_of_contacts'
    log_messages_by_default       = 'log_messages_by_default'
    accept_files_by_default       = 'accept_files_by_default'
    show_notifications_by_default = 'show_notifications_by_default'
    log_file_masking              = 'log_file_masking'
    ask_password_for_log_access   = 'ask_password_for_log_access'

    # Shared Gateway settings
    serial_error_correction       = 'serial_error_correction'
    serial_baudrate               = 'serial_baudrate'

    # Transmitter settings
    nc_bypass_messages            = 'nc_bypass_messages'
    confirm_tm_files              = 'confirm_tm_files'
    double_space_exits            = 'double_space_exits'
    traffic_masking               = 'traffic_masking'
    tm_static_delay               = 'tm_static_delay'
    tm_random_delay               = 'tm_random_delay'
    require_resends               = 'require_resends'
    autoreplay_times              = 'autoreplay_times'
    autoreplay_loop               = 'autoreplay_loop'

    # Relay Settings
    allow_contact_requests        = 'allow_contact_requests'

    # Receiver settings
    new_message_notify_preview    = 'new_message_notify_preview'
    new_message_notify_duration   = 'new_message_notify_duration'
    max_decompress_size_mb        = 'max_decompress_size_mb'


class ContactSettingAttr(StrEnum):
    """Contact setting attributes."""
    LOG_MESSAGES   = 'log_messages'
    FILE_RECEPTION = 'file_reception'
    NOTIFICATIONS  = 'notifications'


class RelaySettingKey(StrEnum):
    """Relay setting keys."""
    serial_error_correction       = 'serial_error_correction'
    serial_baudrate               = 'serial_baudrate'
    allow_contact_requests        = 'allow_contact_requests'
    require_resends               = 'require_resends'
    autoreplay_times              = 'autoreplay_times'
    autoreplay_loop               = 'autoreplay_loop'


# ┌───────────────────────────────────────────────────────────────────────────┐
# │                              Multiprocessing                              │
# └───────────────────────────────────────────────────────────────────────────┘

@enum.unique
class KeyDBMgmt(StrEnum):
    """Key database management signals."""
    INSERT_ROW        = 'INSERT_ROW'
    DELETE_ROW        = 'DELETE_ROW'
    WAIT_FOR_SYNC     = 'WAIT_FOR_SYNC'
    RELEASE_WAIT      = 'RELEASE_WAIT'
    UPDATE_ROW_COUNT  = 'UPDATE_ROW_COUNT'
    UPDATE_MASTER_KEY = 'UPDATE_MASTER_KEY'


@enum.unique
class LocalKeyDBMgmt(StrEnum):
    """Local key database management signals."""
    INSERT_ROW        = 'INSERT_ROW'
    DELETE_ROW        = 'DELETE_ROW'
    WAIT_FOR_SYNC     = 'WAIT_FOR_SYNC'
    RELEASE_WAIT      = 'RELEASE_WAIT'
    UPDATE_MASTER_KEY = 'UPDATE_MASTER_KEY'


@enum.unique
class LogWriterMgmt(StrEnum):
    """Log writer management signals."""
    WAIT_FOR_SYNC     = 'WAIT_FOR_SYNC'
    RELEASE_WAIT      = 'RELEASE_WAIT'
    UPDATE_MASTER_KEY = 'UPDATE_MASTER_KEY'


@enum.unique
class QueueSignal(StrEnum):
    """Queue signals"""
    RP_ADD_CONTACT_HEADER    = 'RAC'
    RP_REMOVE_CONTACT_HEADER = 'RRC'


@enum.unique
class MonitorQueueSignal(StrEnum):
    """Monitor queue signals."""
    EXIT = 'EXIT'
    WIPE = 'WIPE'


# ┌───────────────────────────────────────────────────────────────────────────┐
# │                              IPC / Networking                             │
# └───────────────────────────────────────────────────────────────────────────┘

@enum.unique
class NetworkLiterals(StrEnum):
    """Network literals."""
    LOCALHOST    = 'localhost'
    LOCALHOST_IP = '127.0.0.1'


@enum.unique
class SocketNumber(IntEnum):
    """Data diode socket simulator numbers."""
    SRC_DD_LISTEN = 5005
    RP_LISTEN     = 5006
    DST_DD_LISTEN = 5007
    DST_LISTEN    = 5008


@enum.unique
class PortNumber(IntEnum):
    """Port numbers."""
    TOR_CONTROL_PORT = 951
    TOR_SOCKS_PORT   = 9050
    FLASK_PORT       = 5000


@enum.unique
class QubesLiterals(StrEnum):
    """Qubes literals."""
    QUBES_NET_VM_NAME            = 'TFC-Networker'
    QUBES_DST_VM_NAME            = 'TFC-Destination'
    QUBES_SRC_NET_POLICY         = 'tfc.SourceNetworker'
    QUBES_NET_DST_POLICY         = 'tfc.NetworkerDestination'
    QUBES_BUFFER_INCOMING_DIR    = '/home/user/.tfc/buffered_incoming_packets'
    QUBES_BUFFER_INCOMING_PACKET = 'buffered_incoming_packet'


@enum.unique
class SerialLiterals(Enum):
    """Serial literals."""
    BAUDS_PER_BYTE        = 10
    SERIAL_RX_MIN_TIMEOUT = 0.05


# ┌───────────────────────────────────────────────────────────────────────────┐
# │                               Files and I/O                               │
# └───────────────────────────────────────────────────────────────────────────┘

@enum.unique
class TFCDatabaseFileName(StrEnum):
    """TFC database names.

    Used as blacklist for attachments.
    """
    TX_CONTACTS        = 'tx_contacts'
    RX_CONTACTS        = 'rx_contacts'
    TX_GROUPS          = 'tx_groups'
    RX_GROUPS          = 'rx_groups'
    TX_KEYSTORE        = 'tx_keystore'
    RX_KEYSTORE        = 'rx_keystore'
    TX_LOCAL_KEY       = 'tx_local_key'
    RX_LOCAL_KEY       = 'rx_local_key'
    TX_LOGIN_DATA      = 'tx_login_data'
    RX_LOGIN_DATA      = 'rx_login_data'
    TX_MESSAGE_LOG     = 'tx_message_log'
    RX_MESSAGE_LOG     = 'rx_message_log'
    TX_SETTINGS        = 'tx_settings'
    RX_SETTINGS        = 'rx_settings'
    TX_SERIAL_SETTINGS = 'tx_serial_settings.json'
    NC_SERIAL_SETTINGS = 'nc_serial_settings.json'
    RX_SERIAL_SETTINGS = 'rx_serial_settings.json'
    TX_ONION_DB        = 'tx_onion_db'


@enum.unique
class DBName(StrEnum):
    """Database names."""
    CONTACTS    = 'contacts'
    GROUPS      = 'groups'
    KEY_STORE   = 'key_store'
    LOCAL_KEY   = 'local_key'
    LOGIN_DATA  = 'login_data'
    MESSAGE_LOG = 'message_log'
    SETTINGS    = 'settings'
    ONION_DB    = 'onion_db'


@enum.unique
class BufferFileName(StrEnum):
    """Buffer file names."""
    RELAY_BUF_OUTGOING_FILE    = 'buffered_file'
    RELAY_BUF_OUTGOING_MESSAGE = 'buffered_message'


@enum.unique
class BufferFileDir(StrEnum):
    """Buffer file directories."""
    RELAY_BUF_OUTGOING_FILES    = 'buffered_outgoing_files'
    RELAY_BUF_OUTGOING_MESSAGES = 'buffered_outgoing_messages'
    RELAY_BUF_INCOMING_FILES    = 'buffered_incoming_files'
    RELAY_BUF_INCOMING_MESSAGES = 'buffered_incoming_messages'


@enum.unique
class DataDir(StrEnum):
    """Default directories"""
    USER_DATA      = 'user_data'
    EXT_BASE_DIR   = f"{os.getenv('HOME')}/Downloads/tfc"
    RECEIVED_FILES = f'{EXT_BASE_DIR}/received_files'
    EXPORTED_LOGS  = f'{EXT_BASE_DIR}/exported_logs'


class WorkingDir(StrEnum):
    """Working directories."""
    NORMAL = f"{os.getenv('HOME')}/.tfc"
    TAILS  = f"{os.getenv('HOME')}/Persistent/tfc"


class DatabaseLiterals(IntEnum):
    """Database literals."""
    DB_WRITE_RETRY_LIMIT = 10


# ┌───────────────────────────────────────────────────────────────────────────┐
# │                               User Interface                              │
# └───────────────────────────────────────────────────────────────────────────┘

@enum.unique
class VT100(StrEnum):
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


@enum.unique
class SpecialHandle(StrEnum):
    """Special handle types.

    These distinguish messages that do not originate from contacts.
    """
    SYSTEM_MESSAGE = '-!-'
    EVENT          = 'EVENT'
    USER           = 'Me'


@enum.unique
class StatusMsg(StrEnum):
    """Status messages"""
    DONE = 'DONE'


@enum.unique
class B58Guide(StrEnum):
    """Base58 key input guides"""
    B58_PUBLIC_KEY_GUIDE = '   A       B       C       D       E       F       G       H       I       J       K       L   '
    B58_LOCAL_KEY_GUIDE  = ' A   B   C   D   E   F   G   H   I   J   K   L   M   N   O   P   Q '


class CLIIndentLiterals(IntEnum):
    """CLI indents."""
    CONTACT_LIST_INDENT  = 4
    FILE_TRANSFER_INDENT = 4
    SETTINGS_INDENT      = 2


# ┌───────────────────────────────────────────────────────────────────────────┐
# │                                  Encoding                                 │
# └───────────────────────────────────────────────────────────────────────────┘

class EncodingLiteral(IntEnum):
    """Encoding literals."""
    BITS_PER_BYTE = 8
    MAX_INT       = 2 ** 64 - 1


class CompressionLiterals(IntEnum):
    """Compression literals."""
    COMPRESSION_LEVEL   = 9
    MAX_MESSAGE_SIZE_MB = 100


class SettingLimitsBool(Enum):
    """Shared bounds for boolean settings."""
    MIN = False
    MAX = True


class SettingLimitsInt(IntEnum):
    """Integer limits for configurable settings."""
    AUTOREPLAY_TIMES_MIN            = 1
    AUTOREPLAY_TIMES_MAX            = 20
    MAX_DECOMPRESS_SIZE_MB_MIN      = 1
    MAX_DECOMPRESS_SIZE_MB_MAX      = 300
    MAX_NUMBER_OF_CONTACTS_MIN      = 10
    MAX_NUMBER_OF_CONTACTS_MAX      = 10_000
    MAX_NUMBER_OF_GROUP_MEMBERS_MIN = 10
    MAX_NUMBER_OF_GROUP_MEMBERS_MAX = 1_000
    MAX_NUMBER_OF_GROUPS_MIN        = 10
    MAX_NUMBER_OF_GROUPS_MAX        = 1_000
    SERIAL_BAUDRATE_MIN             = 50
    SERIAL_BAUDRATE_MAX             = 4_000_000
    SERIAL_ERROR_CORRECTION_MIN     = 1
    SERIAL_ERROR_CORRECTION_MAX     = 127


class SettingLimitsFloat(float, Enum):
    """Float limits for configurable settings."""
    TM_STATIC_DELAY_MIN             = 0.1
    TM_STATIC_DELAY_MAX             = 60.0
    TM_RANDOM_DELAY_MIN             = 0.1
    TM_RANDOM_DELAY_MAX             = 60.0
    NEW_MESSAGE_NOTIFY_DURATION_MIN = 0.05
    NEW_MESSAGE_NOTIFY_DURATION_MAX = 60.0


@enum.unique
class B58Literals(bytes, Enum):
    """Base58 literals"""
    MAINNET_HEADER = b'\x80'
    TESTNET_HEADER = b'\xef'


@enum.unique
class B58Alphabet(StrEnum):
    """Base58 alphabet."""
    B58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'


@enum.unique
class B58KeyType(StrEnum):
    """Base58 key types"""
    B58_PUBLIC_KEY = 'b58_public_key'
    B58_LOCAL_KEY  = 'b58_local_key'


# ┌───────────────────────────────────────────────────────────────────────────┐
# │                                Cryptography                               │
# └───────────────────────────────────────────────────────────────────────────┘

class KeyLength(IntEnum):
    """Key lengths.

    Isolated namespace for valid CSPRNG inputs.
    """
    X448_PRIVATE_KEY          = 56
    ONION_SERVICE_PRIVATE_KEY = 32
    SYMMETRIC_KEY             = 32
    XCHACHA20_NONCE           = 24
    ARGON2_SALT               = 32


class CryptoVarLength(IntEnum):
    """Crypto variable lengths."""
    X448_PUBLIC_KEY          = 56
    X448_SHARED_SECRET       = 56
    FINGERPRINT              = 32
    POLY1305_TAG             = 16
    BLAKE2_DIGEST            = 32
    BLAKE2_DIGEST_MIN        = 1
    BLAKE2_DIGEST_MAX        = 64
    BLAKE2_KEY_MAX           = 64
    BLAKE2_SALT_MAX          = 16
    BLAKE2_PERSON_MAX        = 16
    RATCHET_CTR              = 8
    PADDING                  = 255
    ENCODED_B58_PUB_KEY      = 84
    ENCODED_B58_KEK          = 51
    ONION_SERVICE_PUBLIC_KEY = 32


class HashRatchet(IntEnum):
    """Hash ratchet values values."""
    INITIAL_RATCHET_VALUE  = 0
    CATCHUP_WARN_THRESHOLD = 100_000


class Argon2Literals(IntEnum):
    """Argon2 literals."""
    ARGON2_MIN_TIME_COST      = 1
    ARGON2_MIN_MEMORY_COST    = 8
    ARGON2_MEMORY_COST_STEP   = 1_000      # kibibytes
    ARGON2_MEMORY_RESTART_MIN = 5 * 1_024  # kibibytes
    ARGON2_MIN_PARALLELISM    = 1
    ARGON2_PSK_TIME_COST      = 25
    ARGON2_PSK_MEMORY_COST    = 512 * 1024  # kibibytes -> 512MiB
    ARGON2_PSK_PARALLELISM    = 2
    PASSWORD_MIN_BIT_STRENGTH = 128
    ITERATIONS_PER_CONFIG     = 3


class Argon2KDTime(float, Enum):
    """Argon2 key derivation time literals."""
    MIN_KEY_DERIVATION_TIME = 3.0  # seconds
    MAX_KEY_DERIVATION_TIME = 4.0  # seconds


class OnionLiterals(bytes, Enum):
    """Onion literals."""
    ONION_ADDRESS_CHECKSUM_ID = b'.onion checksum'
    ONION_SERVICE_VERSION     = b'\x03'


class OnionAddress(StrEnum):
    """Onion address chars (base-32)"""
    CHARSET = 'abcdefghijklmnopqrstuvwxyz234567'


class RemoteInputLiterals(float, Enum):
    """Remote input literals."""
    ACCOUNT_SIMILARITY_MIN_PERCENTAGE = 75.0


@enum.unique
class DomainSeparator(bytes, Enum):
    """Domain separators."""
    MESSAGE_KEY = b'message_key'
    HEADER_KEY  = b'header_key'
    FINGERPRINT = b'fingerprint'
    BUFFER_KEY  = b'buffer_key'


# ┌───────────────────────────────────────────────────────────────────────────┐
# │                                  Security                                 │
# └───────────────────────────────────────────────────────────────────────────┘

class TrafficMaskingLiterals(Enum):
    """Traffic masking literals."""
    NOISE_PACKET_BUFFER = 100


class TrafficMaskingData(bytes, Enum):
    """Traffic masking data."""
    PLACEHOLDER_DATA = AsmPacket.P_N_HEADER.value + bytes(CryptoVarLength.PADDING.value)


@enum.unique
class CTDelayType(StrEnum):
    """Constant time delay types"""
    STATIC          = 'static'
    TRAFFIC_MASKING = 'traffic_masking'


@enum.unique
class TrafficMaskingOmittedSettings(StrEnum):
    """Settings omitted during traffic masking."""
    serial_error_correction = 'serial_error_correction'
    serial_baudrate         = 'serial_baudrate'
    allow_contact_requests  = 'allow_contact_requests'
    max_number_of_contacts  = 'max_number_of_contacts'


@enum.unique
class TFCSettingKey(StrEnum):
    """TFC setting keys."""
    # Shared settings
    DISABLE_GUI_DIALOG            = 'disable_gui_dialog'
    MAX_NUMBER_OF_GROUP_MEMBERS   = 'max_number_of_group_members'
    MAX_NUMBER_OF_GROUPS          = 'max_number_of_groups'
    MAX_NUMBER_OF_CONTACTS        = 'max_number_of_contacts'
    LOG_MESSAGES_BY_DEFAULT       = 'log_messages_by_default'
    ACCEPT_FILES_BY_DEFAULT       = 'accept_files_by_default'
    SHOW_NOTIFICATIONS_BY_DEFAULT = 'show_notifications_by_default'
    LOG_FILE_MASKING              = 'log_file_masking'
    ASK_PASSWORD_FOR_LOG_ACCESS   = 'ask_password_for_log_access'

    # Transmitter settings
    NC_BYPASS_MESSAGES            = 'nc_bypass_messages'
    CONFIRM_TM_FILES              = 'confirm_tm_files'
    DOUBLE_SPACE_EXITS            = 'double_space_exits'
    TRAFFIC_MASKING               = 'traffic_masking'
    TM_STATIC_DELAY               = 'tm_static_delay'
    TM_RANDOM_DELAY               = 'tm_random_delay'
    REQUIRE_RESENDS               = 'require_resends'
    AUTOREPLAY_TIMES              = 'autoreplay_times'
    AUTOREPLAY_LOOP               = 'autoreplay_loop'

    # Relay Settings
    ALLOW_CONTACT_REQUESTS        = 'allow_contact_requests'

    # Receiver settings
    NEW_MESSAGE_NOTIFY_PREVIEW    = 'new_message_notify_preview'
    NEW_MESSAGE_NOTIFY_DURATION   = 'new_message_notify_duration'
    MAX_DECOMPRESS_SIZE_MB        = 'max_decompress_size_mb'

    # Serial interface settings
    SERIAL_BAUDRATE               = 'serial_baudrate'
    SERIAL_ERROR_CORRECTION       = 'serial_error_correction'



class Delay(float, Enum):
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
    RELAY_CLIENT_MAX_DELAY            = 8.0
    RELAY_CLIENT_MIN_DELAY            = 0.125
    RELAY_CLIENT_MIN_RANDOM_DELAY     = 0.0
    RELAY_CLIENT_MAX_RANDOM_DELAY     = 2.0
    CLIENT_OFFLINE_THRESHOLD          = 4.0


class RelayLimits(IntEnum):
    """Relay-side resource limits"""
    MAX_FILE_SIZE              = 200 * 1024 ** 2  # 200 MiB in total
    FILE_FETCH_CHUNK_SIZE      =  64 * 1024       #  64 KiB in total
    FILE_FRAGMENT_SIZE         = 512 * 1024       # 512 MiB in total
    CONTACT_REQUEST_QUEUE_SIZE = 300
    CONTACT_REQUEST_CACHE_SIZE = 300


class ReplayLimits(IntEnum):
    """Packet replay limits."""
    HASH_WINDOW_SIZE             = 51
    IDLE_REPLAY_PACKET_COUNT     = 50
    OUTGOING_DATAGRAM_CACHE_SIZE = 5000


# ┌───────────────────────────────────────────────────────────────────────────┐
# │                               Field Lengths                               │
# └───────────────────────────────────────────────────────────────────────────┘

class FieldLength(IntEnum):
    """Field lengths."""
    ASSEMBLY_PACKET_HEADER  = 1
    B58_CHECKSUM            = 4
    CONFIRM_CODE            = 1
    CONTACT_SETTING_HEADER  = 2
    DATAGRAM_HEADER         = 1
    ENCODED_BOOLEAN         = 1
    ENCODED_BYTE            = 1
    ENCODED_FLOAT           = 8
    ENCODED_INTEGER         = 8
    FILE_ETA_FIELD          = 8
    FILE_PACKET_CTR         = 8
    FILE_SIZE_FIELD         = 8
    GROUP_DB_HEADER         = 32
    GROUP_ID                = 4
    GROUP_ID_ENC            = 13
    GROUP_MGMT_HEADER       = 1
    GROUP_MSG_ID            = 16
    KEK_HASH                = 32
    KEX_STATUS              = 1
    MESSAGE_HEADER          = 1
    ONION_ADDRESS           = 56
    ONION_ADDRESS_CHECKSUM  = 2
    ONION_ADDRESS_TRUNC     = 5
    ONION_SERVICE_VERSION   = 1
    ORIGIN_HEADER           = 1
    PACKET_CHECKSUM         = 16
    PADDED_UTF32_STR        = 1024
    RECEIVER_COMMAND_HEADER = 2
    RELAY_COMMAND_HEADER    = 2
    TIMESTAMP_LONG          = 8
    TIMESTAMP_SHORT         = 4
    UNIT_SEPARATOR          = 1


class CompoundFieldLength(IntEnum):
    """Compound field lengths."""
    ASSEMBLY_PACKET_PT = (FieldLength.ASSEMBLY_PACKET_HEADER.value + CryptoVarLength.PADDING.value)

    CT_HEADER          = (KeyLength.XCHACHA20_NONCE.value + CryptoVarLength.RATCHET_CTR.value + CryptoVarLength.POLY1305_TAG.value)
    CT_ASSEMBLY_PACKET = (KeyLength.XCHACHA20_NONCE.value + ASSEMBLY_PACKET_PT                + CryptoVarLength.POLY1305_TAG.value)

    MESSAGE_CT               = (CT_HEADER + CT_ASSEMBLY_PACKET)
    COMMAND_DATAGRAM_PAYLOAD = (CT_HEADER + CT_ASSEMBLY_PACKET)

    MESSAGE_DATAGRAM_PAYLOAD = (FieldLength.ONION_ADDRESS.value + MESSAGE_CT)

    MESSAGE_DATAGRAM         = (FieldLength.DATAGRAM_HEADER.value + MESSAGE_DATAGRAM_PAYLOAD)
    COMMAND_DATAGRAM         = (FieldLength.DATAGRAM_HEADER.value + COMMAND_DATAGRAM_PAYLOAD)

    MESSAGE_RECEIVER_PAYLOAD = (FieldLength.ONION_ADDRESS.value + FieldLength.ORIGIN_HEADER.value + MESSAGE_CT)

    MESSAGE_RECEIVER_PACKET  = (FieldLength.DATAGRAM_HEADER.value + FieldLength.TIMESTAMP_LONG.value + MESSAGE_RECEIVER_PAYLOAD)
    COMMAND_RECEIVER_PACKET  = (FieldLength.DATAGRAM_HEADER.value + FieldLength.TIMESTAMP_LONG.value + COMMAND_DATAGRAM_PAYLOAD)

    LOCAL_KEY_CT = (KeyLength.XCHACHA20_NONCE.value + KeyLength.SYMMETRIC_KEY.value
                                                    + KeyLength.SYMMETRIC_KEY.value
                                                    + FieldLength.CONFIRM_CODE.value + CryptoVarLength.POLY1305_TAG.value)

    LOCAL_KEY_DATAGRAM = (FieldLength.DATAGRAM_HEADER.value + LOCAL_KEY_CT)

    LOCAL_KEY_RECEIVER_PACKET = (LOCAL_KEY_DATAGRAM
                                 + FieldLength.TIMESTAMP_LONG.value)

    PUBLIC_KEY_DATAGRAM = (FieldLength.ONION_ADDRESS.value
                           + KeyLength.X448_PRIVATE_KEY.value)

    FILE_HEADER = (FieldLength.ASSEMBLY_PACKET_HEADER.value
                   + FieldLength.FILE_ETA_FIELD.value
                   + FieldLength.FILE_SIZE_FIELD.value
                   + FieldLength.UNIT_SEPARATOR.value)

    COMMAND = COMMAND_DATAGRAM

    # Largest normal packet Relay forwards to Receiver. File packets are unbounded.
    PACKET = MESSAGE_RECEIVER_PACKET

    GROUP_STATIC = (FieldLength.PADDED_UTF32_STR.value
                    + FieldLength.GROUP_ID.value
                    + 2 * FieldLength.ENCODED_BOOLEAN.value)

    CONTACT = (FieldLength.ONION_ADDRESS.value
               + 2 * CryptoVarLength.FINGERPRINT.value
               + 1 * FieldLength.ENCODED_BYTE.value
               + 3 * FieldLength.ENCODED_BOOLEAN.value
               + FieldLength.PADDED_UTF32_STR.value)

    KEYSET = (FieldLength.ONION_ADDRESS.value
              + 4 * KeyLength.SYMMETRIC_KEY.value
              + 2 * CryptoVarLength.RATCHET_CTR.value)

    PSK_FILE_SIZE = (KeyLength.ARGON2_SALT.value
                     + FieldLength.ENCODED_INTEGER.value
                     + FieldLength.ENCODED_INTEGER.value
                     + FieldLength.ENCODED_INTEGER.value
                     + KeyLength.XCHACHA20_NONCE.value
                     + 2 * KeyLength.SYMMETRIC_KEY.value
                     + CryptoVarLength.POLY1305_TAG.value)

    LOG_ENTRY = (CryptoVarLength.ONION_SERVICE_PUBLIC_KEY.value
                 + FieldLength.TIMESTAMP_SHORT.value
                 + FieldLength.ORIGIN_HEADER.value
                 + ASSEMBLY_PACKET_PT)

    ENC_LOG_ENTRY = (KeyLength.XCHACHA20_NONCE
                     + LOG_ENTRY
                     + CryptoVarLength.POLY1305_TAG)

    MASTERKEY_DB_SIZE = (KeyLength.ARGON2_SALT.value
                         + CryptoVarLength.BLAKE2_DIGEST.value
                         + 3 * FieldLength.ENCODED_INTEGER.value)

    SETTING = (KeyLength.XCHACHA20_NONCE.value
               + 4 * FieldLength.ENCODED_INTEGER.value
               + 3 * FieldLength.ENCODED_FLOAT.value
               + 12 * FieldLength.ENCODED_BOOLEAN.value
               + CryptoVarLength.POLY1305_TAG.value)

    # Variable length as arbitrary number of FieldLength.ONION_ADDRESS long addresses will trail these fields.
    ONION_SERVICE_SETUP_DATA_MIN = (  KeyLength.SYMMETRIC_KEY.value
                                    + KeyLength.ONION_SERVICE_PRIVATE_KEY.value
                                    + FieldLength.CONFIRM_CODE.value
                                    + FieldLength.ENCODED_BOOLEAN.value
                                    + FieldLength.ENCODED_INTEGER.value)

    ATTACHMENT_CT_MIN = (KeyLength.XCHACHA20_NONCE
                         + FieldLength.ENCODED_BOOLEAN.value
                         + CryptoVarLength.POLY1305_TAG)
