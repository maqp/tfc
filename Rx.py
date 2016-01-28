#!/usr/bin/env python
# -*- coding: utf-8 -*-

# TFC-NaCl 0.16.01 beta || Rx.py

"""
GPL License

This software is part of the TFC application, which is free software: You can
redistribute it and/or modify it under the terms of the GNU General Public
License as published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.

TFC is distributed in the hope that it will be useful, but WITHOUT ANY
WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
A PARTICULAR PURPOSE. See the GNU General Public License for more details. For
a copy of the GNU General Public License, see <http://www.gnu.org/licenses/>.
"""

from argparse import ArgumentParser
from base64 import b64decode
from binascii import hexlify, unhexlify
from csv import reader, writer
from datetime import datetime
from fcntl import ioctl
from multiprocessing import Process, Queue
from multiprocessing.connection import Listener
from os import chdir, listdir, makedirs, rename, system
from os.path import dirname, exists, isfile
from random import choice, randrange, randint as sysrandint
from readline import clear_history
from serial import Serial, serialutil
from struct import unpack
from subprocess import Popen, check_output
from sys import path, stdin, stdout
from termios import TIOCGWINSZ
from threading import Thread
from time import sleep
from hashlib import sha256
import curses

from simplesha3 import sha3256
from passlib.hash import pbkdf2_sha256
from passlib.utils import ab64_decode
from nacl.exceptions import CryptoError
from nacl.secret import SecretBox


str_version = "0.16.01 beta"
int_version = 1601

###############################################################################
#                                CONFIGURATION                                #
###############################################################################

# UI settings
l_ts = "%Y-%m-%d %H:%M:%S"  # Format of timestamps in log files

d_ts = "%H:%M"              # Format of timestamps printed on screen

display_time = True         # False disables timestamps of received messages

startup_banner = True       # False disables the animated startup banner

l_message_incoming = True   # False disables notification of long transmission

print_noise_pkg = False     # True displays trickle connection noise packets

disp_opsec_warning = True   # False disables warning when receiving files


# File settings
file_saving = False         # True permanently enables file reception for all

keep_local_files = False    # True stores local copies of files sent to contact

a_close_f_recv = True       # False keeps reception on after file is received


# Message logging
log_messages = False        # True permanently enables message logging

create_syslog = True        # False does not log warnings to syslog.tfc


# Local testing
local_testing = False       # True enables testing of TFC on a single computer


# Serial port settings
baud_rate = 9600            # The serial interface speed

checksum_len = 8            # Data diode error detection rate. 8 hex = 32-bit

nh_usb_adapter = True       # False = use integrated serial interface


###############################################################################
#                               ERROR CLASSES                                 #
###############################################################################

class CriticalError(Exception):
    """
    Variety of errors during which Rx.py should gracefully exit.
    """

    def __init__(self, function_name, error_message):
        system("clear")
        print("\nError: M(%s): %s\n" % (function_name, error_message))
        graceful_exit()


class FunctionParameterTypeError(Exception):
    """
    Rx.py should gracefully exit if function is called with incorrect
    parameter types.
    """

    def __init__(self, function_name):
        system("clear")
        print("\nError: M(%s): Wrong input type.\n" % function_name)
        graceful_exit()


class InvalidDecryptionKeyError(Exception):
    """
    Rx.py should gracefully exit if loaded key is invalid.
    """

    def __init__(self, account):
        system("clear")
        print("\nError: Invalid key in keyfile 'keys/%s.e.'\n" % account)
        graceful_exit()


###############################################################################
#                                CRYPTOGRAPHY                                 #
###############################################################################

def sha2_256(message):
    """
    Generate SHA256 digest from message.

    :param message: Input to hash function.
    :return:        Hex representation of SHA256 digest.
    """

    if not isinstance(message, str):
        raise FunctionParameterTypeError("sha2_256")

    h_function = sha256()
    h_function.update(message)
    hex_digest = hexlify(h_function.digest())

    return hex_digest


def sha3_256(message):
    """
    Generate SHA3-256 digest from message.

    :param message: Input to hash function.
    :return:        Hex representation of SHA3-256 digest.
    """

    if not isinstance(message, str):
        raise FunctionParameterTypeError("sha3_256")

    return hexlify(sha3256(message))


def pbkdf2_hmac_sha256(key, rounds=1000, salt=''):
    """
    Generate next decryption key by deriving it using PBKDF2 HMAC-SHA256.

      1 000 iterations are used to refresh key after every message.
     25 000 iterations are used when generating symmetric keys.

    Salt is intentionally not used, as it would have to be pre-shared,
    but is left as a parameter to enable unittesting with test vectors.

    :param key:    Previous key.
    :param rounds: PBKDF2 iteration count.
    :param salt:   Used only for unittesting.
    :return:       Key after derivation.
    """

    if not isinstance(key, str) or not \
            isinstance(rounds, (int, long)) or not \
            isinstance(salt, str):
        raise FunctionParameterTypeError("pbkdf2_hmac_sha256")

    if rounds < 1:
        raise CriticalError("pbkdf2_hmac_sha256", "Rounds < 1")

    derived_key = pbkdf2_sha256.encrypt(key, rounds=rounds, salt=salt)

    # Separate hash from derived key
    parted_hash = derived_key.split('$')[4]

    hash_bin = ab64_decode(parted_hash)
    hash_hex = hexlify(hash_bin)

    return hash_hex


def auth_and_decrypt(account, ct_tag, keyid):
    """
    Authenticate Poly1305 MAC and decrypt XSalsa20 ciphertext.

    :param account: The contact's account name (i.e. alice@jabber.org).
    :param ct_tag:  Encrypted packet; nonce||ciphertext||tag.
    :param keyid:   The purported keyID for packet.
    :return:        MAC verification success boolean, plaintext/error message.
    """

    if not isinstance(account, str) or not \
            isinstance(ct_tag, str) or not \
            isinstance(keyid, (int, long)):
        raise FunctionParameterTypeError("auth_and_decrypt")

    # Load stored key
    hex_key = get_key(account)

    # Calculate the offset between stored keyID and purported keyID
    offset = keyid - get_keyid(account)

    if offset > 0:

        # Notify user about missing messages implicated by the offset
        if account == "me.local":
            print("\nWARNING! Previous %s commands were not received.\n"
                  % offset)

        elif account.startswith("me."):
            print("\nWARNING! Previous %s messages sent to %s were not "
                  "received locally.\n" % (offset, get_nick(account)))

        else:
            print("\nWARNING! Previous %s messages from %s were not "
                  "received.\n" % (offset, get_nick(account)))

        # Iterate key through PBKDF2 until there is no offset
        i = 0
        while i < offset:
            stdout.write("\x1b[1A")
            print("Key catch up: %s/%s iterations left"
                  % ((offset - i), offset))

            hex_key = pbkdf2_hmac_sha256(hex_key)
            i += 1

        print("\x1b[1A\x1b[2K")  # Remove catch up message

    try:
        # Construct new crypto_box
        box = SecretBox(unhexlify(hex_key))

        # Authenticate and decrypt ciphertext
        plaintext = box.decrypt(ct_tag)

        # Store next key
        rotate_key(account, hex_key)

        # Store keyID
        write_keyid(account, keyid + 1)

        # Remove padding
        plaintext = rm_padding(plaintext)

        # Log information about missing messages to user's logfile
        if offset > 0:
                write_log_entry('', account, '', str(offset))

    except CryptoError:
        return False, "MAC_FAIL"

    return True, plaintext


###############################################################################
#                                KEY MANAGEMENT                               #
###############################################################################

def get_keyfile_list():
    """
    Get list of '{me, rx}.account.e' keyfiles in keys folder.

    :return: List of keyfiles.
    """

    ensure_dir("keys/")
    kf_list = []

    for f in listdir("keys/"):
        if f.endswith(".e"):
            if f.startswith("me.") or f.startswith("rx."):
                kf_list.append(f)

    kf_list.sort()

    return kf_list


def get_key(account):
    """
    Load decryption key for selected contact.

    :param account: The sender's account name (i.e. alice@jabber.org).
    :return:        Stored decryption key.
    """

    if not isinstance(account, str):
        raise FunctionParameterTypeError("get_key")

    try:
        key = open("keys/%s.e" % account).readline()

    except IOError:
        raise CriticalError("get_key", "%s.e IOError." % account)

    if not validate_key(key):
        raise InvalidDecryptionKeyError(account)

    return key


def key_writer(account, key):
    """
    Write symmetric key to keyfile.

    :param account: The recipient's account name (e.g. alice@jabber.org).
    :param key:     Symmetric key to write.
    :return:        None
    """

    if not isinstance(account, str) or not isinstance(key, str):
        raise FunctionParameterTypeError("key_writer")

    ensure_dir("keys/")

    try:
        open("keys/%s" % account, "w+").write(key)
        written_key = open("keys/%s" % account).readline()

    except IOError:
        raise CriticalError("key_writer", "%s.e IOError." % account)

    if written_key != key:
        raise CriticalError("key_writer", "Key writing failed.")

    return None


def rotate_key(account, old_key):
    """
    Derive next decryption with PBKDF2-HMAC-SHA256.

    :param account: The sender's account name (e.g. alice@jabber.org).
    :param old_key: Old key to pass through HKDF.
    :return:        None
    """

    if not isinstance(account, str) or not isinstance(old_key, str):
        raise FunctionParameterTypeError("rotate_key")

    new_key = pbkdf2_hmac_sha256(old_key)

    write_t = Thread(target=key_writer, args=("%s.e" % account, new_key))
    write_t.start()
    write_t.join()

    return None


def display_pub_key(parameters):
    """
    Display public key received from contact.

    :param parameters: Packet containing public key.
    :return:           None
    """

    if not isinstance(parameters, str):
        raise FunctionParameterTypeError("display_pub_key")

    try:
        app, model, sender_ver, pt, public_key, account = parameters.split('|')

    except ValueError:
        print("\nReceived invalid public key packet.\n")
        return None

    public_key = public_key.strip().strip('\n')

    if not validate_key(public_key):
        print("\nReceived an invalid public key.\n")
        return None

    # Ignore public keys received from TxM
    if account.startswith("me."):
        return None

    chksm = sha3_256(public_key)[:8]
    split = [public_key[i:i+8] for i in range(0, len(public_key), 8)]
    final = " ".join(split)

    print("Received an ephemeral public key from %s:\n" % account[3:])

    if local_testing:
        print("    %s%s\n\n" % (public_key, chksm))
    else:
        print("    %s %s\n\n" % (final, chksm))

    return None


def ecdhe_command(packet):
    """
    Add contact defined in encrypted packet.

    :param packet: Packet to process.
    :return:       None
    """

    if not isinstance(packet, str):
        raise FunctionParameterTypeError("ecdhe_command")

    global l_msg_coming
    global msg_received
    global m_dictionary

    try:
        header, account, nick, ssk_me, ssk_rx = packet.split('|')

    except (ValueError, IndexError):
        print("\nError: Received invalid packet from TxM.\n")
        return None

    if not validate_key(ssk_me) or not validate_key(ssk_rx):
        print("\nError: Symmetric key received from TxM was invalid.\n")
        return None

    ensure_dir("keys/")

    # Write keys using threads
    write_t = Thread(target=key_writer, args=("me.%s.e" % account, ssk_me))
    write_t.start()
    write_t.join()

    write_t = Thread(target=key_writer, args=("rx.%s.e" % account, ssk_rx))
    write_t.start()
    write_t.join()

    add_contact(("me." + account), nick)
    add_contact(("rx." + account), nick)

    # Initialize dictionaries
    l_msg_coming[("me." + account)] = False
    l_msg_coming[("rx." + account)] = False
    msg_received[("me." + account)] = False
    msg_received[("rx." + account)] = False
    m_dictionary[("me." + account)] = ''
    m_dictionary[("rx." + account)] = ''

    l_file_onway[("me." + account)] = False
    l_file_onway[("rx." + account)] = False
    filereceived[("me." + account)] = False
    filereceived[("rx." + account)] = False
    f_dictionary[("me." + account)] = ''
    f_dictionary[("rx." + account)] = ''

    if log_messages:
        acco_store_l[("me." + account)] = True
        acco_store_l[("rx." + account)] = True
    else:
        acco_store_l[("me." + account)] = False
        acco_store_l[("rx." + account)] = False

    acco_store_f[("me." + account)] = True

    if file_saving:
        acco_store_f[("rx." + account)] = True
    else:
        acco_store_f[("rx." + account)] = False

    system("clear")
    print("\nAdded %s (%s).\n" % (nick, account))

    return None


def psk_command(packet):
    """
    Add PSK and contact defined in encrypted packet.

    :param packet: Packet to process.
    :return:       None
    """

    if not isinstance(packet, str):
        raise FunctionParameterTypeError("ecdhe_command")

    global l_msg_coming
    global msg_received
    global m_dictionary

    try:
        header, account, nick, psk, = packet.split('|')

    except (ValueError, IndexError):
        print("\nError: Received invalid packet from TxM.\n")
        return None

    if not validate_key(psk):
        print("\nError: PSK received from TxM was invalid.\n")
        return None

    ensure_dir("keys/")

    write_t = Thread(target=key_writer, args=("me.%s.e" % account, psk))
    write_t.start()
    write_t.join()

    add_contact(("me." + account), nick)
    sleep(0.5)

    # Initialize data storage dictionaries
    l_msg_coming[("me." + account)] = False
    msg_received[("me." + account)] = False
    m_dictionary[("me." + account)] = ''

    l_file_onway[("me." + account)] = False
    filereceived[("me." + account)] = False
    acco_store_f[("me." + account)] = True
    f_dictionary[("me." + account)] = ''

    if log_messages:
        acco_store_l[("me." + account)] = True
    else:
        acco_store_l[("me." + account)] = False

    system("clear")
    print("\nAdded PSK for %s (%s).\n" % (nick, account))

    return None


def remove_instructions():
    """
    Remove placement instructions that trail PSK file names.

    :return: None
    """

    for f in listdir('keys/'):
        if 'Give this file to' in f:
            new_name = f.split(' - Give this file to')[0]
            rename('keys/%s' % f, 'keys/%s' % new_name)

    return None


###############################################################################
#                               SECURITY RELATED                              #
###############################################################################

def print_opsec_warning():
    """
    Display OPSEC warning to user to remind them
    not to break the security of TCB separation.

    :return: None
    """

    print("\n                         WARNING!                             \n"
          "----------------------------------------------------------------\n"
          "DO NOT MOVE RECEIVED FILES FROM RxM TO LESS SECURE ENVIRONMENTS \n"
          "ESPECIALLY IF THEY ARE CONNECTED TO NETWORK EITHER DIRECTLY OR  \n"
          "INDIRECTLY! DOING SO WILL RENDER SECURITY PROVIDED BY SEPARATED \n"
          "TCB UNITS USELESS, AS MALWARE 'STUCK' IN RxM CAN EXFILTRATE KEYS\n"
          "AND/OR PLAINTEXT THROUGH THIS CHANNEL BACK TO THE ADVERSARY!    \n"
          "                                                                \n"
          "TO RETRANSFER A DOCUMENT, EITHER READ IT FROM RxM SCREEN USING  \n"
          "OCR SOFTWARE RUNNING ON TxM, OR SCAN DOCUMENT IN ANALOG FORMAT. \n"
          "IF YOUR LIFE DEPENDS ON IT, DESTROY THE USED TRANSMISSION MEDIA.\n"
          "----------------------------------------------------------------\n")

    return None


def packet_anomaly(error_type='', packet_type=''):
    """
    Display message and make log entry about packet anomaly to syslog.tfc.

    :param error_type:  Error type determines the warning displayed.
    :param packet_type: Determines if packet is message or command.
    :return:            None
    """

    if not isinstance(error_type, str) or not isinstance(packet_type, str):
        raise FunctionParameterTypeError("packet_anomaly")

    if error_type == "MAC":
        print("\nWARNING! MAC of received %s failed!\n"
              "This might indicate a tampering attempt!" % packet_type)
        log_msg = "MAC of %s failed." % packet_type

    elif error_type == "replay":
        print("\nWARNING! %s has expired/invalid keyID!\n"
              "This might indicate a replay attack!" % packet_type)
        log_msg = "Replayed %s." % packet_type

    elif error_type == "tamper":
        print("\nWARNING! Received a malformed %s.\n"
              "This might indicate a tampering attempt!" % packet_type)
        log_msg = "Tampered / malformed %s." % packet_type

    elif error_type == "checksum":
        print("\nERROR! Packet checksum fail. This might\n"
              "indicate a problem in your RxM data diode.")
        log_msg = "Checksum error in %s." % packet_type

    elif error_type == "hash":
        print("\nWARNING! Long %s hash failed. This might\n"
              "indicate tampering or dropped packets." % packet_type)
        log_msg = "Invalid hash in long %s." % packet_type

    else:
        raise CriticalError("packet_anomaly", "Invalid error type.")

    if create_syslog:

        ts = datetime.now().strftime(l_ts)
        try:
            with open("syslog.tfc", "a+") as f:
                f.write("%s Automatic log entry: %s\n" % (ts, log_msg))

        except IOError:
            raise CriticalError("packet_anomaly", "syslog.tfc IOError.")

    print("\nThis event has been logged to syslog.tfc.\n")
    return None


def clean_exit(message=''):
    """
    Print message and exit Rx.py.

    :param message: Message to print.
    :return:        [no return value]
    """

    if not isinstance(message, str):
        raise FunctionParameterTypeError("clean_exit")

    system("clear")

    if message:
        print("\n%s\n" % message)

    print("\nExiting TFC-NaCl.\n")
    exit()


def graceful_exit():
    """
    Input exit command to queue.

    :return: None
    """

    if unittesting:
        raise SystemExit
    else:
        pc_queue.put("exit")
        sleep(2)


def validate_key(key):
    """
    Check that hex representation of key was valid.

    :param key: Key to validate.
    :return:    None
    """

    if not isinstance(key, str):
        raise FunctionParameterTypeError("validate_key")

    # Verify key consists only from hex chars
    if not set(key.lower()).issubset("abcdef0123456789"):
        print("\nError: Illegal character detected.\n")
        return False

    # Verify key length
    if len(key) != 64:
        print("\nError: Illegal length key.\n")
        return False

    return True


###############################################################################
#                             CONTACT MANAGEMENT                              #
###############################################################################

def add_contact(account, nick):
    """
    Add new contact to .rx_contacts

    Contacts are stored in CSV file. Each contact has it's own line.
    Settings are stored with following format: [account,nick,keyID].

    :param account: The contact's account name (e.g. alice@jabber.org).
    :param nick:    Nick of new contact.
    :return:        None
    """

    if not isinstance(account, str) or not isinstance(nick, str):
        raise FunctionParameterTypeError("add_contact")

    if not isfile(".rx_contacts"):
        open(".rx_contacts", "a+").close()

    try:
        # If account exists, only change nick and keyID.
        db = open(".rx_contacts").readlines()
        for line in db:
            if account in line:
                write_keyid(account, 1)
                write_nick(account, nick)
                return None

        open(".rx_contacts", "a+").write("%s,%s,1\n" % (account, nick))

    except IOError:
        raise CriticalError("add_contact", ".rx_contacts IOError.")

    return None


def add_keyfiles():
    """
    Prompt nicknames for new contacts and store them to .rx_contacts.

    :return: None
    """

    c_list = []

    try:
        with open(".rx_contacts", "a+") as f:
            for row in reader(f):
                c_list.append(row)

    except IOError:
        raise CriticalError("add_keyfiles", ".rx_contacts IOError.")

    for kf in get_keyfile_list():
        existing = False
        account = kf[:-2]

        for c in c_list:
            if account in c[0]:
                existing = True

        if not existing:

            if account == "me.local":
                add_contact("me.local", "local")

            elif account.startswith("rx."):
                local_nick = account.split('@')[0][3:]
                add_contact(account, local_nick)
                continue

            elif account.startswith("me."):
                system("clear")
                print("TFC-NaCl %s || Rx.py\n" % str_version)
                print("New contact '%s' found." % account)
                def_nick = account.split('@')[0][3:]
                def_nick = def_nick.capitalize()
                nick = ''

                while True:

                    try:
                        nick = raw_input("\nEnter nickname [%s]: " % def_nick)
                    except KeyboardInterrupt:
                        graceful_exit()

                    if ',' in nick or '|' in nick:
                        print("\nError: Nick can't contain ',' or '|'.\n")

                    elif nick == "local":
                        print("\nError: Nick can't refer to local keyfile.\n")
                        nick = ''

                    elif nick in get_list_of_accounts():
                        print("\nError: Nick can't be an account.\n")
                        nick = ''

                    else:
                        if nick == '':
                            nick = def_nick
                        break

                add_contact(account, nick)

    return None


def get_keyid(account):
    """
    Get keyID for account.

    The loaded keyID is the counter that defines the number of times keys need
    to be iterated through PBKDF2-HMAC-SHA256 to produce current key. keyID is
    increased by one after every message and command decryption.

    :param account: The recipient's account name (e.g. alice@jabber.org).
    :return:        The keyID (integer).
    """

    if not isinstance(account, str):
        raise FunctionParameterTypeError("get_keyid")

    try:
        c_list = []
        key_id = 0
        id_fnd = False

        with open(".rx_contacts") as f:
            for row in reader(f):
                c_list.append(row)

        for i in range(len(c_list)):
            if c_list[i][0] == account:
                key_id = int(c_list[i][2])
                id_fnd = True

        if not id_fnd:
            return -1

        # Verify keyID is positive
        if key_id > 0:
            return key_id
        else:
            raise CriticalError("get_keyid", "%s keyID less than 1." % account)

    except IndexError:
        raise CriticalError("get_keyid", "%s keyID IndexError." % account)

    except ValueError:
        raise CriticalError("get_keyid", "%s keyID ValueError." % account)

    except IOError:
        raise CriticalError("get_keyid", ".rx_contacts IOError.")


def get_nick(account):
    """
    Load nick from .rx_contacts.

    :param account: The contact's account name (e.g. alice@jabber.org).
    :return:        The nickname for specified account.
    """

    if not isinstance(account, str):
        raise FunctionParameterTypeError("get_nick")

    clst = []
    nick = ''
    keyid = ''

    try:
        with open(".rx_contacts") as f:
            for row in reader(f):
                clst.append(row)

        for i in range(len(clst)):
            if clst[i][0] == account:
                nick = clst[i][1]
                keyid = clst[i][2]

    except IOError:
        raise CriticalError("get_nick", ".rx_contacts IOError.")

    except IndexError:
        raise CriticalError("get_nick", ".rx_contacts IndexError.")

    if nick == '' or keyid == '':
        raise CriticalError("get_nick", "Found no nick for %s." % account)

    return nick


def write_keyid(account, keyid):
    """
    Write new keyID for contact to .rx_contacts.

    :param account: The recipient's account name (e.g. alice@jabber.org).
    :param keyid:   The counter of message, defines the offset in keyfile.
    :return:        None
    """

    if not isinstance(account, str) or not isinstance(keyid, (int, long)):
        raise FunctionParameterTypeError("write_keyid")

    if keyid < 1:
        raise CriticalError("write_keyid", "Keyid less than 1.")

    try:
        c_list = []

        with open(".rx_contacts") as f:
            for row in reader(f):
                c_list.append(row)

        account_found = False

        for i in range(len(c_list)):
            if c_list[i][0] == account:
                account_found = True
                c_list[i][2] = keyid

        if not account_found:
            raise CriticalError("write_keyid", "No %s in .rx_contacts."
                                % account)

        with open(".rx_contacts", 'w') as f:
            writer(f).writerows(c_list)

    except IOError:
        raise CriticalError("write_keyid", ".rx_contacts IOError.")

    if keyid != get_keyid(account):
        raise CriticalError("write_keyid", "keyID writing failed." % account)

    return None


def write_nick(account, nick):
    """
    Write new nick for contact to .rx_contacts.

    :param account: The contact's account name (e.g. alice@jabber.org).
    :param nick:    New nick for contact.
    :return:        None
    """

    if not isinstance(account, str) or not isinstance(nick, str):
        raise FunctionParameterTypeError("write_nick")

    try:
        c_list = []

        with open(".rx_contacts") as f:
            for row in reader(f):
                c_list.append(row)

        account_found = False

        for i in range(len(c_list)):
            if c_list[i][0] == account:
                account_found = True
                c_list[i][1] = nick

        if not account_found:
            raise CriticalError("write_nick", "No %s in .rx_contacts."
                                % account)

        with open(".rx_contacts", 'w') as f:
            writer(f).writerows(c_list)

    except IOError:
        raise CriticalError("write_nick", ".rx_contacts IOError.")

    if nick != get_nick(account):
        raise CriticalError("write_keyid", "Nick writing failed." % account)

    return None


def get_list_of_accounts():
    """
    Get list of available accounts.

    :return: List of accounts.
    """

    account_list = []
    ensure_dir("keys/")

    for f in listdir("keys/"):
        if f.endswith(".e") and (f.startswith("me.") or f.startswith("rx.")):
            account_list.append(f[:-2])

    account_list.sort()

    return account_list


def check_keyfile_parity():
    """
    Check that all me.account.e and rx.account.e files have matching pair.

    :return: None
    """

    me_list = []
    rx_list = []

    for f in listdir("keys/"):
        if f.endswith(".e") and f.startswith("me.") and f != "me.local.e":
            me_list.append(f[3:][:-2])

    for f in listdir("keys/"):
        if f.endswith(".e") and f.startswith("rx."):
            rx_list.append(f[3:][:-2])

    # Cross-compare lists
    no_rx = []
    no_me = []
    no_rx += [c for c in me_list if c not in rx_list]
    no_me += [c for c in rx_list if c not in me_list]

    if no_rx:
        print("\nWarning: Missing keyfiles! Messages received\n"
              "from following contact(s) can not be decrypted:\n")
        for contact in no_rx:
            print("  %s\n" % contact)

    if no_me:
        print("\nWarning: Missing keyfiles! Messages sent to\n"
              "following contact(s) can not be decrypted locally:\n")
        for contact in no_me:
            print("  %s\n" % contact)

    return None


def rm_contact(parameters):
    """
    Remove account and keyfile from TxM and RxM.

    :param parameters: User account to be separated from command.
    :return:           None
    """

    if not isinstance(parameters, str):
        raise FunctionParameterTypeError("rm_contact")

    try:
        account = parameters.split('|')[1]

    except IndexError:
        print("\nError: Account not specified.\n")
        return None

    old = open(".rx_contacts").read().splitlines()
    with open(".rx_contacts", 'w') as f:
        for line in old:
            if account not in line:
                f.write(line + '\n')

    found = False
    for db_account in get_list_of_accounts():
        if db_account[3:] == account:
            found = True

    if not found:
        print("\nRxM has no contact %s to remove.\n" % account)
        return None

    if isfile("keys/me.%s.e" % account):
        Popen("shred -n 3 -z -u keys/me.%s.e" % account, shell=True).wait()

    if isfile("keys/rx.%s.e" % account):
        Popen("shred -n 3 -z -u keys/rx.%s.e" % account, shell=True).wait()

    print("\n%s removed.\n" % account)
    return None


###############################################################################
#                               MSG PROCESSING                                #
###############################################################################

def base64_decode(content):
    """
    Decode base64-encoded string.

    :param content: String to be decoded.
    :return:        Decoded string.
    """

    if not isinstance(content, str):
        raise FunctionParameterTypeError("base64_decode")

    try:
        decoded = b64decode(content)
    except TypeError:
        return "B64D_ERROR"

    return decoded


def rm_padding(string):
    """
    Remove padding from plaintext.

    :param string: String from which padding is removed.
    :return:       String padding is removed from.
    """

    if not isinstance(string, str):
        raise FunctionParameterTypeError("rm_padding")

    return string[:-ord(string[-1:])]


###############################################################################
#                           COMMANDS AND FUNCTIONS                            #
###############################################################################


def write_log_entry(nick, account, message, dropped=''):
    """
    Write log file to store conversations.

    :param nick:    Nickname for contact.
    :param account: The contact's account name (i.e. alice@jabber.org).
    :param message: Message to store in log file.
    :param dropped: Number of dropped messages.
    :return:        None
    """

    if not isinstance(nick, str) or not \
            isinstance(account, str) or not \
            isinstance(message, str) or not \
            isinstance(dropped, str):
        raise FunctionParameterTypeError("write_log_entry")

    message = message.strip('\n')
    t_stamp = datetime.now().strftime(l_ts)
    ensure_dir("logs/")

    try:
        if dropped:
            with open("logs/RxM - logs.%s.tfc" % account[3:], "a+") as f:
                if account.startswith("me"):
                    target = "to %s" % account[3:]
                else:
                    target = "from %s" % account[3:]

                f.write("\n%s (noise) messages /file packets %s were "
                        "dropped.\n\n" % (dropped, target))
        else:
            with open("logs/RxM - logs.%s.tfc" % account, "a+") as f:
                f.write("%s %s: %s\n\n" % (t_stamp, nick, message))

    except IOError:
        raise CriticalError("write_log_entry", "Logfile IOError.")

    return None


def yes(prompt):
    """
    Prompt user a question that is answered with yes / no.

    :param prompt: Question to be asked.
    :return:       True if user types 'y' or 'yes', otherwise returns False.
    """

    if not isinstance(prompt, str):
        raise FunctionParameterTypeError("yes")

    while True:
        try:
            answer = raw_input("%s (y/n): " % prompt)

        except KeyboardInterrupt:
            raise

        if answer.lower() in ("yes", 'y'):
            return True

        elif answer.lower() in ("no", 'n'):
            return False


def phase(string, dist):
    """
    Print name of next phase. Next message (about completion), printed after
    the phase will be printed on same line as the name specified by 'string'.

    :param string: String to be printed.
    :param dist:   Indentation of completion message.
    :return:       None
    """

    if not isinstance(string, str) or not isinstance(dist, (int, long)):
        raise FunctionParameterTypeError("phase")

    stdout.write(string + ((dist - len(string)) * ' '))
    stdout.flush()
    sleep(0.02)

    return None


def get_tty_wh():
    """
    Get width and height of terminal Tx.py is running in.

    :return: Width (and height) of terminal.
    """

    def ioctl_gwin_size(fd):
        """
        Get terminal window size from input/output control.

        :param fd: File descriptor.
        :return:   Width and height.
        """

        return unpack("hh", ioctl(fd, TIOCGWINSZ, "1234"))

    cr = ioctl_gwin_size(0) or ioctl_gwin_size(1) or ioctl_gwin_size(2)

    return int(cr[1]), int(cr[0])


def print_banner():
    """
    Print animated startup banner.

    Style 3:
        Matrix-Curses - See how deep the rabbit hole goes.
        Copyright (c) 2012 Tom Wallroth
        http://github.com/devsnd/matrix-curses/

        Used and modified under GNU GPL version 3

    :return: None
    """

    string = "Tinfoil Chat NaCl %s" % str_version

    system("clear")
    width, height = get_tty_wh()

    print((height / 2) - 1) * '\n'

    # Style 1
    animation = sysrandint(1, 3)
    if animation == 1:
        i = 0
        while i <= len(string):
            stdout.write("\x1b[1A" + ' ')
            stdout.flush()

            if i == len(string):
                print((width - len(string)) / 2) * ' ' + string[:i]
            else:
                rc = chr(randrange(32, 126))
                print((width - len(string)) / 2) * ' ' + string[:i] + rc

            i += 1
            sleep(0.03)

    # Style 2
    if animation == 2:
        char_l = len(string) * ['']

        while True:
            stdout.write("\x1b[1A" + ' ')
            stdout.flush()
            st = ''

            for i in range(len(string)):
                if char_l[i] != string[i]:
                    char_l[i] = chr(randrange(32, 126))
                else:
                    char_l[i] = string[i]
                st += char_l[i]

            print((width - len(string)) / 2) * ' ' + st

            sleep(0.004)
            if st == string:
                break

    # Style 3
    if animation == 3:

        string = "Tinfoil Chat NaCl 0.16.1"
        dropping_chars = 50
        random_cleanup = 80
        min_speed = 3
        max_speed = 7
        sleep_ms = 0.005

        scroll_chars = ''
        for a in range(32, 126):
            scroll_chars += chr(a)

        class FChar(object):

            list_chr = list(scroll_chars)
            normal_attr = curses.A_NORMAL
            highlight_attr = curses.A_REVERSE

            def __init__(self, o_width, speed_min, speed_max):
                self.x = 0
                self.y = 0
                self.speed = 1
                self.char = ' '
                self.offset = randint(0, self.speed)
                self.reset(o_width, speed_min, speed_max)
                self.completed = []

            def reset(self, c_width, speed_min, speed_max):
                self.char = choice(FChar.list_chr)
                self.x = randint(1, c_width - 1)
                self.y = 0
                self.speed = randint(speed_min, speed_max)
                self.offset = randint(0, self.speed)

            def get_completed(self):
                return self.completed

            def tick(self, scr, steps):
                win_h, win_w = scr.getmaxyx()
                if self.advances(steps):

                    # If window was re-sized and char is out of bounds, reset
                    self.out_of_bounds_reset(win_w, win_h)

                    # Make previous char curses.A_NORMAL
                    scr.addstr(self.y, self.x, self.char, curses.A_NORMAL)

                    # Choose new char and draw it A_NORMAL if not out of bounds
                    self.y += 1
                    if self.y == win_h / 2:
                        indent_len = (win_w - len(string)) / 2
                        prepended_ind = (indent_len * ' ')
                        final_string = prepended_ind + string + ' '

                        if self.x > indent_len - 1:
                            try:
                                self.char = final_string[self.x]
                                self.completed.append(self.x)
                            except IndexError:
                                self.char = choice(FChar.list_chr)
                    else:
                        self.char = choice(FChar.list_chr)

                    if not self.out_of_bounds_reset(win_w, win_h):
                        scr.addstr(self.y, self.x, self.char, curses.A_NORMAL)

            def out_of_bounds_reset(self, win_w, win_h):
                if self.x > win_w - 2:
                    self.reset(win_w, min_speed, max_speed)
                    return True
                if self.y > win_h - 2:
                    self.reset(win_w, min_speed, max_speed)
                    return True
                return False

            def advances(self, steps):
                if steps % (self.speed + self.offset) == 0:
                    return True
                return False

        # Use insecure but fast PRNG
        def rand():
            p = sysrandint(0, 1000000000)
            while True:
                p ^= (p << 21) & 0xffffffffffffffff
                p ^= (p >> 35)
                p ^= (p << 4) & 0xffffffffffffffff
                yield p

        def randint(_min, _max):
            n = r.next()
            return (n % (_max - _min)) + _min

        def main():
            steps = 0
            scr = curses.initscr()
            scr.nodelay(1)
            curses.curs_set(0)
            curses.noecho()

            win_h, win_w = scr.getmaxyx()

            if win_w < len(string):
                raise KeyboardInterrupt

            window_animation = None
            lines = []

            for _ in range(dropping_chars):
                fc = FChar(win_w, min_speed, max_speed)
                fc.y = randint(0, win_h - 2)
                lines.append(fc)

            scr.refresh()
            completion = []
            delay = 0

            while True:
                win_h, win_w = scr.getmaxyx()

                for line in lines:
                    line.tick(scr, steps)
                    completed = line.get_completed()
                    for c in completed:
                        if c not in completion:
                            completion.append(c)

                if len(completion) >= len(string):
                    if delay > 600:
                        raise KeyboardInterrupt
                    else:
                        delay += 1

                for _ in range(random_cleanup):
                    x = randint(0, win_w - 1)
                    y = randint(0, win_h - 1)

                    indent_len = (win_w - len(string)) / 2
                    prepended_ind = (indent_len * ' ')

                    if y == win_h / 2:
                        if x < len(prepended_ind):
                            scr.addstr(y, x, ' ')
                        if x > len(prepended_ind + string):
                            scr.addstr(y, x, ' ')
                    else:
                        scr.addstr(y, x, ' ')

                if window_animation is not None:
                    if not window_animation.tick(scr, steps):
                        window_animation = None

                scr.refresh()
                sleep(sleep_ms)
                steps += 1
        try:
            r = rand()
            main()
        except KeyboardInterrupt:
            curses.endwin()
            curses.curs_set(1)
            curses.reset_shell_mode()
            curses.echo()
            system("clear")

    sleep(0.3)
    system("clear")
    return None


def verify_checksum(packet):
    """
    Detect transmission errors by verifying tweakable SHA-256 based checksum.

    :param packet: Packet to verify.
    :return:       True if packet checksum matched, else False.
    """

    if not isinstance(packet, str):
        raise FunctionParameterTypeError("verify_chksum")

    chksum_pckt = packet[-checksum_len:]
    separated_p = packet[:-(checksum_len+1)]
    chksum_calc = sha2_256(separated_p)[:checksum_len]

    if chksum_calc == chksum_pckt:
        return True
    else:
        print("\nChecksum error: Command / message was discarded.\n"
              "If error persists, check RxM data diode batteries.\n")
        return False


def ensure_dir(directory):
    """
    Ensure directory exists.

    :param directory: Specified directory.
    :return:          None
    """

    if not isinstance(directory, str):
        raise FunctionParameterTypeError("ensure_dir")

    try:
        name = dirname(directory)
        if not exists(name):
            makedirs(name)
    except OSError:
        raise CriticalError("ensure_dir", "No directory specified.")

    return None


###############################################################################
#                     PROCESS COMMAND/MSG HEADER                              #
###############################################################################

def noise_packet(account):
    """
    Process noise message packet.

    If print_noise_pkg is True, show a notification about noise packet.
    Discard long messages being received from sender.

    :param account: Sender's account (e.g. alice@jabber.org).
    :return:        None
    """

    if not isinstance(account, str):
        raise FunctionParameterTypeError("noise_packet")

    if l_msg_coming[account]:
        if account.startswith("me."):
            print("Long message to %s cancelled.\n" % get_nick(account))
        if account.startswith("rx."):
            print("%s cancelled long message.\n" % get_nick(account))

    if print_noise_pkg:
        if account.startswith("me."):
            print("Received noise message sent to %s." % get_nick(account))
        if account.startswith("rx."):
            print("Received noise message from %s." % get_nick(account))

    msg_received[account] = True
    l_msg_coming[account] = False
    m_dictionary[account] = ''
    return None


def cancel_message(account):
    """
    Process cancel message packet.

    Discard long messages being received from sender.

    :param account: Sender's account (e.g. alice@jabber.org).
    :return:        None
    """

    if not isinstance(account, str):
        raise FunctionParameterTypeError("cancel_message")

    if l_msg_coming[account]:
        if account.startswith("me."):
            print("Long message to %s cancelled.\n" % get_nick(account))
        if account.startswith("rx."):
            print("%s cancelled long message.\n" % get_nick(account))

    l_msg_coming[account] = False
    msg_received[account] = False
    m_dictionary[account] = ''
    return None


def cancel_file(account):
    """
    Process cancel file packet.

    :param account: Sender's account (e.g. alice@jabber.org).
    :return:        None
    """

    if not isinstance(account, str):
        raise FunctionParameterTypeError("cancel_file")

    if account.startswith("me."):
        print("\nFile transmission to %s cancelled.\n"
              % get_nick(account))
    if account.startswith("rx."):
        print("\n%s cancelled file transmission.\n"
              % get_nick(account))

    if l_file_onway[account]:
        l_file_onway[account] = False
        filereceived[account] = False
        f_dictionary[account] = ''

    return None


def short_message(account, packet):
    """
    Process short message packet.

    Strip header from packet and add message to m_dictionary.

    :param account: Sender's account (e.g. alice@jabber.org).
    :param packet:  Packet to process.
    :return:        None
    """

    if not isinstance(account, str) or not isinstance(packet, str):
        raise FunctionParameterTypeError("short_message")

    if l_msg_coming[account]:
        if account.startswith("me."):
            print("Long message to %s cancelled.\n" % get_nick(account))
        if account.startswith("rx."):
            print("%s cancelled long message.\n" % get_nick(account))

    msg_received[account] = True
    l_msg_coming[account] = False
    m_dictionary[account] = packet[1:]
    return None


def short_file(account, packet):
    """
    Process short file packet.

    Strip header from packet and add file to m_dictionary.

    :param account: Sender's account (e.g. alice@jabber.org).
    :param packet:  Packet to process.
    :return:        None
    """

    if not isinstance(account, str) or not isinstance(packet, str):
        raise FunctionParameterTypeError("short_file")

    if file_saving or acco_store_f[account]:
        if l_file_onway[account]:
            if account.startswith("me."):
                print("\nFile transmission to %s cancelled.\n" 
                      % get_nick(account))
            if account.startswith("rx."):
                print("\n%s cancelled file transmission.\n" 
                      % get_nick(account))

        filereceived[account] = True
        l_file_onway[account] = False
        f_dictionary[account] = packet[1:]

    else:
        print("\n%s tried to send a file but file reception is disabled.\n"
              % get_nick(account))

    return None


def long_message_start(account, packet):
    """
    Process first packet of long message.

    Strip header from packet and add first part of message to m_dictionary.

    :param account: Sender's account (e.g. alice@jabber.org).
    :param packet:  Packet to process.
    :return:        None
    """

    if not isinstance(account, str) or not isinstance(packet, str):
        raise FunctionParameterTypeError("long_message_start")

    if account.startswith("rx."):
        if l_msg_coming[account]:
            print("\n%s cancelled long message." % get_nick(account))

        if l_message_incoming:
            print("\nIncoming long message from %s." % get_nick(account))

    print('')
    msg_received[account] = False
    l_msg_coming[account] = True
    m_dictionary[account] = packet[1:]
    return None


def long_file_start(account, packet):
    """
    Process first packet of file.

    Strip header from packet and add first part of file to f_dictionary.

    :param account: Sender's account (e.g. alice@jabber.org).
    :param packet:  Packet to process.
    :return:        None
    """

    if not isinstance(account, str) or not isinstance(packet, str):
        raise FunctionParameterTypeError("long_file_start")

    if file_saving or acco_store_f[account]:
        if l_file_onway[account]:
            if account.startswith("me."):
                print("\nFile transmission to %s cancelled.\n" 
                      % get_nick(account))
            if account.startswith("rx."):
                print("\n%s cancelled file transmission.\n" 
                      % get_nick(account))

        name, size, p_count, eta, data = packet.split('|')

        # Print notification about receiving file
        if account.startswith("me."):
            print("\nReceiving file sent to %s.\n" % get_nick(account))

        if account.startswith("rx."):
            print("\nIncoming file from %s " % get_nick(account))
            print("  %s (%s)" % (name[1:], size))
            print("  ETA: %s (~%s packets)\n" % (eta, p_count))

        filereceived[account] = False
        l_file_onway[account] = True
        f_dictionary[account] = packet[1:]

    else:
        if account.startswith("rx."):
            print("\n%s is sending file but file reception is disabled.\n"
                  % get_nick(account))

        elif account.startswith("me.") and keep_local_files:
            print("\nReceiving copy of sent file "
                  "but file reception is disabled.\n")

    return None


def long_message_append(account, packet):
    """
    Process appended packet to message.

    Strip header from packet and append part of message to m_dictionary.

    :param account: Sender's account (e.g. alice@jabber.org).
    :param packet:  Packet to process.
    :return:        None
    """

    if not isinstance(account, str) or not isinstance(packet, str):
        raise FunctionParameterTypeError("long_message_append")

    msg_received[account] = False
    l_msg_coming[account] = True
    m_dictionary[account] += packet[1:]
    return None


def long_file_append(account, packet):
    """
    Process appended packet to file.

    Strip header from packet and append part of file to f_dictionary.

    :param account: Sender's account (e.g. alice@jabber.org).
    :param packet:  Packet to process.
    :return:        None
    """

    if not isinstance(account, str) or not isinstance(packet, str):
        raise FunctionParameterTypeError("long_file_append")

    if file_saving or acco_store_f[account]:
        filereceived[account] = False
        l_file_onway[account] = True
        f_dictionary[account] += packet[1:]

    return None


def long_message_end(account, packet):
    """
    Process last packet to message.

    Strip header from packet and append last part of message to m_dictionary.

    :param account: Sender's account (e.g. alice@jabber.org).
    :param packet:  Packet to process.
    :return:        None
    """

    if not isinstance(account, str) or not isinstance(packet, str):
        raise FunctionParameterTypeError("long_message_end")

    m_dictionary[account] += packet[1:]
    message_content = m_dictionary[account][:-64]
    hash_of_message = m_dictionary[account][-64:]

    if sha3_256(message_content) != hash_of_message:
        system("clear")
        packet_anomaly("hash", "message")
        return None

    msg_received[account] = True
    l_msg_coming[account] = False
    m_dictionary[account] = message_content

    if file_saving or acco_store_f[account]:
        filereceived[account] = False

    return None


def long_file_end(account, packet):
    """
    Process last packet to file.

    Strip header from packet and append last part of file to f_dictionary.

    :param account: Sender's account (e.g. alice@jabber.org).
    :param packet:  Packet to process.
    :return:        None
    """

    if not isinstance(account, str) or not isinstance(packet, str):
        raise FunctionParameterTypeError("long_file_end")

    if file_saving or acco_store_f[account]:
        f_dictionary[account] += packet[1:]
        file_content = f_dictionary[account][:-64]
        hash_of_file = f_dictionary[account][-64:]

        if sha3_256(file_content) != hash_of_file:
            system("clear")
            packet_anomaly("hash", "file")
            return None

        f_dictionary[account] = file_content
        filereceived[account] = True
        msg_received[account] = False
        l_file_onway[account] = False

    return None


def process_received_messages(account):
    """
    Show message and if log_messages is True, add message to logfile.

    :param account: Sender's account (e.g. alice@jabber.org).
    :return:        None
    """

    if not isinstance(account, str):
        raise FunctionParameterTypeError("process_received_messages")

    if msg_received[account]:

        if m_dictionary[account] == '':
            return None

        if account.startswith("me."):
            nick = "Me > %s" % get_nick(account)
        else:
            nick = "     %s" % get_nick("me.%s" % account[3:])

        # Print timestamp and message to user
        if display_time:
            ts = datetime.now().strftime(d_ts)
            print("%s  %s:  %s" % (ts, nick, m_dictionary[account]))
        else:
            print("%s:  %s" % (nick, m_dictionary[account]))

        # Log messages if logging is enabled
        if acco_store_l[account]:
            if nick.startswith("Me > "):
                spacing = len(get_nick("me." + account[3:])) - 2
                nick = spacing * ' ' + "Me"
                write_log_entry(nick,     account[3:], m_dictionary[account])
            else:
                write_log_entry(nick[5:], account[3:], m_dictionary[account])

        msg_received[account] = False
        l_msg_coming[account] = False
        m_dictionary[account] = ''

    return None


def process_received_files(account):
    """
    Decode and store received file.

    :param account: Sender's account (e.g. alice@jabber.org).
    :return:        None
    """

    if not isinstance(account, str):
        raise FunctionParameterTypeError("process_received_files")

    if file_saving or acco_store_f[account]:
        if filereceived[account]:

            if account.startswith("rx.") or \
                    (account.startswith("me.") and keep_local_files):

                ensure_dir("files/")

                packet = str(f_dictionary[account])
                f_data = packet.split('|')[4]
                f_name = packet.split('|')[0]
                f_orig = f_name

                if account.startswith("me."):
                    f_name = "Local copy - %s" % f_name

                # Concatenate '(n)' for duplicate file names
                fn_lst = f_name.split('.')
                filext = fn_lst[-1]
                fn_lst.pop(-1)
                f_name = '.'.join(fn_lst)
                f_init = f_name

                if isfile("files/%s.%s" % (f_name, filext)):
                    i = 1
                    while isfile("files/%s.%s" % (f_name, filext)):
                        f_name = "%s(%s)" % (f_init, i)
                        i += 1

                # Decode and store file data
                decoded = base64_decode(f_data)
                open("files/%s.%s" % (f_name, filext), "w+").write(decoded)

                # Print notification
                if account.startswith("me."):
                    print("\nReceived copy of %s sent to %s.\n"
                          % (f_orig, get_nick(account)))

                if account.startswith("rx."):
                    print("\nReceived %s from %s.\n"
                          % (f_orig, get_nick(account)))

                if disp_opsec_warning:
                    print_opsec_warning()
                else:
                    print('')

            if account.startswith("me.") and not keep_local_files:
                print("\nLocally received file was discarded.\n")

            filereceived[account] = False
            l_file_onway[account] = False
            f_dictionary[account] = ''

            # if a_close_f_recv is True, turn file reception off.
            if a_close_f_recv and not file_saving:
                if account.startswith("rx."):
                    acco_store_f[account] = False
                    print("\nFile reception for %s has been disabled.\n"
                          % account[3:])

    return None


###############################################################################
#                          RECEIVED DATA PROCESSING                           #
###############################################################################

def nh_packet_loading_process(ret=False):
    """
    Load packet from NH via serial port / IPC. If local_testing boolean is
    enabled, use IPC (multiprocessing socket) instead of serial.

    :param ret: True returns packet instead of putting it to nh_queue.
    :return:    [no return value]
    """

    if local_testing:
        try:
            while True:
                sleep(0.001)
                packet = str(conn.recv())

                if packet == '':
                    continue

                packet = packet.strip('\n')
                if verify_checksum(packet):
                    if ret:
                        return packet[:-9]                    
                    else:
                        nh_queue.put(packet[:-9])

        except EOFError:
            system("clear")
            print("\nNH <> RxM IPC disconnected.\n")
            graceful_exit()

    else:
        while True:
            sleep(0.001)
            packet = port_to_nh.readline()

            if packet == '':
                continue

            packet = packet.strip('\n')
            if verify_checksum(packet):
                if ret:
                    return packet[:-9]
                else:
                    nh_queue.put(packet[:-9])


def message_packet(packet):
    """
    Process received message packet.

    :param packet: Packet to process.
    :return:       None
    """

    if not isinstance(packet, str):
        raise FunctionParameterTypeError("message_packet")

    try:
        app, model, sender_v, pt, encoded, keyid, account = packet.split('|')
        keyid = int(keyid)

    except (IndexError, ValueError):
        packet_anomaly("tamper", "message")
        return None

    ct_tag = base64_decode(encoded)

    if ct_tag == "B64D_ERROR":
        packet_anomaly("tamper", "message")
        return None

    try:
        # Check that keyID for account exists
        if get_keyid(account) == -1:
            print("\nFailed to load key ID for %s.\n"
                  "Message/file could not be decrypted.\n") % account[3:]
            return None

        # Check that purported keyID is greater than stored one
        if keyid < get_keyid(account):
            packet_anomaly("replay", "message")
            return None

    except (UnboundLocalError, ValueError):
        if account.startswith("me."):
            print("\nFailed to load KeyID for %s.\n"
                  "Local decryption of packet failed.\n" % account[3:])

        if account.startswith("rx."):
            print("\nFailed to load KeyID for %s.\n"
                  "Decryption of packet failed.\n" % account[3:])

        else:
            print("\nInvalid account header.\n")

        return None

    except (KeyError, TypeError):
        packet_anomaly("tamper", "message")
        return None

    # Check that keyfile for decryption exists
    if not isfile("keys/%s.e" % account):
        print("\nError: keyfile for contact %s was not found.\n"
              "Message could not be decrypted.\n" % account)
        return None

    # Decrypt message if MAC verification succeeds
    valid_mac, packet = auth_and_decrypt(account, ct_tag, keyid)

    if not valid_mac:
        packet_anomaly("MAC", "message")
        return None

    process_message(packet, account)
    return None


def process_message(packet, account):
    """
    Process messages / files received from TxM / contact.

    :param packet:  Message /file packet.
    :param account: Sender's account (e.g. alice@jabber.org).
    :return:        None
    """

    if not isinstance(packet, str) or not isinstance(account, str):
        raise FunctionParameterTypeError("process_message")

    if packet.startswith('n'):
        noise_packet(account)

    elif packet.startswith('c'):
        cancel_message(account)

    elif packet.startswith('C'):
        cancel_file(account)

    elif packet.startswith('s'):
        short_message(account, packet)

    elif packet.startswith('S'):
        short_file(account, packet)

    elif packet.startswith('l'):
        long_message_start(account, packet)

    elif packet.startswith('L'):
        long_file_start(account, packet)

    elif packet.startswith('a'):
        long_message_append(account, packet)

    elif packet.startswith('A'):
        long_file_append(account, packet)

    elif packet.startswith('e'):
        long_message_end(account, packet)

    elif packet.startswith('E'):
        long_file_end(account, packet)

    else:
        print("Error: Received packet had an incorrect header.")
        return None

    process_received_messages(account)
    process_received_files(account)
    return None


def command_packet(packet):
    """
    Process received command packet.

    :param packet: Command packet.
    :return:       None
    """

    if not isinstance(packet, str):
        raise FunctionParameterTypeError("command_packet")

    try:
        app, model, txm_v, pt, encoded, keyid = packet.split('|')
        keyid = int(keyid)

    except (ValueError, IndexError):
        packet_anomaly("tamper", "command")
        return None

    ct_tag = base64_decode(encoded)

    if ct_tag == "B64D_ERROR":
        packet_anomaly("tamper", "command")
        return None

    try:
        # Check that keyID for local key exists
        if get_keyid("me.local") == -1:
            print("\nError! Missing keyID:\nCommand couldn't be decrypted.\n")
            return None

        # Check that purported keyID is greater than stored one
        if keyid < get_keyid("me.local"):
            packet_anomaly("replay", "command")
            return None

    except (UnboundLocalError, ValueError):
        print("\nFailed to load key ID local keyfile.\n"
              "Command couldn't be decrypted.\n")
        return None

    except (KeyError, TypeError):
        packet_anomaly("tamper", "command")
        return None

    # Check that RxM side local keyfile exists
    if not isfile("keys/me.local.e"):
        print("\nError: me.local.e was not found.\n"
              "Command could not be decrypted.\n")
        return None

    # Decrypt command if MAC verification succeeds
    valid_mac, decrypted_cmd = auth_and_decrypt("me.local", ct_tag, keyid)

    if not valid_mac:
        packet_anomaly("MAC", "command")
        return None

    # Process command
    process_command(decrypted_cmd)
    return None


def process_command(cmd):
    """
    Process commands received from TxM.

    :param cmd: Command string.
    :return:    None
    """

    if not isinstance(cmd, str):
        raise FunctionParameterTypeError("process_command")

    global file_saving
    global l_file_onway
    global filereceived
    global f_dictionary
    global acco_store_f
    global acco_store_l

    # Discard noise commands
    if cmd == 'N':
        if print_noise_pkg:
            print("Received noise command from local TxM.")
        return None

    # New contact public keys
    elif cmd.startswith('A'):
        ecdhe_command(cmd)

    # Contact PSK
    elif cmd.startswith("PSK"):
        psk_command(cmd)

    # Remove contact
    elif cmd.startswith("REMOVE"):
        rm_contact(cmd)

    # Exit Rx.py
    elif cmd.startswith("EXIT"):
        system("clear")
        graceful_exit()

    # Encrypted screen clearing
    elif cmd == "CLEAR":
        system("clear")

    # Global message logging
    elif cmd == "LOGGING|ENABLE":
        all_enabled = True
        for account in get_list_of_accounts():
            if not acco_store_l[account]:
                all_enabled = False

        if all_enabled:
            print("\nLogging is already enabled for every contact.\n")
        else:
            print("\nLogging has been enabled for every contact.\n")
            for account in get_list_of_accounts():
                acco_store_l[account] = True

    elif cmd == "LOGGING|DISABLE":
        all_disabled = True
        for account in get_list_of_accounts():
            if acco_store_l[account]:
                all_disabled = False

        if all_disabled:
            print("\nLogging is already disabled for every contact.\n")
        else:
            print("\nLogging has been disabled for every contact.\n")
            for account in get_list_of_accounts():
                acco_store_l[account] = False

    # Account specific logging control
    elif cmd.startswith("LOGGING|ENABLE|"):
        try:
            account = cmd.split('|')[2]
            if account not in get_list_of_accounts():
                raise IndexError
        except IndexError:
            print("\nError: Invalid account.\n")
            return None

        if acco_store_l[account] and acco_store_l["rx." + account[3:]]:
            print("\nLogging for %s is already enabled.\n" % account[3:])
        else:
            print("\nLogging for %s has been enabled.\n" % account[3:])
            acco_store_l["me." + account[3:]] = True
            acco_store_l["rx." + account[3:]] = True

    elif cmd.startswith("LOGGING|DISABLE|"):
        try:
            account = cmd.split('|')[2]
            if account not in get_list_of_accounts():
                raise IndexError
        except IndexError:
            print("\nError: Invalid account.\n")
            return None

        if acco_store_l[account] or acco_store_l["rx." + account[3:]]:
            print("\nLogging for %s has been disabled.\n" % account[3:])
            acco_store_l["me." + account[3:]] = False
            acco_store_l["rx." + account[3:]] = False
        else:
            print("\nLogging for %s is already disabled.\n" % account[3:])

    # Global store control
    elif cmd == "STORE|ENABLE":
        all_enabled = True
        for account in get_list_of_accounts():
            if not acco_store_f[account]:
                all_enabled = False

        if all_enabled:
            print("\nFile reception is already enabled for every contact.\n")
        else:
            print("\nFile reception has been enabled for every contact.\n")
            for account in get_list_of_accounts():
                l_file_onway[account] = False
                filereceived[account] = False
                acco_store_f[account] = True
                f_dictionary[account] = ''

    elif cmd == "STORE|DISABLE":
        all_disabled = True
        for account in get_list_of_accounts():
            if acco_store_f[account]:
                all_disabled = False

        if all_disabled:
            print("\nFile reception is already disabled for every contact.\n")
        else:
            print("\nFile reception has been disabled for every contact.\n")
            for account in get_list_of_accounts():
                acco_store_f[account] = False

    # Account specific store control
    elif cmd.startswith("STORE|ENABLE|"):
        try:
            account = cmd.split('|')[2]
            if account not in get_list_of_accounts():
                raise IndexError
        except IndexError:
            print("\nError: Invalid account.\n")
            return None

        if acco_store_f[account]:
            print("\nFile reception for %s is already enabled.\n"
                  % account[3:])
        else:
            print("\nFile reception for %s has been enabled.\n" % account[3:])
            l_file_onway[account] = False
            filereceived[account] = False
            acco_store_f[account] = True
            f_dictionary[account] = ''

    elif cmd.startswith("STORE|DISABLE|"):
        try:
            account = cmd.split('|')[2]
            if account not in get_list_of_accounts():
                raise IndexError
        except IndexError:
            print("\nInvalid account.\n")
            return None

        if not acco_store_f[account]:
            print("\nFile reception for %s is already disabled.\n"
                  % account[3:])
        else:
            print("\nFile reception for %s has been disabled.\n"
                  % account[3:])
            acco_store_f[account] = False

    # Change nick
    elif cmd.startswith("NICK|"):
        header, account, nick = cmd.split('|')

        write_nick(account, nick)
        stored_nick = get_nick(account)
        print("\nChanged %s nick to %s.\n" % (account[3:], stored_nick))

    else:
        raise CriticalError("process_command", "Invalid command.")

    return None


def process_local_key(packet, kdk_in_q=False):
    """
    Decrypt and setup new local key.

    :param packet:   Encrypted local key and device code.
    :param kdk_in_q: True loads key decryption key from multiprocess queue.
    :return:         None
    """

    if not isinstance(packet, str) or not isinstance(kdk_in_q, bool):
        raise FunctionParameterTypeError("process_local_key")

    try:
        app, model, version, p_type, encoded = packet.split('|')
    except (ValueError, IndexError):
        packet_anomaly("tamper", "local key")
        return None

    kdk = ''
    if kdk_in_q:

        # Wait for key decryption key from input process
        try:
            while True:
                sleep(0.1)
                if not kdk_queue.empty():
                    kdk = kdk_queue.get()
                    break
        except KeyboardInterrupt:
            print("\nLocal key decryption aborted.\n")
            return None
    else:
        # Get key decryption key from user
        print("\n    Received encrypted local key. "
              "Enter key decryption key from TxM:")
        while True:
            try:
                if local_testing:
                    print(" %s" % (72 * 'v'))
                else:
                    print("%s" % (9 * " vvvvvvvv"))
                kdk = raw_input(' ').replace(' ', '')
            except KeyboardInterrupt:
                print("\nKey decryption aborted.\n")
                return None

            if not validate_key(kdk[:-8]):
                sleep(1)
                continue

            if sha3_256(kdk[:-8])[:8] != kdk[64:]:
                print("\nKey decryption key checksum fail. Try again.")
                sleep(1)
                continue
            else:
                break

    # Decode and decrypt local key
    try:
        ct_tag = base64_decode(encoded)
        if ct_tag == "B64D_ERROR":
            print("Key B64 Decoding error.")
            return None
        # Construct new Secret Box
        box = SecretBox(unhexlify(kdk[:-8]))

        # Authenticate and decrypt ciphertext
        padded_key = box.decrypt(ct_tag)

    except CryptoError:
        print("\nLocal key decryption error.\n")
        if kdk_in_q:
            return 'MAC_FAIL'
        return None

    local_key = rm_padding(padded_key)
    device_code = local_key[-2:]
    local_key = local_key[:-2]

    if not validate_key(local_key):
        print("\nError: Received invalid local key from TxM.\n")
        return None

    print("\nLocal key added. Device code for TxM: %s\n" % device_code)

    ensure_dir("/keys")

    write_t = Thread(target=key_writer, args=("me.local.e", local_key))
    write_t.start()
    write_t.join()

    add_contact("me.local", "local")
    sleep(0.5)

    return "SUCCESS"


def get_local_key_packet():
    """
    Wait for encrypted local key from TxM.

    :return: None
    """

    print("\nNo local key was found. Send local key with cmd '/localkey'.\n")

    try:
        while True:

            lkey_packet = nh_packet_loading_process(ret=True)

            if lkey_packet.startswith("TFC|N|%s|L|" % int_version):
                status = process_local_key(lkey_packet)
                if status == "SUCCESS":
                    global accept_new_local_keys
                    accept_new_local_keys = False
                    return None
                if status == "MAC_FAIL":
                    return None

            elif lkey_packet.startswith("TFC|N|%s|U|CLEAR" % int_version):
                system("clear")

            if lkey_packet.startswith("TFC|N|%s|P|" % int_version):
                display_pub_key(lkey_packet)

            else:
                print("\nError: Send new local key first.\n")

    except AttributeError:
        pass

    except KeyboardInterrupt:
        system("clear")
        exit()


# Main loop
def main_loop_process():
    """
    Load messages from TxM and RxM queues and process them.

    :return: [no return value]
    """

    global accept_new_local_keys

    try:
        while True:
            sleep(0.01)

            if nh_queue.empty():
                sleep(0.1)
                continue
            nh_packet = nh_queue.get()

            if nh_packet.startswith("TFC|N|%s|P|" % int_version):
                display_pub_key(nh_packet)
                accept_new_local_keys = True

            elif nh_packet.startswith("TFC|N|%s|L|" % int_version):
                if accept_new_local_keys:
                    pc_queue.put("start_kdk_input_process")
                    _ = process_local_key(nh_packet, kdk_in_q=True)

            elif nh_packet.startswith("TFC|N|%s|C|" % int_version):
                command_packet(nh_packet)
                accept_new_local_keys = True

            elif nh_packet.startswith("TFC|N|%s|M|" % int_version):
                message_packet(nh_packet)
                accept_new_local_keys = True

            elif nh_packet.startswith("TFC|N|%s|U|CLEAR" % int_version):
                system("clear")
                accept_new_local_keys = True
            else:
                print("Error: Incorrect message header.")

    except KeyboardInterrupt:
        system("clear")
        graceful_exit()


def kdk_input_process(file_no, _):
    """
    Ask user to input key decryption key.

    :param file_no: Stdin file.
    :param _:       Prevents handling file_no as iterable.
    :return:        None
    """

    import sys
    import os

    sys.stdin = os.fdopen(file_no)
    kdk = ''
    try:
        while True:

            print_headers()
            print("\nReceived encrypted local key. "
                  "Enter key decryption key from TxM:")
            if local_testing:
                print(" %s" % (72 * 'v'))
            else:
                print("%s" % (9 * " vvvvvvvv"))
            kdk = raw_input(' ').replace(' ', '')

            if not validate_key(kdk[:-8]):
                sleep(1)
                continue

            if sha3_256(kdk[:-8])[:8] != kdk[64:]:
                print("\nKey decryption key checksum fail. Try again.")
                sleep(1)
                continue
            else:
                break

        kdk_queue.put(kdk)
        pc_queue.put("terminate_kdk_input_process")
        sleep(1)

    except KeyboardInterrupt:
        pc_queue.put("terminate_kdk_input_process")
        sleep(1)


def print_headers():
    """
    Print headers.

    :return: None
    """

    logs_b = "on" if log_messages else "off"
    file_b = "on" if file_saving else "off"

    system("clear")
    print("TFC-NaCl %s || Rx.py || Logging %s || File "
          "reception %s\n" % (str_version, logs_b, file_b))

    return None


###############################################################################
#                                     MAIN                                    #
###############################################################################

unittesting = False  # Alters function input during unittesting
accept_new_local_keys = True

l_msg_coming = {}
msg_received = {}
m_dictionary = {}
l_file_onway = {}
filereceived = {}
f_dictionary = {}
acco_store_f = {}
acco_store_l = {}

if __name__ == "__main__":

    parser = ArgumentParser("python Tx.py",
                            usage="%(prog)s [OPTION]",
                            description="More options inside Tx.py")

    parser.add_argument("-i",
                        action="store_true",
                        default=False,
                        dest="l_t_notify",
                        help="do not notify about incoming long transmissions")

    parser.add_argument("-f",
                        action="store_true",
                        default=False,
                        dest="f_save",
                        help="enable file saving during start")

    parser.add_argument("-k",
                        action="store_true",
                        default=False,
                        dest="keep_l_f",
                        help="enable storage of locally received files")

    parser.add_argument("-m",
                        action="store_true",
                        default=False,
                        dest="m_logging",
                        help="enable message logging by default")

    parser.add_argument("-l", action="store_true",
                        default=False,
                        dest="local_t",
                        help="enable local testing mode")

    parser.add_argument("-a", action="store_true",
                        default=False,
                        dest="auto_close_fr",
                        help="auto-close file reception after receiving file")

    args = parser.parse_args()

    if args.l_t_notify:
        l_message_incoming = False

    if args.f_save:
        file_saving = True

    if args.keep_l_f:
        keep_local_files = True

    if args.m_logging:
        log_messages = True

    if args.local_t:
        local_testing = True

    if args.auto_close_fr:
        a_close_f_recv = True

    if unittesting:
        print("\nError: Variable unittesting is set true.\n")
        exit()

    if startup_banner:
        print_banner()

    # Set default directory
    chdir(path[0])

    # Enable serial port if local testing is disabled
    if local_testing:
        l = Listener(('', 5003))
        conn = l.accept()

    else:

        # Auto-pick correct serial interface
        dev_files = [df for df in listdir("/dev/")]
        dev_files.sort()
        serial_nh = ''

        if nh_usb_adapter:
            for dev_file in dev_files:
                if dev_file.startswith("ttyUSB"):
                    serial_nh = "/dev/%s" % dev_file
                    break

            if not serial_nh:
                clean_exit("Error: No USB-serial adapter was not found.")

        else:
            os_name = check_output(["grep", "PRETTY_NAME",
                                    "/etc/os-release"])
            rpi_distros = ["Raspbian GNU/Linux"]

            rpi_in_use = False
            for distro in rpi_distros:
                if distro in os_name:
                    rpi_in_use = True

            integrated_if = "ttyAMA0" if rpi_in_use else "ttyS0"

            integrated_found = False
            for dev_file in dev_files:
                if dev_file == integrated_if:
                    integrated_found = True

            if integrated_found:
                serial_nh = "/dev/%s" % integrated_if
            else:
                clean_exit("Error: /dev/%s was not found." % integrated_if)
        try:
            port_to_nh = Serial(serial_nh, baud_rate, timeout=0.1)
        except serialutil.SerialException:
            clean_exit("Error: Serial interface to NH was not found.")

    # Create necessary directories
    ensure_dir("keys/")
    ensure_dir("logs/")
    ensure_dir("files/")

    # Clear readline history
    clear_history()

    # Remove relocation instructions from PSK files
    remove_instructions()

    # Add new keyfiles
    add_keyfiles()

    # Initialize queues for messages
    nh_queue = Queue()
    pc_queue = Queue()
    kdk_queue = Queue()

    # Display configuration on header during start of program
    print_headers()

    if not isfile("keys/me.local.e"):
        get_local_key_packet()

    # Check that me. and rx. keyfiles have their counterpart
    check_keyfile_parity()

    # Set initial dictionaries for file and message reception
    for sender in get_list_of_accounts():
        l_msg_coming[sender] = False
        msg_received[sender] = False
        m_dictionary[sender] = ''

        if log_messages:
            acco_store_l[sender] = True
        else:
            acco_store_l[sender] = False

        l_file_onway[sender] = False
        filereceived[sender] = False
        f_dictionary[sender] = ''

        if sender.startswith("me."):
            acco_store_f[sender] = True

        if sender.startswith("rx."):
            if file_saving:
                acco_store_f[sender] = True
            else:
                acco_store_f[sender] = False

    nhplp = Process(target=nh_packet_loading_process)
    mainl = Process(target=main_loop_process)
    inptp = Process(target=kdk_input_process, args=(stdin.fileno(), ''))

    nhplp.start()
    mainl.start()

    try:
        while True:
            if not pc_queue.empty():
                command = pc_queue.get()
                if command == "exit":
                    nhplp.terminate()
                    mainl.terminate()
                    try:
                        inptp.terminate()
                    except (AttributeError, NameError):
                        pass
                    clean_exit()
                if command == "start_kdk_input_process":
                    inptp = Process(target=kdk_input_process,
                                    args=(stdin.fileno(), ''))
                    inptp.start()
                if command == "terminate_kdk_input_process":
                    try:
                        inptp.terminate()
                    except AttributeError:
                        pass
            sleep(0.1)

    except KeyboardInterrupt:
        nhplp.terminate()
        mainl.terminate()
        try:
            inptp.terminate()
        except (AttributeError, NameError):
            pass
        clean_exit()
