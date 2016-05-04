#!/usr/bin/env python
# -*- coding: utf-8 -*-

# TFC-NaCl 0.16.05 || Tx.py

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

import argparse
import base64
import binascii
import csv
import curses
import datetime
import fcntl
import multiprocessing.connection
import multiprocessing
import os.path
import os
import random
import readline
import serial
import socket
import struct
import subprocess
import sys
import termios
import threading
import time
import tkFileDialog
import Tkinter
import _tkinter

from serial.serialutil import SerialException

try:
    import RPi.GPIO as GPIO
except ImportError:
    GPIO = None

# Import crypto libraries
import Crypto.Cipher.AES
import hashlib
import nacl.encoding
import nacl.public
import nacl.secret
import nacl.utils
import paramiko
from passlib.hash import pbkdf2_sha256
from passlib.utils import ab64_decode
import simplesha3

orig_new = Crypto.Cipher.AES.new

str_version = "0.16.05"
int_version = 1605


###############################################################################
#                                CONFIGURATION                                #
###############################################################################

# UI settings
l_ts = "%Y-%m-%d %H:%M:%S"  # Format of timestamps in TxM side log files

clear_input_screen = False  # True clears screen after each input

print_members_in_g = True   # True shows members of groups when listing groups

startup_banner = True       # False disables the animated startup banner

confirm_file = True         # Ask user for confirmation before sending files

show_file_prompts = True    # Prompt keyfile location instead of def. folders


# Security settings
panic_exit = False          # True enables panic exit with 'double space' msg

txm_side_logging = False    # True enables TxM side message logging


# Metadata hiding
trickle_connection = False  # True enables trickle connection to hide metadata

print_ct_stats = False      # Prints details about trickle connection delay

trickle_c_delay = 2.0       # Constant time delay between trickle packets

trickle_r_delay = 1.0       # Max random delay, helps against timing attacks

lt_random_delay = False     # True adds random delay to trickle/long packets

lt_max_delay = 10.0         # Maximum delay time for lt_random_delay


# Packet settings
packet_delay = 0.5          # Delay between long transmissions: prevents flood


# Local testing
local_testing = False       # True enables testing of TFC on a single computer

dd_socket = False           # True changes socket for data diode simulator


# Serial port settings
baud_rate = 9600            # The serial interface speed

checksum_len = 8            # Data diode error detection rate. 8 hex = 32-bit

nh_usb_adapter = True       # False = use integrated serial interface


# HWRNG local settings
gpio_port = 4               # Broadcom layout GPIO pin number for HWRNG


# HWRNG over SSH settings
use_ssh_hwrng = False       # True loads HWRNG entropy from Raspbian over SSH

hwrng_host = "192.168.1.2"  # IP of Raspberry Pi HWRNG is connected to

hwrng_name = "pi"           # Account for SSH connection (default = pi)

hwrng_pass = "raspberry"    # Password for SSH connection (default = raspberry)


###############################################################################
#                               ERROR CLASSES                                 #
###############################################################################

class CriticalError(Exception):
    """
    Variety of errors during which Tx.py should gracefully exit.
    """

    def __init__(self, function_name, error_message):
        graceful_exit("Error: F(%s): %s" % (function_name, error_message),
                      queue=True)


class FunctionParameterTypeError(Exception):
    """
    Tx.py should gracefully exit if function is called with incorrect
    parameter types.
    """

    def __init__(self, function_name):
        graceful_exit("Error: F(%s): Wrong input type." % function_name,
                      queue=True)


class NoLocalKeyError(Exception):
    """
    NoLocalKeyError is a recoverable error, so only error message is printed.
    """

    def __init__(self):
        print("\nError: 'tx.local.e' was not found. Command was not sent. \n"
              "Generate and send new local key with command '/localkey'.\n\n")


class GroupError(Exception):
    """
    GroupError is a recoverable error, so only error message is printed.
    """

    def __init__(self, message):
        print("\nError: %s\n" % message)


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

    h_function = hashlib.sha256()
    h_function.update(message)
    hex_digest = binascii.hexlify(h_function.digest())

    return hex_digest


def sha3_256(message):
    """
    Generate SHA3-256 digest from message.

    :param message: Input to hash function.
    :return:        Hex representation of SHA3-256 digest.
    """

    if not isinstance(message, str):
        raise FunctionParameterTypeError("sha3_256")

    return binascii.hexlify(simplesha3.sha3256(message))


def pbkdf2_hmac_sha256(key, rounds=1000, salt=''):
    """
    Generate next encryption by deriving it using PBKDF2 HMAC-SHA256.

      1 000 iterations are used to refresh key after every message.
     25 000 iterations are used when generating symmetric keys.

    Salt is not used in PFS function as it would have to be pre-shared, but is
    left as a parameter to enable unittesting with test vectors, and to allow
    mixing in other entropy sources.

    :param key:    Current key.
    :param rounds: PBKDF2 iteration count.
    :param salt:   Additional entropy.
    :return:       Key after derivation.
    """

    if not isinstance(key, str) or not \
            isinstance(rounds, (int, long)) or not \
            isinstance(salt, str):
        raise FunctionParameterTypeError("pbkdf2_hmac_sha256")

    if rounds < 1:
        raise CriticalError("pbkdf2_hmac_sha256", "Number of rounds < 1")

    derived_key = pbkdf2_sha256.encrypt(key, rounds=rounds, salt=salt)

    # Separate hash from derived key
    parted_hash = derived_key.split('$')[4]

    hash_bin = ab64_decode(parted_hash)
    hash_hex = binascii.hexlify(hash_bin)

    return hash_hex


def encrypt_and_sign(account, plaintext):
    """
    Encrypt and sign plaintext using PyNaCl library's XSalsa20-Poly1305.

    256-bit XSalsa20 cipher and Poly1305 MAC is designed by Daniel Bernstein.
    The XSalsa20 is a stream cipher based on add-rotate-XOR (ARX). It is used
    with a /dev/urandom spawned, 192-bit nonce (length specified in libsodium).

    Forward secrecy is obtained by replacing previous key with it's 1000th
    PBKDF2-HMAC-SHA256 derivation in between every sent message.

    :param account:   The recipient's account name (e.g. alice@jabber.org).
    :param plaintext: Plaintext to encrypt.
    :return:          Signed ciphertext.
    """

    if not isinstance(account, str) or not isinstance(plaintext, str):
        raise FunctionParameterTypeError("encrypt_and_sign")

    # Load encryption key
    key_hex = get_key(account)

    # Load keyID
    key_id = get_keyid(account)

    # Derive and store next key
    rotate_key(account)

    # Store next keyID
    write_keyid(account, key_id + 1)

    # Construct new SecretBox
    secret_box = nacl.secret.SecretBox(binascii.unhexlify(key_hex))

    # Generate new nonce
    nonce = nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE)

    # Encrypt and sign plaintext
    signed_ciphertext = secret_box.encrypt(plaintext, nonce)

    return signed_ciphertext


###############################################################################
#                                KEY MANAGEMENT                               #
###############################################################################

def get_keyfile_list(include_local=False):
    """
    Get list of 'tx.account.e' keyfiles in keys folder.

    :param include_local: True includes tx.local.e.
    :return:              List of keyfiles.
    """

    if not isinstance(include_local, bool):
        raise FunctionParameterTypeError("get_keyfile_list")

    ensure_dir("keys/")
    kf_list = []

    for f in os.listdir("keys/"):
        if f.startswith("tx.") and f.endswith(".e"):
            if not include_local and f == "tx.local.e":
                continue
            kf_list.append(f)

    kf_list.sort()

    return kf_list


def get_key(account):
    """
    Load key for selected contact.

    :param account: The recipient's account name (e.g. alice@jabber.org).
    :return:        Stored key.
    """

    if not isinstance(account, str):
        raise FunctionParameterTypeError("get_key")

    try:
        key = open("keys/tx.%s.e" % account).readline()

    except IOError:
        raise CriticalError("get_key", "tx.%s.e IOError." % account)

    validate_key(key, account)

    return key


def key_writer(account, key):
    """
    Write key to keyfile.

    :param account: The recipient's account name (e.g. alice@jabber.org).
    :param key:     Key to write.
    :return:        None
    """

    if not isinstance(account, str) or not isinstance(key, str):
        raise FunctionParameterTypeError("key_writer")

    try:
        validate_key(key, account)

        if '/' in account:
            open(account, "w+").write(key)
            written = open(account).readline()

        else:
            ensure_dir("keys/")
            open("keys/tx.%s.e" % account, "w+").write(key)
            written = open("keys/tx.%s.e" % account).readline()

    except IOError:
        raise CriticalError("key_writer", "tx.%s.e IOError." % account)

    if written != key:
        raise CriticalError("key_writer", "Key writing failed.")

    return None


def rotate_key(account):
    """
    Generate next key by iterating it through PBKDF2-HMAC-SHA256.

    :param account: The recipient's account name (e.g. alice@jabber.org).
    :return:        None
    """

    if not isinstance(account, str):
        raise FunctionParameterTypeError("rotate_key")

    old_key = get_key(account)
    new_key = pbkdf2_hmac_sha256(old_key)

    write_t = threading.Thread(target=key_writer, args=(account, new_key))
    write_t.start()
    write_t.join()

    return None


def new_psk(parameters, first_account=False):
    """
    Generate new pre-shared key for manual key delivery.

    :param parameters:    Account (and nick) yet to be separated.
    :param first_account: Exit during KeyboardInterrupt if True.
    :return:              None
    """

    if not isinstance(parameters, str) or not isinstance(first_account, bool):
        raise FunctionParameterTypeError("new_psk")

    ask_nick = False
    nick = ''
    global acco_store_l

    # Check that account has been specified
    try:
        account = parameters.split()[1]

    except IndexError:
        print("\nError: No account specified.\n")
        return None

    if ':' in account or '/' in account:
        print("\nError: No ':' or '/' characters are allowed.\n")
        return None

    # Try to get nick from parameters
    try:
        nick = parameters.split()[2]
        # Check that nick can fit with account, keys and split chars to packet.
        if (len(nick) + len(account) + 64 + 64 + 5) > 254:
            print("\nError: Specified nick too long.\n")
            ask_nick = True

    except IndexError:

        # If no nick was in parameter, try to load nick of existing contact.
        if account not in get_list_of_accounts():
            ask_nick = True
        else:
            nick = get_nick(account)
            if (len(nick) + len(account) + 64 + 64 + 5) > 254:
                print("\nError: Loaded nick is too long.\n")
                ask_nick = True

    try:
        # If no nick is specified at this point, ask user to enter new nick.
        if ask_nick:
            nick = get_nick_input(account)
        if not os.path.isfile("keys/tx.local.e"):
            raise NoLocalKeyError

        # Generate PSK
        ext_entropy = generate_key("key")
        psk = pbkdf2_hmac_sha256(os.urandom(32), 25000, ext_entropy)

        # Ask user's account name for contact's keyfile generation
        user = ''
        while True:
            user = raw_input("\nEnter your account name:%s" % (37 * ' '))
            if not user:
                print("Error: No account specified.")
                continue
            if ':' in user or '/' in user:
                print("\nError: No ':' or '/' characters are allowed.\n")
                continue
            break

        # Create copy of key for contact
        dest = '' if show_file_prompts else " to 'keys_to_contact'"
        phase("Copying key for contact%s..." % dest, 61)

        if show_file_prompts:
            try:
                root = Tkinter.Tk()
                root.withdraw()
                store_d = tkFileDialog.askdirectory(
                    title="Select removable media for "
                          "key delivery to " + account)
                root.destroy()
                if not store_d:
                    raise KeyboardInterrupt
            except _tkinter.TclError:
                print("\nError: No file dialog available. Storing key to "
                      "directory 'keys_to_contact/'\n")
                store_d = "keys_to_contact/"

        else:
            store_d = "keys_to_contact/"

        ensure_dir(store_d)
        f_name = "%s/rx.%s.e - Give this file to %s" % (store_d, user, account)
        wt = threading.Thread(target=key_writer, args=(f_name, psk))
        wt.start()
        wt.join()
        print("Done.")

        # Send PSK to RxM
        if not unittesting:
            raw_input("\n      Bypass NH if needed and "
                      "press <Enter> to send key.     ")
        phase("\nSending keyset to RxM...", 61)
        command_transmit("PSK|%s|%s|%s" % (account, nick, psk))
        print("Done.")

        # Store key and contact data on TxM. Add logging settings to dict.
        phase("Creating contact...", 61)
        wt = threading.Thread(target=key_writer, args=(account, psk))
        wt.start()
        wt.join()

        add_contact(account, nick)

        if txm_side_logging:
            acco_store_l[account] = True
        else:
            acco_store_l[account] = False

        # If PSK is for active contact, update nick
        if not first_account:
            if account == recipient_acco:
                global recipient_nick
                recipient_nick = nick

        print("Done.")
        print("\nPSK generation successful.\n")
        time.sleep(1.5)
        os.system("clear")

    except KeyboardInterrupt:
        if first_account:
            graceful_exit("PSK generation aborted.")
        else:
            os.system("clear")
            print("\nPSK generation aborted.\n")
            return None

    return None


def digits_to_bytes(di):
    """
    Convert string of binary digits to byte string.

    :param di: Digit string.
    :return:   Byte string.
    """

    if not isinstance(di, str):
        raise FunctionParameterTypeError("digits_to_bytes")

    return ''.join(chr(int(di[i:i + 8], 2)) for i in xrange(0, len(di), 8))


def generate_key(key_purpose):
    """
    Generate keyset containing eight 512-bit keys.

    Generate key by using SHA3-256 to compress together entropy from kernel
    CSPRNG (/dev/urandom) and optionally mix in entropy from HWRNG sampled from
    HWRNG by Raspberry Pi through it's GPIO. Tx.py can either sample the HWRNG
    itself (if run on RPi) or it can SSH into RPi (direct ethernet cable with
    static IP is required) and load entropy that way.

    Before HWRNG sampling starts, a loop collects 3000 samples to 'warm up'.
    Sampling is done at 10Hz frequency to ensure minimal auto-correlation
    between samples.

    :param key_purpose: The purpose of the generated key.
    :return:            256-bit symmetric key.
    """

    if not isinstance(key_purpose, str):
        raise FunctionParameterTypeError("generate_keydata")

    question = "Load entropy for %s from HWRNG?" % key_purpose

    # Detect OS compatibility
    pretty_name = subprocess.check_output(["grep", "PRETTY_NAME",
                                           "/etc/os-release"])
    try:
        if pretty_name == "Raspbian GNU/Linux" and GPIO:
            if not yes(question, (24 - len(key_purpose))):
                key = sha3_256(os.urandom(32))
                return key

            # HWRNG sampling settings
            samples_n = 256
            sample_delay = 0.1
            GPIO.setmode(GPIO.BCM)
            GPIO.setup(gpio_port, GPIO.IN, pull_up_down=GPIO.PUD_DOWN)

            phase("\nWaiting for HWRNG signal from GPIO...", 61)
            warmup_zero = 0
            warmup_one = 0

            while True:
                if warmup_one > 1500 and warmup_zero > 1500:
                    break
                if GPIO.input(gpio_port) == 1:
                    warmup_one += 1
                else:
                    warmup_zero += 1
                time.sleep(0.001)
            print("Acquired.\n")

            # Perform Von Neumann whitening during sampling
            vn_digits = ''

            while True:
                sys.stdout.write("\x1b[1A")
                print("Sampling HWRNG...%s%s/%s bits"
                      % (44 * ' ', len(vn_digits), samples_n))

                if len(vn_digits) >= samples_n:
                    break

                first_bit = GPIO.input(gpio_port)
                time.sleep(sample_delay)

                second_bit = GPIO.input(gpio_port)
                time.sleep(sample_delay)

                if first_bit == second_bit:
                    continue
                else:
                    vn_digits += str(first_bit)

            GPIO.cleanup()
            ent = digits_to_bytes(vn_digits)
            ent = binascii.hexlify(ent)

            if len(ent) != 32:
                raise CriticalError("generate_key",
                                    "Entropy collection failed.")

        else:
            if not use_ssh_hwrng or not yes(question, (24 - len(key_purpose))):
                key = sha3_256(os.urandom(32))
                return key

            # Load entropy over SSH using hwrng-nacl.py on Raspberry Pi.
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            paramiko.util.log_to_file("/dev/null")

            try:
                ssh.connect(hostname=hwrng_host,
                            username=hwrng_name,
                            password=hwrng_pass)
            except socket.error:
                raise CriticalError("generate_keyset", "Socket Error. "
                                                       "Check RPi IP.")
            except paramiko.ssh_exception.AuthenticationException:
                raise CriticalError("generate_key",
                                    "SSH Authentication Error")

            except ValueError:  # Fix IV issue in Paramiko's AES-CTR mode
                ssh.close()
                ssh = paramiko.SSHClient()
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                paramiko.util.log_to_file("/dev/null")
                Crypto.Cipher.AES.new = fixed_aes_new
                ssh.connect(hostname=hwrng_host,
                            username=hwrng_name,
                            password=hwrng_pass)

            ssh_stdin, ssh_stdout, ssh_stderr \
                = ssh.exec_command("python hwrng-nacl.py")
            ssh_stdin.flush()

            phase("Waiting for entropy...", 61)
            output = ssh_stdout.read()
            ent = output.strip('\n')
            print("Done.")

            if ent == "ERROR":
                raise CriticalError("generate_keyset", "HWRNG error")

        validate_key(ent, "HWRNG")

        compressed = sha3_256(binascii.unhexlify(ent))

        return compressed

    except KeyboardInterrupt:
        if GPIO:
            GPIO.cleanup()
        raise


def new_local_key(bootstrap=False):
    """
    Send encrypted local key to RxM, display kdk and ask for device code.

    :param bootstrap: When True, KeyboardInterrupt exits.
    :return:          None
    """

    if not isinstance(bootstrap, bool):
        raise FunctionParameterTypeError("new_local_key")

    try:
        if not bootstrap:
            print('')

        print("Create local key\n----------------\n")

        # Generate local key and key encryption key
        ext_entropy_1 = generate_key("local key")
        local_key = pbkdf2_hmac_sha256(os.urandom(32), 25000, ext_entropy_1)
        ext_entropy_2 = generate_key("local key encryption key")
        key_e_key = pbkdf2_hmac_sha256(os.urandom(32), 25000, ext_entropy_2)

        # Encrypt, sign and send local key with device code to RxM
        dev_code = binascii.hexlify(os.urandom(1))
        padded = padding(local_key + dev_code)
        s_box = nacl.secret.SecretBox(binascii.unhexlify(key_e_key))
        nonce = nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE)
        ct_tag = s_box.encrypt(padded, nonce)
        raw_input("\n%sBypass NH if needed and press <Enter> to send key.%s"
                  % ((6 * ' '), (5 * ' ')))
        packet = "TFC|N|%s|L|%s" % (int_version, base64.b64encode(ct_tag))
        transmit(packet)

        # Print key decryption key
        chksm = sha3_256(key_e_key)[:8]
        split = [key_e_key[i:i + 8] for i in range(0, len(key_e_key), 8)]
        if local_testing:
            kdk = "%s%s" % (key_e_key, chksm)
        else:
            kdk = "%s %s" % (" ".join(split), chksm)
        print("\nLocal key decryption key (to RxM):\n %s\n" % kdk)

        # Ask for device code before storing local key on TxM
        if not unittesting:
            while True:
                devc_purp = raw_input("Device code (from RxM):%s" % (38 * ' '))
                if devc_purp == "resend":
                    transmit(packet)
                elif devc_purp == dev_code:
                    break
                else:
                    print("\nDevice code incorrect. If RxM did not receive"
                          "\nencrypted key, resend key by typing 'resend'.\n")

        phase("Saving local key...", 61)
        # Store tx.local.e to folder 'keys' and add it to .tx_contacts
        wt = threading.Thread(target=key_writer, args=("local", local_key))
        wt.start()
        wt.join()

        add_contact("local", "local")
        print("Done.")

        print("\nLocal key added.\n")
        return None

    except KeyboardInterrupt:
        if bootstrap:
            graceful_exit("Local key generation aborted.")
        else:
            raise


###############################################################################
#                               SECURITY RELATED                              #
###############################################################################

def fixed_aes_new(key, *lst):
    """
    Fix Paramiko's AES counter mode's unnecessary IV.

    :param key:  AES key.
    :param lst:  List of parameters.
    :return:     New function.
    """
    if Crypto.Cipher.AES.MODE_CTR == lst[0]:
        lst = list(lst)
        lst[1] = ''
    return orig_new(key, *lst)


def graceful_exit(message='', queue=False):
    """
    Display a message and exit Tx.py.

    If trickle connection is enabled, put an exit command to
    pc_queue so main loop can kill processes and exit Tx.py.

    :param: message: Message to print.
    :param: queue:   Add command to pc_queue when True.
    :return:         None
    """

    if not isinstance(message, str) or not isinstance(queue, bool):
        raise FunctionParameterTypeError("graceful_exit")

    os.system("clear")

    if message:
        print("\n%s" % message)

    print("\nExiting TFC-NaCl.\n")

    if trickle_connection and queue:
        pc_queue.put("exit")
    else:
        exit()


def validate_key(key, account=''):
    """
    Check that key is valid. Gracefully exit if keys have a problem.

    :param key:     Key to validate.
    :param account: Origin of key.
    :return:        True/False depending on key validation.
    """

    if not isinstance(key, str) or not isinstance(account, str):
        raise FunctionParameterTypeError("validate_key")

    if account == "HWRNG":
        origin = "key from HWRNG."
    else:
        origin = "keyfile tx.%s.e" % account

    # Verify key consists only from hex chars
    if not set(key.lower()).issubset("abcdef0123456789"):
        if not account:
            print("\nError: Illegal character in key.\n")
            return False

        raise CriticalError("validate_keyt",
                            "Illegal character in %s" % origin)

    # Verify key length
    if len(key) != 64:
        if not account:
            print("\nError: Illegal length key.\n")
            return False

        raise CriticalError("validate_key",
                            "Illegal key length in %s" % origin)

    if not account:
        return True


def key_searcher(string):
    """
    Check if input by user appears to contain keys.

    :param string: Input to check.
    :return:       True if input looks like key, else False.
    """

    if not isinstance(string, str):
        raise FunctionParameterTypeError("key_searcher")

    length = 0
    for c in string:
        if c.lower() in set("abcdef0123456789"):
            length += 1
        else:
            length = 0

    if 62 < length < 74:
        return True

    return False


def write_log_entry(account, nick='', msg='', pk_user='', pk_contact=''):
    """
    Write log entry of sent messages for later cross comparison to verify
    recipient has received same messages. During audit this helps in detecting
    malware that could substitute content in logged messages on RxM.

    Write public keys to log file. During audit this helps in detecting if MITM
    was present during key exchange and other public key verification channels.

    :param account:    The recipient's account name (e.g. alice@jabber.org).
    :param nick:       Nickname for contact.
    :param msg:        Message to store in log file.
    :param pk_user:    Public key of user to store in log file.
    :param pk_contact: Public key of contact to store in log file.
    :return:           None
    """

    if not isinstance(account, str) or not \
            isinstance(nick, str) or not \
            isinstance(msg, str) or not \
            isinstance(pk_user, str) or not \
            isinstance(pk_contact, str):
        raise FunctionParameterTypeError("write_log_entry")

    message = msg.strip('\n')
    t_stamp = datetime.datetime.now().strftime(l_ts)

    ensure_dir("logs/")

    try:
        with open("logs/TxM - logs.%s.tfc" % account, "a+") as f:

            if msg:
                f.write("%s Me > %s: %s\n" % (t_stamp, nick, message))

            if pk_user and pk_contact:
                f.write("\n%s key exchange with %s:\n"
                        "       My pub key:  %s\n"
                        "Contact's pub key:  %s\n\n"
                        % (t_stamp, account, pk_user, pk_contact))

    except IOError:
        raise CriticalError("write_log_entry", "Log file IOError.")

    return None


def get_contact_public_key_hex():
    """
    Prompt user to enter ECDHE public key, verify checksum.

    :return: Public key.
    """

    while True:

        os.system("clear")

        print("""
                                 WARNING!
           Key exchange will break the HW separation. Outside
           specific requests TxM (this computer) makes, you
           should NEVER copy ANY data from NH/RxM to TxM. Doing
           so could infect TxM, that could then later covertly
           exfiltrate private keys/messages from TxM to NH and
           onwards to adversary over your Internet connection.

      Enter contact's public key (with or without spaces) from RxM:\n\n""")

        if local_testing:
            print(" %s" % (72 * 'v'))
        else:
            print("%s" % (9 * " vvvvvvvv"))

        try:
            public_key = raw_input(' ').replace(' ', '')

            if not validate_key(public_key[:-8]):
                time.sleep(1)
                continue

            if sha3_256(public_key[:-8])[:8] != public_key[64:]:
                print("\nPublic key checksum fail. Try again.\n")
                time.sleep(1)
                continue
            else:
                return public_key[:-8]

        except KeyboardInterrupt:
            os.system("clear")
            print("\nKey exchange aborted.\n")
            raise


def manual_public_key_entry():
    """
    If MITM is suspected, ask user to manually input contact's public key.

    :return: Contact's public key.
    """

    print("\n\nThis might indicate a man-in-the-middle attack!")
    if yes("Do you want to enter correct key manually?"):
        print("\nAsk contact to read their public key over Signal:")
        while True:

            if local_testing:
                print(" %s" % (72 * 'v'))
            else:
                print("%s" % (9 * " vvvvvvvv"))

            pub_k = raw_input(' ').replace(' ', '')

            if not validate_key(pub_k[:-8]):
                time.sleep(1)
                continue

            if sha3_256(pub_k[:-8])[:8] != pub_k[64:]:
                print("\nPublic key checksum fail. Try again.\n")
                time.sleep(1)
                continue
            else:
                print('')
                return pub_k[:-8]
    else:
        print("\nKey exchange aborted.\n")
        raise KeyboardInterrupt


def verify_public_keys(pub_u, pub_c, contact):
    """
    Print hex representations of public keys of users.

    :param pub_u:   Public key of user.
    :param pub_c:   Public key of contact.
    :param contact: Contact's account name (e.g. alice@jabber.org).
    :return:        pub_c from parameter or pub key from user input.
    """

    if not isinstance(pub_u, str) or not \
            isinstance(pub_c, str) or not \
            isinstance(contact, str):
        raise FunctionParameterTypeError("verify_public_keys")

    os.system("clear")
    print("\nTo verify the public key received from Internet came from your "
          "contact, call them using\nSignal by Open whisper Systems, verify "
          "the two-word SAS and then read and compare keys.\n")

    print("\nYour public key (you read):\n")
    spaced = "  ".join([pub_u[i:i + 8] for i in range(0, len(pub_u), 8)])
    print(" %s  %s" % (spaced, sha3_256(pub_u)[:8]))

    print("\nPurported public key for %s (they read):\n" % contact)
    spaced = "  ".join([pub_c[i:i + 8] for i in range(0, len(pub_c), 8)])
    print(" %s  %s" % (spaced, sha3_256(pub_c)[:8]))

    try:
        if yes("\n\nIs contact's public key correct?", 21):
            return pub_c
        else:
            return manual_public_key_entry()

    except KeyboardInterrupt:
        raise


def start_key_exchange(parameter, first_account=False):
    """
    Start Curve 25519 ECDHE key exchange with recipient.

    :param parameter:     Account name and nick yet to be separated.
    :param first_account: True when first account is generated.
    :return:              None
    """

    if not isinstance(parameter, str) or not isinstance(first_account, bool):
        raise FunctionParameterTypeError("start_key_exchange")

    ask_nick = False
    nick = ''
    global acco_store_l

    # Check that account has been specified
    try:
        account = parameter.split()[1]

    except IndexError:
        print("\nError: No account specified.\n")
        return None

    if ':' in account or '/' in account:
        print("\nError: No ':' or '/' characters are allowed.\n")
        return None

    # Try to separate nick from parameter
    try:
        nick = parameter.split()[2]
        # Check that nick can fit with account, keys and split chars to packet.
        if (len(nick) + len(account) + 64 + 64 + 5) > 254:
            print("\nError: Specified nick too long.\n")
            ask_nick = True

    except IndexError:

        # If no nick was in parameter, try to load nick of existing contact.
        if account not in get_list_of_accounts():
            ask_nick = True
        else:
            nick = get_nick(account)
            if (len(nick) + len(account) + 64 + 64 + 5) > 254:
                print("\nError: Loaded nick is too long.\n")
                ask_nick = True

    try:
        # If no nick is specified at this point, ask user to enter new nick.
        if ask_nick:
            nick = get_nick_input(account)
        if not os.path.isfile("keys/tx.local.e"):
            raise NoLocalKeyError

        # Generate Curve25519 ECDHE private key and derive public key from it
        ext_entropy = generate_key("key")

        phase("Generating ECDHE key pair...", 61)
        ext_entropy = pbkdf2_hmac_sha256(sha3_256(os.urandom(32)), 25000,
                                         ext_entropy)
        tx_sk_bin = nacl.public.PrivateKey.generate(
            binascii.unhexlify(ext_entropy))
        tx_pk_bin = tx_sk_bin.public_key
        tx_pk_hex = tx_pk_bin.encode(encoder=nacl.encoding.HexEncoder)
        print("Done.")

        # Send public key, ask for contact's public key input, log public keys
        phase("Sending public key to contact...", 61)
        transmit("TFC|N|%s|P|%s|%s" % (int_version, tx_pk_hex, account))
        print("Done.")
        time.sleep(0.5)

        rx_pk_hex = get_contact_public_key_hex()
        rx_pk_hex = verify_public_keys(tx_pk_hex, rx_pk_hex, account)
        rx_pk_bin = nacl.public.PublicKey(rx_pk_hex,
                                          encoder=nacl.encoding.HexEncoder)

        phase("Logging public keys...", 61)
        write_log_entry(account, pk_user=tx_pk_hex, pk_contact=rx_pk_hex)
        print("Done.")

        # Generate symmetric keys
        phase("Generating symmetric keys...", 61)
        dhe_box = nacl.public.Box(tx_sk_bin, rx_pk_bin)
        ssk_bin = dhe_box.shared_key()
        ssk_hex = binascii.hexlify(ssk_bin)
        tx_ssk_hex = pbkdf2_hmac_sha256(ssk_hex + rx_pk_hex, 25000)
        rx_ssk_hex = pbkdf2_hmac_sha256(ssk_hex + tx_pk_hex, 25000)
        print("Done.")

        # Send account details and shared keys inside encrypted command to RxM.
        if not unittesting:
            raw_input("\n%sBypass NH if needed and press <Enter> "
                      "to send key.%s" % ((6 * ' '), (5 * ' ')))
        phase("\nSending keypair to RxM...", 61)
        p_str = "A|%s|%s|%s|%s" % (account, nick, tx_ssk_hex, rx_ssk_hex)
        command_transmit(p_str)
        print("Done.")

        # Store key and contact data on TxM. Add logging settings to dict.
        phase("Creating contact...", 61)
        wt = threading.Thread(target=key_writer, args=(account, tx_ssk_hex))
        wt.start()
        wt.join()

        add_contact(account, nick)

        if txm_side_logging:
            acco_store_l[account] = True
        else:
            acco_store_l[account] = False

        # If keypair is for active contact, update nick
        if not first_account:
            if account == recipient_acco:
                global recipient_nick
                recipient_nick = nick

        print("Done.")

        print("\nKey generation successful.\n")
        time.sleep(1.5)
        os.system("clear")

    except KeyboardInterrupt:
        if first_account:
            graceful_exit("Key exchange aborted.")
        else:
            os.system("clear")
            print("\nKey exchange aborted.\n")
            return None

    return None


###############################################################################
#                             CONTACT MANAGEMENT                              #
###############################################################################

def change_recipient(parameter):
    """
    Change global recipient_acco, recipient_nick and group variables.

    :param parameter: Recipient's account yet to be separated.
    :return:          None
    """

    if not isinstance(parameter, str):
        raise FunctionParameterTypeError("change_recipient")

    try:
        new_recip = parameter.split()[1]

    except IndexError:
        print("\nError: Invalid command.\n")
        return '', '', ''

    if new_recip in get_list_of_accounts():
        nick = get_nick(new_recip)
        os.system("clear")
        print("\nSelected '%s' (%s)\n" % (nick, new_recip))
        return new_recip, nick, ''

    elif new_recip in get_list_of_groups():

        if trickle_connection:
            print("\nError: Groups are disabled during trickle connection.\n")
            return '', '', ''

        os.system("clear")
        group_status = '' if get_group_members(new_recip) else " (empty)"
        print("\nSelected group '%s'%s\n" % (new_recip, group_status))
        return '', new_recip, new_recip

    else:
        try:
            account, nick = select_contact(selection=new_recip, menu=False)
            os.system("clear")
            print("\nSelected '%s' (%s)\n" % (nick, account))
            return account, nick, ''

        except (IndexError, ValueError):
            print("\nError: Invalid contact / group selection.\n")
            return '', '', ''


def get_contact_quantity():
    """
    Load number number of contacts from .tx_contacts.

    :return: Number of contacts (integer).
    """

    local_exists = False
    try:
        with open(".tx_contacts") as f:
            for line in f:
                if "local,local," in line:
                    local_exists = True

        no_contacts = sum(1 for _ in open(".tx_contacts"))
        if local_exists:
            no_contacts -= 1

        return no_contacts

    except IOError:
        raise CriticalError("get_contact_quantity", ".tx_contacts IOError.")


def get_list_of_accounts():
    """
    Get list of existing accounts.

    :return: List of accounts.
    """

    account_list = []

    ensure_dir("keys/")

    for f in os.listdir("keys/"):
        if f.startswith("tx.") and f.endswith(".e") and f != "tx.local.e":
            account_list.append(f[3:][:-2])

    account_list.sort()
    return account_list


def print_contact_list(spacing=False):
    """
    Print list of available contacts and their nicknames.

    :param spacing: When True, add spacing around the printed table.
    :return:        1) c_dst tells select_contact() how much to indent caret.
                    2) None when '/names' command is used to list contacts.
    """

    if not isinstance(spacing, bool):
        raise FunctionParameterTypeError("print_contact_list")

    if spacing:
        os.system("clear")
        print('')

    c_l = ["Account", "ID", "Nick"]
    a_lst = get_list_of_accounts()

    if not a_lst:
        if spacing:
            print("\nError: No accounts were found\n")
            if clear_input_screen:
                raw_input(" Press <enter> to continue.")
            return None
        else:
            return 0

    gap_1 = len(max(a_lst, key=len)) - len(c_l[0]) + 3
    c_str = c_l[0] + gap_1*' ' + c_l[1] + "  " + c_l[2]
    c_dst = int(c_str.index(c_l[1][0]))

    print(c_str)
    print(get_tty_wh(wo=True) * '-')

    for a in a_lst:
        a_id = str(a_lst.index(a))
        nick = get_nick(a)

        d1 = c_str.index(c_l[1][0]) - len(a)
        d2 = c_str.index(c_l[2][0]) - len(a) - d1 - len(a_id)

        print(a + d1 * ' ' + a_id + d2 * ' ' + nick)

    print('\n')

    if spacing:
        print('')
        if clear_input_screen:
            raw_input(" Press <enter> to continue.")
        return None

    else:
        return c_dst


def print_selection_error(invalid_selection):
    """
    Reset the contact selection screen inside select_contact() function.

    :param invalid_selection: Invalid selection made by user.
    :return:                  None
    """

    if not isinstance(invalid_selection, str):
        raise FunctionParameterTypeError("print_selection_error")

    os.system("clear")
    print("TFC-NaCl %s || Tx.py\n" % str_version)
    print("Error: Invalid selection '%s'\n" % invalid_selection)
    print_contact_list()

    return None


def select_contact(c_dist=0, selection='', menu=True):
    """
    Select contact to send messages to.

    :param c_dist:    Indentation of caret.
    :param selection: Contact selection number.
    :param menu:      When True, display menu.
    :return:          Account and nickname.
    """

    if not isinstance(c_dist, (int, long)) or not \
            isinstance(selection, str) or not \
            isinstance(menu, bool):
        raise FunctionParameterTypeError("select_contact")

    while True:
        try:
            # If no selection is provided and menu is False, ask for input.
            if selection == '' or menu:
                selection = raw_input("Select contact:" + (c_dist - 15) * ' ')
            selection = ' '.join(selection.split())

            # Load contact based on account
            if selection in get_list_of_accounts():
                return selection, get_nick(selection)

            # Load contact based on ID
            try:
                selection = int(selection)
                if selection < 0:
                    if menu:
                        print_selection_error(str(selection))
                        continue
                    else:
                        raise ValueError

                account = get_list_of_accounts()[selection]
                if account == "local":
                    if menu:
                        print_selection_error(selection)
                        continue
                    else:
                        raise ValueError

            except (IndexError, ValueError):
                if menu:
                    print_selection_error(str(selection))
                    continue
                else:
                    raise ValueError

            # If this point is reached, account is valid.
            return account, get_nick(account)

        except KeyboardInterrupt:
            graceful_exit(queue=True)


def get_list_of_targets():
    """
    Targets are the labels to which messages
    are sent to: nick names and group names.

    :return: List of targets.
    """

    target_list = []
    for account_file in get_list_of_accounts():
        target_list.append(get_nick(account_file))

    for group_file in get_list_of_groups():
        target_list.append(group_file)

    return target_list


# .tx_contacts management
def add_first_contact():
    """
    Add account name and nick of first contact.

    :return: None
    """

    nick = ''
    account = ''

    try:
        while True:

            os.system("clear")
            print("TFC-NaCl %s || Tx.py\n\n" % str_version)
            print("Add new contact\n---------------\n")
            account = raw_input("Contact account: %s" % (44 * ' '))

            # Remove related commands user might give
            for s in ["/dh ", "/add ", "/psk ", ' ']:
                account = account.replace(s, '')

            if key_searcher(account):
                print("\nError: Account looks like key.\n")
                time.sleep(1)
                continue

            if account == '':
                print("\nError: Can't give empty account.\n")
                time.sleep(1)
                continue

            if ':' in account or '/' in account:
                print("\nError: No ':' or '/' characters are allowed.\n")
                continue

            nick = get_nick_input(account)

            if yes("\nConfirm contact %s?" % nick, (36 - len(nick))):
                break

        if yes("Use ECDHE key exchange?", 30):
            start_key_exchange("/add %s %s" % (account, nick),
                               first_account=True)
            return None

        else:
            new_psk("/psk %s %s" % (account, nick), first_account=True)
            return None

    except KeyboardInterrupt:
        graceful_exit()


def add_contact(account, nick):
    """
    Add new contact to .tx_contacts.

    Contacts are stored in CSV file. Each contact has it's own line.
    Settings are stored with following format: [account,nick,keyID].

    :param account: The recipient's account name (e.g. alice@jabber.org).
    :param nick:    Nick of new contact.
    :return:        None
    """

    if not isinstance(account, str) or not isinstance(nick, str):
        raise FunctionParameterTypeError("add_contact")

    if not os.path.isfile(".tx_contacts"):
        open(".tx_contacts", "a+").close()

    try:
        # If account exists, only change nick and keyID
        db = open(".tx_contacts").readlines()
        for line in db:
            if account in line:
                write_keyid(account, 1)
                write_nick(account, nick)
                return None

        open(".tx_contacts", "a+").write("%s,%s,1\n" % (account, nick))

    except IOError:
        raise CriticalError("add_contact", ".tx_contacts IOError.")

    return None


def add_keyfiles():
    """
    Prompt nicknames for new contacts and store them to .tx_contacts.

    :return: None
    """

    c_list = []

    try:
        with open(".tx_contacts", "a+") as f:
            for row in csv.reader(f):
                c_list.append(row)

    except IOError:
        raise CriticalError("add_keyfiles", ".tx_contacts IOError.")

    for kf in get_keyfile_list(include_local=True):
        existing = False
        account = kf[3:][:-2]

        for c in c_list:
            if account in c[0]:
                existing = True

        if not existing:
            if account == "local":
                add_contact("local", "local")

            else:
                os.system("clear")
                print("TFC-NaCl %s || Tx.py\n" % str_version)
                print("New contact '%s' found." % account)

                nick = get_nick_input(account)
                add_contact(account, nick)

    return None


def get_keyid(account):
    """
    Get keyID for account.

    The loaded keyID is the counter that defines the number of times keys need
    to be iterated through PBKDF2-HMAC-SHA256 to produce current key. keyID is
    increased by one after every encrypted message and command.

    :param account: The recipient's account name (e.g. alice@jabber.org).
    :return:        The keyID (integer).
    """

    if not isinstance(account, str):
        raise FunctionParameterTypeError("get_keyid")

    try:
        c_list = []
        key_id = 0

        with open(".tx_contacts") as f:
            for row in csv.reader(f):
                c_list.append(row)

        for i in range(len(c_list)):
            if c_list[i][0] == account:
                key_id = int(c_list[i][2])

        if key_id > 0:
            return key_id
        else:
            raise CriticalError("get_keyid", "%s keyID less than 1." % account)

    except IndexError:
        raise CriticalError("get_keyid", "%s keyID IndexError." % account)

    except ValueError:
        raise CriticalError("get_keyid", "%s keyID ValueError." % account)

    except IOError:
        raise CriticalError("get_keyid", ".tx_contacts IOError.")


def get_nick(account):
    """
    Load nick from .tx_contacts.

    :param account: The recipient's account name (e.g. alice@jabber.org).
    :return:        The nickname for specified account.
    """

    if not isinstance(account, str):
        raise FunctionParameterTypeError("get_nick")

    clist = []
    nick = ''
    keyid = ''

    try:
        with open(".tx_contacts") as f:
            for row in csv.reader(f):
                clist.append(row)

        for i in range(len(clist)):
            if clist[i][0] == account:
                nick = clist[i][1]
                keyid = clist[i][2]

    except IOError:
        raise CriticalError("get_nick", ".tx_contacts IOError.")

    except IndexError:
        raise CriticalError("get_nick", ".tx_contacts IndexError.")

    if nick == '' or keyid == '':
        raise CriticalError("get_nick", "Couldn't find nick for %s." % account)

    return nick


def get_nick_input(account):
    """
    Ask user to input nickname for account. Nick max length is based on
    command packet content that transmits symmetric keys to RxM.

    :param account: Account to parse nick max length from.
    :return:        Nick input by user.
    """

    if not isinstance(account, str):
        raise FunctionParameterTypeError("get_nick_input")

    def_nick = account.split('@')[0]
    def_nick = def_nick.capitalize()
    def_nick = def_nick[:(254 - (128 + 5 + len(account)))]
    nickname = ''

    try:
        while True:
            nickname = raw_input("Contact nickname [%s]: %s"
                                 % (def_nick, ((40 - len(def_nick)) * ' ')))

            if ',' in nickname or '|' in nickname:
                print("\nError: Nick can't contain ',' or '|'.\n")
                continue

            if nickname == "local":
                print("\nError: Nick can't refer to local keyfile.\n")
                continue

            if nickname in get_list_of_accounts():
                print("\nError: Nick can't be an account.\n")
                continue

            if nickname == '':
                nickname = def_nick
                break

            if (len(nickname) + len(account) + 128 + 5) > 254:
                print("\nError: Nick is too long.\n")
            else:
                break

        return nickname

    except KeyboardInterrupt:
        raise


def write_keyid(account, keyid):
    """
    Write new keyID for contact to .tx_contacts.

    :param account: The recipient's account name (e.g. alice@jabber.org).
    :param keyid:   The counter of message, defines the offset in keyfile.
    :return:        None
    """

    if not isinstance(account, str) or not isinstance(keyid, (int, long)):
        raise FunctionParameterTypeError("write_keyid")

    if keyid < 1:
        raise CriticalError("write_keyid", "KeyID less than 1.")

    try:
        c_list = []

        with open(".tx_contacts") as f:
            for row in csv.reader(f):
                c_list.append(row)

        account_found = False

        for i in range(len(c_list)):
            if c_list[i][0] == account:
                account_found = True
                c_list[i][2] = keyid

        if not account_found:
            raise CriticalError("write_keyid", "No %s in .tx_contacts."
                                % account)

        with open(".tx_contacts", 'w') as f:
            csv.writer(f).writerows(c_list)

    except IOError:
        raise CriticalError("write_keyid", ".tx_contacts IOError.")

    if keyid != get_keyid(account):
        raise CriticalError("write_keyid", " %s keyID write fail." % account)

    return None


def write_nick(account, nick):
    """
    Write new nick for contact to .tx_contacts.

    :param account: The recipient's account name (e.g. alice@jabber.org).
    :param nick:    New nick for contact.
    :return:        None
    """

    if not isinstance(account, str) or not isinstance(nick, str):
        raise FunctionParameterTypeError("write_nick")

    try:
        c_list = []

        with open(".tx_contacts") as f:
            for row in csv.reader(f):
                c_list.append(row)

        nick_changed = False

        for i in range(len(c_list)):
            if c_list[i][0] == account:
                c_list[i][1] = nick
                nick_changed = True

        if not nick_changed:
            raise CriticalError("write_nick", "No %s in .tx_contacts."
                                % account)

        with open(".tx_contacts", 'w') as f:
            csv.writer(f).writerows(c_list)

    except IOError:
        raise CriticalError("write_nick", ".tx_contacts IOError.")

    if nick != get_nick(account):
        raise CriticalError("write_nick", "Nick writing failed.")

    return None


def rm_contact(parameters):
    """
    Remove account and keyfile from TxM and RxM.

    :param parameters: Target account to be separated from command.
    :return:           None
    """

    if not isinstance(parameters, str):
        raise FunctionParameterTypeError("rm_contact")

    try:
        account = parameters.split()[1]

    except IndexError:
        print("\nError: Account not specified.\n")
        return None

    if ':' in account or '/' in account:
        print("\nError: No ':' or '/' characters are allowed.\n")
        return None

    if account in "me.local":
        print("\nError: Can't remove local keyfile.\n")
        return None

    if not yes("\nRemove %s completely?" % account):
        return None

    files_to_process = [".tx_contacts"]
    for g in get_list_of_groups():
        files_to_process.append("groups/g.%s.tfc" % g)

    for lf in files_to_process:
        old = open(lf).read().splitlines()

        with open(lf, "w+") as f:
            for l in old:
                if account not in l.split(',')[0]:
                    f.write("%s\n" % l)

    command_transmit("REMOVE|%s" % account)

    if not os.path.isfile("keys/tx.%s.e" % account):
        print("\nTxM has no keyfile for %s to remove.\n" % account)
        return None

    subprocess.Popen("shred -n 3 -z -u keys/tx.%s.e" % account,
                     shell=True).wait()
    print("\n%s removed.\n" % account)
    time.sleep(1)
    return None


###############################################################################
#                               MSG PROCESSING                                #
###############################################################################

def long_t_pre_process(payload):
    """
    Prepare long payloads for transmission in multiple parts.

    :param payload: Long message to be transmitted in multiple parts.
    :return:        List of max packet size (254) long messages with headers.
    """

    if not isinstance(payload, str):
        raise FunctionParameterTypeError("long_t_pre_process")

    type_m = False
    type_f = False

    # Determine packet type
    if payload.startswith('m'):
        type_m = True
    elif payload.startswith('f'):
        type_f = True
    else:
        raise CriticalError("long_msg_pre_process", "Unknown packet type.")

    # Remove the {m,f} header and new lines
    payload = payload[1:].strip('\n')

    # Append SHA3-256 hash of payload to packet
    str_hash = sha3_256(payload)
    payload += str_hash

    # Split to list with 252 (maximum length - 2) long messages: room for one
    # char header and prevent dummy blocks when padding prior to encryption.
    packet_l = [payload[i:i + 252] for i in range(0, len(payload), 252)]

    if type_m:
        for i in xrange(len(packet_l)):
            packet_l[i] = 'a' + packet_l[i]    # 'a' = appended message
        packet_l[-1] = 'e' + packet_l[-1][1:]  # 'e' = end long message
        packet_l[0] = 'l' + packet_l[0][1:]    # 'l' = start long message

    elif type_f:
        for i in xrange(len(packet_l)):
            packet_l[i] = 'A' + packet_l[i]    # 'A' = appended file
        packet_l[-1] = 'E' + packet_l[-1][1:]  # 'E' = end long file
        packet_l[0] = 'L' + packet_l[0][1:]    # 'L' = start long file

    return packet_l


def padding(string):
    """
    Pad input to always match the packet max size (254 bytes).

    Byte used in padding is determined by how much padding is needed.

    :param string: String to be padded.
    :return:       Padded string.
    """

    if not isinstance(string, str):
        raise FunctionParameterTypeError("padding")

    if len(string) > 254:
        raise CriticalError("padding", "Input length exceeded 254.")

    length = 254 - (len(string) % 254)
    string += length * chr(length)

    # Ensure padded packet is exactly 254 bytes long
    if len(string) != 254:
        raise CriticalError("padding", "Incorrect padding length.")

    return string


###############################################################################
#                              ENCRYPTED COMMANDS                             #
###############################################################################

def change_logging(parameters, ret=False):
    """
    Send encrypted and signed packet to RxM via NH to enable / disable logging.

    :param parameters: Command and it's parameters.
    :param ret:        True returns the command.
    :return:           Log change command if ret is True, else None.
    """

    if not isinstance(parameters, str) or not isinstance(ret, bool):
        raise FunctionParameterTypeError("change_logging")

    global acco_store_l
    global_change = True

    try:
        parameters = parameters.split()

        if parameters[1] == "on":
            log_cmd = "LOGGING|ENABLE"

        elif parameters[1] == "off":
            log_cmd = "LOGGING|DISABLE"

        else:
            print("\nError: Invalid command.\n")
            if ret:
                return ''
            else:
                return None

    except IndexError:
            print("\nError: Invalid command.\n")
            if ret:
                return ''
            else:
                return None

    # If account is specified, enable logging only for that contact.
    try:
        if parameters[2]:
            if parameters[2] in get_list_of_accounts():
                log_cmd = "%s|me.%s" % (log_cmd, parameters[2])
                global_change = False
            else:
                print("\nError: Invalid contact.\n")
                return None

    except IndexError:
        pass

    # Check that local keyfile exists
    if not os.path.isfile("keys/tx.local.e"):
        raise NoLocalKeyError

    if global_change:
        if log_cmd == "LOGGING|ENABLE":
            for account in get_list_of_accounts():
                acco_store_l[account] = True

        if log_cmd == "LOGGING|DISABLE":
            for account in get_list_of_accounts():
                acco_store_l[account] = False

    else:
        if log_cmd.startswith("LOGGING|ENABLE"):
            acco_store_l[parameters[2]] = True

        if log_cmd.startswith("LOGGING|DISABLE"):
            acco_store_l[parameters[2]] = False

    if ret:
        return "C|%s" % log_cmd
    else:
        command_transmit(log_cmd)
        return None


def change_nick(account, parameter, ret=False):
    """
    Change nick of active 'account' to specified on TxM and RxM.

    :param account:   The recipient's account name (e.g. alice@jabber.org).
    :param parameter: New nickname yet to be separated.
    :param ret        True returns nick change command plaintext.
    :return:          Nick change command if ret is True, else None.
    """

    if not isinstance(account, str) or not \
            isinstance(parameter, str) or not \
            isinstance(ret, bool):
        raise FunctionParameterTypeError("change_nick")

    if group:
        print("\nError: Group is selected. Can't change nick.\n")
        return None

    try:
        new_nick = parameter.split()[1]
    except IndexError:
        print("\nError: Invalid command.\n")
        return None

    global recipient_nick

    # Check that specified nick is acceptable
    if (len(new_nick) + len(account) + 128 + 5) > 254:
        print("\nError: Nick too long.\n")

    elif new_nick == '':
        print("\nError: Can't give empty nick.\n")

    elif new_nick == "local":
        print("\nError: Nick can't refer to local keyfile.\n")

    elif ',' in new_nick or '|' in new_nick:
        print("\nError: Nick can't not contain characters ',' or '|'.\n")

    elif new_nick in get_list_of_accounts():
        print("\nError: Nick can't be an account.\n")

    else:
        if not os.path.isfile("keys/tx.local.e"):
            raise NoLocalKeyError

        write_nick(account, new_nick)
        recipient_nick = new_nick

        ch_cmd = "NICK|me.%s|%s" % (account, new_nick)

        print("\nChanged %s nick to %s.\n" % (account, new_nick))

        if ret:
            return "C|" + ch_cmd
        else:
            command_transmit(ch_cmd)

    if ret:
        return ''
    else:
        return None


def change_file_storing(parameters, ret=False):
    """
    Send STORE command to RxM to control file storage settings.

    :param parameters: Command and it's parameters.
    :param ret:        True returns store file command.
    :return:           Store file command if ret is True, else None.
    """

    if not isinstance(parameters, str) or not isinstance(ret, bool):
        raise FunctionParameterTypeError("change_file_storing")

    try:
        parameters = parameters.split()

        if parameters[1] == "on":
            store_cmd = "STORE|ENABLE"
        elif parameters[1] == "off":
            store_cmd = "STORE|DISABLE"
        else:
            print("\nError: Invalid command.\n")
            if ret:
                return ''
            else:
                return None

    except IndexError:
        print("\nError: Invalid command.\n")
        if ret:
            return ''
        else:
            return None

    # If account is specified, enable file reception only for that contact.
    try:
        if parameters[2]:
            if parameters[2] in get_list_of_accounts():
                store_cmd = "%s|rx.%s" % (store_cmd, parameters[2])
    except IndexError:
        pass

    # Check that local keyfile exists
    if not os.path.isfile("keys/tx.local.e"):
        raise NoLocalKeyError

    if ret:
        return "C|%s" % store_cmd
    else:
        command_transmit(store_cmd)
        return None


def clear_displays(account='', trickle=False):
    """
    Send command to NH.py, Pidgin and Rx.py to clear screens.

    Display clearing is disabled in NH and Pidgin during trickle connection
    because command needs to be transmitted in encrypted form to RxM to prevent
    NH from figuring out commands are being issued. Due to random output in
    packet type, RxM screen clearing takes time, meaning the efficiency to
    prevent shoulder surfing is decreased.

    :param account: The Pidgin conversation window to clear.
    :param trickle: True returns cmd_packet without NH headers / account name.
    :return:        None / clear screen command.
    """

    if not isinstance(account, str) or not isinstance(trickle, bool):
        raise FunctionParameterTypeError("clear_displays")

    if not os.path.isfile("keys/tx.local.e") and trickle:
        raise NoLocalKeyError

    os.system("clear")
    if trickle:
        return "C|CLEAR"
    else:
        cmd_packet = "TFC|N|%s|U|CLEAR|%s" % (int_version, account)
        return cmd_packet


###############################################################################
#                    COMMAND / MESSAGE / FILE TRANSMISSION                    #
###############################################################################

def command_thread(cmd, _=''):
    """
    Pad, encrypt, sign, encode and transmit command.

    :param cmd: The plaintext command.
    :param _:   Second parameter prevents thread from splitting chars
                of parameter 'command' to a set of separate parameters.
    :return:    None
    """

    if not isinstance(cmd, str) or not isinstance(_, str):
        raise FunctionParameterTypeError("command_thread")

    padded = padding(cmd)
    key_id = get_keyid("local")
    ct_tag = encrypt_and_sign("local", padded)
    b64enc = base64.b64encode(ct_tag)
    packet = "TFC|N|%s|C|%s|%s" % (int_version, b64enc, key_id)
    transmit(packet)
    return None


def command_transmit(cmd):
    """
    Run command_thread() as a thread.

    :param cmd: Command to transmit in thread.
    :return:    None
    """

    if not isinstance(cmd, str):
        raise FunctionParameterTypeError("command_transmit")

    wt = threading.Thread(target=command_thread, args=(cmd, ''))
    wt.start()
    wt.join()

    return None


def message_thread(message, account):
    """
    Pad, encrypt, sign, encode and transmit message.

    :param message: The plaintext message.
    :param account: The recipient's account name (e.g. alice@jabber.org).
    :return:        None
    """

    if not isinstance(message, str) or not isinstance(account, str):
        raise FunctionParameterTypeError("message_thread")

    padded = padding(message)
    key_id = get_keyid(account)
    ct_tag = encrypt_and_sign(account, padded)
    b64enc = base64.b64encode(ct_tag)
    packet = "TFC|N|%s|M|%s|%s|%s" % (int_version, b64enc, key_id, account)
    transmit(packet)
    return None


def message_transmit(message, account):
    """
    Run message_thread() as a thread.

    :param message: Message to transmit in the thread.
    :param account: The recipient's account name (e.g. alice@jabber.org).
    :return:        None
    """

    if not isinstance(message, str) or not isinstance(account, str):
        raise FunctionParameterTypeError("message_transmit")

    wt = threading.Thread(target=message_thread, args=(message, account))
    wt.start()
    wt.join()

    return None


def long_msg_transmit(plaintext, account):
    """
    Send long messages to contact and local RxM.

    :param plaintext: Long plaintext message.
    :param account:   The recipient's account name (e.g. alice@jabber.org).
    :return:          None
    """
    if not isinstance(plaintext, str) or not isinstance(account, str):
        raise FunctionParameterTypeError("long_msg_transmit")

    p_list = long_t_pre_process(plaintext)

    type_m = False
    type_f = False
    cancel = False

    if plaintext.startswith('m'):
        print("\nMessage transfer over %s packets. ^C cancels." % len(p_list))
        type_m = True

    elif plaintext.startswith('f'):
        print("\nFile transfer over %s packets. ^C cancels." % len(p_list))
        type_f = True

    else:
        raise CriticalError("long_msg_transmit", "Invalid plaintext type.")

    for p in p_list:

        if cancel:

            # Send cancel packet
            if type_f:
                print("\nFile transmission aborted.\n")
                message_transmit('C', account)

            if type_m:
                print("\nMessage transmission aborted.\n")
                message_transmit('c', account)

            return None

        try:
            start = get_ms()
            message_transmit(p, account)
            stop = get_ms()
            final_time = packet_delay - ((stop - start) / 1000.0)

            if final_time > 0:
                time.sleep(final_time)
            else:
                time.sleep(packet_delay)  # Error handling

            if lt_random_delay:
                if not p.startswith('e') and not p.startswith('E'):

                    sleep_time = random.SystemRandom().uniform(0, lt_max_delay)
                    indent_len = (13 - len(str(sleep_time))) * ' '
                    phase("Adding %s%s second delay between packet..."
                          % (sleep_time, indent_len), 55)

                    time.sleep(sleep_time)
                    print("Done.")

        except KeyboardInterrupt:
            cancel = True

    p_type = "File" if type_f else "Message"
    print("\n%s transmission complete.\n" % p_type)

    return None


def transmit_exit():
    """
    Send encrypted exit command to RxM and unencrypted command to NH.

    When local_testing is True, sleep to avoid premature exit of NH.py and
    Rx.py when IPC socket disconnects. This ensures TFC behaves the same way as
    it would when operating through serial interfaces.

    :return: None
    """

    command_transmit("EXIT")
    transmit("TFC|N|%s|U|EXIT" % int_version)
    if local_testing:
        time.sleep(1)
    graceful_exit(queue=True)


def recipient_chooser(payload):
    """
    Send message/file to a contact/group.

    :param payload: Message / file content to be sent.
    :return:        None
    """

    if not isinstance(payload, str):
        raise FunctionParameterTypeError("recipient_chooser")

    if group:

        group_member_list = get_group_members(group)

        # Detect empty group
        if not group_member_list:
            p = "message" if payload.startswith('m') else "file"
            print("\nSelected group is empty. No %s was sent.\n" % p)
            return None

        # Multi-cast message/file
        for member in group_member_list:
            print("           > %s" % member)

            if len(payload) > 252:
                long_msg_transmit(payload, member)

            else:
                if payload.startswith('m'):
                    message_transmit('s' + payload[1:], member)
                    if acco_store_l[member]:
                        nick = get_nick(member)
                        write_log_entry(member, nick, payload[1:])

                elif payload.startswith('f'):
                    message_transmit('S' + payload[1:], member)

                else:
                    raise CriticalError("recipient_chooser",
                                        "Invalid packet header")
                time.sleep(packet_delay)

        print('')

    # Standard message/file transmission
    else:
        if len(payload) > 252:
            long_msg_transmit(payload, recipient_acco)

        else:
            if payload.startswith('m'):
                message_transmit('s' + payload[1:], recipient_acco)
                if acco_store_l[recipient_acco]:
                    write_log_entry(recipient_acco,
                                    get_nick(recipient_acco),
                                    payload[1:])

            elif payload.startswith('f'):
                message_transmit('S' + payload[1:], recipient_acco)

            else:
                raise CriticalError("recipient_chooser",
                                    "Invalid packet header")
    return None


def load_file_data(parameters):
    """
    Load file data to payload.

    :param parameters: Target path/file yet to be separated from command.
    :return:           File data
    """

    if not isinstance(parameters, str):
        raise FunctionParameterTypeError("load_file_data")

    if parameters == "/file":
        try:
            root = Tkinter.Tk()
            root.withdraw()
            file_name = tkFileDialog.askopenfilename()
            root.destroy()
        except _tkinter.TclError:
            print("\nError: file dialog not available.\n")
            return "ABORT"
        if not file_name:
            return "ABORT"
    else:
        try:
            file_name = parameters.split()[1]

        except IndexError:
            print("\nError: Invalid command.\n")
            return "ABORT"

    if not os.path.isfile(file_name):
        print("\nError: File not found.\n")
        return "ABORT"

    r_size = readable_size(os.path.getsize(file_name))
    trunc_fn = file_name.split('/')[-1]

    phase("\nLoading file data...", 22)

    # Encode file to base64 format
    subprocess.Popen("base64 %s > .tfc_tmp_file" % file_name,
                     shell=True).wait()

    # Read data
    data = file(".tfc_tmp_file", "rb").read()

    # Shred encoded temp file
    subprocess.Popen("shred -n 3 -z -u .tfc_tmp_file", shell=True).wait()
    print("Done.\n")

    if not data:
        print("\nError: target file was empty. No file was sent.\n")
        time.sleep(0.5)
        return "ABORT"

    # Calculate average delay based on delays and performance
    if trickle_connection:
        avg_delay = 2 * (trickle_c_delay + (trickle_r_delay / 2.0))
    else:
        avg_delay = packet_delay
    if lt_random_delay:
        avg_delay += (lt_max_delay / 2.0)

    # Estimate packet count and delivery time
    p_count = 0
    datalen = len(data) + len(trunc_fn) + len(r_size) + 4

    while datalen > 0:
        p_count += 1
        datalen -= 252

    init_est = p_count * avg_delay
    d_human_r = time.strftime("%Hh %Mm %Ss", time.gmtime(init_est))
    d_human_r = d_human_r.replace("00h ", '').replace("00m ", '')
    datalen += (len(d_human_r) + len(str(p_count)))

    while datalen > 0:
        p_count += 1
        datalen -= 252

    if len("%s|%s|%s|%s|" % (trunc_fn, r_size, p_count, d_human_r)) > 252:
        print("\nError: Size of header exceeds one packet.\n")
        time.sleep(0.5)
        return "ABORT"

    data = "%s|%s|%s|%s|%s" % (trunc_fn, r_size, p_count, d_human_r, data)

    if confirm_file:
        m = str("Send %s (%s, ~%s packets, time: %s)?" % (trunc_fn, r_size,
                                                          p_count, d_human_r))
        if not yes(m):
            print("\nFile sending aborted.\n")
            time.sleep(0.5)
            return "ABORT"

    print('')
    return str(data)


def transmit(packet):
    """
    Concatenate tweakable SHA-256 based checksum to packet,
    output it to NH via serial / or NH.py via IPC socket.

    :param packet: Packet to send.
    :return:       None
    """

    if not isinstance(packet, str):
        raise FunctionParameterTypeError("transmit")

    chksum = sha2_256(packet)[:checksum_len]
    packet = "%s|%s\n" % (packet, chksum)

    if unittesting:
        open("unitt_txm_out", "w+").write(packet)
        return None

    if local_testing:
        ipc_nh.send(packet)
    else:
        port_nh.write(packet)

    return None


###############################################################################
#                              GROUP MANAGEMENT                               #
###############################################################################

def get_group_members(group_name):
    """
    Get members of group.

    :param group_name: Name of target group.
    :return:           List of group members.
    """

    if not isinstance(group_name, str):
        raise FunctionParameterTypeError("get_group_members")

    try:
        ensure_dir("groups/")
        members = open("groups/g.%s.tfc" % group_name).read().splitlines()
        return members

    except IOError:
        raise CriticalError("get_group_members", "g.%s.tfc IOError."
                            % group_name)


def get_list_of_groups():
    """
    Get list of existing groups.

    :return: List of groups.
    """

    ensure_dir("groups/")
    g_file_list = []

    try:
        for f in os.listdir("groups/"):
            if f.startswith("g.") and f.endswith(".tfc"):
                g_file_list.append(f[2:][:-4])

    except OSError:
        print("Error: Could not find folder 'groups'")

    g_file_list.sort()

    return g_file_list


def group_create(parameters):
    """
    Create a new group.

    :param parameters: Command string to be parsed.
    :return:           None
    """

    if not isinstance(parameters, str):
        raise FunctionParameterTypeError("group_create")

    try:
        parameters = parameters.split()
        group_name = parameters[2]

    except IndexError:
        raise GroupError("No group name specified.")

    ensure_dir("groups/")

    # If group exists, ask to overwrite / abort
    if os.path.isfile("groups/g.%s.tfc" % group_name):
        if not yes("\nGroup already exists. Overwrite?"):
            print("\nGroup creation aborted.\n")
            return None

    if group_name in ["create", "add", "rm"]:
        raise GroupError("Group name can't be a command.")

    for f in get_keyfile_list():
        if group_name in get_nick(f[3:][:-2]):
            raise GroupError("Group name can't be nick of contact.")

        if group_name in f[3:][:-2]:
            raise GroupError("Group name can't be an account.")

        if group_name in f[:-2] or group_name in f:
            raise GroupError("Group name can't have name of a keyfile.")

    # Initialize lists
    accepted = []
    rejected = []
    c_eval_l = parameters[3:]
    existing = get_list_of_accounts()

    for c in c_eval_l:
        if c == "local":
            continue
        elif c in existing:
            accepted.append(c)
        else:
            rejected.append(c)
    try:
        with open("groups/g.%s.tfc" % group_name, "w+") as f:
            if accepted:
                print("\nCreated group %s with following members:"
                      % group_name)
                for c in accepted:
                    f.write("%s\n" % c)
                    print("    %s" % c)
            else:
                f.write('')
                print("\nCreated an empty group %s." % group_name)
    except IOError:
        raise CriticalError("group_create", "g.%s.tfc IOError" % group_name)

    print('')

    # Alphabetize contacts
    sort_group(group_name)

    if rejected:
        print("\nFollowing accounts are not in contacts:")
        for c in rejected:
            print("    %s" % c)
        print('')

    if clear_input_screen:
        raw_input(" Press <enter> to continue.")

    return None


def group_add_member(parameters):
    """
    Add members to specified group. Create new
    group is specified group doesn't exist.

    :param parameters: Group name and member list yet to be separated.
    :return:           None
    """

    if not isinstance(parameters, str):
        raise FunctionParameterTypeError("group_add_member")

    try:
        param_list = parameters.split()
        group_name = param_list[2]
    except IndexError:
        raise GroupError("No group name specified.")

    try:
        c_eval_lst = param_list[3:]
    except IndexError:
        raise GroupError("No new contacts specified.")
    if not c_eval_lst:
        raise GroupError("No contacts specified.")

    c_addlist = []
    c_unknown = []
    ensure_dir("groups/")

    if not os.path.isfile("groups/g.%s.tfc" % group_name):
        if yes("\nGroup %s was not found. Create new group?" % group_name):
            try:
                group_create(parameters)
                return None
            except GroupError:
                raise
        else:
            print("Group creation aborted.\n")
            return None

    contacts = get_list_of_accounts()

    for c in c_eval_lst:
        if c == "local":
            continue
        elif c in contacts:
            c_addlist.append(c)
        else:
            c_unknown.append(c)

    c_ready = []
    c_added = []

    try:
        with open("groups/g.%s.tfc" % group_name, "a+") as f:
            for c in c_addlist:
                if c not in get_group_members(group_name):
                    f.write("%s\n" % c)
                    c_added.append(c)
                else:
                    c_ready.append(c)

    except IOError:
        raise CriticalError("group_add_member", "g.%s.tfc IOError."
                            % group_name)

    sort_group(group_name)

    if c_added:
        print("\nAdded following accounts to %s:" % group_name)
        for c in c_added:
            print("    %s" % c)
        print('')

    if c_ready:
        print("\nFollowing accounts were already in %s:" % group_name)
        for c in c_ready:
            print("    %s" % c)
        print('')

    if c_unknown:
        print("\nFollowing accounts are not in contacts:")
        for c in c_unknown:
            print("    %s" % c)
        print('\n')

    if clear_input_screen:
        raw_input(" Press <enter> to continue.")

    return None


def group_rm_member(parameters):
    """
    Remove specified members from group. If no members
    are specified, overwrite and delete group file.

    :param parameters: Group name and list of accounts to remove.
    :return:           None
    """

    if not isinstance(parameters, str):
        raise FunctionParameterTypeError("group_rm_member")

    try:
        param_list = parameters.split()
        group_name = param_list[2]

    except IndexError:
        raise GroupError("No group specified.")

    try:
        c_eval_lst = param_list[3:]
    except IndexError:
        raise GroupError("No group member specified.")

    ensure_dir("groups/")

    if not os.path.isfile("groups/g.%s.tfc" % group_name):
        raise GroupError("Group does not exist.")

    if not c_eval_lst:
        if yes("\nRemove group '%s'?" % group_name):
            shred_command = "shred -n 3 -z -u groups/g.%s.tfc" % group_name
            subprocess.Popen(shred_command, shell=True).wait()
            print("\nRemoved group %s.\n" % group_name)
        else:
            print("\nGroup removal aborted.\n")
        return None

    c_ingroup = get_group_members(group_name)
    c_rm_list = []
    c_unknown = []
    c_removed = []
    c_n_exist = []
    contact_l = get_list_of_accounts()

    for c in c_eval_lst:
        if c == "local":
            continue
        elif c in contact_l:
            c_rm_list.append(c)
        else:
            c_unknown.append(c)

    try:
        with open("groups/g.%s.tfc" % group_name, 'w') as f:
            for c in c_rm_list:
                if c not in c_ingroup:
                    c_n_exist.append(c)

            for c in c_ingroup:
                if c in c_rm_list:
                    c_removed.append(c)
                else:
                    f.write("%s\n" % c)

    except IOError:
        raise CriticalError("group_rm_member", "g.%s.tfc IOError."
                            % group_name)

    if c_removed:
        print("\nRemoved following accounts from group %s:" % group_name)
        for c in c_removed:
            print("    %s" % c)
        print('')

    if c_n_exist:
        print("\nFollowing accounts were not in group %s:" % group_name)
        for c in c_n_exist:
            print("    %s" % c)
        print('')

    if c_unknown:
        print("\nFollowing accounts are not in contacts:")
        for c in c_unknown:
            print("    %s" % c)
        print('\n')

    if clear_input_screen:
        raw_input(" Press <enter> to continue.")

    return None


def print_group_list():
    """
    Print list of groups and if print_group_contacts is True, their members.

    :return: None
    """

    g_file_list = get_list_of_groups()

    if g_file_list:

        s = " and their members" if print_members_in_g else ''
        print("\nAvailable groups%s:" % s)

        for g in g_file_list:
            print("    %s" % g)
            if print_members_in_g:
                try:
                    print_group_members(g, True)
                except GroupError:
                    pass
        print('')
    else:
        print("\nThere are currently no groups.\n")

    if clear_input_screen:
        raw_input(" Press <enter> to continue.")

    return None


def print_group_members(group_name, short=False):
    """
    Print list of existing groups (and their members).

    :param group_name: Target group yet to be separated.
    :param short:      When printing members of groups as part
                       of '/groups' command, leave out headers.
    :return:           None
    """

    if not isinstance(group_name, str) or not isinstance(short, bool):
        raise FunctionParameterTypeError("print_group_members")

    if not group and group_name == '':
        print("\nNo group is selected.\n")
        return None

    if group and group_name == '':
        group_name = group

    try:
        ensure_dir("groups/")
        g_members = open("groups/g.%s.tfc" % group_name).read().splitlines()

        if g_members:

            # Leave out description if printed as part of all group files
            if short:
                for member in g_members:
                    print("        %s" % member)
                print('')

            else:
                print("\nMembers in group %s:" % group_name)
                for member in g_members:
                    print("    %s" % member)
                print('')

        else:
            if short:
                print("        Group is empty.")
            else:
                print("\nGroup is empty.\n")

    except IOError:
        if short:
            print("    Group %s does not exist." % group_name)
        else:
            print("\nGroup %s does not exist.\n" % group_name)

    if clear_input_screen and not short:
        raw_input(" Press <enter> to continue.")

    return None


def sort_group(group_name):
    """
    Alphabetize members of specified group.

    :param group_name: Name of groups to sort.
    :return:           None
    """

    if not isinstance(group_name, str):
        raise FunctionParameterTypeError("sort_group")

    ensure_dir("groups/")

    try:
        members = open("groups/g.%s.tfc" % group_name).readlines()

        members.sort()

        with open("groups/g.%s.tfc" % group_name, 'w') as f:
            for m in members:
                f.write(m)

    except IOError:
        raise CriticalError("sort_group", "g.%s.tfc IOError." % group_name)

    return None


###############################################################################
#                                    MISC                                     #
###############################################################################

def ensure_dir(directory):
    """
    Ensure directory exists.

    :param directory: Specified directory.
    :return:          None
    """

    if not isinstance(directory, str):
        raise FunctionParameterTypeError("ensure_dir")

    try:
        name = os.path.dirname(directory)
        if not os.path.exists(name):
            os.makedirs(name)
    except OSError:
        raise CriticalError("ensure_dir", "No directory specified.")

    return None


def print_about():
    """
    Print URLs that direct to TFC project site and documentation.

    :return: None
    """

    os.system("clear")
    print(" Tinfoil Chat NaCl %s\n\n" % str_version +
          " Website:     https://github.com/maqp/tfc-nacl/                \n"
          " White paper: https://cs.helsinki.fi/u/oottela/tfc.pdf         \n"
          " Manual:      https://cs.helsinki.fi/u/oottela/tfc-manual.pdf\n\n")

    if clear_input_screen:
        raw_input(" Press <enter> to continue.")

    return None


def print_help():
    """
    Print the list of commands. Switch to more
    compact style if terminal is too narrow.

    :return: None
    """

    def help_printer(tuple_list, wide):
        """
        Print help menu, style depending on terminal width.

        :param tuple_list: List of command-description tuples.
        :param wide:       When True, use wide print style.
        :return:           None
        """
        for cmd, desc in tuple_list:
            if wide:
                print("  %s %s%s" % (cmd, ((25 - len(cmd)) * ' '), desc))
            else:
                print("%s:\n  %s\n" % (desc, cmd))
        return None

    common = [("/about", "Show information about TFC"),
              ("/help", "Display this list of commands"),
              ("/clear, '  '", "Clear screens"),
              ("/exit", "Exit TFC on TxM, NH and RxM"),
              ("/localkey", "Generate new local key pair"),
              ("/add <account>( <nick>)", "Start key exchange with contact"),
              ("/psk <account>( <nick>)", "Create pre-shared key for contact"),
              ("/rm <account>", "Remove keyfiles and account from TxM/RxM"),
              ("/logging {on,off}( A)", "Change logging (for A)"),
              ("/store {on,off}( A)", "Change file reception (for A)"),
              ("/file{, path}", "Send file to contact"),
              ("/cf", "Cancel file transmission during trickle connection"),
              ("/cm", "Cancel message transmission during trickle connection"),
              ("/paste", "Start paste mode"),
              ("/nick <nick>", "Change nickname of active contact to <nick>"),
              ("/msg {account,ID,group}", "Change recipient"),
              ("/names", "List existing contacts"),
              ("/shift + PgUp/PgDn", "Scroll terminal up/down")]

    groupc = [("/groups", "List currently available groups"),
              ("/group", "List accounts in active group"),
              ("/group G", "List accounts in group G"),
              ("/group create G A1 .. An", "Create group G and add A1 .. An"),
              ("/group add G A1 .. An", "Add accounts A1 .. An to group G"),
              ("/group rm G A1 .. An", "Remove A1 .. An from group G"),
              ("/group rm G", "Remove group G")]

    width = get_tty_wh(wo=True)

    os.system("clear")
    print("List of commands:")
    help_printer(common, (width > 80))

    print("%s\nGroup management:" % (width * '-'))
    help_printer(groupc, (width > 80))
    print("%s\n" % (width * '-'))

    if clear_input_screen:
        raw_input(" Press <enter> to continue.")

    return None


def tab_complete(text, state):
    """
    Get tab-complete list.

    :param text:  [Not defined]
    :param state: [Not defined]
    :return:      [Not defined]
    """

    options = [t for t in get_tab_complete_list() if t.startswith(text)]
    try:
        return options[state]

    except IndexError:
        return None


def get_tab_complete_list():
    """
    Create list of words that tab-complete fills.

    :return: List of tab-complete words.
    """

    tc_list = []

    # Add list of files
    dir_files = [f for f in os.listdir('.') if
                 os.path.isfile(os.path.join('.', f))]
    tfc_files = ["Tx.py", "Tx.pyc", "test_tx.py", "setup.py",
                 "Rx.py", "Rx.pyc", "test_rx.py", ".tx_contacts",
                 "NH.py", "NH.pyc", "test_nh.py", ".rx_contacts"
                 "dd.py", "syslog.tfc", "hwrng.py"]

    usr_files = set(dir_files) - set(tfc_files)
    tc_list += [f for f in usr_files]

    # Add list of commands
    tc_list += ["about", "add ", "clear", "create ", "exit",
                "file ", "group ", "help", "logging ", "msg ",
                "nick ", "quit", "rm ", "select ", "store ",
                "localkey", "rxkey"]

    # Add list of groups
    tc_list += [(c + ' ') for c in get_list_of_accounts()]

    # Add list of groups
    tc_list += [(g + ' ') for g in get_list_of_groups()]

    return tc_list


def readable_size(size):
    """
    Returns the size of file in human readable form.

    :param size: Size of file in bytes.
    :return:     Human readable format of bytes.
    """

    if not isinstance(size, (int, long)):
        raise FunctionParameterTypeError("readable_size")

    for unit in ['', 'K', 'M', 'G', 'T', 'P', 'E', 'Z']:
        if abs(size) < 1024.0:
            return "%3.1f%sB" % (size, unit)
        size /= 1024.0

    return "%.1f%sB" % (size, 'Y')


def yes(prompt, indent=0):
    """
    Prompt user a question that is answered with yes / no.

    :param prompt: Question to be asked.
    :param indent: Indent of answer.
    :return:       True if user types 'y' or 'yes', otherwise returns False.
    """

    if not isinstance(prompt, str) or not isinstance(indent, int):
        raise FunctionParameterTypeError("yes")

    while True:
        try:
            answer = raw_input("%s (y/n): %s" % (prompt, indent * ' '))

        except KeyboardInterrupt:
            raise

        if answer.lower() in ("yes", 'y'):
            return True

        elif answer.lower() in ("no", 'n'):
            return False


def phase(string, dist):
    """
    Print name of next phase. Next message (about completion), printed after
    the phase will be printed on same line as the name specified by 'string'
    at same distance regardless of leading newlines.

    :param string: String to be printed.
    :param dist:   Indentation of completion message.
    :return:       None
    """

    if not isinstance(string, str) or not isinstance(dist, (int, long)):
        raise FunctionParameterTypeError("phase")

    n = 0
    for i in range(len(string)):
        if string[i] == '\n':
            n += 1
        else:
            break

    spaces = (dist - len(string) + n) * ' '
    sys.stdout.write(string + spaces)
    sys.stdout.flush()

    return None


def get_tty_wh(wo=False):
    """
    Get width and height of terminal Tx.py is running in.

    :param wo: When True, return only width of terminal.
    :return:   Width (and height) of terminal.
    """

    def ioctl_gwin_size(fd):
        """
        Get terminal window size from input/output control.

        :param fd: File descriptor.
        :return:   Width and height.
        """

        return struct.unpack("hh", fcntl.ioctl(fd, termios.TIOCGWINSZ, "1234"))

    cr = ioctl_gwin_size(0) or ioctl_gwin_size(1) or ioctl_gwin_size(2)

    if wo:
        return int(cr[1])
    else:
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

    os.system("clear")
    width, height = get_tty_wh()

    print(((height / 2) - 1) * '\n')

    # Style 1
    animation = random.randint(1, 3)
    if animation == 1:
        i = 0
        while i <= len(string):
            sys.stdout.write("\x1b[1A" + ' ')
            sys.stdout.flush()

            if i == len(string):
                print(((width - len(string)) / 2) * ' ' + string[:i])
            else:
                rc = chr(random.randrange(32, 126))
                print(((width - len(string)) / 2) * ' ' + string[:i] + rc)

            i += 1
            time.sleep(0.03)

    # Style 2
    if animation == 2:
        char_l = len(string) * ['']

        while True:
            sys.stdout.write("\x1b[1A" + ' ')
            sys.stdout.flush()
            st = ''

            for i in range(len(string)):
                if char_l[i] != string[i]:
                    char_l[i] = chr(random.randrange(32, 126))
                else:
                    char_l[i] = string[i]
                st += char_l[i]

            print(((width - len(string)) / 2) * ' ' + st)

            time.sleep(0.004)
            if st == string:
                break

    # Style 3
    if animation == 3:

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
                self.char = random.choice(FChar.list_chr)
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
                                self.char = random.choice(FChar.list_chr)
                    else:
                        self.char = random.choice(FChar.list_chr)

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
            p = random.randint(0, 1000000000)
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
                time.sleep(sleep_ms)
                steps += 1
        try:
            r = rand()
            main()
        except KeyboardInterrupt:
            curses.endwin()
            curses.curs_set(1)
            curses.reset_shell_mode()
            curses.echo()
            os.system("clear")

    time.sleep(0.3)
    os.system("clear")
    return None


def process_arguments():
    """
    Define Tx.py settings from arguments passed from command line.

    :return: None
    """

    parser = argparse.ArgumentParser("python Tx.py",
                                     usage="%(prog)s [OPTION]",
                                     description="More options inside Tx.py")

    parser.add_argument("-c",
                        action="store_true",
                        default=False,
                        dest="clear_ip_s",
                        help="clear input screen after each entry")

    parser.add_argument("-p",
                        action="store_true",
                        default=False,
                        dest="panic",
                        help="panic exit with double space command")

    parser.add_argument("-m",
                        action="store_true",
                        default=False,
                        dest="m_logging",
                        help="enable message logging by default")

    parser.add_argument("-t",
                        action="store_true",
                        default=False,
                        dest="trickle",
                        help="enable trickle connection to hide metadata")

    parser.add_argument("-s",
                        action="store_true",
                        default=False,
                        dest="trickle_stats",
                        help="Print statistics about constant time delay")

    parser.add_argument("-l",
                        action="store_true",
                        default=False,
                        dest="local",
                        help="enable local testing mode")

    parser.add_argument("-d",
                        action="store_true",
                        default=False,
                        dest="ddsockets",
                        help="data diode simulator socket configuration")

    args = parser.parse_args()

    global clear_input_screen
    global panic_exit
    global txm_side_logging
    global trickle_connection
    global print_ct_stats
    global local_testing
    global dd_socket

    if args.clear_ip_s:
        clear_input_screen = True

    if args.panic:
        panic_exit = True

    if args.m_logging:
        txm_side_logging = True

    if args.trickle:
        trickle_connection = True

    if args.trickle_stats:
        print_ct_stats = True

    if args.local:
        local_testing = True

    if args.ddsockets:
        dd_socket = True


def search_serial_interfaces():
    """
    Search serial interfaces.

    :return: Serial interface to use.
    """

    dev_files = [df for df in os.listdir("/dev/")]
    dev_files.sort()
    serial_iface = ''

    if nh_usb_adapter:
        for dev_file in dev_files:
            if dev_file.startswith("ttyUSB"):
                serial_iface = "/dev/%s" % dev_file
                break

        if not serial_iface:
            graceful_exit("Error: No USB-serial adapter was not found.")

    else:
        os_name = subprocess.check_output(["grep", "PRETTY_NAME",
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
            serial_iface = "/dev/%s" % integrated_if
        else:
            graceful_exit("Error: /dev/%s was not found." % integrated_if)

        return serial_iface


###############################################################################
#                               TRICKLE CONNECTION                            #
###############################################################################

def heads():
    """
    Use Kernel CSPRNG to generate a secure coin toss.

    :return: True / False
    """

    return ord(os.urandom(1)) % 2 == 1


def get_ms():
    """
    Get current system time.

    :return: system time in milliseconds (int).
    """

    return int(round(time.time() * 1000))


def trickle_delay(start):
    """
    Obfuscate processing time, add delay to prevent congestion and optionally
    add further delay to avoid triggering spam guards of IM servers.

    This function first compares the initial timestamp from start of
    sender_process() loop against current timestamp. It'll then calculate the
    difference between elapsed time and variable trickle_c_delay, and sleep
    that time. This way time.sleep(ct_filler) returns ~2000 ms after start of
    sender_process(). Encryption-times longer than 2000ms will gracefully exit.

    The constant time sleep hides metadata on platform speed that could be used
    to identify end point hardware configuration. The delay is set high
    intentionally to avoid flooding the IM server, and to reduce the amount of
    cyclic KDF 'catch up' time for Rx.py of contact if he or she goes offline
    for a period of time.

    The function then adds uniform random delay between [0, trickle_r_delay] to
    obfuscate inaccuracies in constant time delay implementation. This adds
    further protection against timing attacks. The randomness comes from
    /dev/urandom to keep the internal state of RNG secure.

    Finally, if the lt_random_delay boolean is True, the function will sleep
    additional random time (defined by /dev/urandom) between [0, lt_max_delay].
    This is mainly intended to make communication more human-like, so it
    doesn't alert IM server spam guards. The nature of the randomness is
    however uniform, so it's detectable with very simple statistical analysis.
    This means it doesn't prevent a state adversary from detecting use of
    trickle connection.

    :param start: System time in ms when sender_process() loop started.
    :return:      None
    """

    final_time = get_ms()
    f_duration = (final_time - start) / 1000.0
    ct_filler = trickle_c_delay - f_duration

    if ct_filler < 0:
        raise CriticalError("trickle_delay",
                            "Function execute time exceeded trickle_c_delay.\n"
                            "Increase the value from settings and restart.\n")

    time.sleep(ct_filler)
    t_after_ct_sleep = get_ms() - start

    t_r_delay = random.SystemRandom().uniform(0, trickle_r_delay)
    time.sleep(t_r_delay)

    l_t_delay = 0
    if lt_random_delay:
        l_t_delay = random.SystemRandom().uniform(0, lt_max_delay)
        time.sleep(l_t_delay)

    if print_ct_stats:
        print("Time after constant time delay %sms (setting=%sms)" %
              (t_after_ct_sleep, trickle_c_delay * 1000))

        print("(Packet process time: %sms, CT delay length: %sms)" %
              (f_duration * 1000, ct_filler * 1000))

        print("Trickle random delay: %sms\n" % (t_r_delay * 1000))

        if lt_random_delay:
            print("Random lt_delay: %sms" % l_t_delay * 1000)

    return None


def sender_process():
    """
    Load pre-processed messages / file (part if long transmission) from queue,
    flip a coin and based on result output either actual command/message/file,
    or a noise packet of opposite type.

    The purpose of trickle connection and this process is to hide metadata
    about when and how much communication is actually taking place.

    Since Python's multiprocess.Queue doesn't have priority feature, two
    Queues are used: msg_queue and file_queue -- where msg_queue has priority
    over the other. At the start of every loop, the two queues are checked. If
    msg_queue has data, it's loaded, and the file queue is ignored: Users
    retain the ability to communicate, and file transmission occurs when there
    are no messages to be sent.

    Based on whether packet loaded from queue was a command or a message/file,
    the process will enter one of two loops. At the beginning of the loop, the
    process will call function heads(), that outputs true/false based on
    evaluation of ord(os.urandom(1)) % 2 == 1. The choice is thus always
    uniformly random: CSPRNG keeps the result of next coin toss computationally
    unpredictable.

    If the coin lands on heads, the process will output the packet and exit the
    loop. If the coin landed on tails, the process will output noise packet of
    opposite type and restart the loop.

    If both queues are empty, the coin toss determines whether to output noise
    command or noise message. The ratio between the two packet types is always
    1:1.

    At the start of the loop, the process gets the current time in milliseconds
    and after the command or message has been output, the process calls
    tickle_delay() while passing it the system time in ms at the start of the
    loop as a parameter. Trickle delay will even out the processing time and
    add random amount of delay to obfuscate errors in timing. If a noise
    packet is output instead, the function timer is restarted immediately after
    trickle_delay() returns.

    :return: [no return value]
    """

    while True:

        start = get_ms()
        sys.stdout.write('\r' + ' ' * (len(readline.get_line_buffer())) + '\r')

        if msg_queue.empty() and file_queue.empty():
            if heads():
                command_transmit('N')
                trickle_delay(start)
                continue
            else:
                message_transmit('n', recipient_acco)
                trickle_delay(start)
                continue

        if not msg_queue.empty():
            packet = msg_queue.get()
        elif not file_queue.empty():
            packet = file_queue.get()
        else:
            continue

        if packet.startswith("C|"):
            while True:
                if heads():
                    command_transmit(packet[2:])
                    trickle_delay(start)
                    break
                else:
                    message_transmit('n', recipient_acco)
                    trickle_delay(start)
                    start = get_ms()
        else:
            while True:
                if heads():
                    message_transmit(packet, recipient_acco)
                    trickle_delay(start)
                    break
                else:
                    command_transmit('N')
                    trickle_delay(start)
                    start = get_ms()


def input_process(file_no, _):
    """
    Get command, message or file content, pre-process long transmissions
    and place un-padded plaintext packets to msg_queue or file_queue.

    The process separates loading time of long messages and files to ensure
    minimal effect on processing time of sender_process() that outputs data.

    :param file_no: Stdin file.
    :param _:       Prevents handling file_no as iterable.
    :return:        None
    """

    sys.stdin = os.fdopen(file_no)
    kb_string = ''

    try:
        while True:

            # If previous message exceeded terminal width, print newline.
            if kb_string:
                if (9 + len(recipient_nick + kb_string)) > get_tty_wh(wo=True):
                    print('')

            if clear_input_screen:
                os.system("clear")
                print("TFC-NaCl %s || Tx.py || Trickle connection enabled\n"
                      % str_version)

            kb_string = raw_input("Msg to %s: " % recipient_nick)

            # Disabled commands
            for c in ["/msg", "/paste", "/group", "/dh",
                      "/psk", "/rm", "/add", "/localkey"]:

                if kb_string.startswith(c):
                    print("\nError: Command disabled during trickle mode.\n")
                    if clear_input_screen:
                        time.sleep(1)
                    kb_string = ''
                    continue

            if kb_string == '':
                continue

            # Locally handled commands
            elif kb_string.startswith("/help"):
                print_help()

            elif kb_string.startswith("/about"):
                print_about()

            elif kb_string.startswith("/names"):
                print_contact_list(True)

            # Transmitted commands
            elif kb_string == "/exit" or (kb_string == "  " and panic_exit):
                transmit_exit()

            elif kb_string.startswith("/nick "):
                try:
                    cmd = change_nick(recipient_acco, kb_string, ret=True)
                    if cmd:
                        msg_queue.put(cmd)
                except NoLocalKeyError:
                    pass

            elif kb_string.startswith("/logging "):
                try:
                    cmd = change_logging(kb_string, ret=True)
                    if cmd:
                        msg_queue.put(cmd)
                except NoLocalKeyError:
                    pass

            elif kb_string.startswith("/store "):
                try:
                    cmd = change_file_storing(kb_string, ret=True)
                    if cmd:
                        msg_queue.put(cmd)
                except NoLocalKeyError:
                    pass

            elif kb_string == "/clear" or kb_string == "  ":
                try:
                    cmd = clear_displays(trickle=True)
                    if cmd:
                        msg_queue.put(cmd)
                except NoLocalKeyError:
                    pass

            elif kb_string == "/cm":
                while not msg_queue.empty():
                    msg_queue.get()
                msg_queue.put('c')

            elif kb_string == "/cf":
                while not file_queue.empty():
                    file_queue.get()
                file_queue.put('C')

            elif kb_string.startswith("/file"):
                file_data = load_file_data(kb_string)
                if file_data != "ABORT":

                    if len(file_data) > 252:
                        file_part_list = long_t_pre_process('f' + file_data)
                        for f_part in file_part_list:
                            file_queue.put(f_part)
                    else:
                        file_queue.put('S' + file_data)

            elif kb_string.startswith('/'):
                print("\nInvalid command.\n")

            else:
                if len(kb_string) > 252:
                    message_part_list = long_t_pre_process('m' + kb_string)
                    for m_part in message_part_list:
                        msg_queue.put(m_part)
                else:
                    msg_queue.put('s' + kb_string)

    except KeyboardInterrupt:
        graceful_exit(queue=True)


###############################################################################
#                             STANDARD CONNECTION                             #
###############################################################################

def get_normal_input():
    """
    Get input from user from raw_input() or stdin if paste mode is enabled.

    :return: User's input.
    """

    user_input = ''

    global paste

    if group:
        prompt = "Msg to group %s: " % recipient_nick
    else:
        prompt = "Msg to %s: " % recipient_nick

    if paste:
        try:
            os.system("clear")
            print("TFC-NaCl %s || Tx.py\n" % str_version)
            print("Paste mode on || 2x ^D sends || ^C exits\n\n%s\n" % prompt)

            try:
                lines = sys.stdin.read()
            except IOError:
                print("\nError in stdio. Please try again.\n")
                time.sleep(1.5)
                return ''

            if not lines:
                return ''

            user_input = "\n%s" % lines
            print("\nSending...\n")
            time.sleep(0.25)

        except KeyboardInterrupt:
            os.system("clear")
            print("TFC-NaCl %s || Tx.py       \n" % str_version)
            print("Closing paste mode...\n\n%s\n" % prompt)

            paste = False
            time.sleep(0.25)
            os.system("clear")
            return ''
    else:
        try:
            if clear_input_screen:
                os.system("clear")
                print("TFC-NaCl %s || Tx.py \n\n\n" % str_version)

            try:
                user_input = raw_input(prompt)
            except EOFError:
                print('')
                pass

            if user_input == "/paste":
                paste = True
                return ''

        except (KeyboardInterrupt, ValueError):
            graceful_exit()

    return user_input


def main_loop(user_input=''):
    """
    Send a command or message to contact based on user_input content.

    :param user_input: Message, noise packet or command.
    :return:           None
    """

    if not isinstance(user_input, str):
        raise FunctionParameterTypeError("main_loop")

    stop_loop = True if user_input else False

    while True:
        global recipient_acco
        global recipient_nick
        global group

        if not stop_loop:

            if not get_list_of_accounts():
                add_first_contact()
                caret_dst = print_contact_list()
                recipient_acco, recipient_nick = select_contact(caret_dst)
                group = ''

            if recipient_nick not in get_list_of_targets():
                os.system("clear")
                print("TFC-NaCl %s || Tx.py\n\n"
                      "No contact is currently active.\n" % str_version)

                group = ''

                caret_dist = print_contact_list()
                recipient_acco, recipient_nick = select_contact(caret_dist)

                os.system("clear")
                print("\nSelected '%s' (%s)\n" % (recipient_nick,
                                                  recipient_acco))

            # If previous message exceeded terminal width, print newline.
            prev_line_len = 9 + len(recipient_nick + user_input)
            if user_input and prev_line_len > get_tty_wh(True):
                print('')

            user_input = get_normal_input()

        # Refresh tab-complete list
        readline.set_completer(tab_complete)
        readline.parse_and_bind("tab: complete")

        if user_input == '':
            pass

        # Local group management commands
        elif user_input.startswith("/group create "):
            try:
                group_create(user_input)
            except GroupError:
                continue

        elif user_input == "/group":
            try:
                print_group_members(group)
            except GroupError:
                continue

        elif user_input.startswith("/group add "):
            try:
                group_add_member(user_input)
            except GroupError:
                continue

        elif user_input.startswith("/group rm "):
            try:
                group_rm_member(user_input)
            except GroupError:
                continue

        elif user_input.startswith("/group "):
            try:
                print_group_members(user_input.split()[1])
            except GroupError:
                continue
            except IndexError:
                print("\nError: No group specified.\n")

        elif user_input == "/groups":
            print_group_list()

        # Other local commands
        elif user_input == "/help":
            print_help()

        elif user_input == "/about":
            print_about()

        elif user_input == "/names":
            print_contact_list(True)

        elif user_input.startswith("/msg "):
            r, n, g = change_recipient(user_input)
            if g:
                recipient_nick = n
                group = g
            elif r:
                recipient_acco = r
                recipient_nick = n
                group = ''
            else:
                continue

        # Commands that output packets
        elif (user_input == "  " and panic_exit) or user_input == "/exit":
            transmit_exit()

        elif user_input == "  " or user_input == "/clear":
            try:
                cmd = clear_displays(recipient_acco)
                if cmd:
                    transmit(cmd)
            except NoLocalKeyError:
                pass

        elif user_input.startswith("/nick "):
            try:
                change_nick(recipient_acco, user_input)
            except NoLocalKeyError:
                pass

        elif user_input.startswith("/logging "):
            try:
                change_logging(user_input)
            except NoLocalKeyError:
                pass

        elif user_input.startswith("/store "):
            try:
                change_file_storing(user_input)
            except NoLocalKeyError:
                pass

        # Contact key management commands
        elif user_input.startswith("/add ") or user_input.startswith("/dh "):
            try:
                start_key_exchange(user_input)
            except NoLocalKeyError:
                pass

        elif user_input.startswith("/psk"):
            try:
                new_psk(user_input)
            except NoLocalKeyError:
                pass

        elif user_input.startswith("/rxkey"):
            command_transmit("ASKRXKF")

        elif user_input.startswith("/localkey"):
            try:
                new_local_key()
            except KeyboardInterrupt:
                pass

        elif user_input.startswith("/rm "):
            rm_contact(user_input)

        elif user_input.startswith('/') and not user_input.startswith("/file"):
            print("\nError: Invalid command.\n")

        else:
            if key_searcher(user_input):
                if not yes("\nMessage appears to contain a key. Proceed?"):
                    continue

            if user_input.startswith("/file"):
                user_input = load_file_data(user_input)

                if user_input != "ABORT":
                    recipient_chooser('f' + user_input)
            else:
                recipient_chooser('m' + user_input)

        if stop_loop:
            break


###############################################################################
#                                     MAIN                                    #
###############################################################################

unittesting = False  # Alters function input during unittesting
acco_store_l = {}

if __name__ == "__main__":

    process_arguments()

    if unittesting:
        graceful_exit("Error: Variable 'unittesting' is set true.")

    if startup_banner:
        print_banner()

    # Set default directory
    os.chdir(sys.path[0])

    # Select IPC / Serial interface depending on local_testing boolean
    if local_testing:
        if dd_socket:
            nh_socket = 5000
        else:
            nh_socket = 5001

        try:
            os.system("clear")
            print("TFC-NaCl %s || Tx.py\n\n" % str_version)
            phase("Waiting for socket from NH.py...", 35)
            ipc_nh = multiprocessing.connection.Client(("localhost",
                                                        nh_socket))
            print("Connection established.\n")
            time.sleep(0.5)
            os.system("clear")

        except KeyboardInterrupt:
            graceful_exit()

    else:

        try:
            serial_nh = search_serial_interfaces()
            port_nh = serial.Serial(serial_nh, baud_rate, timeout=0.1)
            transmit("TFC|N|%s|I|" % int_version)  # NH interface config

        except SerialException:
            graceful_exit("Error: Serial interface to NH was not found.")

    # Create directories
    ensure_dir("keys/")
    ensure_dir("groups/")
    ensure_dir("logs/")
    ensure_dir("files/")
    ensure_dir("keys_to_contact/")

    # Add new keyfiles
    add_keyfiles()

    # Set default values
    group = ''
    paste = False

    # Initialize tab-complete
    readline.set_completer(tab_complete)
    readline.parse_and_bind("tab: complete")

    # Contact specific log setting dictionary
    for acco in get_list_of_accounts():
        if txm_side_logging:
            acco_store_l[acco] = True
        else:
            acco_store_l[acco] = False

    # If local key does not exist, ask user to generate it.
    if not os.path.isfile("keys/tx.local.e"):
        os.system("clear")
        print("TFC-NaCl %s || Tx.py\n\n" % str_version)
        new_local_key(bootstrap=True)

    # If no contacts are available, ask user to add one.
    if not get_keyfile_list():
        add_first_contact()

    # Select contact
    recipient_acco, recipient_nick = select_contact(print_contact_list())

    os.system("clear")

    if trickle_connection:
        msg_queue = multiprocessing.Queue()
        file_queue = multiprocessing.Queue()
        pc_queue = multiprocessing.Queue()
        ip = multiprocessing.Process(target=input_process,
                                     args=(sys.stdin.fileno(), ''))
        sp = multiprocessing.Process(target=sender_process)

        ip.start()
        sp.start()

        try:
            while True:
                if not pc_queue.empty():
                    command = pc_queue.get()
                    if command == "exit":
                        ip.terminate()
                        sp.terminate()
                        graceful_exit()
                time.sleep(0.001)

        except KeyboardInterrupt:
            ip.terminate()
            sp.terminate()
            graceful_exit()
    else:
        try:
            main_loop()
        except KeyboardInterrupt:
            graceful_exit()
