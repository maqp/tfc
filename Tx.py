#!/usr/bin/env python
# -*- coding: utf-8 -*-

# TFC 0.16.10 || Tx.py

"""
Copyright (C) 2013-2016  Markus Ottela

This file is part of TFC.

TFC is free software: you can redistribute it and/or modify it under the terms
of the GNU General Public License as published by the Free Software Foundation,
either version 3 of the License, or (at your option) any later version.

TFC is distributed in the hope that it will be useful, but WITHOUT ANY
WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with
TFC. If not, see <http://www.gnu.org/licenses/>.
"""

import argparse
import base64
import binascii
import curses
import datetime
import fcntl
import getpass
import inspect
import itertools
import multiprocessing.connection
import multiprocessing
import os.path
import os
import random
import re
import serial
import socket
import struct
import subprocess
import sys
import termios
import textwrap
import threading
import time
import tkFileDialog
import Tkinter
import _tkinter
import zlib

import string as string_c
from _curses import error as curses_error
from serial.serialutil import SerialException

try:
    import RPi.GPIO as GPIO
except ImportError:
    GPIO = None
    import paramiko
    import Crypto.Cipher.AES
    orig_new = Crypto.Cipher.AES.new

import hashlib
import nacl.secret
import nacl.encoding
import nacl.exceptions
import nacl.public
import nacl.utils

from passlib.hash import pbkdf2_sha256
from passlib.utils import ab64_decode
import simplesha3

str_version = "0.16.10"
int_version = 1610


###############################################################################
#                                CONFIGURATION                                #
###############################################################################

# User interface
l_ts = "%Y-%m-%d %H:%M:%S"  # Timestamp format of logged messages

clear_input_screen = False  # True clears screen after each message / command

nh_bypass_messages = True   # False removes interrupting NH bypass messages

confirm_sent_files = True   # False sends files without asking for confirmation

disable_gui_dialog = False  # True replaces Tkinter dialogs with CLI prompts


# Security
double_space_exits = False  # True exits with doubles space, else clears screen


# Trickle connection
trickle_connection = False  # True enables trickle connection to hide metadata

trickle_stat_delay = 2.0    # Static delay between trickle packets (def 2.0)

trickle_rand_delay = 2.0    # Max random delay for timing obfuscation (def 2.0)


# Packet delays
long_packet_rand_d = False  # True adds spam guard evading delay

max_val_for_rand_d = 10.0   # Spam guard evasion max delay (def 10.0)


# Message logging
txm_side_m_logging = False  # Default TxM-side logging setting for new contacts

log_noise_messages = False  # True enables TxM-side noise packet logging


# Database padding
m_members_in_group = 20     # Max number of groups (Rx.py must have same value)

m_number_of_groups = 20     # Max members in group (Rx.py must have same value)

m_number_of_accnts = 20     # Max number of accounts (Rx.py must have same val)


# Local testing
local_testing_mode = False  # True enables testing of TFC on a single computer

data_diode_sockets = False  # True changes socket for data diode simulator


# Serial port
serial_usb_adapter = True   # False searches for integrated serial interface

serial_iface_speed = 19200  # The speed of serial interface in bauds per sec

e_correction_ratio = 5      # N/o byte errors serial datagrams can recover from


# HWRNG native sampling
broadcom_gpio_port = 4      # Broadcom layout GPIO pin number for HWRNG


# HWRNG management
ssh_hwrng_sampling = False  # True asks to load entropy from RPi HWRNG over SSH

hwrng_host = "192.168.1.2"  # IP-address of RPi the HWRNG is connected to

hwrng_user = "pi"           # User account for Raspberry Pi (default: pi)


###############################################################################
#                               ERROR CLASSES                                 #
###############################################################################

class CriticalError(Exception):
    """A variety of errors during which Tx.py should gracefully exit."""

    def __init__(self, error_message):
        graceful_exit("Critical error in function '%s()':\n%s"
                      % (inspect.stack()[1][3], error_message))


class FunctionParameterTypeError(Exception):
    """Gracefully exit if function is called with invalid parameter types."""

    def __init__(self, f_name, parameter_index, wrong_type, expected_type):
        graceful_exit(
            "Error: %s parameter of function '%s()':\nGot %s instead of %s."
            % (parameter_index, f_name, wrong_type, expected_type))


class FunctionReturn(Exception):
    """Print return message and return to exception handler function."""

    def __init__(self, return_msg, output=True):

        self.message = return_msg

        if output:
            print("\n%s\n" % self.message)

        if clear_input_screen:
            time.sleep(1.5)


###############################################################################
#                                CRYPTOGRAPHY                                 #
###############################################################################

def sha3_256(message):
    """
    Generate SHA3-256 digest from message.

    :param message: Input to hash function
    :return:        Hex representation of SHA3-256 digest
    """

    input_validation((message, str))

    return binascii.hexlify(simplesha3.sha3256(message))


def pbkdf2_hmac_sha256(key, rounds=65536, salt=''):
    """
    Generate key from input by deriving it using PBKDF2 HMAC-SHA256.

     65 536 iterations for key derivation, min value for password derivation
          1 iteration for hash ratchet that enables per-packet forward secrecy

    Salt is used when mixing in other entropy sources, but not
    as part of hash ratchet, as it would have to be pre-shared.

    :param key:    Input (key/password)
    :param rounds: PBKDF2 iteration count
    :param salt:   Additional entropy
    :return:       Key after derivation
    """

    input_validation((key, str), (rounds, int), (salt, str))

    assert rounds > 0

    f_output = pbkdf2_sha256.encrypt(key, rounds=rounds, salt=salt)

    # Separate hash from output
    sep_hash = f_output.split('$')[4]
    hash_hex = binascii.hexlify(ab64_decode(sep_hash))

    assert len(hash_hex) == 64
    assert set(hash_hex.lower()).issubset("0123456789abcdef")

    return hash_hex


def encrypt_and_sign(plaintext, account='', key='', pad=True, encode=True):
    """
    Encrypt and sign plaintext using PyNaCl library's XSalsa20-Poly1305.

    256-bit XSalsa20 cipher and Poly1305 MAC are designed by Daniel Bernstein.
    The XSalsa20 is a stream cipher based on add-rotate-XOR (ARX). It is used
    with a /dev/urandom spawned, 192-bit nonce (length specified in libsodium).

    :param plaintext: Plaintext to encrypt
    :param account:   The contact's account name (e.g. alice@jabber.org)
    :param key:       When specified, used as encryption key
    :param pad:       When False, skips padding of pt before encryption
    :param encode:    When False, does not encode nonce, ciphertext and tag
    :return:          (Base64 encoded) nonce, ciphertext and tag
    """

    input_validation((plaintext, str), (account, str), (key, str), (pad, bool))

    if account:
        key_hex = c_dictionary[account]["key"]

        # Hash ratchet
        c_dictionary[account]["key"] = pbkdf2_hmac_sha256(key_hex, rounds=1)
        c_dictionary[account]["harac"] += 1
        run_as_thread(contact_db, c_dictionary)

    else:
        key_hex = key

    if pad:
        plaintext = padding(plaintext)

    s_box = nacl.secret.SecretBox(binascii.unhexlify(key_hex))
    nonce = nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE)
    cttag = s_box.encrypt(plaintext, nonce)

    if encode:
        cttag = b64e(cttag)

    return cttag


def padding(string, len_check=True):
    """
    Pad input to always match the packet max size (255 bytes).

    Maximum input size for sent packets is 254 bytes: This ensures no dummy
    blocks are appended to sent plaintexts. Byte used in padding is determined
    by how much padding is needed.

    :param string:    String to be padded
    :param len_check: When False, disables length checks (used in data storage)
    :return:          Padded string
    """

    input_validation((string, str), (len_check, bool))

    if len_check:
        assert len(string) <= 254

    length = 255 - (len(string) % 255)
    string += length * chr(length)

    if len_check:
        assert len(string) == 255

    return string


def rm_padding(string):
    """
    Remove padding from plaintext.

    The length of padding is determined by the ord-value
    of last character that is always a padding character.

    :param string: String from which padding is removed
    :return:       String without padding
    """

    input_validation((string, str))

    return string[:-ord(string[-1:])]


def encrypt_data(f_name, data, key='', salt=''):
    """
    Store encrypted data into file.

    Data is encrypted and signed using XSalsa20-Poly1305 and key before
    storing. If encryption key was derived from password, prepend salt to ct.

    :param f_name: Name (and path) of file to store data in
    :param data:   Plaintext data
    :param key:    Data encryption key
    :param salt:   Data encryption salt (if key was derived from password)
    :return:       None
    """

    input_validation((f_name, str), (data, str), (key, str), (salt, str))

    ensure_dir("%s%s/" % ('/' if f_name.startswith('/') else '',
                          '/'.join(f_name.split('/')[:-1])))

    key = key if key else master_key

    ct_tag = encrypt_and_sign(data, key=key, pad=False)
    ct_tag = salt + ct_tag if salt else ct_tag

    open(f_name, "w+").write(ct_tag)


def decrypt_data(nonce_ct_tag, key=''):
    """
    Authenticate and decrypt signed XSalsa20-Poly1305 ciphertext.

    :param nonce_ct_tag: Base64 encoded nonce, ciphertext and tag
    :param key:          When not specified, uses master key for decryption
    :return:             Plaintext data if MAC is OK (else, gracefully exit)
    """

    input_validation((nonce_ct_tag, str), (key, str))

    key = key if key else master_key

    try:
        secretbox = nacl.secret.SecretBox(binascii.unhexlify(key))
        plaintext = secretbox.decrypt(base64.b64decode(nonce_ct_tag))
    except nacl.exceptions.CryptoError:
        raise CriticalError("Ciphertext MAC fail.")
    except TypeError:
        raise CriticalError("Ciphertext decoding failed.")

    return plaintext


###############################################################################
#                                KEY GENERATION                               #
###############################################################################

def native_sampler(purpose, ent_size):
    """
    Sample ent_size bits from GPIO HWRNG when running natively on Raspberry Pi.

    This function loads entropy from free hardware design HWRNG connected to
    GPIO port (no. 4 in Broadcom layout by default) of Raspberry Pi. The
    function first runs a warm up sequence that collects 3000 samples (1500
    ones, 1500 zeros) before proceeding to actual collection. This is to
    allocate time for HWRNG signal to stabilize in cases where HWRNG is turned
    on after sampling has started.

    Actual sampling is done using slow, 10Hz rate. Sampling performs real-time
    Von Neumann whitening on samples. This ensures correct number of bits is
    always collected, and that simple bias is removed from start.

    While Von Neumann whitening algorithm can't eliminate issues in randomness,
    it can turn truly random, biased source into truly random unbiased one. Bad
    spots in signal (such as stream of zeros if the HWRNG is turned off) are
    ignored as they provide no rising or falling edges sampled by VN algorithm.

    :param purpose:  Purpose of entropy
    :param ent_size: Size of entropy to sample
    :return:         ent_size bits of entropy
    """

    input_validation((purpose, str), (ent_size, int))

    assert ent_size in [256, 512, 768]

    GPIO.setmode(GPIO.BCM)
    GPIO.setup(broadcom_gpio_port, GPIO.IN, pull_up_down=GPIO.PUD_DOWN)

    phase("Initializing sampling...")
    init0 = 0
    init1 = 0
    while init0 < 1500 or init1 < 1500:
        time.sleep(0.001)
        if GPIO.input(broadcom_gpio_port) == 1:
            init1 += 1
        else:
            init0 += 1
    print("Done.\n")

    vnd = ''
    bad = ''  # Discarded bits
    white_space = (27 - len(purpose)) * ' '
    while len(vnd) != ent_size:

        first_bit = GPIO.input(broadcom_gpio_port)
        time.sleep(sample_delay)

        second_bit = GPIO.input(broadcom_gpio_port)
        time.sleep(sample_delay)

        if first_bit == second_bit:
            bad += str(first_bit)
        else:
            vnd += str(first_bit)

        print("%sLoading entropy for %s from HWRNG...%s%s/%s bits"
              % (cu, purpose, white_space, len(vnd), ent_size))

    GPIO.cleanup()

    assert len(vnd) == ent_size

    # Convert bit string to bytes
    ent = ''.join(chr(int(vnd[i:i + 8], 2)) for i in xrange(0, len(vnd), 8))
    ent = binascii.hexlify(ent)

    return split_string(ent, 64)


def fixed_aes_new(key, *lst):
    """
    Fix unnecessary IV of Paramiko's AES counter mode that already uses nonce.

    :param key: AES key
    :param lst: List of parameters
    :return:    New function
    """

    if Crypto.Cipher.AES.MODE_CTR == lst[0]:
        lst = list(lst)
        lst[1] = ''

    return orig_new(key, *lst)


def ssh_pwd(incorrect_pwd=False):
    """
    Load/store SSH password.

    Decrypt SSH password from SSH login file with master key if file exists.
    If file doesn't exist, ask for password and encrypt it to the file using
    the master key.

    Passwords are padded to next 255 bytes prior to encryption to hide the
    length of the password, the XSalsa20 stream cipher would otherwise reveal.

    :param incorrect_pwd: When True, asks new password that overwrites the old
    :return:              None
    """

    input_validation((incorrect_pwd, bool))

    if incorrect_pwd:
        print("\nError: Incorrect password.\n")

    # Generate new password
    if not os.path.isfile(ssh_l_file) or incorrect_pwd:
        ssh_pass = new_password("RPi SSH")
        padded_p = padding(ssh_pass, len_check=False)
        run_as_thread(encrypt_data, ssh_l_file, padded_p)
        return ssh_pwd()

    # Load existing password
    if os.path.isfile(ssh_l_file):
        return rm_padding(decrypt_data(open(ssh_l_file).readline()))


def sampling_over_ssh(purpose, ent_size):
    """
    Load ent_size bits of entropy over SSH by running hwrng.py on Raspbian.

    :param purpose:  Purpose of entropy
    :param ent_size: Size of entropy to sample
    :return:         ent_size bits of entropy
    """

    input_validation((purpose, str), (ent_size, int))

    assert ent_size in [256, 512, 768]

    iv_fix_enabled = False
    hwrng_pass = ssh_pwd()

    while True:
        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            paramiko.util.log_to_file("/dev/null")

            ssh.connect(hostname=hwrng_host,
                        username=hwrng_user,
                        password=hwrng_pass)

        except socket.error:
            raise CriticalError("Socket Error. Check RPi IP.")

        except paramiko.ssh_exception.AuthenticationException:
            ssh.close()
            hwrng_pass = ssh_pwd(incorrect_pwd=True)
            continue

        except paramiko.ssh_exception.SSHException:
            raise CriticalError("SSHException. Check RPi is reachable.")

        except ValueError:  # Fix IV issue in Paramiko's AES-CTR mode
            if iv_fix_enabled:
                raise CriticalError("Paramiko IV fix failed.")
            ssh.close()
            Crypto.Cipher.AES.new = fixed_aes_new
            iv_fix_enabled = True
            continue

        ssh_stdin, ssh_stdout, _ = ssh.exec_command("./hwrng.py %s" % ent_size)
        ssh_stdin.flush()
        break

    print('')
    ent = ''
    w_s = ' ' * (19 - len(purpose))
    ctr = 0
    for char in iter(lambda: ssh_stdout.read(1), ''):
        if char == 'N':
            ctr += 1
            print("%sLoading entropy for %s from HWRNG via SSH...%s%s/%s bits"
                  % (cu, purpose, w_s, ctr, ent_size))

        elif char in "0123456789abcdef":
            ent += char
        elif char == 'L':
            raise CriticalError("hwrng.py: Invalid entropy length.")
        elif char == 'S':
            raise CriticalError("hwrng.py: Invalid n/o sample parameter.")

    if not ent:
        raise CriticalError("No entropy. Check ~/hwrng.py exists on RPi.")

    assert len(ent) == ent_size / 4

    return split_string(ent, 64)


def csprng_sampler(purpose, ent_size):
    """
    Generate ent_size bits of entropy with Kernel CSPRNG (/dev/urandom).

    :param purpose:  Purpose of entropy
    :param ent_size: Size of entropy to sample
    :return:         ent_size bits of entropy
    """

    input_validation((purpose, str), (ent_size, int))

    assert ent_size in [256, 512, 768]

    phase("Loading entropy for %s from /dev/urandom..." % purpose)
    ent = binascii.hexlify(os.urandom(ent_size / 8))
    print("Done.")

    return split_string(ent, 64)


def generate_key(kp):
    """
    Generate key, header key and optionally key encryption key.

    Generate each key by using PBKDF2-HMAC-SHA256 to compress together
    256 bits of entropy from /dev/urandom (kernel CSPRNG) and SHA3-256
    compressed entropy returned by a sampler.

    The available samplers are
        1. Kernel CSPRNG (/dev/urandom)
        2. Native sampling of HWRNG (when Tx.py is run on Raspberry Pi)
        3. Remote sampling of HWRNG over SSH to Raspberry Pi

    :param kp: Purpose of generated key
    :return:   List of 256-bit symmetric keys
    """

    input_validation((kp, str))

    sampler = csprng_sampler

    question = "Load entropy for %s from HWRNG?" % kp

    if rpi_os and GPIO and yes(question):
        sampler = native_sampler

    if not rpi_os and ssh_hwrng_sampling and yes(question):
        sampler = sampling_over_ssh

    no_bits = {"local key": 768, "PSK": 512, "private key": 256}[kp]
    ent_list = sampler(kp, no_bits)

    assert len(ent_list) == no_bits / 256
    for e in ent_list:
        validate_key(e, "%s entropy from sampler" % kp)

    phase("Deriving keys...")
    keys = []
    for e in ent_list:
        keys.append(pbkdf2_hmac_sha256(os.urandom(32), salt=sha3_256(e)))
    print("Done.")

    assert len(keys) == no_bits / 256
    return keys


###############################################################################
#                               PASSWORD LOGIN                                #
###############################################################################

def login_screen():
    """
    Show login screen, ask for password.

    :return: Master decryption key
    """

    string = "Tinfoil Chat %s" % str_version
    pwdstr = "Enter password"

    def rand():
        """Generate random numbers with fast and insecure RNG."""

        a = random.randrange(1, 10000000000)

        while True:
            a ^= (a << 21) & 0xffffffffffffffff
            a ^= (a >> 35)
            a ^= (a << 4) & 0xffffffffffffffff
            yield a

    def randint(_min, _max):
        """Generate random int."""

        n = r.next()
        try:
            random_value = (n % (_max - _min)) + _min
        except ZeroDivisionError:
            random_value = random.randint(_min, _max)
        return random_value

    class FallingChar(object):
        """Class for each falling vertical string."""

        def __init__(self, scr, tear=False):

            height, width = scr.getmaxyx()

            self.x = 0
            self.y = 0
            self.clear_y = 0
            self.tear = tear
            self.speed = 1
            self.length = 1
            self.char = ' '
            self.reset(width, height)
            self.offset = randint(0, self.speed)
            self.logo_tuples = []

        def reset(self, width, height):
            """Move object to random position at the top."""

            if self.tear:
                self.char = ' '
            else:
                self.char = chr(randint(32, 126))

            self.x = randint(1, width - 1)
            try:
                min_len = 4
                max_len = height // 2
            except ZeroDivisionError:
                min_len = 1
                max_len = 3
            self.length = randint(min_len, max_len)

            self.y = 0
            self.clear_y = 0 - self.length
            self.speed = randint(4, 7)
            self.offset = randint(0, self.speed)

        def tick(self, scr, steps):
            """Evaluate falling char activity for next frame."""

            if self.advances(steps):

                height, width = scr.getmaxyx()

                self.out_of_bounds_reset(width, height)

                self.y += 1
                self.clear_y += 1

                if not self.tear:
                    if self.clear_y >= 1:
                        if (self.clear_y, self.x) not in self.logo_tuples:
                            scr.addstr(self.clear_y, self.x, ' ')

                if not self.out_of_bounds_reset(width, height):
                    if self.y < height:

                        # Draw next char
                        if self.tear:
                            scr.addstr(self.y, self.x, ' ')
                            return None

                        self.char = chr(randint(32, 126))
                        scr.addstr(self.y, self.x, self.char)

                        if not rpi_os:
                            # Each previous char has 5% chance of changing
                            for y in xrange(1, self.length):
                                if (randint(1, 20) == 1) and self.y - y > 0:
                                    self.char = chr(randint(32, 126))
                                    scr.addstr(self.y - y, self.x, self.char)

        def out_of_bounds_reset(self, width, height):
            """Check that falling char is within bounds."""

            if (self.x > width - 2) or (self.clear_y > height - 2):
                if rpi_os:
                    self.tear = True
                self.reset(width, height)
                return True
            return False

        def advances(self, steps):
            """Check if it's time for falling char to move."""

            if self.tear and rpi_os:
                return False

            return steps % (self.speed + self.offset) == 0

    def get_logo_tuples(height, width):
        """Get coordinate-tuples for placed logo."""

        logo = ["        O                 O        ",
                "       OOO               OOO       ",
                "     OOOOOO             OOOOOO     ",
                "   OOOOOOOOO           OOOOOOOOO   ",
                "  OOOOOOOOOOO         OOOOOOOOOOO  ",
                " OOOOOOOOOOOOO       OOOOOOOOOOOOO ",
                " OOOOOOOOOOOOOO     OOOOOOOOOOOOOO ",
                "OOOOOOOOOOOOOOOO   OOOOOOOOOOOOOOOO",
                "OOOOOO                       OOOOOO",
                "OOOOOO                       OOOOOO",
                "OOOOOOOOOOOOOOOO   OOOOOOOOOOOOOOOO",
                "OOOOOOOOOOOOOOOO   OOOOOOOOOOOOOOOO",
                " OOOOOOOOOOOOOOO   OOOOOOOOOOOOOOO ",
                " OOOOOOOOOOOOOOO   OOOOOOOOOOOOOOO ",
                "  OOOOOOOOOOOOOO   OOOOOOOOOOOOOO  ",
                "   OOOOOOOOOOOOO   OOOOOOOOOOOOO   ",
                "    OOOOOOOOOOOO   OOOOOOOOOOOO    ",
                "      OOOOOOOOOO   OOOOOOOOOO      ",
                "        OOOOOOOO   OOOOOOOO        ",
                "           OOOOO   OOOOO           "]

        hs = (height - len(logo)) / 4

        if height < (7 + len(logo)) or width < (1 + len(logo[0])):
            return []

        for _ in xrange(hs):
            logo.insert(0, (len(logo[0]) * ' '))
        indent = (width - len(logo[0])) / 2
        pos_logo = []
        for line in logo:
            pos_logo.append((indent * ' ' + line))

        logo_c = []
        for y in xrange(len(pos_logo)):
            for x in xrange(len(pos_logo[y])):
                if pos_logo[y][x] != ' ':
                    logo_c.append((y, x))
        return logo_c

    def get_string_coordinates(height, width, logo_c):
        """Get coordinate-tuples for strings printed on screen."""

        if height > 26 and logo_c:
            string_y = ((height - 20) / 2) + 20
        else:
            string_y = height / 2

        string_x = (width - len(string)) / 2

        pwdstr_y = string_y + 3
        pwdstr_x = (width - len(pwdstr)) / 2

        return string_y, string_x, pwdstr_y, pwdstr_x

    def reset(scr, teardown=False):
        """Redraw screen."""

        if not teardown:
            scr.clear()

        height, width = scr.getmaxyx()
        logo_c = get_logo_tuples(height, width)

        # Load x-coordinates of logo
        logo_x = []
        for (y, x) in logo_c:
            logo_x.append(x)
        logo_x = list(set(logo_x))

        # Initialize falling chars that draw logo
        falling_chars = []
        try:
            if not teardown and not rpi_os:
                for _ in xrange(10):
                    random.shuffle(logo_x)
                    logo_x.pop()
            for x in logo_x:
                fc = FallingChar(scr, tear=teardown)
                fc.x = x
                falling_chars.append(fc)
        except IndexError:
            pass

        # Initialize rest of falling chars
        if not teardown and not rpi_os:
            for _ in xrange((width - len(logo_x)) / 3):
                fc = FallingChar(scr)
                fc.y = randint(0, height - 2)
                falling_chars.append(fc)

        for fc in falling_chars:
            fc.logo_tuples = logo_c

        return falling_chars, logo_c

    def main():
        """Initialize falling chars and prompt for password."""

        steps = 0
        scr = curses.initscr()
        scr.nodelay(1)
        curses.curs_set(0)
        curses.noecho()

        falling_chars, logo_c = reset(scr)

        # List keeps record of which 'reels' have found char of string
        string_printed_char_list = len(string) * ['']
        string_cleared_char_list = len(string) * ['']

        height, width = scr.getmaxyx()
        sy, sx, py, px = get_string_coordinates(height, width, logo_c)

        resize_teardown = False
        after_correct = False
        correct_pwd = False
        checking_pwd = False
        incorrect_pwd = False
        incorrect_pwd_ctr = 0
        pwd_str = ''
        key_str = ''

        scr.refresh()

        while True:
            try:
                pwd_chr = scr.getkey()
            except curses_error:
                pwd_chr = ''
            if pwd_chr == "KEY_RESIZE":
                scr.clear()
                falling_chars, logo_c = reset(scr, resize_teardown)
                height, width = scr.getmaxyx()
                sy, sx, py, px = get_string_coordinates(height, width, logo_c)
            elif pwd_chr == '\x7f':
                pwd_str = pwd_str[:-1]
            elif pwd_chr == '\n':
                if not checking_pwd and not after_correct:
                    pwd_queue.put(pwd_str)
                    checking_pwd = True
            else:
                pwd_str += pwd_chr

            if not key_queue.empty():
                key_str = key_queue.get()
                if key_str:
                    correct_pwd = True
                    checking_pwd = False
                    after_correct = True
                else:
                    incorrect_pwd = True
                    checking_pwd = False
                    pwd_str = ''

            if after_correct:
                tear_chars, logo_c = reset(scr, teardown=True)
                for fc in falling_chars:
                    fc.tear = True
                falling_chars += tear_chars
                after_correct = False

            try:
                for fc in falling_chars:
                    fc.tick(scr, steps)

                if correct_pwd and not rpi_os:
                    for _ in xrange(3):
                        x = randint(0, width)
                        y = randint(0, height)
                        scr.addstr(y, x, ' ')

                if correct_pwd:
                    st = ''
                    for c in xrange(len(string)):
                        if not string_cleared_char_list[c] == ' ':
                            string_cleared_char_list[c] = chr(randint(32, 126))
                        st += string_cleared_char_list[c]
                    scr.addstr(sy, sx, st)
                    if set(string_cleared_char_list) == {' '}:
                        return key_str
                else:
                    st = ''
                    for c in xrange(len(string)):
                        if not string_printed_char_list[c] == string[c]:
                            string_printed_char_list[c] = chr(randint(32, 126))
                        st += string_printed_char_list[c]
                    scr.addstr(sy, sx, st)

                if incorrect_pwd:
                    incorrect_pwd_ctr += 1
                    if incorrect_pwd_ctr > 100:
                        incorrect_pwd = False
                        incorrect_pwd_ctr = 0
                    scr.addstr(py, px, "Wrong password")
                elif checking_pwd:
                    scr.addstr(py, px, "Password check")
                elif correct_pwd:
                    scr.addstr(py, px, "   Login OK   ")
                else:
                    scr.addstr(py, px, "Enter password")

            except curses_error:
                pass

            scr.refresh()
            time.sleep(0.005)
            steps += 1

    try:
        pcp = multiprocessing.Process(target=check_master_pwd)
        pcp.start()

        r = rand()
        m_key = main()

        curses.endwin()
        curses.curs_set(1)
        curses.reset_shell_mode()
        curses.echo()
        pcp.terminate()

        clear_screen()
        return m_key

    except KeyboardInterrupt:
        curses.endwin()
        curses.curs_set(1)
        curses.reset_shell_mode()
        curses.echo()
        graceful_exit()


def new_master_pwd():
    """
    Create new master password.

    Minimum number of rounds is 65536. Increase based to system performance,
    but keep login time under 4 seconds unless minimum iterations demand more.

    :return: None
    """

    try:
        clear_screen()
        print("\nWelcome to TFC %s\n\n" % str_version)

        salt = sha3_256(os.urandom(32))
        m_pw = new_password("master")

        print("\nDeriving master key. This might take a while.\n")
        rounds = 65536
        while True:
            start = get_ms()
            key = pbkdf2_hmac_sha256(m_pw, rounds, salt)
            t = (get_ms() - start) / 1000.0

            if t > 2.0:
                with open(login_file, "w+") as f:
                    f.write('|'.join([str(rounds), salt, sha3_256(key)]))

                print_on_previous_line()
                print("Setting PBKDF2 iterations to %s (%ss)." % (rounds, t))
                time.sleep(2)
                clear_screen()
                return None

            else:
                print_on_previous_line()
                print("Testing: %s PBKDF2 rounds took only %ss." % (rounds, t))
                rounds *= 2

    except KeyboardInterrupt:
        graceful_exit()


def check_master_pwd():
    """
    Check hash of master password is correct.

    If password is correct, send master key to login_screen() via key_queue.

    :return: [no return value]
    """

    try:
        rounds, salt, hashed_key = open(login_file).readline().split('|')
    except IOError:
        raise CriticalError("Error: Missing login file.")

    assert rounds.isdigit()
    validate_key(salt, "login data salt")
    validate_key(hashed_key, "login data hash")

    while True:
        while pwd_queue.empty():
            time.sleep(0.1)
        password = pwd_queue.get()
        master_k = pbkdf2_hmac_sha256(password, int(rounds), salt)
        key_queue.put(master_k if hashed_key == sha3_256(master_k) else '')

        if unit_test:
            break


###############################################################################
#                                 KEY EXCHANGE                                #
###############################################################################

# Local key
def nh_bypass_msg(key):
    """
    Print messages about bypassing NH.

    :param key: Message key
    :return:    None
    """

    input_validation((key, str))

    m = {'s': "\n    Bypass NH if needed. Press"
              " <Enter> to send local key.    ",
         'f': "%sRemove bypass of NH. Press <Enter> to continue." % cu}

    if nh_bypass_messages:
        raw_input(m[key])


def print_kdk(kdk):
    """
    Print symmetric key decryption key.

    If local testing is not enabled, this function will add spacing between
    key decryption key to help user keep in track of key typing progress. The
    length of the Base58 encoded string varies between 48..50 characters, thus
    spacing is adjusted to get even length for each substring.

    :param kdk: Key decryption key
    :return:    None
    """

    input_validation((kdk, str))

    kdk = b58e(binascii.unhexlify(kdk))
    ssl = {48: 8, 49: 7, 50: 5}[len(kdk)]
    kdk = kdk if local_testing_mode else ' '.join(split_string(kdk, ssl))

    clear_screen()
    print("\nLocal key decryption key (to RxM):\n\n    %s\n" % kdk)


def ask_confirmation_code():
    """Ask user to input confirmation code."""

    return raw_input("Enter confirmation code from RxM: ")


def generate_confirmation_code():
    """Generate new confirmation code."""

    return binascii.hexlify(os.urandom(1))


def new_contact(account, user, nick, key, hek, txpk, rxpk):
    """
    Create new dictionary for contact and store it to database.

    :param account: The contact's account name (e.g. alice@jabber.org)
    :param user:    The user's account name (e.g. bob@jabber.org)
    :param nick:    Contact's nickname
    :param key:     Forward secret encryption key
    :param hek:     Non-forward secret header encryption key
    :param txpk:    User's public key / "psk" if PSK is used
    :param rxpk:    Contact's public key / "psk" if PSK is used
    :return:        None
    """

    input_validation((account, str), (user, str), (nick, str),
                     (hek, str), (txpk, str), (rxpk, str))

    logging = txm_side_m_logging
    if account in c_dictionary.keys():
        logging = c_dictionary[account]["logging"]

    c_dictionary[account] = dict(user=user, nick=nick, harac=1,
                                 key=key, hek=hek, txpk=txpk,
                                 rxpk=rxpk, logging=logging)

    # Remove one dummy account
    for k in c_dictionary.keys():
        if k.startswith("dummy_account"):
            del c_dictionary[k]
            break

    run_as_thread(contact_db, c_dictionary)

    # If key exchange is for active contact, update nick
    active_c['n'] = nick if account == active_c['a'] else active_c['n']


def new_local_key():
    """
    Send encrypted local key to RxM, display kdk and ask for confirmation code.

    :return: None
    """

    clear_screen()
    print("\nCreate local key\n----------------\n")

    key, hek, kek = generate_key("local key")

    # Encrypt and sign local key, header key and confirmation code with kek
    conf_c = generate_confirmation_code()
    ct_tag = encrypt_and_sign(key + hek + conf_c, key=kek,
                              pad=False, encode=False)

    # Send encrypted local key and confirmation code to RxM
    nh_bypass_msg('s')
    transmit('L' + ct_tag)

    # Ask for confirmation code before storing local key on TxM
    while True:
        print_kdk(kek)
        conf_c_purp = ask_confirmation_code()
        if conf_c_purp == conf_c:
            break
        elif conf_c_purp == "resend":
            transmit('L' + ct_tag)
        else:
            print("\nIncorrect confirmation code. If RxM did not receive"
                  "\nencrypted local key, resend it by typing 'resend'.")
            time.sleep(2.0)

    nh_bypass_msg('f')
    clear_screen()

    phase("Saving local key...")
    new_contact("local", "local", "local", key, hek, "psk", "psk")
    print("Done.")

    send_packet("LI", 'c')

    time.sleep(1.5)
    os.system("reset")
    import readline
    readline.clear_history()


# ECHDHE
def get_contact_public_key(mitm=False):
    """
    Prompt user to enter ECDHE public key, verify checksum.

    :param mitm: When True, prompts user to enter pub key received over Signal
    :return:     Public key
    """

    input_validation((mitm, bool))

    yes_given = False

    while True:

        if mitm:
            clear_screen()
            print('')
            c_print("WARNING")
            message_printer("This might indicate a man-in-the-middle attack!")
            question = "Do you want to enter correct key manually?"
            centered = question.center(get_tty_w())
            indent = centered.index('D') - 5

            if yes_given or yes("%s%s" % ((indent * ' '), question), 1):
                yes_given = True
                message_printer("Ask contact to read their hexadecimal "
                                "public key over Signal:", spacing=True)
            else:
                message_printer("Key exchange aborted.", spacing=True)
                raise KeyboardInterrupt

        else:
            clear_screen()
            c_print("WARNING")
            message_printer("Key exchange will break the HW separation. "
                            "Outside specific requests TxM (this computer) "
                            "makes, you should never copy any data from "
                            "NH/RxM to TxM. Doing so could infect TxM, that "
                            "could then later covertly exfiltrate private "
                            "keys/messages to adversary on NH.")

            message_printer("Enter contact's public key from RxM:",
                            spacing=True)
        try:
            if mitm:
                indent = (get_tty_w() - 80) / 2
                pub_k = raw_input(indent * ' ').replace(' ', '')
            else:
                avg_key_len = 49 if local_testing_mode else 56
                indent = (get_tty_w() - avg_key_len) / 2
                pub_k = raw_input(indent * ' ').replace(' ', '')

            # Test key allows dummy SSK creation when no contact exists
            if pub_k == "test":
                pub_k = "2JAT9y2EcnV6DPUGikLJYjWwk5UmUEFXRiQVmTbfSLbL4A4CMp"

            if mitm:
                if sha3_256(pub_k[:-8])[:8] == pub_k[64:]:
                    pub_k = pub_k[:-8]
                else:
                    message_printer("Public key checksum fail. Try again.")
                    time.sleep(1)
                    continue

            else:
                try:
                    pub_k = binascii.hexlify(b58d(pub_k))
                except ValueError:
                    print('')
                    message_printer("Public key checksum fail. Try again.")
                    time.sleep(1)
                    continue

            if not validate_key(pub_k, center=True):
                time.sleep(1)
                continue

            if mitm:
                print('')

            return pub_k

        except KeyboardInterrupt:
            print("Key exchange aborted.")
            raise


def verify_public_keys(pub_u, pub_c, account):
    """
    Ask users to verify hex representations of public keys.

    :param pub_u:   Public key of user
    :param pub_c:   Public key of contact
    :param account: The contact's account name (e.g. alice@jabber.org)
    :return:        pub_c from parameter or pub key from user input
    """

    input_validation((pub_u, str), (pub_c, str), (account, str))

    clear_screen()

    print('')

    def pub_k_printer(public_key):
        """Print public key in wide or narrow format."""

        print('')
        string = public_key + (sha3_256(public_key)[:8])
        split_list = split_string(string, 8)

        spacing = "  "

        if get_tty_w() < 20:
            for i in range(len(split_list)):
                c_print(split_list[i])
        elif get_tty_w() < 30:
            c_print(spacing.join(split_list[0:2]))
            c_print(spacing.join(split_list[2:4]))
            c_print(spacing.join(split_list[4:6]))
            c_print(spacing.join(split_list[6:8]))
            c_print(split_list[8])
        elif get_tty_w() < 90:
            c_print(spacing.join(split_list[0:3]))
            c_print(spacing.join(split_list[3:6]))
            c_print(spacing.join(split_list[6:9]))
        else:
            spaced = spacing.join(split_list)
            c_print(spaced)
        print('')

    message_printer("To verify the public key came from your contact, call "
                    "them using Signal by Open Whisper Systems, verify the "
                    "two-word SAS and then read and compare keys.")
    print('')
    message_printer("Your public key (you read):")
    pub_k_printer(pub_u)
    message_printer("Purported public key for %s (they read):" % account)
    pub_k_printer(pub_c)

    print("\n\n")
    question = "Is the contact's public key correct?"
    indent = question.center(get_tty_w()).index('I') - 5
    if yes((indent * ' ' + question), 1):
        print('')
        return pub_c
    else:
        return get_contact_public_key(mitm=True)


def start_key_exchange(account, user, nick):
    """
    Start Curve 25519 ECDHE key exchange with recipient. Variable naming:

        tx     = user's key                 rx  = contact's key
        sk     = private (secret) key       pk  = public key
        bin    = binary                     hex = hex encoded
        key    = message key                hek = header key
        dh_ssk = DH shared secret

    :param account: The contact's account name (e.g. alice@jabber.org)
    :param user:    The user's account name (e.g. bob@jabber.org)
    :param nick:    Contact's nickname
    :return:        None
    """

    input_validation((account, str), (user, str), (nick, str))

    try:
        external_entropy = binascii.unhexlify(generate_key("private key")[0])

        phase("Generating ECDHE key pair...")
        tx_sk_bin = nacl.public.PrivateKey.generate(ext_e=external_entropy)
        tx_pk_bin = tx_sk_bin.public_key
        tx_pk_hex = tx_pk_bin.encode(encoder=nacl.encoding.HexEncoder)
        print("Done.")

        phase("Sending public key to contact...")
        transmit('P' + tx_pk_hex + user + us + account)
        print("Done.")
        time.sleep(0.5)

        rx_pk_hex = get_contact_public_key()
        rx_pk_hex = verify_public_keys(tx_pk_hex, rx_pk_hex, account)
        rx_pk_bin = nacl.public.PublicKey(rx_pk_hex,
                                          encoder=nacl.encoding.HexEncoder)

        phase("Generating symmetric keys...")
        dh_box = nacl.public.Box(tx_sk_bin, rx_pk_bin)
        dh_ssk = dh_box.shared_key()
        tx_key = pbkdf2_hmac_sha256(dh_ssk, salt=rx_pk_hex)
        tx_hek = pbkdf2_hmac_sha256(dh_ssk, salt=rx_pk_hex[::-1])
        rx_key = pbkdf2_hmac_sha256(dh_ssk, salt=tx_pk_hex)
        rx_hek = pbkdf2_hmac_sha256(dh_ssk, salt=tx_pk_hex[::-1])
        print("Done.")

        packet = us.join(["KE", account, nick, tx_key, tx_hek, rx_key, rx_hek])
        send_packet(packet, 'c')

        phase("Creating contact...")
        new_contact(account, user, nick, tx_key, tx_hek, tx_pk_hex, rx_pk_hex)
        print("Done.")

        time.sleep(1.5)
        clear_screen()

    except KeyboardInterrupt:
        clear_screen()
        print("\nKey exchange aborted.\n")
        raise


# PSK
def new_psk(account, user, nick):
    """
    Generate new pre-shared key for manual key delivery.

    :param account: The contact's account name (e.g. alice@jabber.org)
    :param user:    The user's account name (e.g. bob@jabber.org)
    :param nick:    Nick of contact
    :return:        None
    """

    input_validation((account, str), (user, str), (nick, str))

    try:
        psk, hek = generate_key("PSK")
        salt = sha3_256(os.urandom(32))
        kek = pbkdf2_hmac_sha256(new_password("PSK"), salt=salt)

        store_d = ask_path_gui("Select removable media for %s" % nick)
        f_name = "%s/%s.psk - Give to %s" % (store_d, user, account)
        run_as_thread(encrypt_data, f_name, psk + hek, kek, salt)

        phase("\nSending PSK to RxM...")
        send_packet(us.join(["KT", account, nick, psk, hek]), 'c')
        print("Done.")

        phase("Creating contact...")
        new_contact(account, user, nick, psk, hek, "psk", "psk")
        print("Done.")

        time.sleep(1.5)
        clear_screen()

    except KeyboardInterrupt:
        clear_screen()
        print("\nPSK generation aborted.\n")
        raise


###############################################################################
#                               SECURITY RELATED                              #
###############################################################################

def pub_keys():
    """
    Display public keys for active contact if available.

    :return: None
    """

    if active_c['g']:
        raise FunctionReturn("Error: Group is selected.")

    else:
        tx_key = c_dictionary[active_c['a']]["txpk"]
        rx_key = c_dictionary[active_c['a']]["rxpk"]

        tx_key = ' '.join(split_string(tx_key, 8))
        rx_key = ' '.join(split_string(rx_key, 8))

        if tx_key == "psk" and rx_key == "psk":
            print("\nPSK in use with %s.\n" % active_c['a'])

        else:
            print("\nYour public key (you read):\n\n  %s\n" % tx_key)
            print("\nPublic key for %s (they read):\n\n  %s\n"
                  % (active_c['a'], rx_key))

    if clear_input_screen:
        raw_input(" Press <enter> to continue.")


def validate_key(key, origin='', center=False):
    """
    Check that encryption key is valid.

    :param key:    Key to validate
    :param origin: Origin of key
    :param center: Centers message when true
    :return:       True/False depending on key validation
    """

    input_validation((key, str), (origin, str), (center, bool))

    def printer(string, c):
        if c:
            c_print(string)
        else:
            print(string)

    if not set(key.lower()).issubset("0123456789abcdef"):
        if origin:
            raise CriticalError("Illegal character in %s." % origin)
        printer(" Error: Illegal character in key.", center)
        return False

    if len(key) != 64:
        if origin:
            raise CriticalError("Illegal key length in %s." % origin)
        printer(" Error: Illegal key length.", center)
        return False

    return True


def input_validation(*param_tuples):
    """
    Validate function input parameters with tuples.

    :param param_tuples: Parameter tuples to check
    :return:             None
    """

    if not isinstance(param_tuples, tuple):
        raise FunctionParameterTypeError("input_validation", "First",
                                         type(param_tuples), tuple)

    for t in list(param_tuples):
        if not isinstance(t[0], t[1]):
            f_name = inspect.stack()[1][3]

            nth = {1: "First", 2: "Second",  3: "Third", 4: "Fourth",
                   5: "Fifth", 6: "Sixth", 7: "Seventh", 8: "Eight",
                   9: "Ninth", 10: "Tenth"}

            n = list(param_tuples).index(t) + 1

            raise FunctionParameterTypeError(f_name, nth[n], type(t[0]), t[1])


def graceful_exit(message=''):
    """
    Display a message and exit Tx.py.

    :param: message: Message to print
    :return:         None
    """

    input_validation((message, str))

    clear_screen()
    if message:
        print("\n%s" % message)
    print("\nExiting TFC.\n")
    exit()


def write_log_entry(account, msg):
    """
    Encrypt packet sent to contact with master key and add it to common logfile
    together with name of recipient account/group and a timestamp. This allows
    reconstruction of conversation while protecting the metadata about held
    conversations other log file formats would reveal. If log_noise_messages is
    enabled, every noise packet IM client outputs to contact is also logged:
    this provides additional protection to metadata about quantity of
    communication, should end point be physically compromised.

    TxM only logs sent messages. This is not useful for recalling conversations
    but serves an important role in audit of RxM-side logs, where malware could
    have substituted content.

    To protect possibly sensitive files that must not be logged, only
    placeholder data is logged about them. This helps hiding the amount of
    communication comparison with log file size and output packet count would
    otherwise reveal.

    :param account: The contact's account name (e.g. alice@jabber.org)
    :param msg:     Message to store in log file
    :return:        None
    """

    input_validation((account, str), (msg, str))

    ts = datetime.datetime.now().strftime(l_ts)
    pt = ''.join([(padding(i)) for i in [account, ts, msg]])
    ct = encrypt_and_sign(pt, key=master_key, pad=False)

    open(txlog_file, "a+").write("%s\n" % ct)


def access_history(export=False):
    """
    Decrypt and display/export log of sent messages on TxM/RxM.

    :param export: When True, exports log file in plaintext format
    :return:       None
    """

    input_validation((export, bool))

    recipient = active_c['a'] if active_c['a'] else active_c['g']

    if export:
        print('')
        if not yes("Export log files in plaintext format?"):
            raise FunctionReturn("Export aborted by user.")

    send_packet(us.join(["LF", recipient, ['d', 'e'][export]]), 'c')

    if not os.path.isfile(txlog_file):
        raise FunctionReturn("Error: Could not find '%s'." % txlog_file)

    phase("Reading logfile...")
    log_data = open(txlog_file).read().splitlines()
    print("Done.")

    if len(log_data) == 0:
        raise FunctionReturn("No messages in logfile.")

    phase("Decrypting logfile...")
    log_data = [decrypt_data(l) for l in log_data]
    print("Done.")

    phase("Assembling logfile...")
    messages = []
    m_buffer = ''

    ttyw = 79 if export else get_tty_w()
    hc = ttyw * '-' + '\n' if export else "\033[1m"
    tc = '\n' + ttyw * '-' if export else "\033[0m"
    for entry in log_data:
        purp_recip, ts, msg = [rm_padding(i) for i in split_string(entry, 255)]

        if msg[:2] == "ap":
            if recipient != purp_recip:
                continue

            header = "%s%s%s" % (hc, ts, tc)
            messages.append("%s\n%s\n\n"
                            % (header, textwrap.fill(msg[3:], ttyw)))
            m_buffer = ''

        elif msg[:2] == "ag":
            _, group, message = msg.split(us)
            if recipient != group:
                continue

            header = "%s%s (copy to %s)%s" % (hc, ts, purp_recip, tc)
            messages.append("%s\n%s\n\n"
                            % (header, textwrap.fill(message, ttyw)))
            m_buffer = ''

        elif msg[0] in ['b', 'c']:
            m_buffer += msg[1:]

        elif msg[0] == 'd':
            m_buffer += msg[1:]
            msg_key = m_buffer[-64:]
            payload = m_buffer[:-64]
            message = decrypt_data(payload, msg_key)
            message = zlib.decompress(message)
            m_buffer = ''

            if message[0] == 'p':
                header = "%s%s%s" % (hc, ts, tc)
                messages.append("%s\n%s\n\n"
                                % (header, textwrap.fill(message[2:], ttyw)))

            elif message[0] == 'g':
                _, group, message = message.split(us)
                if recipient != group:
                    continue
                header = "%s%s (copy to %s)%s" % (hc, ts, purp_recip, tc)
                messages.append("%s\n%s\n\n"
                                % (header, textwrap.fill(message, ttyw)))
    print("Done.")

    if not messages:
        raise FunctionReturn("No messages for %s." % recipient)

    messages.insert(0, "\nLogfile of sent messages to %s:\n" % recipient)

    if export:
        f_name = "TxM - Plaintext log (%s)" % recipient
        open(f_name, "w+").write('\n'.join(messages))
        print("\nLog of sent messages to %s exported into file '%s'.\n"
              % (recipient, f_name))
    else:
        clear_screen()
        for m in messages:
            print m


###############################################################################
#                             CONTACT MANAGEMENT                              #
###############################################################################

def select_key_exchange():
    """
    Ask user to select key exchange method for new contact.

    :return: Selected key exchange
    """

    while True:

        s = "Choose key exchange method (E)CDHE, (P)SK: %s" % (18 * ' ')
        answer = raw_input(s)

        print_on_previous_line()

        if answer.lower() in "ecdhe":
            print("%sECDHE" % s)
            key_exchange = "ecdhe"

        elif answer.lower() in "psk":
            print("%sPSK" % s)
            key_exchange = "psk"

        else:
            continue

        return key_exchange


def add_new_contact(parameters=''):
    """
    Add new contact and interactively ask parameters not passed to function.

    :param parameters: Command entered by user
    :return:           None
    """

    input_validation((parameters, str))

    if len(get_list_of("accounts")) >= m_number_of_accnts:
        raise FunctionReturn("Error: TFC settings only allow %s contacts."
                             % m_number_of_accnts)

    try:
        clear_screen()
        print("Add new contact\n---------------\n")

        acco = ''
        user = ''
        nick = ''
        keyx = ''

        # Get account from parameters / user input
        acco_given = True
        try:
            acco = parameters.split()[1]
            if not validate_account(acco):
                acco_given = False
        except IndexError:
            acco_given = False

        if acco_given:
            print("Contact account:%s%s" % ((45 * ' '), acco))
        else:
            while True:
                acco = raw_input("Contact account:%s" % (45 * ' '))
                acco = acco.strip()
                if validate_account(acco, 3):
                    break

        # Get user account from parameters / user input
        user_given = True
        try:
            user = parameters.split()[2]
            if not validate_account(user):
                user_given = False
        except IndexError:
                user_given = False

        if user_given:
            print("Your account:%s%s" % ((48 * ' '), user))
        else:
            while True:
                user = raw_input("Your account:%s" % (48 * ' '))
                if validate_account(user, 3):
                    break

        # Get nick from parameters / user input
        nick_given = True
        try:
            nick = parameters.split()[3]
            if not validate_nick(nick):
                nick_given = False
        except IndexError:
            nick_given = False

        if nick_given:
            print("Contact nickname:%s%s" % ((44 * ' '), nick))
        else:
            if acco in get_list_of("accounts"):
                nick = c_dictionary[acco]["nick"]
            else:
                nick = get_nick_input(acco)

        # Get key exchange from parameters / user input
        keyx_given = True
        try:
            keyx = parameters.split()[4]
            if keyx.lower() not in ['e', 'p', "ecdhe", "psk"]:
                keyx_given = False
        except IndexError:
            keyx_given = False

        if not keyx_given:
            keyx = select_key_exchange()

        if keyx.lower() in "ecdhe":
            if keyx_given:
                print("Key exchange method:%sECDHE" % (41 * ' '))

            start_key_exchange(acco, user, nick)

        elif keyx.lower() in "psk":
            if keyx_given:
                print("Key exchange method:%sPSK" % (41 * ' '))

            new_psk(acco, user, nick)

    except KeyboardInterrupt:
        raise FunctionReturn("Contact creation aborted by user.")


def rm_contact(parameters):
    """
    Remove account and keyfile from TxM.

    :param parameters: Contact's account to be separated
    :return:           None
    """

    input_validation((parameters, str))

    try:
        account = parameters.split()[1]
    except IndexError:
        raise FunctionReturn("Error: No account specified.")

    if not validate_account(account):
        raise FunctionReturn("Invalid account", output=False)

    if not yes("\nRemove %s completely?" % account):
        raise FunctionReturn("Removal of contact aborted.")

    send_packet(us.join(["CR", account]), 'c')

    if account in get_list_of("accounts"):
        del c_dictionary[account]
        run_as_thread(contact_db, c_dictionary)
        print("\nRemoved %s from contacts.\n" % account)
    else:
        print("\nTxM has no %s to remove.\n" % account)

    was_in_group = False
    for g in get_list_of("groups"):
        if account in get_list_of("members", g):
            g_dictionary[g]["members"].remove(account)
            was_in_group = True
    if was_in_group:
        run_as_thread(group_db, g_dictionary)
        print("Removed %s from group(s)." % account)


def get_nick_input(account):
    """
    Ask user to input nickname for account.

    :param account: Account to parse nick from
    :return:        Nick input by user
    """

    input_validation((account, str))
    d_nick = account.split('@')[0]
    d_nick = d_nick.capitalize()

    while True:
        ind = (40 - len(d_nick.decode("utf-8"))) * ' '
        nickname = raw_input("Contact nickname [%s]: %s" % (d_nick, ind))

        if nickname == '':
            nickname = d_nick

        nickname = nickname.strip()

        if not validate_nick(nickname, 3):
            continue

        print_on_previous_line()
        print("Contact nickname [%s]: %s%s" % (d_nick, ind, nickname))
        return nickname


def validate_account(account, retlines=2, print_m=True):
    """
    Validate account name.

    :param account:  Account to validate
    :param retlines: Number of lines to go up after error message
    :param print_m:  When False, does not print message.
    :return:         True if account is valid, else False
    """

    input_validation((account, str), (retlines, int), (print_m, bool))

    error_msg = ''

    if len(account) > 254:
        error_msg = "Account must be shorter than 255 chars"

    if not re.match("(^.[^/:,]*@.[^/:,]*\.[^/:,]*.$)", account):
        error_msg = "Invalid account"

    if not all(c in string_c.printable for c in account):
        error_msg = "Account must be printable."

    if error_msg:
        if print_m:
            print("\nError: %s." % error_msg)
            time.sleep(1.5)
            print_on_previous_line(retlines)
        return False

    return True


def validate_nick(nick, retlines=2, print_m=True):
    """
    Validate nickname for account.

    :param nick:     Nick to validate
    :param retlines: Number of lines to go up after error message
    :param print_m:  When False, does not print message.
    :return:         True if nick is valid, else False
    """

    input_validation((nick, str), (retlines, int), (print_m, bool))

    error_msg = ''

    if len(nick) > 254:
        error_msg = "Nick must be shorter than 255 chars."

    if not all(c in string_c.printable for c in nick):
        error_msg = "Nick must be printable."

    if nick == '':
        error_msg = "Nick can't be empty."

    if nick.lower() == "me":
        error_msg = "'Me' is a reserved nick."

    if nick == "local":
        error_msg = "Nick can't refer to local keyfile."

    if validate_account(nick, print_m=False):
        error_msg = "Nick can't be an account."

    if nick in get_list_of("nicks"):
        error_msg = "Nick already in use."

    if nick in get_list_of("groups"):
        error_msg = "Nick can't be a group name."

    if error_msg:
        if print_m:
            print("\nError: %s" % error_msg)
            time.sleep(1.5)
            print_on_previous_line(retlines)
        return False
    return True


def get_list_of(key, g_name=''):
    """
    Return list of data specified by a key.

    :param key:    Key that defines type of list to generate
    :param g_name: Group name when loading members
    :return:       List of data based on key
    """

    input_validation((key, str), (g_name, str))

    if key == "accounts":
        lst = [a for a in c_dictionary.keys()
               if a != "local" and not a.startswith("dummy_account")]

    elif key == "nicks":
        lst = [c_dictionary[a]["nick"] for a in c_dictionary.keys()
               if a != "local"]

    elif key == "groups":
        lst = [g for g in g_dictionary.keys()
               if not g.startswith("dummy_group")]

    elif key == "members":
        g_name = g_name if g_name else active_c['g']
        if g_name not in g_dictionary.keys():
            raise FunctionReturn("Error: Unknown group.")

        lst = [m for m in g_dictionary[g_name]["members"]
               if m != "dummy_member"]
    else:
        raise KeyError

    lst.sort()
    return lst


###############################################################################
#                              CONTACT SELECTION                              #
###############################################################################

def change_recipient(parameter):
    """
    Change recipient.

    :param parameter: Recipient to be separated
    :return:          None
    """

    input_validation((parameter, str))

    try:
        new_recip = parameter.split()[1]
    except IndexError:
        raise FunctionReturn("Error: Invalid command.")

    try:
        return select_contact(selection=new_recip, menu=False)
    except ValueError:
        raise FunctionReturn("Error: Invalid contact / group selection.")


def print_contact_list(spacing=False):
    """
    Print list of available contacts and their nicknames.

    :param spacing: When True, add spacing around the printed table
    :return:        None
    """

    input_validation((spacing, bool))

    if spacing:
        clear_screen()
        print('')

    c1 = ["Account"]
    c2 = ["Nick"]
    c3 = ["Key type"]
    c4 = ["Logging"]

    for a in sorted(c_dictionary.keys()):
        if a.startswith("dummy_account") or a == "local":
            continue
        c1.append(a)
        c2.append(c_dictionary[a]["nick"])
        c3.append("PSK" if c_dictionary[a]["txpk"] == "psk" else "Curve25519")
        c4.append("on" if c_dictionary[a]["logging"] else "off")

    lst = []
    for acco, nick, keyex, log in zip(c1, c2, c3, c4):
        lst.append("{0:{4}} {1:{5}} {2:{6}} {3}".format(
            acco, nick, keyex, log,
            len(max(c1, key=len)) + 4,
            len(max(c2, key=len)) + 4,
            len(max(c3, key=len)) + 4,
            len(max(c4, key=len)) + 4))

    lst.insert(1, get_tty_w() * '-')

    print '\n'.join(str(l) for l in lst)
    try:
        print_group_details(all_g=True, petc=False)
    except FunctionReturn:
        pass

    if spacing:
        print('')
        if clear_input_screen:
            raw_input(" Press <enter> to continue.")


def select_contact(selection='', menu=True):
    """
    Select new contact.

    :param selection: Contact selection number
    :param menu:      When True, ask for user input
    :return:          None
    """

    input_validation((selection, str), (menu, bool))

    while True:
        try:
            if selection == '' or menu:
                print_contact_list()
                selection = raw_input("Select contact: ")
                selection = ''.join(selection.split())

            if selection in get_list_of("accounts"):
                send_packet(us.join(["WS", selection]), 'c')
                active_c['a'] = selection
                active_c['n'] = c_dictionary[selection]["nick"]
                active_c['g'] = ''
                clear_screen()
                print("\nSelected %s (%s).\n" % (active_c['n'], active_c['a']))
                return None

            elif selection in get_list_of("nicks"):
                for account in get_list_of("accounts"):
                    if c_dictionary[account]["nick"] == selection:
                        send_packet(us.join(["WS", account]), 'c')
                        active_c['a'] = account
                        active_c['n'] = selection
                        active_c['g'] = ''
                        clear_screen()
                        print("\nSelected %s (%s).\n" % (selection, account))
                        return None

            elif selection in get_list_of("groups"):
                send_packet(us.join(["WS", selection]), 'c')
                active_c['a'] = ''
                active_c['n'] = selection
                active_c['g'] = selection
                clear_screen()
                g_s = '' if get_list_of("members", selection) else " (empty)"
                print("\nSelected group %s%s.\n" % (selection, g_s))
                return None

            if menu:
                clear_screen()
                print("Error: Invalid selection '%s'.\n" % selection)
                continue
            raise ValueError

        except KeyboardInterrupt:
            graceful_exit()


###############################################################################
#                             DATABASE MANAGEMENT                             #
###############################################################################

def contact_db(write_db=None):
    """
    Manage encrypted database for contacts and their keys.

    :param write_db: If provided, write new database to file.
    :return:         None if write is specified, else database dictionary.
    """

    keys = ["user", "nick", "harac", "key", "hek", "txpk", "rxpk", "logging"]

    os.system("touch %s" % datab_file)

    if write_db is None:
        acco_d = dict()
        f_data = open(datab_file).readline().strip('\n')
        if f_data:
            acco_l = split_string(decrypt_data(f_data), 255 * (len(keys) + 1))
            for a in acco_l:
                a_data = [rm_padding(p) for p in split_string(a, 255)]
                if not a_data[0].startswith("dummy_account"):
                    acco_d[a_data[0]] = dict(zip(keys, a_data[1:]))
                    acco_d[a_data[0]]["harac"] = int(a_data[3])
                    acco_d[a_data[0]]["logging"] = (a_data[8] == "True")

            if len(acco_l) < m_number_of_accnts:
                contact_db(write_db=acco_d)
                return contact_db()

            if len(acco_d) > m_number_of_accnts:
                raise CriticalError("m_number_of_accnts must be at least %s."
                                    % len(acco_l))
        return acco_d

    # Remove current dummy accounts
    for k in write_db.keys():
        if k.startswith("dummy_account_"):
            del write_db[k]

    # Add dummy accounts
    dummy_fields = dict(zip(keys, len(keys) * ["dummy_data"]))
    for i in xrange(m_number_of_accnts - len(write_db)):
        write_db["dummy_account_%s" % i] = dummy_fields

    plaintext = ''
    for a in write_db:
        plaintext += padding(a)
        plaintext += ''.join([padding(str(write_db[a][k])) for k in keys])

    # Store accounts into encrypted database
    with open(datab_file, "w+") as f:
        f.write(encrypt_and_sign(plaintext, key=master_key, pad=False))


def group_db(write_db=None):
    """
    Manage encrypted database for groups and their members.

    :param write_db: If provided, write new database to file.
    :return:         None if write is specified, else database dictionary.
    """

    os.system("touch %s" % group_file)

    if write_db is None:
        g_dict = dict()
        f_data = open(group_file).readline().strip('\n')

        update_dummies = False
        largest_group = 0
        if f_data:
            groups = decrypt_data(f_data).split(rs)

            for g in groups:
                g_data = [rm_padding(b64d(p)) for p in g.split(us)]
                g_size = len(g_data[2:])

                if g_size > m_members_in_group:
                    largest_group = max(largest_group, g_size)

                if g_size < m_members_in_group:
                    update_dummies = True

                if g_data[0].startswith("dummy_group"):
                    continue

                g_dict[g_data[0]] = dict(logging=g_data[1] == "True",
                                         members=g_data[2:])

            if largest_group > 0:
                raise CriticalError("m_members_in_group must be at "
                                    "least %s." % largest_group)

            if len(groups) > m_number_of_groups:
                raise CriticalError("m_number_of_groups must be at "
                                    "least %s." % len(groups))

            if len(groups) < m_number_of_groups:
                update_dummies = True

        if update_dummies:
            group_db(write_db=g_dict)
            return group_db()
        return g_dict

    # Remove current dummy groups
    for k in write_db.keys():
        if k.startswith("dummy_group"):
            del write_db[k]

    # Add new dummy groups
    for i in xrange(m_number_of_groups - len(write_db)):
        write_db["dummy_group_%s" % i] = dict(logging="False", members=[])

    # Add dummy members
    for g in write_db:
        dummy_count = m_members_in_group - len(write_db[g]["members"])
        write_db[g]["members"] += dummy_count * ["dummy_member"]

    records = []
    for g in write_db:
        fields = [g, str(write_db[g]["logging"])] + write_db[g]["members"]
        records.append(us.join([b64e(padding(f)) for f in fields]))

    with open(group_file, "w+") as f:
        f.write(encrypt_and_sign(rs.join(records), key=master_key, pad=False))


###############################################################################
#                               LOCAL COMMANDS                                #
###############################################################################

def print_about():
    """
    Print URLs that direct to TFC project site and documentation.

    :return: None
    """

    clear_screen()
    print(" Tinfoil Chat %s\n\n" % str_version +
          " Website:     https://github.com/maqp/tfc/            \n"
          " Wikipage:    https://github.com/maqp/tfc/wiki        \n"
          " White paper: https://cs.helsinki.fi/u/oottela/tfc.pdf\n")

    if clear_input_screen:
        raw_input(" Press <enter> to continue.")


def print_help():
    """
    Print the list of commands.

    :return: None
    """

    def help_printer(tuple_list):
        """
        Print help menu, style depending on terminal width.

        Skip help commands that are not available.

        :param tuple_list: List of command-description-display tuples
        :return:           None
        """

        for help_c, desc, disp in tuple_list:
            if disp == 't' and not trickle_connection:
                continue
            if disp == 's' and trickle_connection:
                continue

            wrapper = textwrap.TextWrapper(width=max(1, get_tty_w() - 26))
            lines = wrapper.fill(desc).split('\n')
            print help_c + (26 - len(help_c)) * ' ' + lines[0]
            for line in lines[1:]:
                print 26 * ' ' + line

    common = [("/about",
               "Show information about TFC", 'b'),
              ("/add( A U N {'e','p'})",
               "Add new contact. Missing parameters are input interactively",
               's'),
              ("/cf",
               "Cancel file transmission during trickle connection", 't'),
              ("/clear, '  '",
               "Clear screens from TxM, RxM and Pidgin", 'b'),
              ("/cm",
               "Cancel message transmission", 't'),
              ("/cmd, '//'",
               "Display command tab on RxM", 's'),
              ("/exit",
               "Exit TFC on TxM, NH and RxM", 'b'),
              ("/export",
               "Export plaintext history on TxM/RxM for account or group",
               'b'),
              ("/file",
               "Send file to contact or group", 'b'),
              ("/help",
               "Display this list of commands", 'b'),
              ("/history",
               "Print log history on TxM/RxM for account or group", 'b'),
              ("/localkey",
               "Generate new local key pair", 's'),
              ("/logging {on,off}(' all')",
               "Change logging setting (for all contacts)", 'b'),
              ("/msg {A,N,G}",
               "Change recipient", 's'),
              ("/names",
               "List accounts, nicks and groups", 'b'),
              ("/nick N",
               "Change nickname of active contact to N", 'b'),
              ("/paste",
               "Start paste mode to send multi-line messages", 'b'),
              ("/psk",
               "Open PSK import dialog on RxM", 's'),
              ("/pubkeys",
               "Print public keys of user and contact", 'b'),
              ("/reset",
               "Reset ephemeral session on TxM and RxM. Clear Pidgin", 'b'),
              ("/rm A",
               "Remove keyfiles and account from TxM and RxM", 's'),
              ("/store {on,off}(' all')",
               "Change file reception (for all contacts)", 'b'),
              ("/unread, ' '",
               "List windows with new notifications on RxM", 's'),
              ("/winpriv {on,off}(' all')",
               "Change notification privacy (for all contacts)", 'b'),
              ("Shift + PgUp/PgDn",
               "Scroll terminal up/down", 'b')]

    groupc = [("/groups",
               "Display list of groups", 's'),
              ("/group",
               "Display members in active group", 's'),
              ("/group G",
               "Display members in group G", 's'),
              ("/group create G A1 .. An",
               "Create group G and add accounts A1 .. An", 's'),
              ("/group add G A1 .. An",
               "Add accounts A1 .. An to group G", 's'),
              ("/group rm G A1 .. An",
               "Remove accounts A1 .. An from group G", 's'),
              ("/group rm G",
               "Remove group G", 's')]

    w = get_tty_w()

    clear_screen()
    print textwrap.fill("List of commands:", w)
    print('')
    print textwrap.fill("A=account, U=user, N=nick, G=group", w)
    print('')
    help_printer(common)

    if not trickle_connection:
        print("%s\nGroup management:" % (w * '-'))
        help_printer(groupc)
    print("%s\n" % (w * '-'))

    if clear_input_screen:
        raw_input(" Press <enter> to continue.")


###############################################################################
#                              ENCRYPTED COMMANDS                             #
###############################################################################

def change_nick(parameter):
    """
    Change nick of active account to specified on TxM and RxM.

    :param parameter: New nickname to be separated
    :return:          None
    """

    input_validation((parameter, str))

    try:
        new_nick = parameter.split()[1]
    except IndexError:
        raise FunctionReturn("Error: No nick specified.")

    if active_c['g']:
        raise FunctionReturn("Error: Group is selected.")

    if not validate_nick(new_nick):
        raise FunctionReturn("invalid nick", output=False)

    active_c['n'] = new_nick

    c_dictionary[active_c['a']]["nick"] = new_nick
    run_as_thread(contact_db, c_dictionary)

    send_packet(us.join(["CN", active_c['a'], new_nick]), 'c')
    print("\nChanged %s nick to %s.\n" % (active_c['a'], new_nick))


def change_setting(parameters):
    """
    Send encrypted and signed packet to RxM via NH to enable or
    disable logging, private message notifications or file storage.

    :param parameters: Command and it's parameters
    :return:           None
    """

    input_validation((parameters, str))

    try:
        parameters = parameters.split()
        command = dict(logging="CL", store="CF",
                       winpriv="CP")[parameters[0][1:]]
        s_value = dict(on='e', off='d')[parameters[1]]
        b_value = dict(on=True, off=False)[parameters[1]]
    except (IndexError, KeyError):
        raise FunctionReturn("Error: Invalid command.")

    try:
        target = ''
        if parameters[2] == "all":
            c_value = s_value.upper()
        else:
            raise FunctionReturn("Error: Invalid command.")
    except IndexError:
        target = active_c['a'] if active_c['a'] else active_c['g']
        c_value = us.join([s_value, target])

    if command == "CL":
        if target:
            if active_c['a']:
                c_dictionary[active_c['a']]["logging"] = b_value
                run_as_thread(contact_db, c_dictionary)
            else:
                g_dictionary[active_c['g']]["logging"] = b_value
                run_as_thread(group_db, g_dictionary)
        else:
            for a in get_list_of("accounts"):
                c_dictionary[a]["logging"] = b_value
            for g in get_list_of("groups"):
                g_dictionary[g]["logging"] = b_value
            run_as_thread(contact_db, c_dictionary)
            run_as_thread(group_db, g_dictionary)

    send_packet(us.join([command, c_value]), 'c')


def clear_displays(cmd):
    """
    Send command to NH.py, Pidgin and Rx.py to clear/reset screens.
    When resetting, Rx.py clears history for all messages during the session.

    Display clear/reset is disabled in NH and Pidgin during trickle connection
    because command needs to be transmitted in encrypted form to RxM to prevent
    adversary monitoring NH from figuring out, commands are being issued. As
    only every other packet is a command, the speed is reduced during trickle
    connection.

    :param: cmd: Command to issue
    :return:     None
    """

    input_validation((cmd, str))

    assert cmd in ["SC", "SR"]

    if cmd == "SC":
        clear_screen()
        print('')
    else:
        os.system("reset")

    window = active_c['a'] if active_c['a'] else active_c['g']
    rx_cmd = cmd if cmd == "SC" else us.join([cmd, window])
    send_packet(rx_cmd, 'c')
    time.sleep(0.3)

    if trickle_connection:
        return None

    if active_c['a']:
        transmit('U' + cmd + active_c['a'])

    if active_c['g'] and get_list_of("members", active_c['g']):
        transmit('U' + cmd + get_list_of("members", active_c['g'])[0])


###############################################################################
#                    COMMAND / MESSAGE / FILE TRANSMISSION                    #
###############################################################################

def readable_size(size):
    """
    Returns the size of file in human readable form.

    :param size: Size of file in bytes
    :return:     Human readable format of bytes
    """

    input_validation((size, (int, long)))

    for unit in ['', 'K', 'M', 'G', 'T', 'P', 'E', 'Z']:
        if abs(size) < 1024.0:
            return "%3.1f%sB" % (size, unit)
        size /= 1024.0

    return "%.1f%sB" % (size, 'Y')


def t_time(no_packets):
    """
    Calculate transmission time based on average delays and settings.

    :param no_packets: Number of packets to deliver
    :return:           Human readable estimation of delivery time
    """

    input_validation((no_packets, int))

    assert no_packets >= 0

    no_members = 1 if active_c['a'] else len(get_list_of("members"))

    if trickle_connection:
        avg_delay = trickle_stat_delay + (trickle_rand_delay / 2.0)

        if long_packet_rand_d:
            avg_delay += (max_val_for_rand_d / 2.0)

        init_est = 2 * no_members * no_packets * avg_delay
        init_est += no_packets * 0.1  # Static queue load time

    else:
        avg_delay = 0.3 + (400.0 / serial_iface_speed)

        if long_packet_rand_d:
            avg_delay += (max_val_for_rand_d / 2.0)

        init_est = no_members * no_packets * avg_delay

    sd = datetime.timedelta(seconds=int(init_est))
    dt = datetime.datetime(1, 1, 1) + sd

    if dt.second == 0:
        return "00d 00h 00m 00s", "00s"

    human_r = ''
    static = ''
    for i in [(dt.day - 1, 'd'), (dt.hour, 'h'),
              (dt.minute, 'm'), (dt.second, 's')]:
        if i[0] > 0:
            human_r += str(i[0]).zfill(2) + "%s " % i[1]
        static += str(i[0]).zfill(2) + "%s " % i[1]

    return static[:-1], human_r[:-1]


def load_file_data(parameters):
    """
    Load file data to payload.

    :param parameters: Target path/file to be separated
    :return:           File data
    """

    input_validation((parameters, str))

    path_to_file = ask_path_gui("Select file", get_file=True)
    if not os.path.isfile(path_to_file):
        raise FunctionReturn("Error: File not found.")

    f_size = readable_size(os.path.getsize(path_to_file))
    if os.path.getsize(path_to_file) == 0:
        raise FunctionReturn("Error: Target file is empty. No file was sent.")

    f_name = str(path_to_file.split('/')[-1])

    phase("\nLoading file data...")
    f_data = open(path_to_file, "rb").read()
    print("Done.")

    phase("Compressing file...")
    f_data = zlib.compress(f_data, 9)
    print("Done.")

    phase("Encrypting file...")
    file_key = sha3_256(os.urandom(32))
    f_data = encrypt_and_sign(f_data, key=file_key, pad=False)
    f_data += file_key
    print("Done.")

    phase("Evaluating delivery time...")
    payload = us.join(['p', f_name, f_size, "00d 00h 00m 00s", f_data])
    p_t, hr = t_time(len(split_string(payload, 253)))
    final_p = us.join([f_name, f_size, p_t, f_data])
    print("Done.")

    if len(us.join(['p', f_name, f_size, p_t, '1'])) > 254:
        raise FunctionReturn("Error: Too long file name. No file was sent.")

    if confirm_sent_files:
        g_m = "%s members" % active_c['g'] if active_c['g'] else active_c['n']
        m = str("Send %s (%s) to %s (time: %s)? " % (f_name, f_size, g_m, hr))
        print('')
        if not yes(m):
            raise FunctionReturn("File sending aborted by user.")

    print('')
    return str(final_p)


def add_packet_assembly_headers(payload, p_type):
    """
    Prepare long payloads for transmission in multiple parts.

    :param payload: Long message to be transmitted in multiple parts
    :param p_type:  Type of packet
    :return:        List of 255 byte messages, prepended with assembly headers
    """

    input_validation((payload, str), (p_type, str))

    payload = payload.strip('\n')

    if len(payload) < 255:
        return [dict(m='a', f='A', c='0')[p_type] + payload]

    if p_type == 'c':
        payload += sha3_256(payload)

    elif p_type == 'm':
        payload = zlib.compress(payload, 9)

        # Encrypt for sender based control on partially transmitted message
        msg_key = sha3_256(os.urandom(32))
        payload = encrypt_and_sign(payload, key=msg_key, pad=False)
        payload += msg_key

    # Split to 253 char long msg parts: room for 1 char header
    packet_l = split_string(payload, 253)

    s_header = dict(m='b', f='B', c='1')[p_type]
    a_header = dict(m='c', f='C', c='2')[p_type]
    e_header = dict(m='d', f='D', c='3')[p_type]

    packet_list = ([s_header + packet_l[0]] +
                   [a_header + p for p in packet_l[1:-1]] +
                   [e_header + packet_l[-1]])

    return packet_list


def recipient_chooser(payload, p_type):
    """
    Send message/file to a contact/group.

    :param payload: Message / file content to be sent
    :param p_type:  Type of packet to send
    :return:        None
    """

    input_validation((payload, str), (p_type, str))

    global cancel_lt

    group = active_c['g']
    if group:
        members = get_list_of("members", group)
        if not members:
            raise FunctionReturn("Group is empty. No %s was sent."
                                 % dict(m="message", f="file")[p_type])

        for m in members:
            send_packet(us.join(['g', group, payload]), p_type, m)
            if cancel_lt:
                break
    else:
        send_packet(us.join(['p', payload]), p_type, active_c['a'])

    if cancel_lt:
        cancel_lt = False


def send_packet(payload, p_type, account="local"):
    """
    Send message/file/command.

    During trickle connection, packets are placed
    into one of three queues based on packet type.

    :param payload: Data to send
    :param p_type:  Type of packet to send
    :param account: Contact to send data to
    :return:        None
    """

    input_validation((payload, str), (p_type, str), (account, str))

    packet_list = add_packet_assembly_headers(payload, p_type)

    if trickle_connection and trickle_q:
        queue = dict(m=rm_queue, f=rf_queue, c=rc_queue)[p_type]
        for p in packet_list:
            queue.put(padding(p))

    else:
        if len(packet_list) == 1:
            run_as_thread(packet_thread, packet_list[0], account)
        else:
            try:
                long_transmit(packet_list, p_type, account)
            except FunctionReturn:
                pass


def long_transmit(p_list, p_type, account=''):
    """
    Send long transmissions in multiple parts.

    :param p_list:  Long plaintext message
    :param p_type:  Type of packet
    :param account: The contact's account name (e.g. alice@jabber.org)
    :return:        None
    """

    input_validation((p_list, list), (p_type, str), (account, str))

    s = dict(m="Message", f="File", c="Command")[p_type]

    nick = "RxM" if p_type == 'c' else c_dictionary[account]["nick"]

    global cancel_lt

    for p in p_list:
        print_on_previous_line()
        m = ("%s transfer to %s (%s). ^C cancels."
             % (s, nick, len(p_list) - p_list.index(p)))
        print m

        if cancel_lt:
            cancel_cmd = dict(m='e', f='E', c='4')[p_type]
            run_as_thread(packet_thread, cancel_cmd, account)
            print('')
            print_on_previous_line(4)
            raise FunctionReturn("%s transfer to %s aborted." % (s, nick))

        try:
            if long_packet_rand_d:
                # Sleep only during long msg start/append packets
                if p[:1] in "bBcC12":
                    st = random.SystemRandom().uniform(0.0, max_val_for_rand_d)
                    print "%s%s  (Random delay: %ss)" % (cu, m, st)
                    time.sleep(st)

            run_as_thread(packet_thread, p, account)

        except KeyboardInterrupt:
            cancel_lt = True

    print_on_previous_line()
    if p_type == 'f':
        print_on_previous_line()
        print("File transmission complete.")
    print('')


def packet_thread(plaintext, account="local"):
    """
    Pad, encrypt, sign, encode, transmit and optionally log sent packet.

    :param plaintext: The plaintext packet
    :param account:   The contact's account name (e.g. alice@jabber.org)
    :return:          None
    """

    input_validation((plaintext, str), (account, str))

    user = c_dictionary[account]["user"]
    hek = c_dictionary[account]["hek"]
    pth = 'C' if (account == "local") else 'M'

    # 64-bits = 580 years @ 1Gbps: Int64 will never overflow with TFC.
    harac_bytes = struct.pack("!Q", c_dictionary[account]["harac"])
    eharac = encrypt_and_sign(harac_bytes, key=hek, pad=False, encode=False)
    ct_tag = encrypt_and_sign(plaintext, account,
                              pad=len(plaintext) != 255, encode=False)

    transmit(pth + eharac + ct_tag + user + us + account)

    if account != "local":
        if plaintext[0] in ['f', 'F'] and not log_noise_messages:
            return None

        if plaintext[0].isupper():
            plaintext = 255 * 'A'  # Log placeholder data instead of file

        if active_c['a'] and c_dictionary[active_c['a']]["logging"]:
            write_log_entry(account, plaintext)

        if active_c['g'] and g_dictionary[active_c['g']]["logging"]:
            write_log_entry(account, plaintext)


def exit_program():
    """
    Send encrypted exit command to RxM and unencrypted exit command to NH.

    When local_testing is True, sleep to avoid premature exit of NH.py
    and Rx.py when IPC socket disconnects. This ensures TFC behaves the
    same way as it would when operating through serial interfaces.

    :return: None
    """

    send_packet("EX", 'c')
    time.sleep(0.3)
    transmit('U' + "EX")

    if local_testing_mode:
        time.sleep(0.8)
    if data_diode_sockets:
        time.sleep(2.2)  # Slow down even more when dd simulators are used

    graceful_exit()


###############################################################################
#                            REED SOLOMON ENCODING                            #
###############################################################################

"""
# Copyright (c) 2012-2015 Tomer Filiba <tomerfiliba@gmail.com>
# Copyright (c) 2015 rotorgit
# Copyright (c) 2015 Stephen Larroque <LRQ3000@gmail.com>

The code below is used under public domain license:
https://github.com/tomerfiliba/reedsolomon/blob/master/LICENSE

The comments/unused code have been intentionally removed. Original code's at
https://github.com/tomerfiliba/reedsolomon/blob/master/reedsolo.py
"""


class ReedSolomonError(Exception):
    pass

gf_exp = bytearray([1] * 512)
gf_log = bytearray(256)
field_charac = int(2 ** 8 - 1)


def init_tables(prim=0x11d, generator=2, c_exp=8):
    """
    Precompute the logarithm and anti-log tables for faster computation later,
    using the provided primitive polynomial. These tables are used for
    multiplication/division since addition/substraction are simple XOR
    operations inside GF of characteristic 2. The basic idea is quite simple:
    since b**(log_b(x), log_b(y)) == x * y given any number b (the base or
    generator of the logarithm), then we can use any number b to precompute
    logarithm and anti-log (exponentiation) tables to use for multiplying two
    numbers x and y.

    That's why when we use a different base/generator number, the log and
    anti-log tables are drastically different, but the resulting computations
    are the same given any such tables. For more information, see
    https://en.wikipedia.org/wiki/Finite_field_arithmetic#Implementation_tricks
    """

    global gf_exp, gf_log, field_charac
    field_charac = int(2 ** c_exp - 1)
    gf_exp = bytearray(field_charac * 2)
    gf_log = bytearray(field_charac + 1)
    x = 1
    for i in xrange(field_charac):
        gf_exp[i] = x
        gf_log[x] = i
        x = fg_mult_nolut(x, generator, prim, field_charac + 1)

    for i in xrange(field_charac, field_charac * 2):
        gf_exp[i] = gf_exp[i - field_charac]

    return [gf_log, gf_exp]


def gf_sub(x, y):
    return x ^ y


def gf_inverse(x):
    return gf_exp[field_charac - gf_log[x]]


def gf_mul(x, y):
    if x == 0 or y == 0:
        return 0
    return gf_exp[(gf_log[x] + gf_log[y]) % field_charac]


def gf_div(x, y):
    if y == 0:
        raise ZeroDivisionError()
    if x == 0:
        return 0
    return gf_exp[(gf_log[x] + field_charac - gf_log[y]) % field_charac]


def gf_pow(x, power):
    return gf_exp[(gf_log[x] * power) % field_charac]


def fg_mult_nolut(x, y, prim=0, field_charac_full=256, carryless=True):
    """
    Galois Field integer multiplication using Russian Peasant Multiplication
    algorithm (faster than the standard multiplication + modular reduction).
    If prim is 0 and carryless=False, then the function produces the result
    for a standard integers multiplication (no carry-less arithmetics nor
    modular reduction).
    """

    r = 0
    while y:
        if y & 1:
            r = r ^ x if carryless else r + x
        y >>= 1
        x <<= 1
        if prim > 0 and x & field_charac_full:
            x ^= prim

    return r


def gf_poly_scale(p, x):
    return bytearray([gf_mul(p[i], x) for i in xrange(len(p))])


def gf_poly_add(p, q):
    r = bytearray(max(len(p), len(q)))
    r[len(r) - len(p):len(r)] = p
    for i in xrange(len(q)):
        r[i + len(r) - len(q)] ^= q[i]
    return r


def gf_poly_mul(p, q):
    """
    Multiply two polynomials, inside Galois Field (but the procedure
    is generic). Optimized function by precomputation of log.
    """

    r = bytearray(len(p) + len(q) - 1)
    lp = [gf_log[p[i]] for i in xrange(len(p))]
    for j in xrange(len(q)):
        qj = q[j]
        if qj != 0:
            lq = gf_log[qj]
            for i in xrange(len(p)):
                if p[i] != 0:
                    r[i + j] ^= gf_exp[lp[i] + lq]
    return r


def gf_poly_div(dividend, divisor):
    """
    Fast polynomial division by using Extended Synthetic Division and optimized
    for GF(2^p) computations (doesn't work with standard polynomials outside of
    this galois field).
    """

    msg_out = bytearray(dividend)
    for i in xrange(len(dividend) - (len(divisor) - 1)):
        coef = msg_out[i]
        if coef != 0:
            for j in xrange(1, len(divisor)):
                if divisor[j] != 0:
                    msg_out[i + j] ^= gf_mul(divisor[j], coef)

    separator = -(len(divisor) - 1)
    return msg_out[:separator], msg_out[separator:]


def gf_poly_eval(poly, x):
    """
    Evaluates a polynomial in GF(2^p) given the value for x.
    This is based on Horner's scheme for maximum efficiency.
    """

    y = poly[0]
    for i in xrange(1, len(poly)):
        y = gf_mul(y, x) ^ poly[i]
    return y


def rs_generator_poly(nsym, fcr=0, generator=2):
    """
    Generate an irreducible generator polynomial
    (necessary to encode a message into Reed-Solomon)
    """

    g = bytearray([1])
    for i in xrange(nsym):
        g = gf_poly_mul(g, [1, gf_pow(generator, i + fcr)])
    return g


def rs_encode_msg(msg_in, nsym, fcr=0, generator=2, gen=None):
    """
    Reed-Solomon main encoding function, using polynomial division (Extended
    Synthetic Division, the fastest algorithm available to my knowledge),
    better explained at http://research.swtch.com/field
    """

    global field_charac
    if (len(msg_in) + nsym) > field_charac:
        raise ValueError("Message is too long (%i when max is %i)"
                         % (len(msg_in) + nsym, field_charac))

    if gen is None:
        gen = rs_generator_poly(nsym, fcr, generator)

    msg_in = bytearray(msg_in)
    msg_out = bytearray(msg_in) + bytearray(len(gen) - 1)
    lgen = bytearray([gf_log[gen[j]] for j in xrange(len(gen))])

    for i in xrange(len(msg_in)):
        coef = msg_out[i]

        if coef != 0:
            lcoef = gf_log[coef]
            for j in xrange(1, len(gen)):
                msg_out[i + j] ^= gf_exp[lcoef + lgen[j]]

    msg_out[:len(msg_in)] = msg_in
    return msg_out


def rs_calc_syndromes(msg, nsym, fcr=0, generator=2):
    """
    Given the received codeword msg and the number of error correcting symbols
    (nsym), computes the syndromes polynomial. Mathematically, it's essentially
    equivalent to a Fourier Transform (Chien search being the inverse).
    """

    return [0] + [gf_poly_eval(msg, gf_pow(generator, i + fcr))
                  for i in xrange(nsym)]


def rs_correct_errata(msg_in, synd, err_pos, fcr=0, generator=2):
    """
    Forney algorithm, computes the values (error magnitude) to correct in_msg.
    """

    global field_charac
    msg = bytearray(msg_in)
    coef_pos = [len(msg) - 1 - p for p in err_pos]
    err_loc = rs_find_errata_locator(coef_pos, generator)
    err_eval = rs_find_error_evaluator(synd[::-1], err_loc,
                                       len(err_loc) - 1)[::-1]

    x_ = []
    for i in xrange(len(coef_pos)):
        l = field_charac - coef_pos[i]
        x_.append(gf_pow(generator, -l))

    e_ = bytearray(len(msg))
    xlength = len(x_)
    for i, Xi in enumerate(x_):
        xi_inv = gf_inverse(Xi)
        err_loc_prime_tmp = []
        for j in xrange(xlength):
            if j != i:
                err_loc_prime_tmp.append(gf_sub(1, gf_mul(xi_inv, x_[j])))

        err_loc_prime = 1
        for coef in err_loc_prime_tmp:
            err_loc_prime = gf_mul(err_loc_prime, coef)

        y = gf_poly_eval(err_eval[::-1], xi_inv)
        y = gf_mul(gf_pow(Xi, 1 - fcr), y)
        magnitude = gf_div(y, err_loc_prime)
        e_[err_pos[i]] = magnitude

    msg = gf_poly_add(msg, e_)
    return msg


def rs_find_error_locator(synd, nsym, erase_loc=None, erase_count=0):
    """
    Find error/errata locator and evaluator
    polynomials with Berlekamp-Massey algorithm
    """

    if erase_loc:
        err_loc = bytearray(erase_loc)
        old_loc = bytearray(erase_loc)
    else:
        err_loc = bytearray([1])
        old_loc = bytearray([1])

    synd_shift = 0
    if len(synd) > nsym:
        synd_shift = len(synd) - nsym

    for i in xrange(nsym - erase_count):
        if erase_loc:
            k_ = erase_count + i + synd_shift
        else:
            k_ = i + synd_shift

        delta = synd[k_]
        for j in xrange(1, len(err_loc)):
            delta ^= gf_mul(err_loc[-(j + 1)], synd[k_ - j])
        old_loc = old_loc + bytearray([0])

        if delta != 0:
            if len(old_loc) > len(err_loc):
                new_loc = gf_poly_scale(old_loc, delta)
                old_loc = gf_poly_scale(err_loc, gf_inverse(delta))
                err_loc = new_loc
            err_loc = gf_poly_add(err_loc, gf_poly_scale(old_loc, delta))

    err_loc = list(itertools.dropwhile(lambda x: x == 0, err_loc))
    errs = len(err_loc) - 1
    if (errs - erase_count) * 2 + erase_count > nsym:
        raise ReedSolomonError("Too many errors to correct")

    return err_loc


def rs_find_errata_locator(e_pos, generator=2):
    """
    Compute the erasures/errors/errata locator polynomial from the
    erasures/errors/errata positions (the positions must be relative to the x
    coefficient, eg: "hello worldxxxxxxxxx" is tampered to
    "h_ll_ worldxxxxxxxxx" with xxxxxxxxx being the ecc of length n-k=9, here
    the string positions are [1, 4], but the coefficients are reversed since
    the ecc characters are placed as the first coefficients of the polynomial,
    thus the coefficients of the erased characters are n-1 - [1, 4] = [18, 15]
    = erasures_loc to be specified as an argument.
    """

    e_loc = [1]
    for i in e_pos:
        e_loc = gf_poly_mul(e_loc,
                            gf_poly_add([1], [gf_pow(generator, i), 0]))
    return e_loc


def rs_find_error_evaluator(synd, err_loc, nsym):
    """
    Compute the error (or erasures if you supply sigma=erasures locator
    polynomial, or errata) evaluator polynomial Omega from the syndrome and the
    error/erasures/errata locator Sigma. Omega is already computed at the same
    time as Sigma inside the Berlekamp-Massey implemented above, but in case
    you modify Sigma, you can recompute Omega afterwards using this method, or
    just ensure that Omega computed by BM is correct given Sigma.
    """

    _, remainder = gf_poly_div(gf_poly_mul(synd, err_loc),
                               ([1] + [0] * (nsym + 1)))
    return remainder


def rs_find_errors(err_loc, nmess, generator=2):
    """
    Find the roots (ie, where evaluation = zero) of error polynomial by
    bruteforce trial, this is a sort of Chien's search (but less efficient,
    Chien's search is a way to evaluate the polynomial such that each
    evaluation only takes constant time).
    """

    errs = len(err_loc) - 1
    err_pos = []
    for i in xrange(nmess):
        if gf_poly_eval(err_loc, gf_pow(generator, i)) == 0:
            err_pos.append(nmess - 1 - i)

    if len(err_pos) != errs:
        raise ReedSolomonError("Too many (or few) errors found by Chien "
                               "Search for the errata locator polynomial!")
    return err_pos


def rs_forney_syndromes(synd, pos, nmess, generator=2):
    erase_pos_reversed = [nmess - 1 - p for p in pos]
    fsynd = list(synd[1:])
    for i in xrange(len(pos)):
        x = gf_pow(generator, erase_pos_reversed[i])
        for j in xrange(len(fsynd) - 1):
            fsynd[j] = gf_mul(fsynd[j], x) ^ fsynd[j + 1]
    return fsynd


def rs_correct_msg(msg_in, nsym, fcr=0, generator=2, erase_pos=None,
                   only_erasures=False):
    """Reed-Solomon main decoding function"""

    global field_charac
    if len(msg_in) > field_charac:
        raise ValueError("Message is too long (%i when max is %i)"
                         % (len(msg_in), field_charac))

    msg_out = bytearray(msg_in)
    if erase_pos is None:
        erase_pos = []
    else:
        for e_pos in erase_pos:
            msg_out[e_pos] = 0
    if len(erase_pos) > nsym:
        raise ReedSolomonError("Too many erasures to correct")
    synd = rs_calc_syndromes(msg_out, nsym, fcr, generator)

    if max(synd) == 0:
        return msg_out[:-nsym], msg_out[-nsym:]

    if only_erasures:
        err_pos = []
    else:
        fsynd = rs_forney_syndromes(synd, erase_pos, len(msg_out),
                                    generator)
        err_loc = rs_find_error_locator(fsynd, nsym,
                                        erase_count=len(erase_pos))
        err_pos = rs_find_errors(err_loc[::-1], len(msg_out), generator)
        if err_pos is None:
            raise ReedSolomonError("Could not locate error")

    msg_out = rs_correct_errata(msg_out, synd, (erase_pos + err_pos), fcr,
                                generator)
    synd = rs_calc_syndromes(msg_out, nsym, fcr, generator)
    if max(synd) > 0:
        raise ReedSolomonError("Could not correct message")
    return msg_out[:-nsym], msg_out[-nsym:]


class RSCodec(object):
    """
    A Reed Solomon encoder/decoder. After initializing the object, use
    ``encode`` to encode a (byte)string to include the RS correction code, and
    pass such an encoded (byte)string to ``decode`` to extract the original
    message (if the number of errors allows for correct decoding). The ``nsym``
    argument is the length of the correction code, and it determines the number
    of error bytes (if I understand this correctly, half of ``nsym`` is
    correctable).

    Modifications by rotorgit 2/3/2015:
    Added support for US FAA ADSB UAT RS FEC, by allowing user to specify
    different primitive polynomial and non-zero first consecutive root (fcr).
    For UAT/ADSB use, set fcr=120 and prim=0x187 when instantiating
    the class; leaving them out will default for previous values (0 and
    0x11d)
    """

    def __init__(self, nsym=10, nsize=255, fcr=0, prim=0x11d, generator=2,
                 c_exp=8):
        """
        Initialize the Reed-Solomon codec. Note that different parameters
        change the internal values (the ecc symbols, look-up table values, etc)
        but not the output result (whether your message can be repaired or not,
        there is no influence of the parameters).
        """
        self.nsym = nsym
        self.nsize = nsize
        self.fcr = fcr
        self.prim = prim
        self.generator = generator
        self.c_exp = c_exp
        init_tables(prim, generator, c_exp)

    def encode(self, data):
        """
        Encode a message (ie, add the ecc symbols) using Reed-Solomon,
        whatever the length of the message because we use chunking.
        """
        if isinstance(data, str):
            data = bytearray(data, "latin-1")
        chunk_size = self.nsize - self.nsym
        enc = bytearray()
        for i in xrange(0, len(data), chunk_size):
            chunk = data[i:i + chunk_size]
            enc.extend(rs_encode_msg(chunk, self.nsym, fcr=self.fcr,
                                     generator=self.generator))
        return enc

    def decode(self, data, erase_pos=None, only_erasures=False):
        """Repair a message, whatever its size is, by using chunking."""
        if isinstance(data, str):
            data = bytearray(data, "latin-1")
        dec = bytearray()
        for i in xrange(0, len(data), self.nsize):
            chunk = data[i:i + self.nsize]
            e_pos = []
            if erase_pos:
                e_pos = [x for x in erase_pos if x <= self.nsize]
                erase_pos = [x - (self.nsize + 1)
                             for x in erase_pos if x > self.nsize]
            dec.extend(rs_correct_msg(chunk, self.nsym, fcr=self.fcr,
                                      generator=self.generator,
                                      erase_pos=e_pos,
                                      only_erasures=only_erasures)[0])
        return dec


def transmit(packet):
    """
    Append Reed-Solomon error correction code to packet
    and output it via serial / IPC socket to NH.py.

    :param packet: Packet to send
    :return:       None
    """

    input_validation((packet, str))

    global port_nh

    packet = "1N" + packet  # Protocol version + cipher configuration
    reed_solomon = RSCodec(2 * e_correction_ratio)
    f_packet = reed_solomon.encode(bytearray(packet))

    if unit_test:
        n = len([f for f in os.listdir('.') if f.startswith("unitt_txm_out_")])
        open("unitt_txm_out_%s" % n, "w+").write(b64e(str(f_packet)))
        return None

    if local_testing_mode:
        ipc_nh.send(f_packet)
    else:
        try:
            port_nh.write(f_packet)
            time.sleep(0.3)
        except SerialException:
            if not serial_usb_adapter:
                raise CriticalError(
                    "Integrated serial interface disconnected.")

            phase("\nSerial disconnected. Waiting for interface...")
            while True:
                time.sleep(0.1)
                dev_files = os.listdir("/dev/")
                dev_files.sort()

                for dev_file in dev_files:
                    if dev_file.startswith("ttyUSB"):
                        # Too short delay causes error with iface permissions
                        time.sleep(2)
                        port_nh = serial.Serial("/dev/%s" % dev_file,
                                                serial_iface_speed)
                        print("Found.\n")
                        port_nh.write(f_packet)
                        return None


###############################################################################
#                              GROUP MANAGEMENT                               #
###############################################################################

def group_create(parameters):
    """
    Create a new group.

    :param parameters: Group name and contacts to be separated
    :return:           None
    """

    input_validation((parameters, str))

    try:
        group_name = parameters.split()[2]
    except IndexError:
        raise FunctionReturn("No group name specified.")

    if not all(c in string_c.printable for c in group_name):
        raise FunctionReturn("Group name must be printable.")

    if len(group_name) > 254:
        raise FunctionReturn("Group name must be less than 255 chars long.")

    if group_name.startswith("dummy_group"):
        raise FunctionReturn("Group can't use the name reserved for padding.")

    if group_name in ["create", "add", "rm"]:
        raise FunctionReturn("Group name can't be a group management command.")

    if group_name in get_list_of("accounts"):
        raise FunctionReturn("Group name can't be an account.")

    if group_name in get_list_of("nicks"):
        raise FunctionReturn("Group name can't be nick of contact.")

    if group_name in get_list_of("groups"):
        if not yes("\nGroup already exists. Overwrite?"):
            raise FunctionReturn("Group creation aborted.")

    accounts = set(get_list_of("accounts"))
    purpaccs = set(parameters.split()[3:])
    purpaccs.discard("local")

    accepted = list(accounts & purpaccs)
    rejected = list(purpaccs - accounts)

    accepted.sort()
    rejected.sort()

    if len(accepted) > m_members_in_group:
        raise FunctionReturn("Error: TFC settings only allow %s members per "
                             "group." % m_members_in_group)

    if len(get_list_of("groups")) == m_number_of_groups:
        raise FunctionReturn("Error: TFC settings only allow %s groups."
                             % m_number_of_groups)

    g_dictionary[group_name] = dict(logging=txm_side_m_logging,
                                    members=accepted[:])
    run_as_thread(group_db, g_dictionary)

    g_mgmt_print("new-s", accepted, group_name)
    g_mgmt_print("unkwn", rejected, group_name)

    send_packet(us.join(["GC", group_name] + accepted), 'c')

    if accepted:
        if yes("Publish list of group members to participants?"):
            for member in accepted:
                m_list = accepted[:]
                m_list.remove(member)
                send_packet(us.join(['i', group_name] + m_list), 'm', member)
    else:
        print("\nCreated an empty group %s.\n" % group_name)
    print('')

    if clear_input_screen:
        time.sleep(1)


def group_add_member(parameters):
    """
    Add member(s) to specified group. Create new group if group doesn't exist.

    :param parameters: Group name and list of new members to be separated
    :return:           None
    """

    input_validation((parameters, str))

    try:
        group_name = parameters.split()[2]
    except IndexError:
        raise FunctionReturn("Error: No group name specified.")

    if group_name not in get_list_of("groups"):
        raise FunctionReturn("Error: Unknown group.")

    purpaccs = set(parameters.split()[3:])
    if not purpaccs:
        raise FunctionReturn("Error: No members to add specified.")

    if group_name not in get_list_of("groups"):
        if yes("\nGroup %s was not found. Create new group?" % group_name):
            group_create(parameters)
        else:
            print("Group creation aborted.\n")
        return None

    purpaccs.discard("local")
    accounts = set(get_list_of("accounts"))
    before_a = set(get_list_of("members", group_name))
    ok_accos = set(accounts & purpaccs)
    new_in_g = set(ok_accos - before_a)

    e_asmbly = list(before_a | new_in_g)
    rejected = list(purpaccs - accounts)
    in_alrdy = list(before_a & purpaccs)
    new_in_g = list(new_in_g)

    e_asmbly.sort()
    rejected.sort()
    in_alrdy.sort()
    new_in_g.sort()

    if len(e_asmbly) > m_members_in_group:
        raise FunctionReturn("Error: TFC settings only allow %s members per "
                             "group." % m_members_in_group)

    send_packet(us.join(["GA", group_name] + list(ok_accos)), 'c')

    g_dictionary[group_name]["members"] = e_asmbly[:]
    run_as_thread(group_db, g_dictionary)

    g_mgmt_print("add-s", new_in_g, group_name)
    g_mgmt_print("add-a", in_alrdy, group_name)
    g_mgmt_print("unkwn", rejected, group_name)

    if new_in_g:
        if yes("Publish new list of members to involved?"):
            for member in before_a:
                send_packet(us.join(['n', group_name] + new_in_g), 'm', member)

            for member in new_in_g:
                m_list = e_asmbly[:]
                m_list.remove(member)
                send_packet(us.join(['i', group_name] + m_list), 'm', member)
        print('')

    if clear_input_screen:
        time.sleep(1)


def group_rm_member(parameters):
    """
    Remove specified member(s) from group. If no members
    are specified, overwrite and delete group file.

    :param parameters: Group name and list of accounts to remove
    :return:           None
    """

    input_validation((parameters, str))

    try:
        group_name = parameters.split()[2]
    except IndexError:
        raise FunctionReturn("No group name specified.")

    purpaccs = set(parameters.split()[3:])
    if not purpaccs:
        if not yes("\nRemove group '%s'?" % group_name):
            raise FunctionReturn("Group removal aborted.")

        send_packet(us.join(["GR", group_name]), 'c')

        if group_name not in get_list_of("groups"):
            raise FunctionReturn("TxM has no group %s to remove." % group_name)

        if get_list_of("members", group_name):
            if yes("Notify members about leaving the group?"):
                members = get_list_of("members", group_name)
                for member in members:
                    send_packet(us.join(['l', group_name]), 'm', member)

        if group_name in get_list_of("groups"):
            del g_dictionary[group_name]
            run_as_thread(group_db, g_dictionary)
            raise FunctionReturn("Removed group %s." % group_name)

    purpaccs.discard("local")
    accounts = set(get_list_of("accounts"))
    before_r = set(get_list_of("members", group_name))
    ok_accos = set(purpaccs & accounts)
    remove_l = set(before_r & ok_accos)

    e_asmbly = list(before_r - remove_l)
    not_in_g = list(ok_accos - before_r)
    rejected = list(purpaccs - accounts)
    remove_l = list(remove_l)

    not_in_g.sort()
    remove_l.sort()
    e_asmbly.sort()
    rejected.sort()

    send_packet(us.join(["GR", group_name] + list(ok_accos)), 'c')

    g_dictionary[group_name]["members"] = e_asmbly[:]
    run_as_thread(group_db, g_dictionary)

    g_mgmt_print("rem-s", remove_l, group_name)
    g_mgmt_print("rem-n", not_in_g, group_name)
    g_mgmt_print("unkwn", rejected, group_name)

    if remove_l and e_asmbly:
        if yes("Publish list of removed members to remaining members?"):
            for member in e_asmbly:
                send_packet(us.join(['r', group_name] + remove_l), 'm', member)
        print('')

    if clear_input_screen:
        time.sleep(1)


def g_mgmt_print(key, contacts, g_name=''):
    """
    Lists members at different parts of group management.

    :param key:      Key of string to print
    :param contacts: Members to list
    :param g_name:   Name of group
    :return:         None
    """

    input_validation((key, str), (contacts, list), (g_name, str))

    md = {"new-s": "Created new group '%s' with following members:" % g_name,
          "add-s": "Added following accounts to group '%s':" % g_name,
          "rem-s": "Removed following accounts from group '%s':" % g_name,
          "rem-n": "Following accounts were not in group '%s':" % g_name,
          "add-a": "Following accounts were already in group '%s':" % g_name,
          "unkwn": "Following unknown accounts were ignored:"}

    if contacts:
        print("\n%s " % md[key])
        for c in contacts:
            print("  * %s" % c)
        print('')


def print_group_details(params='', all_g=False, petc=True):
    """
    Print details about groups.

    :param params: Name of group to be separated
    :param all_g:  When True, prints details about all groups
    :param petc:   When False, does not ask user to press enter to continue
    :return:       None
    """

    input_validation((params, str), (all_g, bool), (petc, bool))

    if all_g:

        if not get_list_of("groups"):
            raise FunctionReturn("There are currently no groups.")

        print("\nAvailable groups and their members:\n")
        for g in get_list_of("groups"):
            l_status = {True: "on",
                        False: "off"}[g_dictionary[g]["logging"]]
            print("  %s (Logging %s)" % (g, l_status))
            members = get_list_of("members", g)
            if members:
                for m in members:
                    print("    %s" % c_dictionary[m]["nick"])
            else:
                print("    (empty)")
            print('')

    else:
        try:
            group = params.split()[1]
        except IndexError:
            if active_c['g']:
                group = active_c['g']
            else:
                raise FunctionReturn("No group specified.")

        if group not in get_list_of("groups"):
            raise FunctionReturn("Group %s does not exist." % group)

        members = get_list_of("members", group)
        if not members:
            raise FunctionReturn("Group %s is empty." % group)

        print("\nMembers in group %s:" % group)
        for m in members:
            print "  %s" % c_dictionary[m]["nick"]
        print('')

    if clear_input_screen and petc:
        raw_input(" Press <enter> to continue.")


###############################################################################
#                                    MISC                                     #
###############################################################################

def message_printer(message, spacing=False):
    """
    Print message in the middle of the screen.

    :param message: Message to print
    :param spacing: When true, prints empty lines around string
    :return:        None
    """

    input_validation((message, str), (spacing, bool))

    line_list = (textwrap.fill(message, get_tty_w() - 6)).split('\n')
    if spacing:
        print('')
    for l in line_list:
        c_print(l)
    if spacing:
        print('')


def c_print(string, spacing=False):
    """
    Print string to center of screen.

    :param string:  String to print
    :param spacing: When true, prints empty lines around string
    :return:        None
    """

    input_validation((string, str), (spacing, bool))

    if spacing:
        print('')
    print string.center(get_tty_w())
    if spacing:
        print('')


def ensure_dir(directory):
    """
    Ensure directory exists.

    :param directory: Specified directory
    :return:          None
    """

    input_validation((directory, str))

    name = os.path.dirname(directory)
    if not os.path.exists(name):
        os.makedirs(name)


def yes(prompt, wsl=0):
    """
    Prompt user a question that is answered with yes / no.

    :param prompt: Question to be asked
    :param wsl:    Trailing whitespace length
    :return:       True if user types 'y' or 'yes'
                   False if user types 'n' or 'no'
    """

    input_validation((prompt, str), (wsl, int))

    while prompt.startswith('\n'):
        print('')
        prompt = prompt[1:]

    wsl = 0 if wsl < 0 else wsl
    tws = wsl * ' ' if wsl > 0 else (54 - len(prompt)) * ' '
    string = "%s (y/n):%s" % (prompt, tws)

    while True:
        answer = raw_input(string)
        print_on_previous_line()

        if answer.lower() in "yes":
            print("%sYes" % string)
            return True

        elif answer.lower() in "no":
            print("%sNo" % string)
            return False

        else:
            continue


def new_password(purpose):
    """
    Prompt user to enter password and confirm it.

    :param purpose: Purpose of password
    :return:        Entered password
    """

    input_validation((purpose, str))

    print('')
    ind = (44 - len(purpose)) * ' '

    while True:
        pwd_first = getpass.getpass("Enter %s password: %s" % (purpose, ind))
        pwd_again = getpass.getpass("Repeat %s password:%s" % (purpose, ind))

        if pwd_first == pwd_again:
            return pwd_first

        print("\nError: Passwords did not match. Try again...\n")
        time.sleep(1.5)
        print_on_previous_line(5)


def run_as_thread(function, *args, **kwargs):
    """
    Run specified function as a thread.

    :param function: Target function to run as thread
    :param args:     Arguments for function run as thread
    :param kwargs:   Keyword arguments for function run as thread
    :return:         None
    """

    if not hasattr(function, "__call__"):
        raise CriticalError("First argument was not a function.")

    write_t = threading.Thread(target=function, args=args, kwargs=kwargs)
    write_t.start()
    write_t.join()


def phase(string, dist=61):
    """
    Print name of next phase. Next message (about completion), printed
    after the phase will be printed on same line as the name specified
    by 'string' at same distance regardless of leading newlines.

    :param string: String to be printed
    :param dist:   Indentation of completion message
    :return:       None
    """

    input_validation((string, str), (dist, int))

    n = sum('\n' in c for c in string)

    spaces = (dist - len(string) + n) * ' '
    sys.stdout.write(string + spaces)
    sys.stdout.flush()


def get_ms():
    """
    Get current system time.

    :return: System time in milliseconds
    """

    return int(round(time.time() * 1000))


def split_string(string, item_len):
    """
    Split string into list of specific length substrings.

    :param string:   String to split
    :param item_len: Length of list items
    :return:         String split to list
    """

    input_validation((string, str), (item_len, int))

    return [string[i:i + item_len] for i in xrange(0, len(string), item_len)]


def get_tty_w():
    """
    Get width of terminal Tx.py is running in.

    :return: Width of terminal
    """

    def ioctl_gwin_size(fd):
        """
        Get terminal window size from input/output control.

        :param fd: File descriptor
        :return:   Terminal width
        """

        return struct.unpack("hh", fcntl.ioctl(fd, termios.TIOCGWINSZ, "1234"))

    cr = ioctl_gwin_size(0) or ioctl_gwin_size(1) or ioctl_gwin_size(2)

    return int(cr[1])


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
                        help="Clear input screen after each message/command")

    parser.add_argument("-d",
                        action="store_true",
                        default=False,
                        dest="ddsockets",
                        help="Data diode simulator socket configuration")

    parser.add_argument("-l",
                        action="store_true",
                        default=False,
                        dest="local_t",
                        help="Enable local testing mode")

    parser.add_argument("-m",
                        action="store_true",
                        default=False,
                        dest="m_logging",
                        help="Enable TxM-side message logging by default")

    parser.add_argument("-p",
                        action="store_true",
                        default=False,
                        dest="d_space_e",
                        help="Panic exit with double space command")

    parser.add_argument("-t",
                        action="store_true",
                        default=False,
                        dest="trickle",
                        help="Enable trickle connection to hide metadata")

    args = parser.parse_args()

    global clear_input_screen
    global data_diode_sockets
    global local_testing_mode
    global txm_side_m_logging
    global double_space_exits
    global trickle_connection

    # Alias helps with code signing
    _true = True

    if args.clear_ip_s:
        clear_input_screen = _true

    if args.d_space_e:
        double_space_exits = _true

    if args.m_logging:
        txm_side_m_logging = _true

    if args.trickle:
        trickle_connection = _true

    if args.local_t:
        local_testing_mode = _true

    if args.ddsockets:
        data_diode_sockets = _true


def clear_screen():
    """
    Clear terminal window.

    :return: None
    """

    sys.stdout.write(cs + cc)


def print_on_previous_line(reps=1):
    """
    Next message will be printed on upper line.

    :param reps: Number of times to repeat function
    :return:     None
    """

    for _ in xrange(reps):
        print(cu + cl + cu)


def b58e(string):
    """
    Append checksum to string and encode result with Base58.
    The implementation used is identical to Bitcoin's WIF.

    :param string: String to encode
    :return:       Encoded string
    """

    input_validation((string, str))

    digest = hashlib.sha256(hashlib.sha256(string).digest()).digest()
    string = string + digest[:4]

    b58_chars = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    start_len = len(string)
    string = string.lstrip(b'\0')
    strip_len = len(string)

    p, acc = 1, 0
    for c in map(ord, string[::-1]):
        acc += p * c
        p <<= 8

    result = ''
    while acc > 0:
        acc, mod = divmod(acc, 58)
        result += b58_chars[mod]

    return (result + b58_chars[0] * (start_len - strip_len))[::-1]


def b58d(encoded):
    """
    Decode Base58 string and verify checksum.
    The implementation used is identical to Bitcoin's WIF.

    :param encoded: Encoded base58 string
    :return:        Decoded string
    """

    input_validation((encoded, str))

    if not isinstance(encoded, str):
        encoded = encoded.decode("ascii")

    b58_chars = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    start_len = len(encoded)
    encoded = encoded.lstrip(b58_chars[0])
    strip_len = len(encoded)

    p, acc = 1, 0
    for c in encoded[::-1]:
        acc += p * b58_chars.index(c)
        p *= 58

    result = []
    while acc > 0:
        acc, mod = divmod(acc, 256)
        result.append(mod)

    result = (''.join(map(chr, result)) + b'\0' * (start_len-strip_len))[::-1]

    result, check = result[:-4], result[-4:]
    digest = hashlib.sha256(hashlib.sha256(result).digest()).digest()

    if check != digest[:4]:
        raise ValueError

    return result


def b64e(string):
    """Alias for encoding data with Base64."""

    input_validation((string, str))
    return base64.b64encode(string)


def b64d(string):
    """Alias for decoding Base64 encoded data."""

    input_validation((string, str))
    return base64.b64decode(string)


def establish_socket():
    """
    Establish IPC between Tx.py and NH.py during local testing.

    :return: Client object
    """

    try:
        phase("Waiting for socket from NH.py...", 35)
        s_no = 5000 if data_diode_sockets else 5001
        try:
            client = multiprocessing.connection.Client(("localhost", s_no))

            print("Connection established.")
            time.sleep(0.75)
            print_on_previous_line()

            return client

        except socket.error:
            graceful_exit("Socket timeout.")

    except KeyboardInterrupt:
        graceful_exit()


def search_serial_interfaces():
    """
    Search serial interfaces.

    :return: Serial interface to use
    """

    if serial_usb_adapter:
        notified = False
        print_done = False

        while True:
            time.sleep(0.1)
            dev_files = os.listdir("/dev/")
            dev_files.sort()

            for dev_file in dev_files:
                if dev_file.startswith("ttyUSB"):
                    if print_done:
                        time.sleep(1)
                        print("Found")
                        time.sleep(1)
                    return "/dev/%s" % dev_file
            else:
                if not notified:
                    phase("\nSearching for USB-to-serial interface...")
                    notified = True
                    print_done = True

    else:
        dev_files = os.listdir("/dev/")
        dev_files.sort()

        integrated_if = "serial0" if rpi_os else "ttyS0"
        if integrated_if in dev_files:
            return "/dev/%s" % integrated_if
        graceful_exit("Error: /dev/%s was not found." % integrated_if)


def establish_serial():
    """
    Establish connection to serial interface.

    :return: Serial interface object
    """

    try:
        serial_nh = search_serial_interfaces()
        return serial.Serial(serial_nh, serial_iface_speed)
    except SerialException:
        graceful_exit("SerialException. Ensure $USER is in dialout group.")


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
        pass


def get_tab_complete_list():
    """
    Create list of words that tab-complete fills.

    :return: List of tab-complete words
    """

    tc_list = []

    dir_files = [f for f in os.listdir('.') if
                 os.path.isfile(os.path.join('.', f))]

    tfc_files = ["Tx.py", "Tx.pyc", "test_tx.py",
                 "Rx.py", "Rx.pyc", "test_rx.py",
                 "NH.py", "NH.pyc", "test_nh.py",
                 datab_file, ".rx_database",
                 login_file, ".rx_login_data",
                 group_file, ".rx_groups",
                 txlog_file, ".rx_logs",
                 ssh_l_file,
                 "tfc.desktop", "tfc-dd.desktop",
                 "hwrng.py", "dd.py", "setup.py",
                 "logo.png"]

    tc_list += list(set(dir_files) - set(tfc_files))

    tc_list += ["about", "add ", "all", "clear", "cmd", "create ", "exit",
                "export", "file", "group ", "help", "history", "localkey",
                "logging ", "msg ", "names", "nick ", "paste", "psk",
                "pubkeys", "reset", "rm ", "store ", "unread", "winpriv"]

    tc_list += [(str(c) + ' ') for c in get_list_of("accounts")]

    tc_list += [(str(n) + ' ') for n in get_list_of("nicks")]

    tc_list += [(str(g) + ' ') for g in get_list_of("groups")]

    tc_list += list(set(["%s " % c_dictionary[c]["user"]
                         for c in get_list_of("accounts")]))

    return tc_list


###############################################################################
#                               FILE SELECTION                                #
###############################################################################

def ask_path_gui(prompt_msg, get_file=False):
    """
    Prompt PSK path with Tkinter dialog. Fallback to CLI if not available.

    :param prompt_msg: Directory selection prompt
    :param get_file:   When True, prompts for path to file instead of directory
    :return:           Selected directory
    """

    input_validation((prompt_msg, str), (get_file, bool))

    try:
        if disable_gui_dialog:
            raise _tkinter.TclError

        root = Tkinter.Tk()
        root.withdraw()

        if get_file:
            f_path = tkFileDialog.askopenfilename(title=prompt_msg)
        else:
            f_path = tkFileDialog.askdirectory(title=prompt_msg)
        root.destroy()

        if not f_path:
            t = "File" if get_file else "Path"
            raise FunctionReturn("%s selection aborted." % t)

        return f_path

    except _tkinter.TclError:
        print('')
        return ask_path_cli(prompt_msg, get_file)


def ask_path_cli(prompt_msg, get_f=False):
    """
    Prompt file location / store dir for PSK with tab-complete supported CLI.

    :param get_f:      When true, prompts for file instead of directory
    :param prompt_msg: File/PSK selection prompt
    :return:           Selected directory
    """

    input_validation((prompt_msg, str), (get_f, bool))

    import readline

    class Completer(object):
        """Custom readline tab-completer."""

        @staticmethod
        def listdir(root):
            """Return list of subdirectories (and files)."""

            res = []
            for name in os.listdir(root):
                path = os.path.join(root, name)
                if os.path.isdir(path):
                    name += os.sep
                    res.append(name)
                elif get_f:
                    res.append(name)
            return res

        def complete_path(self, path=None):
            """Return list of directories."""

            # Return subdirectories
            if not path:
                return self.listdir('.')

            dirname, rest = os.path.split(path)
            tmp = dirname if dirname else '.'
            res = [os.path.join(dirname, p)
                   for p in self.listdir(tmp) if p.startswith(rest)]

            # Multiple directories, return list of dirs
            if len(res) > 1 or not os.path.exists(path):
                return res

            # Single directory, return list of files
            if os.path.isdir(path):
                return [os.path.join(path, p) for p in self.listdir(path)]

            # Exact file match terminates this completion
            return [path + ' ']

        def path_complete(self, args):
            """Return list of directories from current directory."""

            if not args:
                return self.complete_path('.')

            # Treat the last arg as a path and complete it
            return self.complete_path(args[-1])

        def complete(self, _, state):
            """Return complete options."""

            line = readline.get_line_buffer().split()
            return (self.path_complete(line) + [None])[state]

    comp = Completer()
    readline.set_completer_delims(" \t\n;")
    readline.parse_and_bind("tab: complete")
    readline.set_completer(comp.complete)

    if get_f:
        while True:
            try:
                path_to_file = raw_input("%s: " % prompt_msg)

                if not path_to_file:
                    print_on_previous_line()
                    raise KeyboardInterrupt

                if os.path.isfile(path_to_file):
                    if path_to_file.startswith("./"):
                        path_to_file = path_to_file[2:]
                    print('')
                    readline.set_completer_delims(default_delims)
                    return path_to_file

                print("\nFile selection error.\n")
                time.sleep(1.5)
                print_on_previous_line(4)

            except KeyboardInterrupt:
                print_on_previous_line()
                readline.set_completer_delims(default_delims)
                raise FunctionReturn("File selection aborted.")

    else:
        while True:
            try:
                directory = raw_input("%s: " % prompt_msg)

                if directory.startswith("./"):
                    directory = directory[2:]

                if directory.startswith('.'):
                    directory = directory[1:]

                if not directory.endswith(os.sep):
                    directory += os.sep

                if not os.path.isdir(directory):
                    print("\nError: Invalid directory\n")
                    time.sleep(1.5)
                    for _ in xrange(4):
                        print_on_previous_line()
                    continue

                readline.set_completer_delims(default_delims)
                return directory

            except KeyboardInterrupt:
                readline.set_completer_delims(default_delims)
                raise FunctionReturn("PSK path selection aborted.")


###############################################################################
#                               TRICKLE CONNECTION                            #
###############################################################################

class ConstantTime:
    """
    Constant time context manager.

    Decorates a function that is joined with a thread that sleeps for defined
    time. By keeping the sleep time higher than function run time, the running
    time of actual function is obfuscated.
    """

    def __init__(self, length):
        self.length = length
        if trickle_connection:
            self.length += random.SystemRandom().uniform(0, trickle_rand_delay)

        if long_packet_rand_d:
            self.length += random.SystemRandom().uniform(0, max_val_for_rand_d)

    def __enter__(self):
        self.timer = threading.Thread(target=time.sleep, args=[self.length])
        self.timer.start()

    def __exit__(self, exc_type, exc_value, traceback):
        if 0:
            print(exc_type, exc_value, traceback)  # Remove PEP8 warning

        self.timer.join()


def sender_process(account_list):
    """
    Load pre-processed and padded packets from queue, and output them while
    obfuscating quantity and schedule of actual communication.

    The sender process uses three queues to load packets from. The packets
    other processes put into queue are already padded to 255 bytes, thus
    loading the packet takes approximately constant time.

    Packets that are sent to contacts are loaded from three queues:
      1. Message queue (highest priority)
      2. File queue    (medium priority; used if no messages are available)
      3. Noise queue   (lowest priority; used if no messages/files are avail.)

    The choice between the queues is done with ~constant time check of states
    of message and file queue. The resulting booleans are used as indexes of
    a nested list (containing references to queues), the lookup time of which
    is constant time.

    As the procedures listed above are not perfectly constant time, the time
    they take are obfuscated by running them under constant time context
    manager, that returns 0.1 seconds (=much) later than execution of the
    actual function took. As the timing of context manager is not perfect,
    random delay between [0, trickle_rand_delay] (determined by /dev/urandom)
    is added for each constant time wait.

    Constant time context manager also helps hide varying times it takes to run
    packet_thread (user can choose not to log noise packets).

    Once the message has been loaded, it will be output to each contact under
    separate constant time context manager, that returns trickle_stat_delay
    seconds later (random delay is again added here). If long_packet_rand_d is
    enabled, even further delay is loaded from /dev/urandom, between
    [0, max_val_for_rand_d]. This randomness is intended to evade simple
    spam guards of IM servers, but as the nature of randomness is uniform, it
    can not obfuscate trickle connection from adversary that can perform simple
    statistical analysis on output delays.

    Between each packet sent to a member of account_list, a command or noise
    command is loaded from another list containing references to command queue
    or noise command queue. The correct queue is again evaluated by checking
    whether command queue has commands in it.

    The command packet is loaded and sent over same constant time window.
    Sending a command always causes pause in output messages, thus additional
    constant time for queue loading would not obfuscate the fact a command was
    output.

    The account_list is intentionally immutable with commands, to ensure user
    doesn't alter it and that way, reveal use times of TFC.

    :param account_list: List of trickle connection contacts
    :return:             [no return value]
    """

    while True:

        sys.stdout.write("\r%s\r" % (len(readline.get_line_buffer()) * ' '))

        with ConstantTime(0.1):

            mi = rm_queue.empty()
            si = rf_queue.empty()

            pq = [[rm_queue, rm_queue], [rf_queue, np_queue]][mi][si]
            m = pq.get()

        for account in account_list:
            with ConstantTime(trickle_stat_delay):
                packet_thread(m, account)

            with ConstantTime(trickle_stat_delay):
                ci = rc_queue.empty()
                cq = [rc_queue, nc_queue][ci]
                c = cq.get()
                packet_thread(c)


def noise_process(char):
    """
    Ensure noise queues have padded noise packets always available.

    :return: [no return value]
    """

    input_validation((char, str))

    q = {"f": np_queue, '5': nc_queue}[char]

    while True:
        if q.qsize() < 1000:
            q.put_nowait(padding(char))
        else:
            time.sleep(0.1)


def input_process(file_no, a_contact):
    """
    Get command, message or file content, pre-process long transmissions
    and place padded plaintext packets to rm_queue, rf_queue or rc_queue.

    The process separates loading time of long messages and files to ensure
    minimal effect on processing time of sender_process() that outputs data.

    :param file_no:  Stdin file
    :param a_contact Active contact details
    :return:         [no return value]
    """

    sys.stdin = os.fdopen(file_no)

    try:
        while True:

            # Refresh tab-complete list
            readline.set_completer(tab_complete)
            readline.parse_and_bind("tab: complete")

            if clear_input_screen:
                clear_screen()

            user_i = raw_input("Msg to %s: " % a_contact['n'])

            # Disabled commands
            for c in ["/msg", "/paste", "/group", "/psk",
                      "/rm", "/add", "/localkey"]:

                if user_i.startswith(c):
                    print("\nCommand is disabled during trickle mode.\n\n")
                    if clear_input_screen:
                        time.sleep(1)
                    user_i = ''
                    continue

            try:
                if user_i == '':
                    print_on_previous_line()

                # Remote commands
                elif user_i == "/exit":
                    exit_program()

                elif user_i == "  " and double_space_exits:
                    exit_program()

                elif user_i == "  " or user_i == "/clear":
                    clear_displays("SC")

                elif user_i == "/reset":
                    clear_displays("SR")

                elif user_i.startswith("/nick "):
                    change_nick(user_i)

                elif user_i.startswith("/logging "):
                    change_setting(user_i)

                elif user_i.startswith("/store "):
                    change_setting(user_i)

                elif user_i.startswith("/winpriv "):
                    change_setting(user_i)

                elif user_i == "/history":
                    access_history()

                elif user_i == "/export":
                    access_history(export=True)

                elif user_i == "/unread" or user_i == ' ':
                    send_packet("SA", 'c')

                elif user_i in ["/cmd", "//"]:
                    send_packet(us.join(["WS", "local"]), 'c')
                    raw_input("\nPress <Enter> to return.")
                    win = active_c['a'] if active_c['a'] else active_c['g']
                    send_packet(us.join(["WS", win]), 'c')
                    print_on_previous_line(3)

                # Local commands
                elif user_i.startswith("/help"):
                    print_help()

                elif user_i.startswith("/about"):
                    print_about()

                elif user_i == "/pubkeys":
                    pub_keys()

                elif user_i.startswith("/names"):
                    print_contact_list(spacing=True)

                # Packet cancel commands
                elif user_i == "/cm":
                    while not rm_queue.empty():
                        rm_queue.get()
                    rm_queue.put(padding('e'))

                elif user_i == "/cf":
                    while not rf_queue.empty():
                        rf_queue.get()
                    rf_queue.put(padding('E'))

                # File transmission
                elif user_i.startswith("/file"):
                    f_data = load_file_data(user_i)
                    send_packet(us.join(['p', f_data]), 'f')

                elif user_i.startswith('/'):
                    raise FunctionReturn("Invalid command.")

                else:
                    if active_c['g']:
                        send_packet(us.join(['g', active_c['g'], user_i]), 'm')

                    elif active_c['a']:
                        send_packet(us.join(['p', user_i]), 'm')

            except FunctionReturn:
                continue

    except KeyboardInterrupt:
        graceful_exit()


###############################################################################
#                             STANDARD CONNECTION                             #
###############################################################################

def get_normal_input():
    """
    Get input from user from raw_input() or stdin if paste mode is enabled.

    :return: Keyboard input from user
    """

    user_input = ''
    global pastemode

    string = "group " if active_c['g'] else ''
    prompt = "Msg to %s%s: " % (string, active_c['n'])

    if pastemode:
        try:
            clear_screen()
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
            clear_screen()
            pastemode = False
            print("Closing paste mode...\n\n%s\n" % prompt)
            time.sleep(0.25)
            clear_screen()
            return ''
    else:
        try:
            if clear_input_screen:
                clear_screen()

            try:
                user_input = raw_input(prompt)
            except EOFError:
                print('')
                pass

            if user_input == "/paste":
                pastemode = True
                return ''

        except (KeyboardInterrupt, ValueError):
            graceful_exit()

    return user_input


def main_loop():
    """
    Send a command or message to contact based on user_input content.

    :return: None
    """

    while True:
        try:
            # Refresh tab-complete list
            readline.set_completer(tab_complete)
            readline.parse_and_bind("tab: complete")

            # If user has removed last contact
            if not get_list_of("accounts"):
                add_new_contact()
                select_contact()

            # If user removes selected contact / group
            nick_list = get_list_of("nicks") + get_list_of("groups")
            if active_c['n'] not in nick_list:
                clear_screen()
                print("\n\nNo contact is currently active.\n")
                select_contact()

            user_i = get_normal_input()

            if user_i == '':
                print_on_previous_line()

            # Group management commands
            elif user_i == "/groups":
                print_group_details(all_g=True)

            elif user_i.startswith("/group create "):
                group_create(user_i)

            elif user_i.startswith("/group add "):
                group_add_member(user_i)

            elif user_i.startswith("/group rm "):
                group_rm_member(user_i)

            elif user_i.startswith("/group"):
                print_group_details(user_i)

            # Remote commands
            elif user_i.startswith("/msg "):
                change_recipient(user_i)

            elif user_i == "/exit":
                exit_program()

            elif user_i == "  " and double_space_exits:
                exit_program()

            elif user_i == "  " or user_i == "/clear":
                clear_displays("SC")

            elif user_i == "/reset":
                clear_displays("SR")

            elif user_i.startswith("/nick "):
                change_nick(user_i)

            elif user_i.startswith("/logging "):
                change_setting(user_i)

            elif user_i.startswith("/store "):
                change_setting(user_i)

            elif user_i.startswith("/winpriv "):
                change_setting(user_i)

            elif user_i.startswith("/rm "):
                rm_contact(user_i)

            elif user_i == "/history":
                access_history()

            elif user_i == "/export":
                access_history(export=True)

            elif user_i in ["/cf", "/cm"]:
                raise FunctionReturn("Error: Trickle connection is disabled.")

            elif user_i == "/unread" or user_i == ' ':
                send_packet("SA", 'c')

            elif user_i.startswith("/psk"):
                if active_c['g']:
                    raise FunctionReturn("Error: Group is selected.")
                if c_dictionary[active_c['a']]["txpk"] != "psk":
                    raise FunctionReturn("Error: ECDHE in use with %s."
                                         % active_c['n'])
                send_packet(us.join(["KR", active_c['a']]), 'c')

            elif user_i in ["/cmd", "//"]:
                send_packet(us.join(["WS", "local"]), 'c')
                raw_input("\nPress <Enter> to return.")
                win = active_c['a'] if active_c['a'] else active_c['g']
                send_packet(us.join(["WS", win]), 'c')
                print_on_previous_line(3)

            # Local commands
            elif user_i == "/help":
                print_help()

            elif user_i == "/about":
                print_about()

            elif user_i == "/pubkeys":
                pub_keys()

            elif user_i == "/names":
                print_contact_list(spacing=True)

            # Contact key management commands
            elif user_i.startswith("/localkey"):
                new_local_key()

            elif user_i.startswith("/add"):
                add_new_contact(user_i)

            # File transmission
            elif user_i == "/file":
                file_data = load_file_data(user_i)
                recipient_chooser(file_data, 'f')

            elif user_i.startswith('/'):
                raise FunctionReturn("Error: Invalid command.")

            else:
                # Message transmission
                recipient_chooser(user_i, 'm')

        except FunctionReturn:
            pass


###############################################################################
#                                     MAIN                                    #
###############################################################################

c_dictionary = dict()
g_dictionary = dict()
active_c = dict(a='', n='', g='')
ssh_l_file = ".ssh_login_data"
login_file = ".tx_login_data"
datab_file = ".tx_database"
group_file = ".tx_groups"
txlog_file = ".tx_logs"
sample_delay = 0.1
unit_test = False
cancel_lt = False
pastemode = False
trickle_q = False

rm_queue = multiprocessing.Queue()  # Real message queue
rf_queue = multiprocessing.Queue()  # Real file queue
rc_queue = multiprocessing.Queue()  # Real command queue
np_queue = multiprocessing.Queue()  # Noise packet queue
nc_queue = multiprocessing.Queue()  # Noise command queue

# Define VT100 codes and other constants
cu = "\x1b[1A"  # Move cursor up 1 line
cl = "\x1b[2K"  # Clear the entire line
cs = "\x1b[2J"  # Clear entire screen
cc = "\x1b[H"   # Move cursor to upper left corner
rs = '\x1e'     # Record delimiter character
us = '\x1f'     # Field delimiter character

if __name__ == "__main__":

    # Set default directory
    os.chdir(sys.path[0])

    process_arguments()

    # Determine platform
    pname = subprocess.check_output(["grep", "PRETTY_NAME", "/etc/os-release"])
    rpi_os = "Raspbian GNU/Linux" in pname

    # Select connection type to NH.py
    if local_testing_mode:
        ipc_nh = establish_socket()
    else:
        port_nh = establish_serial()

    if not os.path.isfile(login_file):
        new_master_pwd()

    # Initialize queues for data
    pwd_queue = multiprocessing.Queue()
    key_queue = multiprocessing.Queue()

    master_key = login_screen()

    # Initialize tab-complete
    import readline  # Import before curses causes issues with terminal resize
    readline.set_completer(tab_complete)
    readline.parse_and_bind("tab: complete")
    default_delims = readline.get_completer_delims()

    # If group database does not exist, fill it with noise groups.
    if not os.path.isfile(group_file):
        g_dictionary["dummy_group"] = dict(logging="False", members=[])
        run_as_thread(group_db, g_dictionary)

    # If database file does not exist, bootstrap it with local key.
    while not os.path.isfile(datab_file):
        try:
            new_local_key()
        except KeyboardInterrupt:
            graceful_exit()

    # Load contact data
    c_dictionary = contact_db()
    g_dictionary = group_db()

    # If no contacts are available, ask user to add one
    while not get_list_of("accounts"):
        try:
            add_new_contact()
        except FunctionReturn:
            pass

    if not trickle_connection:
        try:
            select_contact()
            main_loop()
        except KeyboardInterrupt:
            graceful_exit()

    else:
        trickle_q = True

        # Initialize noise message queues
        noisepp = multiprocessing.Process(target=noise_process, args='f')
        noisecp = multiprocessing.Process(target=noise_process, args='5')

        noisepp.start()
        noisecp.start()

        # Wait for noise message queues to fill
        while any([nq.qsize() != 1000 for nq in [np_queue, nc_queue]]):
            time.sleep(0.1)

        select_contact()

        # Initialize trickle connection
        if active_c['g']:
            acco_list = get_list_of("members", active_c['g'])
        else:
            acco_list = [active_c['a']]

        inptp = multiprocessing.Process(target=input_process,
                                        args=(sys.stdin.fileno(),
                                              active_c))

        sendp = multiprocessing.Process(target=sender_process,
                                        args=[acco_list])

        inptp.start()
        sendp.start()

        def p_kill():
            for process in [sendp, inptp, noisepp, noisecp]:
                process.terminate()
            graceful_exit()

        try:
            while True:
                time.sleep(0.01)
                for pr in [sendp, inptp, noisepp, noisecp]:
                    if not pr.is_alive():
                        p_kill()
        except KeyboardInterrupt:
            p_kill()
