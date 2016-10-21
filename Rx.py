#!/usr/bin/env python
# -*- coding: utf-8 -*-

# TFC 0.16.10 || Rx.py

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
import pipes
import random
import re
import serial
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

import hashlib
import nacl.secret
import nacl.exceptions
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

l_message_incoming = True   # False disables notification of long transmission

disp_opsec_warning = True   # False disables OPSEC warning when receiving files

n_m_notify_privacy = False  # Default privacy notif. setting for new contacts

new_msg_notify_dur = 1.0    # Number of seconds new msg notification appears

disable_gui_dialog = False  # True replaces Tkinter dialogs with CLI prompts


# File reception
store_file_default = False  # Default file storage setting for new contacts

store_copy_of_file = False  # True stores local copies of files sent to contact

auto_disable_store = True   # False keeps reception on after file is received


# Message logging
rxm_side_m_logging = False  # Default RxM-side logging setting for new contacts

log_noise_messages = False  # True enables RxM-side noise packet logging

# Database padding
m_members_in_group = 20     # Max number of groups (Tx.py must have same value)

m_number_of_groups = 20     # Max members in group (Tx.py must have same value)

m_number_of_accnts = 20     # Max number of accounts (Tx.py must have same val)


# Local testing
local_testing_mode = False  # True enables testing of TFC on a single computer


# Serial port
serial_usb_adapter = True   # False searches for integrated serial interface

serial_iface_speed = 19200  # The speed of serial interface in bauds per sec

e_correction_ratio = 5      # N/o byte errors serial datagrams can recover from


###############################################################################
#                               ERROR CLASSES                                 #
###############################################################################

class CriticalError(Exception):
    """A variety of errors during which Rx.py should gracefully exit."""

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
            if "local" in c_dictionary.keys():
                w_print([self.message])
            else:
                print("\n%s\n" % self.message)


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


def pbkdf2_hmac_sha256(key, rounds=1, salt=''):
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
    assert set(hash_hex).issubset("0123456789abcdef")

    return hash_hex


def auth_and_decrypt(account, origin, ct_tag, purp_hrc):
    """
    Authenticate Poly1305 MAC and decrypt XSalsa20 ciphertext.

    :param account:  The contact's account name (e.g. alice@jabber.org)
    :param origin:   Origin of packet (u=user, c=contact)
    :param ct_tag:   Encrypted packet (nonce + ciphertext + tag)
    :param purp_hrc: The purported hash ratchet counter for packet
    :return:         Plaintext message
    """

    input_validation((account, str), (origin, str),
                     (ct_tag, str), (purp_hrc, int))

    assert origin in ['u', 'c']

    hex_key = c_dictionary[account]["%s_key" % origin]

    verb_type = "commands" if account == "local" else "packets"
    direction = dict(u="sent to", c="from")[origin]
    nick_name = "TxM" if account == "local" else c_dictionary[account]["nick"]

    offset = purp_hrc - c_dictionary[account]["%s_harac" % origin]

    if offset > 0:

        print("Warning! Previous %s %s %s %s were not received.\n"
              % (offset, verb_type, direction, nick_name))

        for i in xrange(offset):
            print("%sRefreshing key: %s/%s" % (cu, (offset - i), offset))
            hex_key = pbkdf2_hmac_sha256(hex_key)

        print(cu + cl)

    secretbox = nacl.secret.SecretBox(binascii.unhexlify(hex_key))
    plaintext = secretbox.decrypt(ct_tag)

    if not unit_test:
        plaintext = rm_padding(plaintext)

    # Hash ratchet
    c_dictionary[account]["%s_key" % origin] = pbkdf2_hmac_sha256(hex_key)
    c_dictionary[account]["%s_harac" % origin] = (purp_hrc + 1)
    run_as_thread(contact_db, c_dictionary)

    return plaintext


def padding(string):
    """
    Pad input to always match the packet max size (255 bytes).

    Maximum input size for sent packets is 254 bytes: This ensures no dummy
    blocks are appended to sent plaintexts. Byte used in padding is determined
    by how much padding is needed.

    :param string: String to be padded
    :return:       Padded string
    """

    input_validation((string, str))

    assert len(string) <= 254

    length = 255 - (len(string) % 255)
    string += length * chr(length)

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


def encrypt_data(data):
    """
    Encrypt data with master key using XSalsa20-Poly1305.

    :param data: Plaintext data
    :return:     None
    """

    input_validation((data, str))

    s_box = nacl.secret.SecretBox(binascii.unhexlify(master_key))
    nonce = nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE)
    return b64e(s_box.encrypt(data, nonce))


def decrypt_data(ct_tag, key=''):
    """
    Authenticate and decrypt signed XSalsa20-Poly1305 ciphertext.

    :param ct_tag: Nonce, ciphertext and tag
    :param key:    Decryption key
    :return:       Plaintext data if MAC is OK. MAC fail raises exception.
    """

    input_validation((ct_tag, str), (key, str))

    key = key if key else master_key
    secretbox = nacl.secret.SecretBox(binascii.unhexlify(key))
    return secretbox.decrypt(ct_tag)


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
def kdk_input_process(file_no, _):
    """
    Ask user to input key decryption key for local key.

    :param file_no: Stdin file
    :param _:       Prevents handling file_no as iterable
    :return:        None
    """

    import os
    sys.stdin = os.fdopen(file_no)

    while True:
        try:
            clear_screen()
            message_printer("Received encrypted local key. Enter "
                            "local key decryption key from TxM:")
            print('\n')

            avg_key_len = 49 if local_testing_mode else 56
            indent = (get_tty_w() - avg_key_len) / 2
            kdk = raw_input(indent * ' ').replace(' ', '')

            try:
                kdk = binascii.hexlify(b58d(kdk))
            except ValueError:
                print("\nKey decryption key checksum fail. Try again.")
                time.sleep(1)
                continue

            if not validate_key(kdk):
                time.sleep(1)
                continue

            kdk_queue.put(kdk)
            pc_queue.put("terminate_kdk_input_process")
            time.sleep(1)

        except KeyboardInterrupt:
            print("Key decryption aborted.")
            time.sleep(1)
            pc_queue.put("terminate_kdk_input_process")


def process_local_key(packet):
    """
    Load key decryption key from kdk_queue, decrypt and install new local key.

    :param packet: Encrypted local key, header key and confirmation code in CT
    :return:       None
    """

    input_validation((packet, str))

    try:
        while kdk_queue.empty():
            time.sleep(0.1)
        kdk = kdk_queue.get()
    except KeyboardInterrupt:
        raise FunctionReturn("Local key decryption aborted.")

    try:
        secret_box = nacl.secret.SecretBox(binascii.unhexlify(kdk))
        key_set = secret_box.decrypt(packet)
    except nacl.exceptions.CryptoError:
        raise FunctionReturn("Error: Local key packet MAC fail.")

    packet_k = key_set[:64]
    header_k = key_set[64:-2]
    cnf_code = key_set[-2:]

    for key in [packet_k, header_k]:
        validate_key(key, "local key set")

    # Remove backlogs
    os.system("reset")
    import readline
    readline.clear_history()

    if local_testing_mode:
        # Clear clipboard if kdk was pasted
        root = Tkinter.Tk()
        root.withdraw()
        if b58e(binascii.unhexlify(kdk)) in root.clipboard_get():
            root.clipboard_clear()
        root.destroy()

    new_contact("local", "local", packet_k, header_k, "dummy_key", "dummy_key")
    run_as_thread(contact_db, c_dictionary)

    print("\nLocal key added. Confirmation code (to TxM): %s\n" % cnf_code)


# ECDHE
def display_pub_key(packet):
    """
    Display public key received from contact.

    :param packet: Packet containing public key
    :return:       None
    """

    input_validation((packet, str))

    pub_key = packet[0:64]
    origin = packet[64:65]
    account = packet[65:]

    if not validate_key(pub_key, output=False):
        raise FunctionReturn("Error: Received an invalid "
                             "public key from %s." % account)

    if origin == 'u':
        # Display cached pub key of contact when receiving copy of personal key
        # as it indicates user has initialized key exchange with that contact.
        if account in public_key_d.keys():
            if public_key_d[account]:
                clear_screen()
                print("\nPublic key for %s:\n  %s\n"
                      % (account, public_key_d[account]))

    elif origin == 'c':
        pk = b58e(binascii.unhexlify(pub_key))
        spc = {48: 8, 49: 7, 50: 5}[len(pk)]
        pk = pk if local_testing_mode else ' '.join(split_string(pk, spc))
        public_key_d[account] = pk[:]
        print("\nReceived public key from %s:\n  %s\n" % (account, pk))

    else:
        raise FunctionReturn("Error: Invalid public key origin.")


def ecdhe_command(packet):
    """
    Add contact defined in encrypted packet.

    :param packet: Packet to process
    :return:       None
    """

    input_validation((packet, str))

    try:
        header, account, nick, u_key, u_hek, c_key, c_hek = packet.split(us)
    except (ValueError, IndexError):
        raise FunctionReturn("Error: Received invalid packet from TxM.")

    for key in [u_key, u_hek, c_key, c_hek]:
        if not validate_key(key, output=False):
            raise FunctionReturn("Error: Received invalid key(s) from TxM.")

    public_key_d[account] = ''

    new_contact(account, nick, u_key, u_hek, c_key, c_hek)
    run_as_thread(contact_db, c_dictionary)

    w_print(["Added %s (%s)." % (nick, account)])


# PSK
def add_psk(parameters):
    """
    Import pre-shared key for a contact.

    :return: None
    """

    input_validation((parameters, str))

    try:
        account = parameters.split(us)[1]
    except IndexError:
        raise FunctionReturn("Error: Received invalid PSK command.")

    if account not in get_list_of("accounts"):
        raise FunctionReturn("Error: Unknown account %s." % account)

    nick = c_dictionary[account]["nick"]
    pskf = ask_file_path_gui("Select PSK for %s" % nick)

    key = open(pskf).readline()

    if len(key) != 288:
        raise FunctionReturn("Error: Invalid PSK data length. Aborting.")

    salt = key[:64]

    if not validate_key(salt, output=False):
        raise FunctionReturn("Error: Invalid salt in PSK. Aborting.")

    ct_tag = key[64:]

    plaintext = ''
    while True:
        password = getpass.getpass("Enter password: ")
        kdk = pbkdf2_hmac_sha256(password, rounds=65536, salt=salt)
        try:
            plaintext = decrypt_data(b64d(ct_tag), key=kdk)
        except nacl.exceptions.CryptoError:
            print("\nError: Invalid password.\n")
            time.sleep(1.5)
            print_on_previous_line(4)
            continue
        break

    if not plaintext:
        raise CriticalError("Invalid PSK.")

    c_dictionary[account]["c_key"] = plaintext[:64]
    c_dictionary[account]["c_hek"] = plaintext[64:]
    c_dictionary[account]["c_harac"] = 1
    run_as_thread(contact_db, c_dictionary)

    shell("shred -n 3 -z -u %s" % pipes.quote(pskf))

    print_on_previous_line()
    w_print(["Added rx-keys for %s (%s)." % (nick, account)])

    if os.path.isfile(pskf):
        w_print(["WARNING! Failed to shred keyfile for %s!" % account])
    else:
        w_print(["Successfully shredded keyfile for %s" % account])

    print("Warning! Physically destroy the keyfile transmission media\n"
          "to ensure forward secrecy and to prevent data exfiltration.\n")


def psk_command(packet):
    """
    Add PSK and contact defined in encrypted packet.

    :param packet: Packet to process
    :return:       None
    """

    input_validation((packet, str))

    try:
        header, account, nick, psk, hek = packet.split(us)

    except (ValueError, IndexError):
        raise FunctionReturn("Error: Received invalid packet from TxM.")

    for key in [psk, hek]:
        if not validate_key(key, output=False):
            raise FunctionReturn("Error: Received invalid key(s) from TxM.")

    if not validate_account(account):
        raise FunctionReturn("invalid account", output=False)

    c_key = "dummy_key"
    c_hek = "dummy_key"
    harac = 1

    # If new PSK is being issued, use existing keys and harac for contact
    if account in c_dictionary.keys():
        if c_dictionary[account]["c_key"] != "dummy_key":
            c_key = c_dictionary[account]["c_key"]
            c_hek = c_dictionary[account]["c_hek"]
            harac = c_dictionary[account]["c_harac"]

    new_contact(account, nick, psk, hek, c_key, c_hek, c_harac=harac)
    run_as_thread(contact_db, c_dictionary)
    w_print(["Added tx-keys for %s (%s)." % (nick, account)])


###############################################################################
#                               SECURITY RELATED                              #
###############################################################################

def validate_key(key, origin='', output=True):
    """
    Check that key is valid.

    :param key:    Key to validate
    :param origin: Origin of key
    :param output: When True, outputs message about error
    :return:       True/False depending on key validation
    """

    input_validation((key, str), (origin, str), (output, bool))

    if not set(key.lower()).issubset("0123456789abcdef"):
        if origin:
            raise CriticalError("Illegal character in %s." % origin)
        if output:
            print("Error: Illegal character in key.")
        return False

    if len(key) != 64:
        if origin:
            raise CriticalError("Illegal length in %s." % origin)
        if output:
            print("Error: Illegal key length.")
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


def graceful_exit(message='', queue=False):
    """
    Display a message and exit Rx.py.

    If queue is True, put an exit command to pc_queue
    so main loop can kill processes and exit Rx.py.

    :param: message: Message to print
    :param: queue:   Add command to pc_queue when True
    :return:         None
    """

    input_validation((message, str), (queue, bool))

    if queue and not unit_test:
        if message:
            print("%s\n" % message)
        pc_queue.put("exit")

    else:
        clear_screen()
        if message:
            print("%s\n" % message)
        print("Exiting TFC.\n")
        exit()


def write_log_entry(packet, account, origin):
    """
    Encrypt received packet with master key and add it to common logfile
    together with the associated account, nick, timestamp and possible group
    name. Together this data allows reconstruction of message logs while
    protecting not only confidentiality of log files, but metadata about each
    logged entry. If log_noise_messages is enabled, every noise packet IM
    contacts send is logged: this provides additional protection to metadata
    about quantity of communication.

    Rx.py logs both sent and received messages to log the entire conversation.
    As infiltrating malware could substitute content of displayed/logged
    messages, users who wish to audit their systems, can cross-compare their
    RxM log with TxM log of each participant of the conversation.

    The timestamp and origin headers are shorter than 255 bytes, thus they are
    concatenated with unit separator to reduce overhead in log files. This has
    no negative effect on security yet it saves 340 bytes per logged message.

    To protect possibly sensitive files that must not be logged, only
    placeholder data is logged about them. This helps hiding the amount of
    communication comparison with log file size and output packet count would
    otherwise reveal.

    :param packet:  The received plaintext assembly packet
    :param account: The account of the one sender ('me' for user)
    :param origin:  Origin of packet (u=user, c=contact)
    :return:        None
    """

    input_validation((packet, str), (account, str), (origin, str))

    ts = datetime.datetime.now().strftime(l_ts)
    to = us.join([ts, origin])

    pt = ''.join([(padding(i)) for i in [to, packet, account]])
    ct = encrypt_data(pt)

    open(rxlog_file, "a+").write("%s\n" % ct)


def access_history(parameters):
    """
    Decrypt and display/export log of sent messages on TxM/RxM.

    :param parameters: Account name and export setting to be separated
    :return:           None
    """

    input_validation((parameters, str))

    try:
        header, conversation, es = parameters.split(us)
        export = dict(e=True, d=False)[es]
    except (ValueError, IndexError, KeyError):
        raise FunctionReturn("Error: Invalid command.")

    if not os.path.isfile(rxlog_file):
        raise FunctionReturn("Error: Could not find '%s'." % rxlog_file)

    phase("Reading logfile...")
    log_data = open(rxlog_file).read().splitlines()
    print("Done.")

    if len(log_data) == 0:
        raise FunctionReturn("No messages in logfile.")

    phase("Decrypting logfile...")
    log_data = [decrypt_data(b64d(l)) for l in log_data]
    print("Done.")

    phase("Assembling logfile...")
    messages = []
    buffer_d = dict()

    ttyw = 79 if export else get_tty_w()
    hc = ttyw * '-' + '\n' if export else "\033[1m"
    tc = '\n' + ttyw * '-' if export else "\033[0m"

    for entry in log_data:
        to, packet, account = [rm_padding(i) for i in split_string(entry, 255)]
        ts, origin = to.split(us)

        if origin == 'u':
            nick = "Me"
        else:
            if account in c_dictionary:
                nick = c_dictionary[account]["nick"]
            else:
                nick = account

        if packet[:2] == "ap":
            if account != conversation:
                continue

            header = "%s%s %s: %s" % (hc, ts, nick, tc)
            messages.append("%s\n%s\n\n"
                            % (header, textwrap.fill(packet[3:], ttyw)))
            buffer_d[account] = ''

        elif packet[:2] == "ag":

            _, group, message = packet.split(us)
            if conversation != group:
                continue

            header = "%s%s %s: %s" % (hc, ts, nick, tc)
            messages.append("%s\n%s\n\n"
                            % (header, textwrap.fill(message, ttyw)))
            buffer_d[account] = ''

        elif packet[0] == 'b':
            buffer_d[account] = packet[1:]

        elif packet[0] == 'c':
            buffer_d[account] += packet[1:]

        elif packet[0] == 'd':
            buffer_d[account] += packet[1:]
            m_buffer = buffer_d[account]
            msg_key = m_buffer[-64:]
            payload = m_buffer[:-64]
            message = decrypt_data(b64d(payload), msg_key)
            message = zlib.decompress(message)
            buffer_d[account] = ''

            if message[0] == 'p':
                header = "%s%s %s: %s" % (hc, ts, nick, tc)
                messages.append("%s\n%s\n\n"
                                % (header, textwrap.fill(message[2:], ttyw)))

            elif message[0] == 'g':
                _, group, message = message.split(us)
                if conversation != group:
                    continue
                header = "%s%s %s: %s" % (hc, ts, nick, tc)
                messages.append("%s\n%s\n\n"
                                % (header, textwrap.fill(message, ttyw)))
    print("Done.")

    if not messages:
        raise FunctionReturn("No messages for %s." % conversation)

    messages.insert(0, "\nLogfile for %s:\n" % conversation)

    if export:
        f_name = "RxM - Plaintext log (%s)" % conversation
        open(f_name, "w+").write('\n'.join(messages))
        print("\nLog for %s exported into file '%s'.\n"
              % (conversation, f_name))
    else:
        clear_screen()
        for m in messages:
            print m


###############################################################################
#                             CONTACT MANAGEMENT                              #
###############################################################################

def rm_contact(parameters):
    """
    Remove account and keyfile from RxM.

    :param parameters: Contact's account to be separated
    :return:           None
    """

    input_validation((parameters, str))

    try:
        account = parameters.split(us)[1]
    except IndexError:
        raise FunctionReturn("Error: No account specified.")

    account_found = False
    if account in get_list_of("accounts"):
        account_found = True
        del c_dictionary[account]
        run_as_thread(contact_db, c_dictionary)
        w_print(["Removed %s from contacts." % account])
    else:
        w_print(["RxM has no %s to remove." % account])

    was_in_group = False
    for g in get_list_of("groups"):
        if account in g_dictionary[g]["members"]:
            g_dictionary[g]["members"].remove(account)
            was_in_group = True
            account_found = True
    if was_in_group:
        run_as_thread(group_db, g_dictionary)
        w_print(["Removed %s from group(s)." % account])
        print('')
    if account == active_window and account_found \
            or not get_list_of("accounts"):
        time.sleep(1.5)
        clear_screen()


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
        if g_name not in g_dictionary.keys():
            raise FunctionReturn("Error: Unknown group.")

        lst = [m for m in g_dictionary[g_name]["members"]
               if m != "dummy_member"]

    elif key == "gm_nicks":
        if g_name not in g_dictionary.keys():
            raise FunctionReturn("Error: Unknown group.")
        lst = [c_dictionary[m]["nick"] for m in get_list_of("members", g_name)]

    elif key == "windows":
        lst = ["local"] + get_list_of("accounts") + get_list_of("groups")

    else:
        raise KeyError

    lst.sort()
    return lst


###############################################################################
#                              WINDOW MANAGEMENT                              #
###############################################################################

def select_window(parameters):
    """
    Select window and load related messages.

    :param parameters: Window name to be separated
    :return:           None
    """

    input_validation((parameters, str))

    try:
        window = parameters.split(us)[1]
    except IndexError:
        raise FunctionReturn("Error: No window specified.")

    if window not in get_list_of("windows"):
        raise FunctionReturn("Error: Unknown window.")

    global active_window
    active_window = window

    clear_screen()
    unread_ctr_d[window] = 0

    if window not in window_log_d.keys():
        window_log_d[window] = []

    if not window_log_d[window]:
        if window in get_list_of("accounts"):
            print("New session for %s started." % c_dictionary[window]["nick"])
        elif window in get_list_of("groups"):
            print("New session for %s started." % window)
        elif window == "local":
            print("No commands have yet been issued.")
        print('')
        return None

    prev_ts = None
    for t in window_log_d[window]:
        msg_ts, sender, msg_l, ind = t

        if prev_ts is None:
            prev_ts = msg_ts

        if msg_ts.date() != prev_ts.date():
            m = "Day changed to %s." % msg_ts.date().strftime("%B %d %Y")
            w = textwrap.TextWrapper(width=get_tty_w())
            wrapped = w.fill(m)
            print("%s\n" % wrapped)
            prev_ts = msg_ts.date()

        # Determine nick
        if sender == "local":
            nick = "-!-"
        elif sender == "me":
            nick = "Me:"
        else:
            if sender not in c_dictionary:
                continue  # Ignore messages from removed contacts
            nick = "%s:" % c_dictionary[sender]["nick"]

        nick_l = ["Me:", "-*-"]

        if window in get_list_of("groups"):
            nick_l += ["%s:" % n for n in get_list_of("gm_nicks", window)]

        elif window in get_list_of("accounts"):
            nick_l += ["%s:" % c_dictionary[window]["nick"]]

        longest_nick = max(nick_l, key=len)
        m_origin = (len(longest_nick) - len(nick)) * ' ' + nick

        bolded = "\033[1m%s %s \033[0m" % (msg_ts.strftime("%H:%M"), m_origin)
        bi = len(bolded) - 8
        wrapper = textwrap.TextWrapper(width=max(1, (get_tty_w() - bi)))
        lines = wrapper.fill(msg_l[0]).split('\n')
        print(bolded + lines[0])
        for l in lines[1:]:
            print (bi * ' ' + l)

        # Additional elements in message list
        if len(msg_l) > 1:
            wrapper = textwrap.TextWrapper(
                initial_indent=bi * ' ' + ind,
                subsequent_indent=(bi + len(ind)) * ' ',
                width=max(1, (get_tty_w() - bi)))

            for m in msg_l[1:]:
                wrapped = wrapper.fill(m)
                print(wrapped)

        print('')


def w_print(msg_l, window="local", sender="local", ind=''):
    """
    Print message and add it to window message history dictionary.

    If window is not active, print temporary notification.

    :param msg_l:  List of messages to print on separate lines
    :param window: Window to show message in
    :param sender: Sender of message to window
    :param ind:    Indentation format
    :return:       None
    """

    input_validation((msg_l, list), (window, str),
                     (sender, str), (ind, str))

    cur_t = datetime.datetime.now()
    if window not in win_last_msg.keys():
        win_last_msg[window] = cur_t
    pre_t = win_last_msg[window]
    win_last_msg[window] = cur_t
    l_ctr = 0

    # Print day changes
    if pre_t.date() != cur_t.date():
        m = "Day changed to %s." % datetime.datetime.now().strftime("%B %d %Y")
        w = textwrap.TextWrapper(width=get_tty_w())
        wrapped = w.fill(m)
        l_ctr += (3 + wrapped.count('\n'))
        print("\n%s\n" % wrapped)

    # Initialize missing windows
    if window not in window_log_d.keys():
        window_log_d[window] = []
    window_log_d[window].append((cur_t, sender, msg_l, ind))

    if window != active_window:

        # Initialize unread message counter
        if window not in unread_ctr_d.keys():
            unread_ctr_d[window] = 0
        unread_ctr_d[window] += 1

        # Only print notification about received message
        if sender in c_dictionary \
                and c_dictionary[sender]["windowp"] \
                and sender not in ["me", "local"]:
            l_ctr += 1
            print('')

            if window in get_list_of("accounts"):
                nick = c_dictionary[window]["nick"]
            else:
                nick = window

            wrapped = textwrap.fill("\033[1m%s: %s unread message(s)\033[0m"
                                    % (nick, unread_ctr_d[window]),
                                    get_tty_w())
            l_ctr += (1 + wrapped.count('\n'))
            print(wrapped)

            if window == "local" and "local" not in c_dictionary.keys():
                return None

            time.sleep(new_msg_notify_dur)
            print_on_previous_line(l_ctr)
            return None

    # Determine nick
    if sender == "local":
        nick = "-!-"
    elif sender == "me":
        nick = "Me:"
    else:
        nick = "%s:" % c_dictionary[sender]["nick"]

    nick_l = ["Me:", "-*-"]

    if window in get_list_of("groups"):
        nick_l += ["%s:" % n for n in get_list_of("gm_nicks", window)]

    elif window in get_list_of("accounts"):
        nick_l += ["%s:" % c_dictionary[window]["nick"]]

    longest_nick = max(nick_l, key=len)
    m_origin = (len(longest_nick) - len(nick)) * ' ' + nick

    if window != active_window:
        if window in get_list_of("groups"):
            m_origin = "New message (%s > %s)" % (nick, window)
        elif window in get_list_of("accounts"):
            m_origin = "New message from %s" % nick

    bolded = "\033[1m%s %s \033[0m" % (cur_t.strftime("%H:%M"), m_origin)
    bi = len(bolded) - 8
    wrapper = textwrap.TextWrapper(width=max(1, (get_tty_w() - bi)))
    lines = wrapper.fill(msg_l[0]).split('\n')
    l_ctr += len(lines)
    print(bolded + lines[0])
    for l in lines[1:]:
        print (bi * ' ' + l)

    # Additional elements in message list
    if len(msg_l) > 1:
        wrapper = textwrap.TextWrapper(initial_indent=bi * ' ' + ind,
                                       subsequent_indent=(bi + len(ind)) * ' ',
                                       width=max(1, (get_tty_w() - bi)))
        for m in msg_l[1:]:
            wrapped = wrapper.fill(m)
            l_ctr += 1 + (wrapped.count('\n'))
            print(wrapped)

    l_ctr += 1
    print('')

    if window != active_window:
        time.sleep(new_msg_notify_dur)
        print_on_previous_line(l_ctr)


def notify_win_activity():
    """
    Briefly print list of windows that have unread messages.

    :return: None
    """

    a_list = get_list_of("accounts")
    g_list = get_list_of("groups")

    n_msg_win_lst = []
    for w in (a_list + g_list):
        if w in unread_ctr_d.keys():
            if unread_ctr_d[w] > 0:
                n_msg_win_lst.append(w)
        else:
            unread_ctr_d[w] = 0

    print ''
    l_ctr = 1

    if not n_msg_win_lst:
        wrapped = textwrap.fill("No unread messages.", get_tty_w())
        l_ctr += 1 + (wrapped.count('\n'))
        print wrapped

        time.sleep(new_msg_notify_dur)
        print_on_previous_line(l_ctr)
        raise FunctionReturn("no unread messages", output=False)

    wrapped = textwrap.fill("Unread messages:", get_tty_w())
    l_ctr += 1 + (wrapped.count('\n'))
    print(wrapped)

    full_list = [c_dictionary[a]["nick"] for a in a_list] + g_list
    longest = len(max(full_list, key=len))

    for a in a_list:
        if unread_ctr_d[a] > 0:
            nick = c_dictionary[a]["nick"]
            nick = (longest - len(nick)) * ' ' + nick
            msg = "  %s: %s" % (nick, unread_ctr_d[a])
            wrapped = textwrap.fill(msg, get_tty_w())
            l_ctr += 1 + (wrapped.count('\n'))
            print wrapped

    for g in get_list_of("groups"):
        if unread_ctr_d[g] > 0:
            g_name = (longest - len(g)) * ' ' + g
            msg = "  %s: %s" % (g_name, unread_ctr_d[g])
            wrapped = textwrap.fill(msg, get_tty_w())
            l_ctr += 1 + (wrapped.count('\n'))
            print wrapped

    time.sleep(new_msg_notify_dur)
    print_on_previous_line(l_ctr)


###############################################################################
#                             DATABASE MANAGEMENT                             #
###############################################################################

def new_contact(account, nick, u_key, u_hek, c_key, c_hek, c_harac=1):
    """
    Create new dictionary for contact and store it to database.

    :param account: The contact's account name (e.g. alice@jabber.org)
    :param nick:    Contact's nickname
    :param u_key:   Forward secret encryption key for sent messages
    :param u_hek:   Static header encryption key for sent messages
    :param c_key:   Forward secret encryption key for received messages
    :param c_hek:   Static header encryption key for received messages
    :param c_harac: Hash ratchet counter for contact's key
    :return:        None
    """

    input_validation((account, str), (nick, str), (u_key, str), (u_hek, str),
                     (c_key, str), (c_hek, str), (c_harac, int))

    win_n_p = n_m_notify_privacy
    storing = store_file_default
    logging = rxm_side_m_logging
    if account in c_dictionary.keys():
        win_n_p = c_dictionary[account]["windowp"]
        storing = c_dictionary[account]["storing"]
        logging = c_dictionary[account]["logging"]

    c_dictionary[account] = dict(nick=nick,
                                 u_harac=1, c_harac=c_harac,
                                 u_key=u_key, u_hek=u_hek,
                                 c_key=c_key, c_hek=c_hek,
                                 windowp=win_n_p,
                                 storing=storing,
                                 logging=logging)

    # Remove one dummy account
    for k in c_dictionary.keys():
        if k.startswith("dummy_account"):
            del c_dictionary[k]
            break

    run_as_thread(contact_db, c_dictionary)

    for oh in ['u', 'c']:
        for di in [l_m_incoming, l_f_incoming, l_m_received, l_f_received]:
            di[oh + account] = False
        for di in [l_m_p_buffer, l_f_p_buffer]:
            di[oh + account] = ''

    if account not in window_log_d.keys():
        window_log_d[account] = []
    if account not in unread_ctr_d.keys():
        unread_ctr_d[account] = 0
    if account not in win_last_msg.keys():
        win_last_msg[account] = datetime.datetime.now()


def contact_db(write_db=None):
    """
    Manage encrypted database for contacts and their keys.

    :param write_db: If provided, write new database to file.
    :return:         None if write is specified, else database dictionary.
    """

    keys = ["nick", "u_harac", "c_harac", "u_key", "u_hek",
            "c_key", "c_hek", "windowp", "storing", "logging"]

    os.system("touch %s" % datab_file)

    if write_db is None:
        acco_d = dict()
        f_data = open(datab_file).readline().strip('\n')
        if f_data:
            try:
                pt_data = decrypt_data(b64d(f_data))
            except nacl.exceptions.CryptoError:
                raise CriticalError("Contact database MAC failed.")
            except TypeError:
                raise CriticalError("Contact database B64 decoding failed.")

            acco_l = split_string(pt_data, 255 * (len(keys) + 1))
            for a in acco_l:
                a_data = [rm_padding(p) for p in split_string(a, 255)]
                if not a_data[0].startswith("dummy_account"):
                    acco_d[a_data[0]] = dict(zip(keys, a_data[1:]))
                    acco_d[a_data[0]]["u_harac"] = int(a_data[2])
                    acco_d[a_data[0]]["c_harac"] = int(a_data[3])
                    acco_d[a_data[0]]["windowp"] = (a_data[8] == "True")
                    acco_d[a_data[0]]["storing"] = (a_data[9] == "True")
                    acco_d[a_data[0]]["logging"] = (a_data[10] == "True")

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
        f.write(encrypt_data(plaintext))


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
            try:
                groups = decrypt_data(b64d(f_data)).split(rs)
            except nacl.exceptions.CryptoError:
                raise CriticalError("Group database MAC failed.")
            except TypeError:
                raise CriticalError("Group database B64 decoding failed.")

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
        f.write(encrypt_data(rs.join(records)))


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
        group_name = parameters.split(us)[1]
    except IndexError:
        raise FunctionReturn("No group name specified.")

    accounts = set(get_list_of("accounts"))
    purpaccs = set(parameters.split(us)[2:])
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

    g_dictionary[group_name] = dict(logging=rxm_side_m_logging,
                                    members=accepted[:])
    run_as_thread(group_db, g_dictionary)

    g_mgmt_print("new-s", accepted, group_name)
    g_mgmt_print("unkwn", rejected, group_name)

    if not accepted:
        w_print(["Created an empty group %s." % group_name])
    window_log_d[group_name] = []
    win_last_msg[group_name] = datetime.datetime.now()


def group_add_member(parameters):
    """
    Add member(s) to specified group.

    :param parameters: Group name and list of new members to be separated
    :return:           None
    """

    input_validation((parameters, str))

    try:
        group_name = parameters.split(us)[1]
    except IndexError:
        raise FunctionReturn("Error: No group name specified.")

    if group_name not in get_list_of("groups"):
        raise FunctionReturn("Error: Unknown group.")

    purpaccs = set(parameters.split(us)[2:])
    if not purpaccs:
        raise FunctionReturn("Error: No members to add specified.")

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

    g_dictionary[group_name]["members"] = e_asmbly[:]
    run_as_thread(group_db, g_dictionary)

    g_mgmt_print("add-s", new_in_g, group_name)
    g_mgmt_print("add-a", in_alrdy, group_name)
    g_mgmt_print("unkwn", rejected, group_name)


def group_rm_member(parameters):
    """
    Remove specified member(s) from group. If no members
    are specified, overwrite and delete group file.

    :param parameters: Group name and list of accounts to remove
    :return:           None
    """

    input_validation((parameters, str))

    try:
        group_name = parameters.split(us)[1]
    except IndexError:
        raise FunctionReturn("No group name specified.")

    purpaccs = set(parameters.split(us)[2:])
    if not purpaccs:
        if group_name in get_list_of("groups"):
            del g_dictionary[group_name]
            run_as_thread(group_db, g_dictionary)
            raise FunctionReturn("Removed group %s." % group_name)
        else:
            raise FunctionReturn("RxM has no group %s to remove." % group_name)

    if group_name not in get_list_of("groups"):
        raise FunctionReturn("Error: Unknown group.")

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

    g_dictionary[group_name]["members"] = e_asmbly[:]
    run_as_thread(group_db, g_dictionary)

    g_mgmt_print("rem-s", remove_l, group_name)
    g_mgmt_print("rem-n", not_in_g, group_name)
    g_mgmt_print("unkwn", rejected, group_name)


def g_mgmt_print(key, contacts, g_name):
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
        w_print([md[key]] + contacts, ind="  * ")


###############################################################################
#                                    MISC                                     #
###############################################################################

def message_printer(message):
    """Print message in the middle of the screen."""

    input_validation((message, str))

    line_list = (textwrap.fill(message, get_tty_w() - 6)).split('\n')
    for l in line_list:
        c_print(l)


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


def shell(cmd):
    """
    Run terminal command in shell.

    :param cmd: Command to run
    :return:    None
    """

    subprocess.Popen(cmd, shell=True).wait()


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


def c_print(string, e_lines=False):
    """
    Print string to center of screen.

    :param string:  String to print
    :param e_lines: When true, prints empty lines around string
    :return:        None
    """

    input_validation((string, str), (e_lines, bool))

    if e_lines:
        print('')
    print string.center(get_tty_w())
    if e_lines:
        print('')


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
    Get width of terminal Rx.py is running in.

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
    Define Rx.py settings from arguments passed from command line.

    :return: None
    """

    parser = argparse.ArgumentParser("python Rx.py",
                                     usage="%(prog)s [OPTION]",
                                     description="More options inside Rx.py")

    parser.add_argument("-a", action="store_true",
                        default=False,
                        dest="auto_close_fr",
                        help="Auto-close file reception after receiving file")

    parser.add_argument("-f",
                        action="store_true",
                        default=False,
                        dest="f_save",
                        help="Enable file reception for "
                             "new contacts by default")

    parser.add_argument("-i",
                        action="store_true",
                        default=False,
                        dest="l_t_notify",
                        help="Do not notify about incoming long transmissions")

    parser.add_argument("-k",
                        action="store_true",
                        default=False,
                        dest="keep_l_f",
                        help="Enable storage of locally received files")

    parser.add_argument("-l", action="store_true",
                        default=False,
                        dest="local_t",
                        help="Enable local testing mode")

    parser.add_argument("-m",
                        action="store_true",
                        default=False,
                        dest="m_logging",
                        help="Enable message logging for "
                             "new contacts by default")

    args = parser.parse_args()

    global auto_disable_store
    global store_file_default
    global store_copy_of_file
    global l_message_incoming
    global local_testing_mode
    global rxm_side_m_logging

    # Alias helps with publish automation
    _true = True

    if args.l_t_notify:
        l_message_incoming = _true

    if args.f_save:
        store_file_default = _true

    if args.keep_l_f:
        store_copy_of_file = _true

    if args.m_logging:
        rxm_side_m_logging = _true

    if args.local_t:
        local_testing_mode = _true

    if args.auto_close_fr:
        auto_disable_store = _true


def clear_screen():
    """
    Clear terminal window.

    :return: None
    """

    print(cs + cc + cu)


def reset_screen(parameters):
    """
    Reset terminal window and clear message history from it.

    :param parameters: Window name to be separated
    :return:           None
    """

    input_validation((parameters, str))

    try:
        window = parameters.split(us)[1]
    except IndexError:
        raise FunctionReturn("Error: Missing window for reset command.")

    if window not in window_log_d.keys():
        raise FunctionReturn("Error: Unknown window for reset command.")

    os.system("reset")
    window_log_d[window] = []


def print_on_previous_line(repeat=1):
    """
    Next message will be printed on upper line.

    :param repeat: Defines how many previous lines are overwritten
    :return:       None
    """

    for _ in range(repeat):
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
        return serial.Serial(serial_nh, serial_iface_speed, timeout=0.01)
    except SerialException:
        graceful_exit("SerialException. Ensure $USER is in dialout group.")


###############################################################################
#                               FILE SELECTION                                #
###############################################################################

def ask_file_path_gui(prompt_m):
    """
    Prompt for file path with Tkinter dialog. Fallback to CLI if Tkinter is not
    available.

    :param prompt_m: File selection prompt
    :return:         Path to file
    """

    input_validation((prompt_m, str))

    try:
        if disable_gui_dialog:
            raise _tkinter.TclError

        root = Tkinter.Tk()
        root.withdraw()
        path_to_file = tkFileDialog.askopenfilename(title=prompt_m)
        root.destroy()

        if not path_to_file:
            raise FunctionReturn("PSK selection aborted.")
        return path_to_file

    except _tkinter.TclError:

        while not pth_queue.empty():
            pth_queue.get()

        pc_queue.put("start_ask_file_path_cli_process%s%s" % (us, prompt_m))

        while True:
            try:
                while pth_queue.empty():
                    time.sleep(0.1)
                path = pth_queue.get()
                if path == us:  # Non printable '\x1f' used to signify abort
                    print('')
                    print_on_previous_line()
                    pc_queue.put("termitate_ask_file_path_gui_process")
                    raise FunctionReturn("PSK selection aborted.")
                else:
                    pc_queue.put("termitate_ask_file_path_gui_process")
                    return path

            except KeyboardInterrupt:
                pass


def ask_psk_path_cli(prompt_m):
    """
    Prompt for file path from LUI. Tab-complete is supported.

    :param prompt_m: File selection prompt
    :return:         Path to file
    """

    input_validation((prompt_m, str))

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
            return res

        def complete_path(self, path=None):
            """Return list of directories (and files)."""

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
            """Return list of directories and files from current directory."""

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

    while True:
        try:
            path_to_file = raw_input("%s: " % prompt_m)

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
            print('')
            print_on_previous_line()
            readline.set_completer_delims(default_delims)
            raise FunctionReturn("PSK selection aborted.", output=False)


def cli_input_process(file_no, prompt_m):
    """
    Relay file path prompted with cli_input via pth_queue to main_loop process.

    :param file_no:  Stdin file
    :param prompt_m: File selection prompt
    :return:         [No return value]
    """

    try:
        import os
        sys.stdin = os.fdopen(file_no)
        pth_queue.put(ask_psk_path_cli(prompt_m))

    except (KeyboardInterrupt, FunctionReturn):
        pth_queue.put(us)


###############################################################################
#                               ENCRYPTED PACKETS                             #
###############################################################################

def packet_decryption(packet):
    """
    Process and decrypt received packet.

    :param packet: Packet to process
    :return:       None
    """

    input_validation((packet, str))

    enc_harac = packet[0:48]
    enc_packet = packet[48:343]
    origin = packet[343:344]
    account = packet[344:]

    if account not in c_dictionary.keys():
        raise FunctionReturn("Error: Received packet from unknown account.")

    nick = c_dictionary[account]["nick"]

    if origin not in ['u', 'c']:
        raise FunctionReturn("Error: Received packet to/from %s had "
                             "invalid origin-header." % nick)

    direction = dict(u="sent to", c="from")[origin]

    header_k = c_dictionary[account]["%s_hek" % origin]
    if header_k is "dummy_key":  # Catches mainly unimported PSKs of contacts
        raise FunctionReturn("Error: Received packet %s %s but no key exists."
                             % (direction, account))

    try:
        harac_b = decrypt_data(enc_harac, header_k)
        harac_d = struct.unpack("!Q", harac_b)[0]
    except nacl.exceptions.CryptoError:
        raise FunctionReturn("Warning! Received packet %s %s had "
                             "bad hash ratchet MAC." % (direction, nick))

    if harac_d < c_dictionary[account]["%s_harac" % origin]:
        raise FunctionReturn("Warning! Received packet %s %s had old hash "
                             "ratchet counter value." % (direction, nick))

    try:
        pt = auth_and_decrypt(account, origin, enc_packet, harac_d)
    except nacl.exceptions.CryptoError:
        raise FunctionReturn("Warning! Received packet %s %s had bad "
                             "packet MAC." % (direction, nick))

    assemble_packet(pt, account, origin)


def assemble_packet(packet, account, origin):
    """
    Assemble packet (message/file/command) received from TxM / contact.

    :param packet:  Assembly packet data
    :param account: The contact's account name (e.g. alice@jabber.org)
    :param origin:  Origin of packet (u=user, c=contact)
    :return:        None
    """

    input_validation((packet, str), (account, str), (origin, str))

    if account == "local":
        try:
            f = {'0': short_command,
                 '1': long_command_start,
                 '2': long_command_append,
                 '3': long_command_end,
                 '4': long_command_cancel,
                 '5': noise_command}[packet[0]]
        except KeyError:
            raise FunctionReturn(
                "Error: Received command with incorrect header.")

        f(packet)
        process_received_command()

    else:
        try:
            f = {'a': short_message,
                 'A': short_file,
                 'b': long_message_start,
                 'B': long_file_start,
                 'c': long_message_append,
                 'C': long_file_append,
                 'd': long_message_end,
                 'D': long_file_end,
                 'e': long_message_cancel,
                 'E': long_file_cancel,
                 'f': noise_packet}[packet[0]]
        except KeyError:
            raise FunctionReturn(
                "Error: Received packet with incorrect header.")

        logged_p = (255 * 'A') if packet[0].isupper() else packet

        if packet[0] in "abcdeABCDE" and c_dictionary[account]["logging"]:
            write_log_entry(logged_p, account, origin)

        if packet[0] == 'f' and log_noise_messages:
            write_log_entry(logged_p, account, origin)

        f(packet, account, origin)

        try:
            process_received_messages(account, origin)
        except FunctionReturn:
            pass

        try:
            process_received_files(account, origin)
        except FunctionReturn:
            pass


###############################################################################
#                            PROCESS ASSEMBLY PACKET                          #
###############################################################################

def noise_packet(packet, account, origin):
    """
    Process noise packet.

    :param packet:  Packet to process
    :param account: The contact's account name (e.g. alice@jabber.org)
    :param origin:  Origin of packet (u=user, c=contact)
    :return:        None
    """

    input_validation((packet, str), (account, str), (origin, str))

    n = c_dictionary[account]["nick"]

    if l_m_incoming[origin + account] and origin == 'c':
        w_print(["%s cancelled long message." % n], account)

    l_m_received[origin + account] = False
    l_m_incoming[origin + account] = False
    l_m_p_buffer[origin + account] = ''


def noise_command(_):
    """
    Process noise command packet.

    Discard long commands being received from local TxM.

    :return: None
    """

    if l_c_incoming["local"]:
        print("Long command from local TxM cancelled.\n")

    if l_c_incoming["local"]:
        l_c_received["local"] = False
        l_c_incoming["local"] = False
        l_c_p_buffer["local"] = ''


def long_message_cancel(packet, account, origin):
    """
    Process cancel message packet.

    Discard long messages being received from sender.

    :param packet:  Packet to process
    :param account: The contact's account name (e.g. alice@jabber.org)
    :param origin:  Origin of packet (u=user, c=contact)
    :return:        None
    """

    input_validation((packet, str), (account, str), (origin, str))

    n = c_dictionary[account]["nick"]

    if l_m_incoming[origin + account] and origin == 'c':
        w_print(["%s cancelled long message." % n])
    if l_m_incoming[origin + account] and origin == 'u':
        w_print(["Long message to %s cancelled." % n])

    l_m_incoming[origin + account] = False
    l_m_received[origin + account] = False
    l_m_p_buffer[origin + account] = ''


def long_file_cancel(packet, account, origin):
    """
    Process cancel file packet.

    :param packet:  Packet to process
    :param account: The contact's account name (e.g. alice@jabber.org)
    :param origin:  Origin of packet (u=user, c=contact)
    :return:        None
    """

    input_validation((packet, str), (account, str), (origin, str))

    n = c_dictionary[account]["nick"]

    if origin == 'c':
        w_print(["%s cancelled file transmission." % n])
    if origin == 'u':
        w_print(["File transmission to %s cancelled." % n])

    if l_f_incoming[origin + account]:
        l_f_incoming[origin + account] = False
        l_f_received[origin + account] = False
        l_f_p_buffer[origin + account] = ''


def long_command_cancel(_):
    """
    Process cancel command packet.

    :return: None
    """

    if l_c_incoming["local"]:
        w_print(["Long command from local TxM cancelled."])

        l_c_received["local"] = True
        l_c_incoming["local"] = False
        l_c_p_buffer["local"] = ''


def short_message(packet, account, origin):
    """
    Process short message packet.

    Strip header from packet and add message to l_m_p_buffer.

    :param packet:  Packet to process
    :param account: The contact's account name (e.g. alice@jabber.org)
    :param origin:  Origin of packet (u=user, c=contact)
    :return:        None
    """

    input_validation((packet, str), (account, str), (origin, str))

    n = c_dictionary[account]["nick"]

    if l_m_incoming[origin + account] and origin == 'c':
        w_print(["%s cancelled long message." % n], account, account)

    l_m_received[origin + account] = True
    l_m_incoming[origin + account] = False
    l_m_p_buffer[origin + account] = packet[1:]


def short_file(packet, account, origin):
    """
    Process short file packet.

    Strip header from packet and add file to l_m_p_buffer.

    :param packet:  Packet to process
    :param account: The contact's account name (e.g. alice@jabber.org)
    :param origin:  Origin of packet (u=user, c=contact)
    :return:        None
    """

    input_validation((packet, str), (account, str), (origin, str))

    n = c_dictionary[account]["nick"]
    a = account

    if c_dictionary[account]["storing"]:
        if l_f_incoming[origin + account] and origin == 'c':
            w_print(["%s cancelled file transmission." % n], a, a)

        l_f_received[origin + account] = True
        l_f_incoming[origin + account] = False
        l_f_p_buffer[origin + account] = packet[1:]

    else:
        if origin == 'c':
            w_print(["%s is sending file but storing is disabled." % n], a)

        elif origin == 'u' and store_copy_of_file:
            w_print(["Receiving sent file but storing is disabled."], a)


def short_command(packet):
    """
    Process short command packet.

    Strip header from packet and add command to c_dictionary.

    :param packet: Packet to process
    :return:       None
    """

    input_validation((packet, str))

    if l_c_incoming["local"]:
        w_print(["Long command from local TxM cancelled."])

    l_c_received["local"] = True
    l_c_incoming["local"] = False
    l_c_p_buffer["local"] = packet[1:]


def long_message_start(packet, account, origin):
    """
    Process first packet of long message.

    Strip header from packet and add first part of message to l_m_p_buffer.

    :param packet:  Packet to process
    :param account: The contact's account name (e.g. alice@jabber.org)
    :param origin:  Origin of packet (u=user, c=contact)
    :return:        None
    """

    input_validation((packet, str), (account, str), (origin, str))

    n = c_dictionary[account]["nick"]

    if origin == 'c':
        if l_m_incoming[origin + account]:
            w_print(["%s cancelled long message." % n], account)

        if l_message_incoming:
            w_print(["Incoming long message from %s." % n], account)

    l_m_received[origin + account] = False
    l_m_incoming[origin + account] = True
    l_m_p_buffer[origin + account] = packet[1:]


def long_file_start(packet, account, origin):
    """
    Process first packet of file.

    Strip header from packet and add first part of file to l_f_p_buffer.
    Print details about file being received.

    :param packet:  Packet to process
    :param account: The contact's account name (e.g. alice@jabber.org)
    :param origin:  Origin of packet (u=user, c=contact)
    :return:        None
    """

    input_validation((packet, str), (account, str), (origin, str))

    n = c_dictionary[account]["nick"]
    a = account

    l_f_received[origin + account] = False

    if c_dictionary[account]["storing"]:
        if l_f_incoming[origin + account] and origin == 'c':
            w_print(["%s cancelled file transmission." % n], a)

        try:
            header, name, size, eta, data = packet.split(us)
        except ValueError:
            l_f_incoming[origin + account] = False
            l_f_p_buffer[origin + account] = ''
            raise FunctionReturn("Received file packet with illegal header.")

        if origin == 'u' and store_copy_of_file:
            w_print(["Receiving copy of %s sent to %s." % (name, n)], a, a)

        if origin == 'c':
            w_print(["Incoming file from %s " % n,
                     "%s (%s)" % (name, size),
                     "ETA: %s" % eta],
                    a, a, "  ")

        l_f_incoming[origin + account] = True
        l_f_p_buffer[origin + account] = packet[1:]

    else:
        if origin == 'c':
            w_print(["%s is sending file but storing is disabled." % n], a)

        elif origin == 'u' and store_copy_of_file:
            w_print(["Receiving sent file but storing is disabled."], a)


def long_command_start(packet):
    """
    Process first packet of long command.

    Strip header from packet and add first part of command to c_dictionary.

    :param packet: Packet to process
    :return:       None
    """

    input_validation((packet, str))

    if l_c_incoming["local"]:
        print("\nCommand from TxM cancelled.")

    l_c_received["local"] = False
    l_c_incoming["local"] = True
    l_c_p_buffer["local"] = packet[1:]


def long_message_append(packet, account, origin):
    """
    Process appended packet to message.

    Strip header from packet and append part of message to l_m_p_buffer.

    :param packet:  Packet to process
    :param account: The contact's account name (e.g. alice@jabber.org)
    :param origin:  Origin of packet (u=user, c=contact)
    :return:        None
    """

    input_validation((packet, str), (account, str), (origin, str))

    l_m_received[origin + account] = False
    l_m_incoming[origin + account] = True
    l_m_p_buffer[origin + account] += packet[1:]


def long_file_append(packet, account, origin):
    """
    Process appended packet to file.

    Strip header from packet and append part of file to l_f_p_buffer.

    :param packet:  Packet to process
    :param account: The contact's account name (e.g. alice@jabber.org)
    :param origin:  Origin of packet (u=user, c=contact)
    :return:        None
    """

    input_validation((packet, str), (account, str), (origin, str))

    if c_dictionary[account]["storing"]:
        l_f_received[origin + account] = False
        l_f_incoming[origin + account] = True
        l_f_p_buffer[origin + account] += packet[1:]


def long_command_append(packet):
    """
    Process appended packet to command.

    Strip header from packet and append part of command to c_dictionary.

    :param packet: Packet to process
    :return:       None
    """

    input_validation((packet, str))

    l_c_received["local"] = False
    l_c_incoming["local"] = True
    l_c_p_buffer["local"] += packet[1:]


def long_message_end(packet, account, origin):
    """
    Process last packet of message.

    Strip header from packet and append last part of message to l_m_p_buffer.

    :param packet:  Packet to process
    :param account: The contact's account name (e.g. alice@jabber.org)
    :param origin:  Origin of packet (u=user, c=contact)
    :return:        None
    """

    input_validation((packet, str), (account, str), (origin, str))

    l_m_p_buffer[origin + account] += packet[1:]
    l_m_received[origin + account] = True
    l_m_incoming[origin + account] = False

    msg_key = l_m_p_buffer[origin + account][-64:]
    payload = l_m_p_buffer[origin + account][:-64]

    try:
        payload = b64d(payload)
    except TypeError:
        l_m_p_buffer[origin + account] = ''
        l_m_received[origin + account] = False
        raise FunctionReturn("Error: Message %s %s had invalid B64 encoding."
                             % (dict(u="sent to", c="from")[origin],
                                c_dictionary[account]["nick"]))

    try:
        l_m_p_buffer[origin + account] = zlib.decompress(decrypt_data(payload,
                                                                      msg_key))
    except nacl.exceptions.CryptoError:
        l_m_p_buffer[origin + account] = ''
        l_m_received[origin + account] = False
        raise FunctionReturn("Error: Message %s %s had an invalid MAC."
                             % (dict(u="sent to", c="from")[origin],
                                c_dictionary[account]["nick"]))
    except ValueError:
        l_m_p_buffer[origin + account] = ''
        l_m_received[origin + account] = False
        raise FunctionReturn("Error: Message %s %s had an invalid nonce."
                             % (dict(u="sent to", c="from")[origin],
                                c_dictionary[account]["nick"]))


def long_file_end(packet, account, origin):
    """
    Process last packet of file.

    Strip header from packet and append last part of file to l_f_p_buffer.

    :param packet:  Packet to process
    :param account: The contact's account name (e.g. alice@jabber.org)
    :param origin:  Origin of packet (u=user, c=contact)
    :return:        None
    """

    input_validation((packet, str), (account, str), (origin, str))

    if c_dictionary[account]["storing"]:
        l_f_p_buffer[origin + account] += packet[1:]
        l_f_received[origin + account] = True
        l_f_incoming[origin + account] = False


def long_command_end(packet):
    """
    Process last packet of command.

    Strip header from packet and append last part of command to c_dictionary.

    :param packet: Packet to process
    :return:       None
    """

    input_validation((packet, str))

    l_c_p_buffer["local"] += packet[1:]
    command_content = l_c_p_buffer["local"][:-64]
    hash_of_command = l_c_p_buffer["local"][-64:]

    l_c_received["local"] = True
    l_c_incoming["local"] = False

    if sha3_256(command_content) != hash_of_command:
        l_c_p_buffer["local"] = ''
        l_c_received["local"] = False
        raise FunctionReturn("Error: Command from TxM had invalid hash.")

    l_c_p_buffer["local"] = command_content


###############################################################################
#                               PROCESS MESSAGES                              #
###############################################################################

def process_received_messages(account, origin):
    """
    Show message from contact. Do additional processing for group messages.

    :param account: The contact's account name (e.g. alice@jabber.org)
    :param origin:  Origin of packet (u=user, c=contact)
    :return:        None
    """

    input_validation((account, str), (origin, str))

    if not l_m_received[origin + account]:
        raise FunctionReturn("message not yet received", output=False)

    received_msg = l_m_p_buffer[origin + account]

    l_m_received[origin + account] = False
    l_m_incoming[origin + account] = False
    l_m_p_buffer[origin + account] = ''

    try:
        function = dict(g=message_to_group,
                        i=invitation_to_new_group,
                        n=new_members_in_group,
                        r=removed_members_from_group,
                        l=member_left_group,
                        p=message_to_contact)[received_msg[0]]
    except KeyError:
        raise FunctionReturn("Error: Received message had an invalid header.")

    function(received_msg, account, origin)


def invitation_to_new_group(packet, account, origin):
    """
    Print invitation to new group (and group members if published).

    :param packet:  Packet to process
    :param account: The contact's account name (e.g. alice@jabber.org)
    :param origin:  Origin of packet (u=user, c=contact)
    :return:        None
    """

    input_validation((packet, str), (account, str), (origin, str))

    if origin == 'u':
        raise FunctionReturn("Ignored notification from TxM.", output=False)

    try:
        g_name = packet.split(us)[1]
    except IndexError:
        raise FunctionReturn("Error: Received invalid group invitation.")

    members = packet.split(us)[2:]

    existing = [m for m in members
                if m in get_list_of("accounts")]

    unknowns = ["(unknown) %s" % m for m in members
                if m not in get_list_of("accounts")]

    s1 = "joined" if (g_name in get_list_of("groups")) else "invited you to"
    s2 = " with following members:" if members != [] else '.'

    a = g_name if s1 == "joined" else account

    w_print(["%s has %s group '%s'%s" % (account, s1, g_name, s2)]
            + existing + unknowns, a, ind="  * ")


def new_members_in_group(packet, account, origin):
    """
    Print notification that contact added members to group.

    :param packet:  Packet to process
    :param account: The contact's account name (e.g. alice@jabber.org)
    :param origin:  Origin of packet (u=user, c=contact)
    :return:        None
    """

    input_validation((packet, str), (account, str), (origin, str))

    if origin == 'u':
        raise FunctionReturn("Ignored notification from TxM.", output=False)

    try:
        g_name = packet.split(us)[1]
    except IndexError:
        raise FunctionReturn("Error: Received an invalid group notification.")

    members = packet.split(us)[2:]
    if not members:
        raise FunctionReturn("Error: Received an invalid group notification.")

    existing = [m for m in members
                if m in get_list_of("accounts")]

    unknowns = ["(unknown) %s" % m for m in members
                if m not in get_list_of("accounts")]

    w_print(["%s has added following members to group '%s':"
             % (account, g_name)] + existing + unknowns, g_name, ind="  * ")


def removed_members_from_group(packet, account, origin):
    """
    Print notification that contact removed members from their group.

    :param packet:  Packet to process
    :param account: The contact's account name (e.g. alice@jabber.org)
    :param origin:  Origin of packet (u=user, c=contact)
    :return:        None
    """

    input_validation((packet, str), (account, str), (origin, str))

    if origin == 'u':
        raise FunctionReturn("Ignored notification from TxM.", output=False)

    try:
        g_name = packet.split(us)[1]
    except IndexError:
        raise FunctionReturn("Error: Received an invalid group notification.")

    members = packet.split(us)[2:]
    if not members:
        raise FunctionReturn("Error: Received an invalid group notification.")

    existing = [m for m in members
                if m in get_list_of("accounts")]

    unknowns = ["(unknown) %s" % m for m in members
                if m not in get_list_of("accounts")]

    w_print(["%s has removed following members from group '%s':"
             % (account, g_name)] + existing + unknowns, g_name, ind="  * ")


def member_left_group(packet, account, origin):
    """
    Print notification that contact has left from group.

    :param packet:  Packet to process
    :param account: The contact's account name (e.g. alice@jabber.org)
    :param origin:  Origin of packet (u=user, c=contact)
    :return:        None
    """

    input_validation((packet, str), (account, str), (origin, str))

    if origin == 'u':
        raise FunctionReturn("Ignored notification from TxM.", output=False)

    try:
        g_name = packet.split(us)[1]
    except IndexError:
        raise FunctionReturn(
            "Error: Received an invalid group exit notification.",
            output=False)

    if g_name not in get_list_of("groups"):
        raise FunctionReturn("Unknown group in notification.", output=False)

    if account not in get_list_of("members", g_name):
        raise FunctionReturn("User is not member.", output=False)

    nick = c_dictionary[account]["nick"]
    w_print(["%s has left group '%s'." % (nick, g_name),
             "Unless you remove %s from the group yourself, " % nick,
             "%s can still read messages you send to group %s."
             % (nick, g_name)], g_name)


def message_to_group(packet, account, origin):
    """
    Print message to group window / notify about activity in window.

    :param packet:  Packet to process
    :param account: The contact's account name (e.g. alice@jabber.org)
    :param origin:  Origin of packet (u=user, c=contact)
    :return:        None
    """

    input_validation((packet, str), (account, str), (origin, str))

    try:
        header, g_name, message = packet.split(us)
    except (ValueError, IndexError):
        raise FunctionReturn("Error: Received invalid group message.")

    if g_name not in get_list_of("groups"):
        raise FunctionReturn("Ignored msg to unknown group.", output=False)

    if account not in get_list_of("members", g_name):
        raise FunctionReturn("Ignored msg from non-member.", output=False)

    if origin == 'u':
        # Counter to display only last message sent to group
        global group_msg_counter
        if group_msg_counter == 0:
            group_msg_counter = len(get_list_of("members", g_name))
        group_msg_counter -= 1
        if group_msg_counter > 0:
            return None

    w_print([message], g_name, account if origin == 'c' else "me")


def message_to_contact(packet, account, origin):
    """
    Print message to contact window / notify about activity in window.

    :param packet:  Packet to process
    :param account: The contact's account name (e.g. alice@jabber.org)
    :param origin:  Origin of packet (u=user, c=contact)
    :return:        None
    """

    input_validation((packet, str), (account, str), (origin, str))

    w_print([packet[2:]], account, account if origin == 'c' else "me")


###############################################################################
#                                PROCESS FILES                                #
###############################################################################

def process_received_files(account, origin):
    """
    Decode and store received file.

    :param account: The contact's account name (e.g. alice@jabber.org)
    :param origin:  Origin of packet (u=user, c=contact)
    :return:        None
    """

    input_validation((account, str), (origin, str))

    if not l_f_received[origin + account]:
        raise FunctionReturn("file not yet received", output=False)

    if not c_dictionary[account]["storing"]:
        l_f_p_buffer[origin + account] = ''
        raise FunctionReturn("file reception disabled", output=False)

    packet = l_f_p_buffer[origin + account]
    l_f_p_buffer[origin + account] = ''
    l_f_received[origin + account] = False
    l_f_incoming[origin + account] = False

    if origin == 'u' and not store_copy_of_file:
        raise FunctionReturn("Locally received file was discarded.")

    a = account
    nick = c_dictionary[a]["nick"]
    f_path = "received_files/"
    name = os.path.dirname(f_path)
    if not os.path.exists(name):
        os.makedirs(name)

    # Load data
    try:
        f_name = packet.split(us)[1]
        f_data = packet.split(us)[4]
    except IndexError:
        raise FunctionReturn("Error: Invalid packet data. "
                             "Discarded file from %s." % nick)

    # Generate filename
    if f_name.startswith('.'):
        f_name = "Dotfile %s" % f_name[1:]
    if origin == 'u':
        f_name = "Local copy - %s" % f_name

    # Add '(n)' to file if one with same name already exists.
    fn_ext = f_name.split('.')
    if len(fn_ext) == 1:
        n = len([f for f in os.listdir(f_path) if f.startswith(f_name)])
        f_name = "%s(%s)" % (f_name, n) if n > 0 else f_name

    else:
        f_extn = fn_ext[-1]
        f_name = '.'.join(fn_ext[:-1])
        n = len([f for f in os.listdir(f_path) if
                 (f.startswith(f_name) and f.endswith(f_extn))])
        f_name = "%s(%s).%s" % (f_name, n, f_extn) if n > 0 \
            else "%s.%s" % (f_name, f_extn)

    try:
        key = f_data[-64:]
        f_data = b64d(f_data[:-64])
    except TypeError:
        raise FunctionReturn(
            "Error: Invalid encoding. Discarded file from %s." % nick)

    try:
        f_data = decrypt_data(f_data, key)
    except nacl.exceptions.CryptoError:
        raise FunctionReturn(
            "Error: File MAC failed. Discarded file from %s." % nick)

    try:
        f_data = zlib.decompress(f_data)
    except zlib.error:
        raise FunctionReturn(
            "Error in decompression. Discarded file from %s." % nick)

    open("%s%s" % (f_path, f_name), "w+").write(f_data)

    if origin == 'u':
        w_print(["Stored copy of file sent to %s as '%s'" % (a, f_name)])
    else:
        w_print(["Stored file from %s as '%s'." % (a, f_name)])

    ow = ["WARNING!", "Do not move received files from RxM to less secure "
                      "environments especially if they are connected to "
                      "network either directly or indirectly! Doing so "
                      "will render security provided by separated TCB units "
                      "useless, as malware 'stuck' in RxM can exfiltrate "
                      "keys and/or plaintext through this channel back to "
                      "the adversary! To retransfer a document, either read "
                      "it from RxM screen using OCR software running on "
                      "TxM, or scan document in analog format. If your life "
                      "depends on it, destroy the used hardware."]

    if disp_opsec_warning:
        w_print(ow)

    if origin == 'c' and auto_disable_store:
        c_dictionary[account]["storing"] = False
        w_print(["Disabled file reception for %s." % nick])


###############################################################################
#                               PROCESS COMMANDS                              #
###############################################################################

def process_received_command():
    """
    Process received command.

    :return: None
    """

    if not l_c_received["local"]:
        raise FunctionReturn("command not yet received", output=False)

    cmd = l_c_p_buffer["local"]

    l_c_incoming["local"] = False
    l_c_received["local"] = False
    l_c_p_buffer["local"] = ''

    if cmd.startswith("CF"):
        control_settings(cmd)

    elif cmd.startswith("CL"):
        change_logging(cmd)

    elif cmd.startswith("CP"):
        control_settings(cmd)

    elif cmd.startswith("CN"):
        change_nick(cmd)

    elif cmd.startswith("CR"):
        rm_contact(cmd)

    elif cmd.startswith("EX"):
        graceful_exit(queue=True)

    elif cmd.startswith("GA"):
        group_add_member(cmd)

    elif cmd.startswith("GC"):
        group_create(cmd)

    elif cmd.startswith("GR"):
        group_rm_member(cmd)

    elif cmd.startswith("KE"):
        ecdhe_command(cmd)

    elif cmd.startswith("KR"):
        add_psk(cmd)

    elif cmd.startswith("KT"):
        psk_command(cmd)

    elif cmd.startswith("LF"):
        access_history(cmd)

    elif cmd == "LI":
        clear_screen()
        if not get_list_of("accounts"):
            print("Waiting for new contacts\n")

    elif cmd == "SA":
        notify_win_activity()

    elif cmd == "SC":
        clear_screen()

    elif cmd.startswith("SR"):
        reset_screen(cmd)

    elif cmd.startswith("WS"):
        select_window(cmd)

    else:
        raise CriticalError("Invalid command '%s'." % cmd)


def change_nick(parameters):
    """
    Change nick of contact.

    :param parameters: Header, account and nick of command
    :return:           None
    """

    input_validation((parameters, str))

    try:
        header, account, nick = parameters.split(us)
    except ValueError:
        raise FunctionReturn("Error: Invalid data in command packet.")

    if account not in get_list_of("accounts"):
        raise FunctionReturn("Error: Unknown account.")

    c_dictionary[account]["nick"] = nick
    run_as_thread(contact_db, c_dictionary)
    w_print(["Changed %s nick to %s." % (account, nick)])


def change_logging(parameters):
    """
    Enable logging/msg notifications for user/group/all.

    :param parameters: Parameters to be separated
    :return:           None
    """

    input_validation((parameters, str))

    try:
        param_list = parameters.split(us)
    except IndexError:
        raise FunctionReturn("Error: Invalid command.")

    if len(param_list) < 2:
        raise FunctionReturn("Error: Invalid command.")

    if param_list[1] == 'E':
        if all([c_dictionary[a]["logging"] for a in get_list_of("accounts")]
               + [g_dictionary[g]["logging"] for g in get_list_of("groups")]):
            w_print(["Logging is already enabled for every contact."])
        else:
            for a in get_list_of("accounts"):
                c_dictionary[a]["logging"] = True
            for g in get_list_of("groups"):
                g_dictionary[g]["logging"] = True
            run_as_thread(contact_db, c_dictionary)
            run_as_thread(group_db, g_dictionary)
            w_print(["Logging has been enabled for every contact."])

    elif param_list[1] == 'D':
        if any([c_dictionary[a]["logging"] for a in get_list_of("accounts")]
               + [g_dictionary[g]["logging"] for g in get_list_of("groups")]):
            for a in get_list_of("accounts"):
                c_dictionary[a]["logging"] = False
            for g in get_list_of("groups"):
                g_dictionary[g]["logging"] = False
            run_as_thread(contact_db, c_dictionary)
            run_as_thread(group_db, g_dictionary)
            w_print(["Logging has been disabled for every contact."])
        else:
            w_print(["Logging is already disabled for every contact."])

    else:
        try:
            t = param_list[2]
        except IndexError:
            raise FunctionReturn("Error: Missing account/group.")

        if t in get_list_of("accounts"):
            database = c_dictionary
            db_handler = contact_db
        elif t in get_list_of("groups"):
            database = g_dictionary
            db_handler = group_db
        else:
            raise FunctionReturn("No contact / group found.")

        if database[t]["logging"] and param_list[1] == 'e':
            w_print(["Logging for %s is already enabled." % t])
        if not database[t]["logging"] and param_list[1] == 'e':
            database[t]["logging"] = True
            run_as_thread(db_handler, database)
            w_print(["Logging for %s has been enabled." % t])

        if not database[t]["logging"] and param_list[1] == 'd':
            w_print(["Logging for %s is already disabled." % t])
        if database[t]["logging"] and param_list[1] == 'd':
            database[t]["logging"] = False
            run_as_thread(db_handler, database)
            w_print(["Logging for %s has been disabled." % t])


def control_settings(parameters):
    """
    Control window privacy and file reception for accounts

    :param parameters: Setting control key and setting
    :return:           None
    """

    input_validation((parameters, str))

    try:
        param_list = parameters.split(us)
    except IndexError:
        raise FunctionReturn("Error: Invalid command.")

    if len(param_list) < 2:
        raise FunctionReturn("Error: Invalid command.")

    try:
        key, msg = dict(CP=("windowp", "Private notifications"),
                        CF=("storing", "File reception"))[param_list[0]]
    except KeyError:
        raise FunctionReturn("Error: Invalid key in command.")

    if param_list[1] == 'E':
        if all([c_dictionary[a][key] for a in get_list_of("accounts")]):
            w_print(["%s is already enabled for every contact." % msg])
        else:
            for a in get_list_of("accounts"):
                if key == "storing":
                    for h in ['u', 'c']:
                        l_f_incoming[h + a] = False
                        l_f_received[h + a] = False
                        l_f_p_buffer[h + a] = ''
                c_dictionary[a][key] = True
            run_as_thread(contact_db, c_dictionary)
            w_print(["%s has been enabled for every contact." % msg])

    elif param_list[1] == 'D':
        if any([c_dictionary[a][key] for a in get_list_of("accounts")]):
            for a in get_list_of("accounts"):
                c_dictionary[a][key] = False
            run_as_thread(contact_db, c_dictionary)
            w_print(["%s has been disabled for every contact." % msg])
        else:
            w_print(["%s is already disabled for every contact." % msg])

    else:
        try:
            a = param_list[2]
        except IndexError:
            raise FunctionReturn("Error: Missing account.")

        if a not in get_list_of("accounts"):
            raise FunctionReturn("Error: unknown account.")

        if c_dictionary[a][key] and param_list[1] == 'e':
            w_print(["%s for %s is already enabled." % (msg, a)])

        if not c_dictionary[a][key] and param_list[1] == 'd':
            w_print(["%s for %s is already disabled." % (msg, a)])

        if not c_dictionary[a]["storing"] and param_list[1] == 'e':
            if key == "storing":
                for h in ['u', 'c']:
                    l_f_incoming[h + a] = False
                    l_f_received[h + a] = False
                    l_f_p_buffer[h + a] = ''
            c_dictionary[a][key] = True
            run_as_thread(contact_db, c_dictionary)
            w_print(["%s for %s has been enabled." % (msg, a)])

        if c_dictionary[a][key] and param_list[1] == 'd':
            c_dictionary[a][key] = False
            run_as_thread(contact_db, c_dictionary)
            w_print(["%s for %s has been disabled." % (msg, a)])


###############################################################################
#                                  PROCESSES                                  #
###############################################################################

def nh_packet_loading_process():
    """
    Load packet from NH via serial port / IPC.

    If local_testing_mode boolean is enabled, use
    IPC (multiprocessing socket) instead of serial.

    :return: [no return value]
    """

    global port_nh

    if local_testing_mode:
        while True:
            try:
                time.sleep(0.1)
                nh_queue.put(ipc_connection.recv())
            except KeyboardInterrupt:
                pass
            except EOFError:
                graceful_exit("NH <> RxM IPC disconnected.", queue=True)

    else:
        while True:
            try:
                try:
                    packet = ''
                    while True:
                        read_data = port_nh.read(1)
                        packet += read_data
                        if read_data == '':
                            break

                except SerialException:
                    if not serial_usb_adapter:
                        raise CriticalError(
                            "Integrated serial interface disconnected.")

                    phase("Serial disconnected. Waiting for interface...")
                    found = False
                    while True:
                        time.sleep(0.1)
                        dev_files = os.listdir("/dev/")
                        dev_files.sort()

                        for dev_file in dev_files:
                            if dev_file.startswith("ttyUSB"):
                                # Short delay causes error w/ iface permissions
                                time.sleep(2)
                                port_nh = serial.Serial("/dev/%s" % dev_file,
                                                        serial_iface_speed,
                                                        timeout=0.01)
                                print("Found.\n")
                                found = True
                                break
                        if found:
                            break
                    continue

                if packet:
                    nh_queue.put(packet)

            except KeyboardInterrupt:
                pass


def main_loop_process():
    """
    Load packet from highest priority queue and process it.

    :return: [no return value]
    """

    global accept_new_local_keys

    while True:
        try:
            time.sleep(0.1)

            local_key_installed = "local" in c_dictionary.keys()
            contacts_available = any(get_list_of("accounts"))

            if not pubkey_cache.empty() and local_key_installed:
                nh_packet = pubkey_cache.get()
            elif not packet_cache.empty() and local_key_installed:
                nh_packet = packet_cache.get()
            elif not nh_queue.empty():
                try:
                    nh_packet = nh_queue.get()
                    nh_packet = str(reed_solomon.decode(bytearray(nh_packet)))
                except ReedSolomonError:
                    w_print(["Error: Forward error correction "
                             "of received packet failed."])
                    continue
            else:
                continue

            if nh_packet[0] != '1':
                print("\nError: Received packet uses "
                      "unknown protocol version.\n")
            elif nh_packet[1] != 'N':
                print("\nError: Received packet uses "
                      "unknown cipher configuration.\n")
                continue

            packet = nh_packet[2:]
            header = packet[0]

            if header == 'M':
                if contacts_available:
                    packet_decryption(packet[1:])
                else:
                    packet_cache.put(nh_packet)

            elif header == 'C':
                if local_key_installed:
                    packet_decryption(packet[1:])
                else:
                    packet_cache.put(nh_packet)

            elif header == 'P':
                if local_key_installed:
                    display_pub_key(packet[1:])
                    accept_new_local_keys = True
                else:
                    pubkey_cache.put(nh_packet)

            elif header == 'L':
                pc_queue.put("start_kdk_input_process")
                try:
                    process_local_key(packet[1:])
                except FunctionReturn:
                    pass

            else:
                w_print(["Error: Received packet had invalid header."])

        except (KeyboardInterrupt, FunctionReturn):
            pass


###############################################################################
#                                     MAIN                                    #
###############################################################################

accept_new_local_keys = True
unit_test = False

c_dictionary = dict()
g_dictionary = dict()

l_m_incoming = dict()
l_f_incoming = dict()
l_c_incoming = dict()

l_m_received = dict()
l_f_received = dict()
l_c_received = dict()

l_m_p_buffer = dict()
l_f_p_buffer = dict()
l_c_p_buffer = dict()

window_log_d = dict()
unread_ctr_d = dict()
win_last_msg = dict()
public_key_d = dict()

# Set default values
login_file = ".rx_login_data"
datab_file = ".rx_database"
group_file = ".rx_groups"
rxlog_file = ".rx_logs"
active_window = ''
group_msg_counter = 0

reed_solomon = RSCodec(2 * e_correction_ratio)

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
        listener = multiprocessing.connection.Listener(("localhost", 5003))
        ipc_connection = listener.accept()
    else:
        port_nh = establish_serial()

    if not os.path.isfile(login_file):
        new_master_pwd()

    # Initialize queues for data
    nh_queue = multiprocessing.Queue()   # Packet loading queue
    pc_queue = multiprocessing.Queue()   # Process control queue

    kdk_queue = multiprocessing.Queue()  # Key decryption key queue
    pth_queue = multiprocessing.Queue()  # PSK path delivery queue

    packet_cache = multiprocessing.Queue()  # Packet caching queue
    pubkey_cache = multiprocessing.Queue()  # Public key caching queue

    pwd_queue = multiprocessing.Queue()  # Password delivery queue
    key_queue = multiprocessing.Queue()  # Master key return queue

    master_key = login_screen()

    import readline  # Import before curses causes issues with terminal resize
    default_delims = readline.get_completer_delims()

    # If group database does not exist, fill it with noise groups.
    if not os.path.isfile(group_file):
        g_dictionary["dummy_group"] = dict(logging="False", members=[])
        run_as_thread(group_db, g_dictionary)

    # Load contact data
    c_dictionary = contact_db()
    g_dictionary = group_db()

    # Set ephemeral dictionaries for file and message reception
    for acco in get_list_of("accounts"):
        for o in ['u', 'c']:
            l_m_incoming[o + acco] = False
            l_m_received[o + acco] = False
            l_m_p_buffer[o + acco] = ''

            l_f_incoming[o + acco] = False
            l_f_received[o + acco] = False
            l_f_p_buffer[o + acco] = ''

        public_key_d[acco] = ''

    for win in get_list_of("windows"):
        window_log_d[win] = []
        unread_ctr_d[win] = 0
        win_last_msg[win] = datetime.datetime.now()

    l_c_incoming["local"] = False
    l_c_received["local"] = False
    l_c_p_buffer["local"] = ''

    # Start processes
    nh_p_load_p = multiprocessing.Process(target=nh_packet_loading_process)
    main_loop_p = multiprocessing.Process(target=main_loop_process)
    cli_input_p = multiprocessing.Process(target=cli_input_process,
                                          args=(sys.stdin.fileno(), ''))
    kdk_input_p = multiprocessing.Process(target=kdk_input_process,
                                          args=(sys.stdin.fileno(), ''))

    nh_p_load_p.start()
    main_loop_p.start()

    def p_kill():
        for process in [nh_p_load_p, main_loop_p, cli_input_p, kdk_input_p]:
            try:
                process.terminate()
            except (AttributeError, NameError):
                pass
        graceful_exit()

    while True:
        try:
            time.sleep(0.01)
            for pr in [nh_p_load_p, main_loop_p]:
                if not pr.is_alive():
                    p_kill()

            if pc_queue.empty():
                continue

            command = pc_queue.get()

            if command == "exit":
                p_kill()

            elif command == "start_kdk_input_process":
                if cli_input_p.is_alive():
                    continue
                kdk_input_p = multiprocessing.Process(target=kdk_input_process,
                                                      args=(sys.stdin.fileno(),
                                                            ''))
                kdk_input_p.start()

            elif command == "terminate_kdk_input_process":
                try:
                    kdk_input_p.terminate()
                except AttributeError:
                    pass

            elif command.startswith("start_ask_file_path_cli_process"):
                if kdk_input_p.is_alive():
                    continue
                prompt_msg = command.split(us)[1]
                cli_input_p = multiprocessing.Process(target=cli_input_process,
                                                      args=(sys.stdin.fileno(),
                                                            prompt_msg))
                cli_input_p.start()

            elif command == "termitate_ask_file_path_gui_process":
                try:
                    cli_input_p.terminate()
                except AttributeError:
                    pass

        except KeyboardInterrupt:
            pass
