#!/usr/bin/env python
# -*- coding: utf-8 -*-

# TFC 0.16.10 || NH.py

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
import ctypes
import curses
import datetime
import dbus.exceptions
import dbus.mainloop.qt
import dbus
import inspect
import itertools
import multiprocessing.connection
import multiprocessing
import os
import random
import serial
import subprocess
import sys
import time

from _curses import error as curses_error
from PyQt4.QtGui import QApplication
from serial.serialutil import SerialException

str_version = "0.16.10"
int_version = 1610


###############################################################################
#                                CONFIGURATION                                #
###############################################################################

# User interface
t_fmt = "%m-%d / %H:%M:%S"  # Timestamp format of displayed messages

show_curses_banner = True   # False disables the animated startup banner


# Local testing
local_testing_mode = False  # True enables testing of TFC on a single computer

data_diode_sockets = False  # True changes sockets for data diode simulator

relay_to_im_client = True   # False stops sending messages to IM client


# Serial port
serial_iface_speed = 19200  # The speed of serial interface in bauds per sec

e_correction_ratio = 5      # N/o byte errors serial datagrams can recover from

total_usb_adapters = 2      # Number of USB-to-serial adapters used (0, 1 or 2)


###############################################################################
#                               ERROR CLASSES                                 #
###############################################################################

class CriticalError(Exception):
    """A variety of errors during which NH.py should gracefully exit."""

    def __init__(self, error_message):
        graceful_exit("Critical error in function '%s()':\n%s"
                      % (inspect.stack()[1][3], error_message))


class FunctionParameterTypeError(Exception):
    """Gracefully exit if function is called with invalid parameter types."""

    def __init__(self, f_name, parameter_index, wrong_type, expected_type):
        graceful_exit(
            "Error: %s parameter of function '%s()':\nGot %s instead of %s."
            % (parameter_index, f_name, wrong_type, expected_type))


###############################################################################
#                                     MISC                                    #
###############################################################################

def graceful_exit(message=''):
    """
    Display a message and exit NH.py.

    :param: message: Message to print
    :return:         None
    """

    input_validation((message, str))

    clear_screen()
    if message:
        print("\n%s" % message)
    print("\nExiting TFC.\n")
    exit()


def print_banner():
    """
    Print animated startup banner.

    :return: None
    """

    string = "Tinfoil Chat %s" % str_version

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

        return string_y, string_x

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
        sy, sx, = get_string_coordinates(height, width, logo_c)

        close_animation = False
        resize_teardown = False
        after_correct = False
        delay = 0

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
                sy, sx, = get_string_coordinates(height, width, logo_c)

            if after_correct:
                tear_chars, logo_c = reset(scr, teardown=True)
                for fc in falling_chars:
                    fc.tear = True
                falling_chars += tear_chars
                after_correct = False

            try:
                for fc in falling_chars:
                    fc.tick(scr, steps)

                if close_animation and not rpi_os:
                    for _ in xrange(3):
                        x = randint(0, width)
                        y = randint(0, height)
                        scr.addstr(y, x, ' ')

                if close_animation:
                    st = ''
                    for c in xrange(len(string)):
                        if not string_cleared_char_list[c] == ' ':
                            string_cleared_char_list[c] = chr(randint(32, 126))
                        st += string_cleared_char_list[c]
                    scr.addstr(sy, sx, st)
                    if set(string_cleared_char_list) == {' '}:
                        return None
                else:
                    st = ''
                    for c in xrange(len(string)):
                        if not string_printed_char_list[c] == string[c]:
                            string_printed_char_list[c] = chr(randint(32, 126))
                        st += string_printed_char_list[c]
                        if st == string:
                            delay += 1
                            if delay > 300:
                                close_animation = True
                    scr.addstr(sy, sx, st)

            except curses_error:
                pass

            scr.refresh()
            time.sleep(0.005)
            steps += 1

    try:
        r = rand()
        main()

        curses.endwin()
        curses.curs_set(1)
        curses.reset_shell_mode()
        curses.echo()

    except KeyboardInterrupt:
        curses.endwin()
        curses.curs_set(1)
        curses.reset_shell_mode()
        curses.echo()


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


def clear_screen():
    """
    Clear terminal window.

    :return: None
    """

    print(cs + cc + cu)


def search_serial_interfaces():
    """
    Determine correct serial interfaces.

    :return: Two serial interfaces.
    """

    if total_usb_adapters not in [0, 1, 2]:
        graceful_exit("Invalid number (%s) of USB-to-serial adapters. "
                      "Must be 0, 1 or 2." % total_usb_adapters)

    if total_usb_adapters == 0:

        if rpi_os:
            graceful_exit("Error: RPi needs at least "
                          "one USB-to-serial interface.")

        if_list = [d for d in os.listdir("/dev/") if d.startswith("ttyS")]

        if not if_list:
            graceful_exit("Error: No integrated serial interfaces were found.")

        if len(if_list) < 2:
            graceful_exit("Error: Current configuration expects two "
                          "integrated serial interfaces.")

        if_list.sort()
        return "/dev/%s" % if_list[0], \
               "/dev/%s" % if_list[1]

    if total_usb_adapters == 1:
        message_displayed = False
        iface_0 = ''
        try:
            while True:
                time.sleep(0.1)
                for d in os.listdir("/dev/"):
                    if d.startswith("ttyUSB"):
                        time.sleep(2)
                        iface_0 = d
                        break
                if iface_0:
                    break

                if not message_displayed:
                    phase("Searching for USB-to-serial adapter...", 41)
                    message_displayed = True

        except KeyboardInterrupt:
            graceful_exit()

        if message_displayed:
            print("Found.\n")

        iface_1 = "serial0" if rpi_os else "ttyS0"

        if iface_1 not in os.listdir("/dev"):
            graceful_exit("Error: No integrated serial interface was found.")

        return "/dev/%s" % iface_0, \
               "/dev/%s" % iface_1

    if total_usb_adapters == 2:
        message_displayed = False
        try:
            while True:
                time.sleep(0.1)

                usb_if_list = [d for d in os.listdir("/dev/") 
                               if d.startswith("ttyUSB")]
                usb_if_list.sort()

                if len(usb_if_list) >= 2:
                    if message_displayed:
                        print("Found.\n")
                    time.sleep(2)
                    return "/dev/%s" % usb_if_list[0], \
                           "/dev/%s" % usb_if_list[1]

                if not message_displayed:
                    phase("Searching for USB-to-serial adapters...", 41)
                    message_displayed = True

        except KeyboardInterrupt:
            graceful_exit()

        if message_displayed:
            time.sleep(2)


def b64e(string):
    """Alias for encoding data with Base64."""

    input_validation((string, str))
    return base64.b64encode(string)


def b64d(string):
    """Alias for decoding Base64 encoded data."""

    input_validation((string, str))
    return base64.b64decode(string)


def process_arguments():
    """
    Define NH.py settings from arguments passed from command line.

    :return: None
    """

    parser = argparse.ArgumentParser("python NH.py",
                                     usage="%(prog)s [OPTION]",
                                     description="More options inside NH.py")

    parser.add_argument("-p",
                        action="store_true",
                        default=False,
                        dest="quiet",
                        help="Do not output messages to Pidgin")

    parser.add_argument("-l",
                        action="store_true",
                        default=False,
                        dest="local",
                        help="Enable local testing mode")

    parser.add_argument("-d",
                        action="store_true",
                        default=False,
                        dest="ddsockets",
                        help="Enable data diode simulator sockets")

    args = parser.parse_args()

    global data_diode_sockets
    global relay_to_im_client
    global local_testing_mode

    _true = True

    if args.ddsockets:
        data_diode_sockets = _true

    if args.quiet:
        relay_to_im_client = _true

    if args.local:
        local_testing_mode = _true


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
#                            LOCAL DATA PROCESSING                            #
###############################################################################

def header_printer_process():
    """
    Print NH.py headers.

    :return: [no return value]
    """

    try:
        print("TFC %s | NH.py\n" % str_version)

        bus = dbus.SessionBus()
        obj = bus.get_object("im.pidgin.purple.PurpleService",
                             "/im/pidgin/purple/PurpleObject")
        purple = dbus.Interface(obj, "im.pidgin.purple.PurpleInterface")

        print("Active accounts:")
        for a in purple.PurpleAccountsGetAllActive():
            print "  * %s" % purple.PurpleAccountGetUsername(a)[:-1]
        print('')

    except dbus.exceptions.DBusException:
        raise graceful_exit("DBusException. Ensure Pidgin is running.")


def nh_command_process():
    """
    Execute command (clear screen or exit) on NH.

    :return: [no return value]
    """

    bus = dbus.SessionBus()
    obj = bus.get_object("im.pidgin.purple.PurpleService",
                         "/im/pidgin/purple/PurpleObject")
    purple = dbus.Interface(obj, "im.pidgin.purple.PurpleInterface")
    account = purple.PurpleAccountsGetAllActive()[0]

    while True:
        try:
            if nh_side_command.empty():
                time.sleep(0.1)
                continue

            cmd = nh_side_command.get()
            c = cmd[2:]

            if cmd[:2] == "SC":
                if c:
                    new_conv = purple.PurpleConversationNew(1, account, c)
                    purple.PurpleConversationClearMessageHistory(new_conv)
                    clear_screen()

            if cmd[:2] == "SR":
                if c:
                    new_conv = purple.PurpleConversationNew(1, account, c)
                    purple.PurpleConversationClearMessageHistory(new_conv)
                    os.system("reset")
        except KeyboardInterrupt:
            pass


###############################################################################
#                             PACKETS FROM PIDGIN                             #
###############################################################################

def pidgin_connection():
    """
    Check that NH.py has connection to Pidgin before launching other processes.

    :return: [no return value]
    """

    while True:
        try:
            time.sleep(0.1)
            try:
                bus = dbus.SessionBus()
                obj = bus.get_object("im.pidgin.purple.PurpleService",
                                     "/im/pidgin/purple/PurpleObject")
                purple = dbus.Interface(obj,
                                        "im.pidgin.purple.PurpleInterface")
                try:
                    active = purple.PurpleAccountsGetAllActive()[0]
                except IndexError:
                    continue

                _ = purple.PurpleAccountGetUsername(active)[:-1]

            except dbus.exceptions.DBusException:
                continue

            pidgin_ready.put("OK")

        except KeyboardInterrupt:
            pass


def pidgin_to_rxm_queue(account, sender, message, conversation, flags):
    """
    Load message from Pidgin and put it to queue.

    :param account:      Account ID
    :param sender:       Sender account address
    :param message:      Message from sender
    :param conversation: Conversation ID
    :param flags:        Flags
    :return:             [no return value]
    """

    # Clear PEP8 warning
    if 0:
        print(conversation, flags)

    sender = sender.split('/')[0]
    tstamp = datetime.datetime.now().strftime(t_fmt)

    bus = dbus.SessionBus()
    obj = bus.get_object("im.pidgin.purple.PurpleService",
                         "/im/pidgin/purple/PurpleObject")
    purple = dbus.Interface(obj,
                            "im.pidgin.purple.PurpleInterface")

    user = ''
    for a in purple.PurpleAccountsGetAllActive():
        if a == account:
            user = purple.PurpleAccountGetUsername(a)[:-1]

    if message.startswith("TFC"):

        split = str(message).split('|')

        if not split[1].isdigit():
            print("\nError: Invalid version number data from contact.\n")
            return None

        if int(split[1]) != int_version:
            print("\nError: Contact is using different software version.\n")
            return None

        if split[2] != 'N':
            print("\nError: Contact is using unknown cipher suite.\n")
            return None

        if split[3] not in ['P', 'M']:
            print("\nError: Received packet had invalid type ID.\n")
            return None

        if split[3] == 'P':
            packet_to_rxm.put(str('P' + split[4] + 'c' + sender))
            print("%s - pub key %s > %s > RxM" % (tstamp, sender, user))

        elif split[3] == 'M':
            packet_to_rxm.put(bytearray('M'
                                        + b64d(str(split[4]))
                                        + b64d(str(split[5]))
                                        + 'c' + str(sender)))
            print("%s - message %s > %s > RxM" % (tstamp, sender, user))


def dbus_receiver():
    """
    Start Qt loop that loads messages from Pidgin.

    :return: [no return value]
    """

    dbus.mainloop.qt.DBusQtMainLoop(set_as_default=True)
    bus = dbus.SessionBus()
    bus.add_signal_receiver(pidgin_to_rxm_queue,
                            dbus_interface="im.pidgin.purple.PurpleInterface",
                            signal_name="ReceivedImMsg")


def pidgin_receiver_process():
    """
    Start QApplication as a separate process.

    :return: [no return value]
    """

    try:
        app = QApplication(sys.argv)
        dbus_receiver()
        app.exec_()
    except dbus.exceptions.DBusException:
        pass


###############################################################################
#                               PACKETS FROM TxM                              #
###############################################################################

def txm_ipc_receiver_process():
    """
    Load packet from TxM via IPC during local testing.

    :return: [no return value]
    """

    try:
        def ipc_to_queue(conn):
            """
            Load packet from IPC.

            :param conn: Listener object
            :return:     [no return value]
            """

            while True:
                try:
                    time.sleep(0.1)
                    port_recv_buffer.put(conn.recv())
                except KeyboardInterrupt:
                    pass
        try:
            l = multiprocessing.connection.Listener(("localhost", 5001))
            ipc_to_queue(l.accept())
        except EOFError:
            graceful_exit("TxM <> NH IPC disconnected.")

    except KeyboardInterrupt:
        pass


def txm_serial_0_receiver_process(port_0_name_,
                                  port_1_name_,
                                  port_0_connected_,
                                  listening_port_,
                                  lock_):
    """
    Look for packets from port 0.

    :return: [no return value]
    """

    listener = serial.Serial(port_0_name_.value,
                             serial_iface_speed,
                             timeout=0.01)
    while True:
        try:
            try:
                packet = ''
                while True:
                    read_data = listener.read(1)
                    packet += read_data
                    if read_data == '':
                        break

            except SerialException:
                print("\nPort 0 disconnected.\n")
                with lock_:
                    port_0_connected_.value = 0

                while True:
                    time.sleep(0.1)

                    iface = ''
                    for d in ["/dev/%s" % d for d in os.listdir("/dev/")]:
                        if d.startswith("/dev/ttyUSB"):
                            if d != port_1_name_.value:
                                iface = d
                                break
                    if iface:
                        time.sleep(2)
                        try:
                            listener = serial.Serial(iface,
                                                     serial_iface_speed,
                                                     timeout=0.01)
                        except SerialException:
                            continue
                        with lock_:
                            port_0_name_.value = iface
                            port_0_connected_.value = 1
                        print("Port 0 connected to %s.\n" % iface)
                        break
                continue

            if packet:
                with lock_:
                    listening_port_.value = 0
                port_recv_buffer.put(packet)

        except KeyboardInterrupt:
            pass


def txm_serial_1_receiver_process(port_0_name_,
                                  port_1_name_,
                                  port_0_connected_,
                                  port_1_connected_,
                                  listening_port_,
                                  lock_):
    """
    Look for packets from port 1.

    :return: [no return value]
    """

    listener = serial.Serial(port_1_name_.value,
                             serial_iface_speed,
                             timeout=0.01)
    while True:
        try:
            try:
                packet = ''
                while True:
                    read_data = listener.read(1)
                    packet += read_data
                    if read_data == '':
                        break

            except SerialException:
                print("\nPort 1 disconnected.\n")
                with lock_:
                    port_1_connected_.value = 0

                while True:
                    time.sleep(0.1)

                    # If port 0 is also disconnected, let it get mapped first.
                    if port_0_connected_.value == 0:
                        continue

                    iface = ''
                    for d in ["/dev/%s" % d for d in os.listdir("/dev/")]:
                        if d.startswith("/dev/ttyUSB"):
                            if d != port_0_name_.value:
                                iface = d
                                break

                    if iface:
                        time.sleep(2)
                        try:
                            listener = serial.Serial(iface,
                                                     serial_iface_speed,
                                                     timeout=0.01)
                        except SerialException:
                            continue
                        with lock_:
                            port_1_name_.value = iface
                            port_1_connected_.value = 1
                        print("Port 1 connected to %s.\n" % iface)
                        break
                continue

            if packet:
                with lock_:
                    listening_port_.value = 1
                port_recv_buffer.put(packet)

        except KeyboardInterrupt:
            pass


def txm_packet_process():
    """
    Process and forward packets from TxM to IM client and other queues.

    :return: [no return value]
    """

    while True:
        try:
            time.sleep(0.1)

            if port_recv_buffer.empty():
                continue

            packet = port_recv_buffer.get()

            try:
                packet = str(rs.decode(bytearray(packet)))
            except ReedSolomonError:
                print("\nError: Forward error correction failed.\n")
                continue

            if packet[0] != '1':
                print("\nError: TxM has unknown protocol version.\n")
                continue
            elif packet[1] != 'N':
                print("\nError: TxM has unknown cipher configuration.\n")
                continue

            packet = packet[2:]
            header = packet[0]
            timestamp = datetime.datetime.now().strftime(t_fmt)

            if header == 'M':
                eharac = packet[1:49]
                ct_tag = packet[49:344]
                user, acco = packet[344:].split(us)

                message_to_pidgin.put(("TFC|%s|N|M|%s|%s"
                                       % (int_version, b64e(eharac),
                                          b64e(ct_tag)), user, acco))
                packet_to_rxm.put(header + eharac + ct_tag + 'u' + acco)
                print("%s - message TxM > %s > %s" % (timestamp, user, acco))

            elif header == 'C':
                eharac = packet[1:49]
                ct_tag = packet[49:344]
                user, acco = packet[344:].split(us)
                packet_to_rxm.put(header + eharac + ct_tag + 'u' + acco)
                print("%s - command TxM > RxM" % timestamp)

            elif header == 'P':
                pubkey = packet[1:65]
                user, acco = packet[65:].split(us)

                message_to_pidgin.put(("TFC|%s|N|P|%s" % (int_version, pubkey),
                                       user, acco))
                packet_to_rxm.put(header + pubkey + 'u' + acco)
                print("%s - pub key TxM > %s > %s" % (timestamp, user, acco))

            elif header == 'L':
                packet_to_rxm.put(packet)
                print("%s - Local key TxM > RxM" % timestamp)

            elif packet.startswith("UEX"):
                time.sleep(0.5)
                graceful_exit()

            elif packet.startswith("USC"):
                nh_side_command.put(packet[1:])

            elif packet.startswith("USR"):
                nh_side_command.put(packet[1:])

            else:
                print("Unknown packet from TxM:\n%s" % packet)

        except KeyboardInterrupt:
            pass


###############################################################################
#                                PACKETS TO RxM                               #
###############################################################################

def rxm_ipc_sender_process():
    """
    Send packet over IPC to RxM during local testing.

    :return: [no return value]
    """

    while True:
        try:
            if packet_to_rxm.empty():
                time.sleep(0.1)
                continue
            packet = packet_to_rxm.get()
            packet = '1N' + packet
            ipc_rx.send(rs.encode(bytearray(packet)))
        except KeyboardInterrupt:
            pass


def rxm_serial_sender_process(port_0_name_,
                              port_1_name_,
                              port_0_connected_,
                              port_1_connected_,
                              listening_port_):
    """
    Send message using opposite interface to listening_port.

    :return: [no return value]
    """

    while True:

        try:
            time.sleep(0.1)

            if port_0_connected_.value == 0 or port_1_connected_.value == 0:
                continue

            if listening_port_.value == 0:
                rxm_if = port_1_name_.value
            elif listening_port_.value == 1:
                rxm_if = port_0_name_.value
            else:
                continue  # Wait until user has mapped listening port.

            # Prioritize buffered messages received earlier
            if not port_send_buffer.empty():
                packet = port_send_buffer.get()
            elif not packet_to_rxm.empty():
                packet = packet_to_rxm.get()
            else:
                continue

            packet = '1N' + packet
            final = rs.encode(bytearray(packet))
            try:
                rxm_port = serial.Serial(rxm_if, serial_iface_speed)
                rxm_port.write(final)
                time.sleep(0.3)

            except SerialException:
                port_send_buffer.put(packet)

        except KeyboardInterrupt:
            pass


###############################################################################
#                              PACKETS TO PIDGIN                              #
###############################################################################

def pidgin_sender_process():
    """
    Send message from queue to Pidgin.

    :return: [no return value]
    """

    bus = dbus.SessionBus()
    obj = bus.get_object("im.pidgin.purple.PurpleService",
                         "/im/pidgin/purple/PurpleObject")
    purple = dbus.Interface(obj, "im.pidgin.purple.PurpleInterface")

    while True:
        try:
            if message_to_pidgin.empty():
                time.sleep(0.1)
                continue

            message, user, acco = message_to_pidgin.get()

            user_found = False
            for u in purple.PurpleAccountsGetAllActive():
                if user == purple.PurpleAccountGetUsername(u)[:-1]:
                    user_found = True
                    if relay_to_im_client:
                        new_conv = purple.PurpleConversationNew(1, u, acco)
                        sel_conv = purple.PurpleConvIm(new_conv)
                        purple.PurpleConvImSend(sel_conv, message)
                    break

            if not user_found:
                print("\nError: No user %s found.\n" % user)
                continue

        except KeyboardInterrupt:
            pass


###############################################################################
#                                     MAIN                                    #
###############################################################################

rs = RSCodec(2 * e_correction_ratio)

# Define VT100 codes and other constants
cu = "\x1b[1A"  # Move cursor up 1 line
cs = "\x1b[2J"  # Clear entire screen
cc = "\x1b[H"   # Move cursor to upper left corner
us = '\x1f'     # Field delimiter character

if __name__ == "__main__":

    clear_screen()
    process_arguments()

    os_id = ''
    try:
        os_id = subprocess.check_output(["grep", "^ID=", "/etc/os-release"])
        os_id = os_id[3:].strip('\n')
    except subprocess.CalledProcessError:
        try:
            os_id = subprocess.check_output(["grep", "ID=", "/etc/os-release"])
        except subprocess.CalledProcessError:
            graceful_exit("Error: Unsupported OS")

    if os_id == "raspbian":
        rpi_os = True
    elif os_id == "ubuntu":
        rpi_os = False
    elif "TAILS" in os_id:
        rpi_os = False
    else:
        graceful_exit("Error: Unsupported OS")

    process_control = multiprocessing.Queue()
    packet_to_rxm = multiprocessing.Queue()
    nh_side_command = multiprocessing.Queue()
    message_to_pidgin = multiprocessing.Queue()
    message_from_pidgin = multiprocessing.Queue()
    port_send_buffer = multiprocessing.Queue()
    port_recv_buffer = multiprocessing.Queue()
    pidgin_ready = multiprocessing.Queue()

    pc = multiprocessing.Process(target=pidgin_connection)
    hp = multiprocessing.Process(target=header_printer_process)
    ps = multiprocessing.Process(target=pidgin_sender_process)
    cp = multiprocessing.Process(target=nh_command_process)
    pr = multiprocessing.Process(target=pidgin_receiver_process)
    tp = multiprocessing.Process(target=txm_packet_process)

    lr = None
    ls = None
    p0l = None
    p1l = None
    p_s = None

    pc.start()
    phase("Waiting for enabled account in Pidgin...", 41)
    while True:
        time.sleep(0.1)
        if not pidgin_ready.empty():
            if pidgin_ready.get() == "OK":
                print("OK.")
                pc.terminate()
                break

    tp.start()

    if local_testing_mode:
        rxsocket = 5002 if data_diode_sockets else 5003

        try:
            phase("Waiting for socket from Rx.py...", 41)
            ipc_rx = multiprocessing.connection.Client(("localhost", rxsocket))
            print("OK.\n")
            time.sleep(0.5)
            clear_screen()
        except KeyboardInterrupt:
            pass

        lr = multiprocessing.Process(target=txm_ipc_receiver_process)
        ls = multiprocessing.Process(target=rxm_ipc_sender_process)

        lr.start()
        ls.start()

    else:
        port_0, port_1 = search_serial_interfaces()

        port_0_name = multiprocessing.Array(ctypes.c_char, port_0)
        port_1_name = multiprocessing.Array(ctypes.c_char, port_1)
        port_0_connected = multiprocessing.Value('i', 1)
        port_1_connected = multiprocessing.Value('i', 1)
        listening_port = multiprocessing.Value('i', 2)
        lock = multiprocessing.Lock()

        p0l = multiprocessing.Process(target=txm_serial_0_receiver_process,
                                      args=(port_0_name,
                                            port_1_name,
                                            port_0_connected,
                                            listening_port,
                                            lock))

        p1l = multiprocessing.Process(target=txm_serial_1_receiver_process,
                                      args=(port_0_name,
                                            port_1_name,
                                            port_0_connected,
                                            port_1_connected,
                                            listening_port,
                                            lock))

        p_s = multiprocessing.Process(target=rxm_serial_sender_process,
                                      args=(port_0_name,
                                            port_1_name,
                                            port_0_connected,
                                            port_1_connected,
                                            listening_port))

        p0l.start()
        p1l.start()
        p_s.start()

        if show_curses_banner:
            clear_screen()
            print_banner()
            clear_screen()

        hp.start()

    time.sleep(0.5)
    ps.start()
    cp.start()
    pr.start()

    if local_testing_mode:
        if show_curses_banner:
            clear_screen()
            print_banner()
            clear_screen()
        hp.start()

    process_list = [ps, cp, pr, tp]
    process_list += [lr, ls] if local_testing_mode else [p0l, p1l, p_s]

    def p_kill():
        for p in process_list:
            p.terminate()
        graceful_exit()

    try:
        while True:
            time.sleep(0.01)
            for process in process_list:
                if not process.is_alive():
                    p_kill()
    except KeyboardInterrupt:
        p_kill()
