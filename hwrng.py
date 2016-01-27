#!/usr/bin/env python
# -*- coding: utf-8 -*-

# TFC-NaCl 0.16.01 beta || hwrng.py

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

from binascii import hexlify
from os import system
from time import sleep
from hashlib import sha256
from simplesha3 import sha3256

try:
    import RPi.GPIO as GPIO
except ImportError:
    GPIO = None
    pass

str_version = "0.16.01 beta"
int_version = 1601


###############################################################################
#                               ERROR CLASSES                                 #
###############################################################################

class FunctionParameterTypeError(Exception):
    """
    hwrng.py should gracefully exit if function is called with incorrect
    parameter types.
    """

    def __init__(self, function_name):
        system("clear")
        print("\nError: M(%s): Wrong input type.\n" % function_name)
        exit()


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


def get_hwrng_entropy():
    """
    Get HWRNG entropy.

    Load entropy from HWRNG through GPIO pins.

    Before sampling starts, a loop collects 3000 samples to allow the HWRNG
    time to warm. Sampling is done at 10Hz frequency to ensure minimal
    auto-correlation between samples. Entropy is compressed with SHA3-256
    before it is returned.

    :return: 32 bytes of entropy.
    """

    def digits_to_bytes(di):
        """
        Convert string of binary digits to byte string.

        :param di: Digit string.
        :return:   Byte string.
        """

        return ''.join(chr(int(di[i:i + 8], 2)) for i in xrange(0, len(di), 8))

    # Sampling settings
    sample_delay = 0.1
    gpio_port = 4
    samples_n = 256
    GPIO.setmode(GPIO.BCM)
    GPIO.setup(gpio_port, GPIO.IN, pull_up_down=GPIO.PUD_DOWN)

    try:
        warmup_zero = 0
        warmup_one = 0

        while True:
            if warmup_one > 1500 and warmup_zero > 1500:
                break
            if GPIO.input(gpio_port) == 1:
                warmup_one += 1
            else:
                warmup_zero += 1
            sleep(0.001)

        # Perform Von Neumann whitening during sampling
        vn_digits = ''

        while True:

            if len(vn_digits) >= samples_n:
                break

            first_bit = GPIO.input(gpio_port)
            sleep(sample_delay)

            second_bit = GPIO.input(gpio_port)
            sleep(sample_delay)

            if first_bit == second_bit:
                continue
            else:
                vn_digits += str(first_bit)

        hwrng_bytes = digits_to_bytes(vn_digits)

        if len(hwrng_bytes) != 32:
            print("ERROR")

        entropy = sha3_256(hwrng_bytes)

    except KeyboardInterrupt:
        GPIO.cleanup()
        raise

    GPIO.cleanup()
    print entropy

get_hwrng_entropy()
