#!/usr/bin/env python
# -*- coding: utf-8 -*-

# TFC-NaCl 0.16.05 || hwrng-nacl.py

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

import binascii
import time

try:
    import RPi.GPIO as GPIO
except ImportError:
    GPIO = None
    pass


###############################################################################
#                                CONFIGURATION                                #
###############################################################################

sample_delay = 0.1  # Delay in seconds between samples

gpio_port = 4       # RPi's GPIO pin (Broadcom layout) to collect entropy from.


###############################################################################
#                                     MAIN                                    #
###############################################################################

def main():
    """
    Load 32 bytes of entropy from HWRNG.

    :return: None
    """

    def digits_to_bytes(di):
        """
        Convert string of binary digits to byte string.

        :param di: Digit string.
        :return:   Byte string.
        """

        return ''.join(chr(int(di[i:i + 8], 2)) for i in xrange(0, len(di), 8))

    try:
        w0 = 0
        w1 = 0
        while True:
            if w1 > 1500 and w0 > 1500:
                break
            if GPIO.input(gpio_port) == 1:
                w1 += 1
            else:
                w0 += 1
            time.sleep(0.001)

        # Perform Von Neumann whitening during sampling
        vn_digits = ''

        while True:

            if len(vn_digits) >= 256:
                break

            first_bit = GPIO.input(gpio_port)
            time.sleep(sample_delay)

            second_bit = GPIO.input(gpio_port)
            time.sleep(sample_delay)

            if first_bit == second_bit:
                continue
            else:
                vn_digits += str(first_bit)

        entropy = digits_to_bytes(vn_digits)

        if len(entropy) != 32:
            print("ERROR")

    except KeyboardInterrupt:
        GPIO.cleanup()
        raise

    GPIO.cleanup()
    print(binascii.hexlify(entropy))


if __name__ == "__main__":
    GPIO.setmode(GPIO.BCM)
    GPIO.setup(gpio_port, GPIO.IN, pull_up_down=GPIO.PUD_DOWN)

    main()
