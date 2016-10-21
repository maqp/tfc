#!/usr/bin/env python
# -*- coding: utf-8 -*-

# TFC 0.16.10 || hwrng.py

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

import binascii
import time
import sys

try:
    import RPi.GPIO as GPIO
except ImportError:
    GPIO = None
    pass


###############################################################################
#                                CONFIGURATION                                #
###############################################################################

sample_delay = 0.1  # Delay in seconds between samples

gpio_port = 4       # RPi's GPIO pin (Broadcom layout) to collect entropy from


###############################################################################
#                                     MAIN                                    #
###############################################################################

def main():
    """
    Load 256 or 512 bits of entropy from HWRNG.

    :return: None
    """

    GPIO.setmode(GPIO.BCM)
    GPIO.setup(gpio_port, GPIO.IN, pull_up_down=GPIO.PUD_DOWN)

    ent_size = int(sys.argv[1])

    if ent_size not in [256, 512, 768]:
        print('S')
        exit()

    init0 = 0
    init1 = 0
    vnd = ''

    while init0 < 1500 or init1 < 1500:
        time.sleep(0.001)

        if GPIO.input(gpio_port) == 1:
            init1 += 1
        else:
            init0 += 1

    while len(vnd) != ent_size:

        # Perform Von Neumann whitening during sampling
        first_bit = GPIO.input(gpio_port)
        time.sleep(sample_delay)

        second_bit = GPIO.input(gpio_port)
        time.sleep(sample_delay)

        if first_bit == second_bit:
            continue
        else:
            vnd += str(first_bit)
            sys.stdout.flush()
            sys.stdout.write("N\n")

    # Convert bits to byte string
    ent = ''.join(chr(int(vnd[i:i + 8], 2)) for i in range(0, len(vnd), 8))

    if len(ent) != ent_size / 8:
        print('L')

    GPIO.cleanup()
    print(binascii.hexlify(ent))

if __name__ == "__main__":
    main()
