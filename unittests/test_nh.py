#!/usr/bin/env python
# -*- coding: utf-8 -*-

# TFC 0.16.10 || test_nh.py

"""
Copyright (C) 2013-2016  Markus Ottela

This file is part of TFC.

TFC is free software: you can redistribute it and/or modify it under the terms
of the GNU General Public License as published by the Free Software Foundation,
either version 3 of the License, or (at your option) any later version.

TFC is distributed in the hope that it will be useful, but WITHOUT ANY
WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
PARTICULAR PURPOSE.  See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with
TFC. If not, see <http://www.gnu.org/licenses/>.
"""

import NH
from NH import *
import unittest


###############################################################################
#                               UNITTEST HELPERS                              #
###############################################################################

not_str = [1, 1.0, True]
not_int = ["string", 1.0]
not_tup = [1.0, "string", 1, True]


###############################################################################
#                                     MISC                                    #
###############################################################################

class TestGracefulExit(unittest.TestCase):

    class TestGracefulExit(unittest.TestCase):
        def test_1_input_parameter(self):
            for a in not_str:
                with self.assertRaises(SystemExit):
                    graceful_exit(a)

        def test_2_function(self):
            with self.assertRaises(SystemExit):
                graceful_exit()


class TestPrintBanner(unittest.TestCase):

    def test_1_non_rpi(self):

        # Setup
        NH.rpi_os = False

        # Test
        self.assertIsNone(print_banner())

    def test_2_rpi(self):

        # Setup
        NH.rpi_os = True

        # Test
        self.assertIsNone(print_banner())


class TestInputValidation(unittest.TestCase):

    def test_1_input_parameter(self):
        for a in not_tup:
            with self.assertRaises(TypeError):
                input_validation(a)


class TestPhase(unittest.TestCase):

    def test_1_input_parameters(self):
        for a in not_str:
            for b in not_int:
                with self.assertRaises(SystemExit):
                    phase(a, b)

    def test_2_output_type(self):
        self.assertIsNone(phase("test", 10))
        print("Done.")
        self.assertIsNone(phase("\ntest", 10))
        print("Done.")
        self.assertIsNone(phase("\n\n\ntest", 10))
        print("Done.")


class TestClearScreen(unittest.TestCase):

    def test_1_function(self):
        self.assertIsNone(clear_screen())


class TestGetSerialInterfaces(unittest.TestCase):
    """
    This function doesn't have any tests yet.
    """


class TestProcessArguments(unittest.TestCase):
    """
    This function doesn't have any tests yet.
    """


###############################################################################
#                            REED SOLOMON ENCODING                            #
###############################################################################

class TestRSEncode(unittest.TestCase):

    def test_1_correction(self):

        string = 10 * "Testmessage"
        print("Original: %s" % string)

        encoded = rs.encode(string)
        print ("After encoding: %s" % encoded)

        error = NH.e_correction_ratio
        altered = os.urandom(error) + encoded[error:]
        print("After errors: %s" % altered)

        corrected = rs.decode(altered)
        print("Corrected: %s" % corrected)

        self.assertEqual(corrected, string)


###############################################################################
#                            LOCAL DATA PROCESSING                            #
###############################################################################

class TestHeaderPrinterProcess(unittest.TestCase):
    """
    This function doesn't have any tests yet.
    """


class TestNHCommandProcess(unittest.TestCase):
    """
    This function doesn't have any tests yet.
    """


###############################################################################
#                             PACKETS FROM PIDGIN                             #
###############################################################################

class TestPidginConnection(unittest.TestCase):
    """
    This function doesn't have any tests yet.
    """


class TestPidginToRxMQueue(unittest.TestCase):
    """
    This function doesn't have any tests yet.
    """


class TestDBusReceiver(unittest.TestCase):
    """
    This function doesn't have any tests yet.
    """


class TestPidginReceiverProcess(unittest.TestCase):
    """
    This function doesn't have any tests yet.
    """


###############################################################################
#                               PACKETS FROM TxM                              #
###############################################################################

class TestTxMIPCReceiverProcess(unittest.TestCase):
    """
    This function doesn't have any tests yet.
    """


class TestTxMSerial0ReceiverProcess(unittest.TestCase):
    """
    This function doesn't have any tests yet.
    """


class TestTxMSerial1ReceiverProcess(unittest.TestCase):
    """
    This function doesn't have any tests yet.
    """


class TestTxMPacketProcess(unittest.TestCase):
    """
    This function doesn't have any tests yet.
    """


###############################################################################
#                                PACKETS TO RxM                               #
###############################################################################

class TestRxMIPCSenderProcess(unittest.TestCase):
    """
    This function doesn't have any tests yet.
    """


class TestRxMSerialSenderProcess(unittest.TestCase):
    """
    This function doesn't have any tests yet.
    """


###############################################################################
#                              PACKETS TO PIDGIN                              #
###############################################################################

class TestPidginSenderProcess(unittest.TestCase):
    """
    This function doesn't have any tests yet.
    """


###############################################################################
#                                     MAIN                                    #
###############################################################################

if __name__ == "__main__":

    NH.unit_testing = True

    try:
        os.remove("NH.pyc")
    except OSError:
        pass

    unittest.main(exit=False)

    try:
        os.remove("NH.pyc")
    except OSError:
        pass
