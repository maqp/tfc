#!/usr/bin/env python
# -*- coding: utf-8 -*-

# TFC-CEV 0.16.05 || test_nh.py

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

import NH
from NH import *
import binascii
import unittest

# Import crypto libraries
import hashlib


###############################################################################
#                               UNITTEST HELPERS                              #
###############################################################################

def ut_sha2_256(message):
    h_function = hashlib.sha256()
    h_function.update(message)
    return binascii.hexlify(h_function.digest())


###############################################################################
#                                   HELPERS                                   #
###############################################################################

NH.unittesting = True


class TestPhase(unittest.TestCase):

    def test_1_input_parameters(self):
        for a in [1, 1.0, True]:
            for b in ["string", 1.0, True]:
                with self.assertRaises(SystemExit):
                    phase(a, b)

    def test_2_output_type(self):
        self.assertIsNone(phase("test", 10))


class TestSHA256(unittest.TestCase):

    def test_1_input_parameter(self):
        for a in [1, 1.0, True]:
            with self.assertRaises(SystemExit):
                sha2_256(a)

    def test_2_SHA256_vector(self):
        """
        Test SHA256 with official test vector:
        http://csrc.nist.gov/groups/ST/toolkit/
        documents/Examples/SHA_All.pdf // page 14
        """

        self.assertEqual(sha2_256("abc"), "ba7816bf8f01cfea414140de5dae2223"
                                          "b00361a396177a9cb410ff61f20015ad")


class TestVerifyChecksum(unittest.TestCase):

    def test_1_input_parameter(self):
        for a in [1, 1.0, True]:
            with self.assertRaises(SystemExit):
                verify_checksum(a)

    def test_2_function(self):
        pt = "test_packet"
        tv = ut_sha2_256(pt)
        self.assertTrue(verify_checksum("%s|%s" % (pt, tv[:NH.checksum_len])))


class TestGracefulExit(unittest.TestCase):

    def test_1_function(self):
        with self.assertRaises(SystemExit):
            graceful_exit()


class TestGetTTyWH(unittest.TestCase):

    def test_output_types(self):
        w, h = get_tty_wh()

        self.assertTrue(isinstance(w, int))
        self.assertTrue(isinstance(h, int))


class TestPrintBanner(unittest.TestCase):

    def test_output_type(self):
        self.assertIsNone(print_banner())


class TestGetSerialInterfaces(unittest.TestCase):
    """
    This function doesn't have any tests yet.
    """


###############################################################################
#                                   RECEIVER                                  #
###############################################################################

class TestDBusReceiver(unittest.TestCase):
    """
    This function doesn't have any tests yet.
    """


class TestPidginToRxMQueue(unittest.TestCase):
    """
    This function doesn't have any tests yet.
    """


class TestPidginReceiverProcess(unittest.TestCase):
    """
    This function doesn't have any tests yet.
    """


###############################################################################
#                                    OTHER                                    #
###############################################################################

class TestHeaderPrinterProcess(unittest.TestCase):
    """
    This function doesn't have any tests yet.
    """


class TestNHSideCommandProcess(unittest.TestCase):
    """
    This function doesn't have any tests yet.
    """


class TestQueueToPidginProcess(unittest.TestCase):
    """
    This function doesn't have any tests yet.
    """


class NHToRxMSenderProcess(unittest.TestCase):
    """
    This function doesn't have any tests yet.
    """


###############################################################################
#                               PACKETS FROM TxM                              #
###############################################################################

class TestChooseTxMPacketQueues(unittest.TestCase):

    def test_1_input_parameter(self):
        for a in [1, 1.0, True]:
            with self.assertRaises(SystemExit):
                choose_txm_packet_queues(a)


class TestTxMPacketLoadProcess(unittest.TestCase):
    """
    This function doesn't have any tests yet.
    """


class TestRxMPortListener(unittest.TestCase):
    """
    This function doesn't have any tests yet.
    """


class TestTxMPortListener(unittest.TestCase):
    """
    This function doesn't have any tests yet.
    """


class TestProcessArguments(unittest.TestCase):
    """
    This function doesn't have any tests yet.
    """


###############################################################################
#                                     MAIN                                    #
###############################################################################

if __name__ == "__main__":
    unittest.main(exit=False)
