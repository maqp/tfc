#!/usr/bin/env python3.7
# -*- coding: utf-8 -*-

"""
# Copyright (c) 2012-2015 Tomer Filiba <tomerfiliba@gmail.com>
# Copyright (c) 2015 rotorgit
# Copyright (c) 2015 Stephen Larroque <LRQ3000@gmail.com>

The Reed Solomon erasure code library has been released to the public domain.

https://github.com/lrq3000/reedsolomon/blob/master/LICENSE
https://github.com/tomerfiliba/reedsolomon/blob/master/LICENSE
"""

import unittest

from random import sample
from typing import Dict, List, Union

from src.common.reed_solomon import (RSCodec, ReedSolomonError, find_prime_polys, gf_add, gf_div, gf_mul, gf_mult_nolut,
                                     gf_mult_nolut_slow, gf_neg, gf_poly_mul, gf_poly_mul_simple, gf_poly_neg, gf_sub,
                                     init_tables, itertools, rs_check, rs_correct_msg, rs_correct_msg_nofsynd,
                                     rs_encode_msg, rs_generator_poly, rs_generator_poly_all, rs_simple_encode_msg)


class TestReedSolomon(unittest.TestCase):

    def test_simple(self) -> None:
        rs           = RSCodec()
        msg          = bytearray("hello world " * 10, "latin1")
        enc          = rs.encode(msg)
        dec, dec_enc = rs.decode(enc)
        self.assertEqual(dec, msg)
        self.assertEqual(dec_enc, enc)

    def test_correction(self) -> None:
        rs         = RSCodec()
        msg        = bytearray("hello world " * 10, "latin1")
        enc        = rs.encode(msg)
        rmsg, renc = rs.decode(enc)
        self.assertEqual(rmsg, msg)
        self.assertEqual(renc, enc)
        for i in [27, -3, -9, 7, 0]:
            enc[i]     = 99
            rmsg, renc = rs.decode(enc)
            self.assertEqual(rmsg, msg)
        enc[82] = 99
        self.assertRaises(ReedSolomonError, rs.decode, enc)

    def test_check(self) -> None:
        rs         = RSCodec()
        msg        = bytearray("hello world " * 10, "latin1")
        enc        = rs.encode(msg)
        rmsg, renc = rs.decode(enc)
        self.assertEqual(rs.check(enc), [True])
        self.assertEqual(rs.check(renc), [True])
        for i in [27, -3, -9, 7, 0]:
            enc[i]     = 99
            rmsg, renc = rs.decode(enc)
            self.assertEqual(rs.check(enc), [False])
            self.assertEqual(rs.check(renc), [True])

    def test_long(self) -> None:
        rs           = RSCodec()
        msg          = bytearray("a" * 10000, "latin1")
        enc          = rs.encode(msg)
        dec, dec_enc = rs.decode(enc)
        self.assertEqual(dec, msg)
        self.assertEqual(dec_enc, enc)
        enc2           = list(enc)
        enc2[177]      = 99
        enc2[2212]     = 88
        dec2, dec_enc2 = rs.decode(bytes(enc2))
        self.assertEqual(dec2, msg)
        self.assertEqual(dec_enc2, enc)

    def test_prim_fcr_basic(self) -> None:
        nn          = 30
        kk          = 18
        tt          = nn - kk
        rs          = RSCodec(tt, fcr=120, prim=0x187)
        hex_enc_msg = ('00faa123555555c000000354064432'
                     'c02800fe97c434e1ff5365cf8fafe4')
        strf        = str
        enc_msg     = bytearray.fromhex(strf(hex_enc_msg))
        dec_msg     = enc_msg[:kk]
        tem         = rs.encode(dec_msg)
        self.assertEqual(enc_msg, tem, msg="encoded does not match expected")

        tdm, rtem = rs.decode(tem)
        self.assertEqual(tdm, dec_msg, msg="decoded does not match original")
        self.assertEqual(rtem, tem,    msg="decoded mesecc does not match original")

        tem1 = bytearray(tem)  # Clone a copy

        # Encoding and decoding intact message seem OK, so test errors
        num_errs = tt >> 1  # Inject tt/2 errors (expected to recover fully)
        for i in sample(range(nn), num_errs):  # inject errors in random places
            tem1[i] ^= 0xff  # flip all 8 bits
        tdm, _ = rs.decode(tem1)
        self.assertEqual(tdm, dec_msg, msg="decoded with errors does not match original")

        tem1 = bytearray(tem)  # Clone another copy
        num_errs += 1  # Inject tt/2 + 1 errors (expected to fail and detect it)
        for i in sample(range(nn), num_errs):  # Inject errors in random places
            tem1[i] ^= 0xff  # Flip all 8 bits
        # If this fails, it means excessive errors not detected
        self.assertRaises(ReedSolomonError, rs.decode, tem1)

    def test_prim_fcr_long(self) -> None:
        nn          = 48
        kk          = 34
        tt          = nn - kk
        rs          = RSCodec(tt, fcr=120, prim=0x187)
        hex_enc_msg = ('08faa123555555c000000354064432c0280e1b4d090cfc04'
                       '887400000003500000000e1985ff9c6b33066ca9f43d12e8')
        strf        = str
        enc_msg     = bytearray.fromhex(strf(hex_enc_msg))
        dec_msg     = enc_msg[:kk]
        tem         = rs.encode(dec_msg)
        self.assertEqual(enc_msg, tem, msg="encoded does not match expected")

        tdm, rtem = rs.decode(tem)
        self.assertEqual(tdm, dec_msg, msg="decoded does not match original")
        self.assertEqual(rtem, tem,    msg="decoded mesecc does not match original")

        tem1    = bytearray(tem)
        num_errs = tt >> 1
        for i in sample(range(nn), num_errs):
            tem1[i] ^= 0xff
        tdm, rtem = rs.decode(tem1)
        self.assertEqual(tdm, dec_msg, msg="decoded with errors does not match original")
        self.assertEqual(rtem, tem,    msg="decoded mesecc with errors does not match original")

        tem1     = bytearray(tem)
        num_errs += 1
        for i in sample(range(nn), num_errs):
            tem1[i] ^= 0xff
        self.assertRaises(ReedSolomonError, rs.decode, tem1)

    def test_generator_poly(self) -> None:
        """\
        Test if generator poly finder is working correctly and if
        the all generators poly finder does output the same result
        """
        n = 11
        k = 3

        # Base 2 test
        fcr       = 120
        generator = 2
        prim      = 0x11d
        init_tables(generator=generator, prim=prim)
        g = rs_generator_poly_all(n, fcr=fcr, generator=generator)
        self.assertEqual(list(g[n-k]), list(rs_generator_poly(n-k, fcr=fcr, generator=generator)))
        self.assertEqual(list(g[n-k]), [1, 106, 9, 105, 86, 5, 166, 76, 9])

        # Base 3 test
        fcr       = 0
        generator = 3
        prim      = 0x11b
        init_tables(generator=generator, prim=prim)
        g = rs_generator_poly_all(n, fcr=fcr, generator=generator)
        self.assertEqual(list(g[n-k]), list(rs_generator_poly(n-k, fcr=fcr, generator=generator)))
        self.assertEqual(list(g[n-k]), [1, 128, 13, 69, 36, 145, 199, 165, 30])

    def test_prime_poly_build(self) -> None:
        """\
        Try if the prime polynomials finder works correctly for
        different GFs (ie, GF(2^6) to GF(2^10)) and with different
        generators.
        """
        params = {"count":     7,
                  "c_exp":     [6, 7, 7, 8, 8, 9, 10],
                  "generator": [2, 2, 3, 2, 3, 2, 2],
                  "expected":
                      [
                          [67, 91, 97, 103, 109, 115],
                          [131, 137, 143, 145, 157, 167, 171, 185, 191, 193, 203, 211, 213, 229, 239, 241, 247, 253],
                          [131, 137, 143, 145, 157, 167, 171, 185, 191, 193, 203, 211, 213, 229, 239, 241, 247, 253],
                          [285, 299, 301, 333, 351, 355, 357, 361, 369, 391, 397, 425, 451, 463, 487, 501],
                          [283, 313, 319, 333, 351, 355, 357, 361, 375, 397, 415, 419, 425, 451, 501, 505],

                          [529, 539, 545, 557, 563, 601, 607, 617, 623, 631, 637, 647, 661, 675, 677, 687,
                           695, 701, 719, 721, 731, 757, 761, 787, 789, 799, 803, 817, 827, 847, 859, 865,
                           875, 877, 883, 895, 901, 911, 949, 953, 967, 971, 973, 981, 985, 995, 1001, 1019],

                          [1033, 1051, 1063, 1069, 1125, 1135, 1153, 1163, 1221, 1239, 1255, 1267, 1279, 1293, 1305,
                           1315, 1329, 1341, 1347, 1367, 1387, 1413, 1423, 1431, 1441, 1479, 1509, 1527, 1531, 1555,
                           1557, 1573, 1591, 1603, 1615, 1627, 1657, 1663, 1673, 1717, 1729, 1747, 1759, 1789, 1815,
                           1821, 1825, 1849, 1863, 1869, 1877, 1881, 1891, 1917, 1933, 1939, 1969, 2011, 2035, 2041]
                      ]
                  }

        for i in range(params['count']):
            self.assertEqual(find_prime_polys(generator=params['generator'][i],
                                              c_exp=params['c_exp'][i]),
                             params["expected"][i])

    def test_init_tables(self) -> None:
        """\
        Try if the look up table generator (galois field generator)
        works correctly for different parameters.
        """
        params = [
                        [0x11d, 2, 8],
                        [0x11b, 3, 8],
                        [0xfd,  3, 7]
                       ]
        expected = [
            [
                [0, 0, 1, 25, 2, 50, 26, 198, 3, 223, 51, 238, 27, 104, 199, 75, 4, 100, 224, 14, 52,
                 141, 239, 129, 28, 193, 105, 248, 200, 8, 76, 113, 5, 138, 101, 47, 225, 36, 15, 33,
                 53, 147, 142, 218, 240, 18, 130, 69, 29, 181, 194, 125, 106, 39, 249, 185, 201, 154,
                 9, 120, 77, 228, 114, 166, 6, 191, 139, 98, 102, 221, 48, 253, 226, 152, 37, 179,
                 16, 145, 34, 136, 54, 208, 148, 206, 143, 150, 219, 189, 241, 210, 19, 92, 131, 56,
                 70, 64, 30, 66, 182, 163, 195, 72, 126, 110, 107, 58, 40, 84, 250, 133, 186, 61, 202,
                 94, 155, 159, 10, 21, 121, 43, 78, 212, 229, 172, 115, 243, 167, 87, 7, 112, 192,
                 247, 140, 128, 99, 13, 103, 74, 222, 237, 49, 197, 254, 24, 227, 165, 153, 119, 38,
                 184, 180, 124, 17, 68, 146, 217, 35, 32, 137, 46, 55, 63, 209, 91, 149, 188, 207,
                 205, 144, 135, 151, 178, 220, 252, 190, 97, 242, 86, 211, 171, 20, 42, 93, 158, 132,
                 60, 57, 83, 71, 109, 65, 162, 31, 45, 67, 216, 183, 123, 164, 118, 196, 23, 73, 236,
                 127, 12, 111, 246, 108, 161, 59, 82, 41, 157, 85, 170, 251, 96, 134, 177, 187, 204,
                 62, 90, 203, 89, 95, 176, 156, 169, 160, 81, 11, 245, 22, 235, 122, 117, 44, 215,
                 79, 174, 213, 233, 230, 231, 173, 232, 116, 214, 244, 234, 168, 80, 88, 175],

                [1, 2, 4, 8, 16, 32, 64, 128, 29, 58, 116, 232, 205, 135, 19, 38, 76, 152, 45, 90,
                 180, 117, 234, 201, 143, 3, 6, 12, 24, 48, 96, 192, 157, 39, 78, 156, 37, 74, 148,
                 53, 106, 212, 181, 119, 238, 193, 159, 35, 70, 140, 5, 10, 20, 40, 80, 160, 93, 186,
                 105, 210, 185, 111, 222, 161, 95, 190, 97, 194, 153, 47, 94, 188, 101, 202, 137, 15,
                 30, 60, 120, 240, 253, 231, 211, 187, 107, 214, 177, 127, 254, 225, 223, 163, 91,
                 182, 113, 226, 217, 175, 67, 134, 17, 34, 68, 136, 13, 26, 52, 104, 208, 189, 103,
                 206, 129, 31, 62, 124, 248, 237, 199, 147, 59, 118, 236, 197, 151, 51, 102, 204, 133,
                 23, 46, 92, 184, 109, 218, 169, 79, 158, 33, 66, 132, 21, 42, 84, 168, 77, 154, 41,
                 82, 164, 85, 170, 73, 146, 57, 114, 228, 213, 183, 115, 230, 209, 191, 99, 198, 145,
                 63, 126, 252, 229, 215, 179, 123, 246, 241, 255, 227, 219, 171, 75, 150, 49, 98, 196,
                 149, 55, 110, 220, 165, 87, 174, 65, 130, 25, 50, 100, 200, 141, 7, 14, 28, 56, 112,
                 224, 221, 167, 83, 166, 81, 162, 89, 178, 121, 242, 249, 239, 195, 155, 43, 86, 172,
                 69, 138, 9, 18, 36, 72, 144, 61, 122, 244, 245, 247, 243, 251, 235, 203, 139, 11, 22,
                 44, 88, 176, 125, 250, 233, 207, 131, 27, 54, 108, 216, 173, 71, 142, 1, 2, 4, 8, 16,
                 32, 64, 128, 29, 58, 116, 232, 205, 135, 19, 38, 76, 152, 45, 90, 180, 117, 234, 201,
                 143, 3, 6, 12, 24, 48, 96, 192, 157, 39, 78, 156, 37, 74, 148, 53, 106, 212, 181,
                 119, 238, 193, 159, 35, 70, 140, 5, 10, 20, 40, 80, 160, 93, 186, 105, 210, 185, 111,
                 222, 161, 95, 190, 97, 194, 153, 47, 94, 188, 101, 202, 137, 15, 30, 60, 120, 240,
                 253, 231, 211, 187, 107, 214, 177, 127, 254, 225, 223, 163, 91, 182, 113, 226, 217,
                 175, 67, 134, 17, 34, 68, 136, 13, 26, 52, 104, 208, 189, 103, 206, 129, 31, 62, 124,
                 248, 237, 199, 147, 59, 118, 236, 197, 151, 51, 102, 204, 133, 23, 46, 92, 184, 109,
                 218, 169, 79, 158, 33, 66, 132, 21, 42, 84, 168, 77, 154, 41, 82, 164, 85, 170, 73,
                 146, 57, 114, 228, 213, 183, 115, 230, 209, 191, 99, 198, 145, 63, 126, 252, 229,
                 215, 179, 123, 246, 241, 255, 227, 219, 171, 75, 150, 49, 98, 196, 149, 55, 110, 220,
                 165, 87, 174, 65, 130, 25, 50, 100, 200, 141, 7, 14, 28, 56, 112, 224, 221, 167, 83,
                 166, 81, 162, 89, 178, 121, 242, 249, 239, 195, 155, 43, 86, 172, 69, 138, 9, 18, 36,
                 72, 144, 61, 122, 244, 245, 247, 243, 251, 235, 203, 139, 11, 22, 44, 88, 176, 125,
                 250, 233, 207, 131, 27, 54, 108, 216, 173, 71, 142],

                255
            ],
            [
                [0, 0, 25, 1, 50, 2, 26, 198, 75, 199, 27, 104, 51, 238, 223, 3, 100, 4, 224, 14, 52,
                 141, 129, 239, 76, 113, 8, 200, 248, 105, 28, 193, 125, 194, 29, 181, 249, 185, 39,
                 106, 77, 228, 166, 114, 154, 201, 9, 120, 101, 47, 138, 5, 33, 15, 225, 36, 18, 240,
                 130, 69, 53, 147, 218, 142, 150, 143, 219, 189, 54, 208, 206, 148, 19, 92, 210, 241,
                 64, 70, 131, 56, 102, 221, 253, 48, 191, 6, 139, 98, 179, 37, 226, 152, 34, 136, 145,
                 16, 126, 110, 72, 195, 163, 182, 30, 66, 58, 107, 40, 84, 250, 133, 61, 186, 43, 121,
                 10, 21, 155, 159, 94, 202, 78, 212, 172, 229, 243, 115, 167, 87, 175, 88, 168, 80,
                 244, 234, 214, 116, 79, 174, 233, 213, 231, 230, 173, 232, 44, 215, 117, 122, 235,
                 22, 11, 245, 89, 203, 95, 176, 156, 169, 81, 160, 127, 12, 246, 111, 23, 196, 73,
                 236, 216, 67, 31, 45, 164, 118, 123, 183, 204, 187, 62, 90, 251, 96, 177, 134, 59,
                 82, 161, 108, 170, 85, 41, 157, 151, 178, 135, 144, 97, 190, 220, 252, 188, 149, 207,
                 205, 55, 63, 91, 209, 83, 57, 132, 60, 65, 162, 109, 71, 20, 42, 158, 93, 86, 242,
                 211, 171, 68, 17, 146, 217, 35, 32, 46, 137, 180, 124, 184, 38, 119, 153, 227, 165,
                 103, 74, 237, 222, 197, 49, 254, 24, 13, 99, 140, 128, 192, 247, 112, 7],

                [1, 3, 5, 15, 17, 51, 85, 255, 26, 46, 114, 150, 161, 248, 19, 53, 95, 225, 56, 72,
                 216, 115, 149, 164, 247, 2, 6, 10, 30, 34, 102, 170, 229, 52, 92, 228, 55, 89, 235,
                 38, 106, 190, 217, 112, 144, 171, 230, 49, 83, 245, 4, 12, 20, 60, 68, 204, 79, 209,
                 104, 184, 211, 110, 178, 205, 76, 212, 103, 169, 224, 59, 77, 215, 98, 166, 241, 8,
                 24, 40, 120, 136, 131, 158, 185, 208, 107, 189, 220, 127, 129, 152, 179, 206, 73,
                 219, 118, 154, 181, 196, 87, 249, 16, 48, 80, 240, 11, 29, 39, 105, 187, 214, 97,
                 163, 254, 25, 43, 125, 135, 146, 173, 236, 47, 113, 147, 174, 233, 32, 96, 160, 251,
                 22, 58, 78, 210, 109, 183, 194, 93, 231, 50, 86, 250, 21, 63, 65, 195, 94, 226, 61,
                 71, 201, 64, 192, 91, 237, 44, 116, 156, 191, 218, 117, 159, 186, 213, 100, 172, 239,
                 42, 126, 130, 157, 188, 223, 122, 142, 137, 128, 155, 182, 193, 88, 232, 35, 101,
                 175, 234, 37, 111, 177, 200, 67, 197, 84, 252, 31, 33, 99, 165, 244, 7, 9, 27, 45,
                 119, 153, 176, 203, 70, 202, 69, 207, 74, 222, 121, 139, 134, 145, 168, 227, 62, 66,
                 198, 81, 243, 14, 18, 54, 90, 238, 41, 123, 141, 140, 143, 138, 133, 148, 167, 242,
                 13, 23, 57, 75, 221, 124, 132, 151, 162, 253, 28, 36, 108, 180, 199, 82, 246, 1, 3,
                 5, 15, 17, 51, 85, 255, 26, 46, 114, 150, 161, 248, 19, 53, 95, 225, 56, 72, 216,
                 115, 149, 164, 247, 2, 6, 10, 30, 34, 102, 170, 229, 52, 92, 228, 55, 89, 235, 38,
                 106, 190, 217, 112, 144, 171, 230, 49, 83, 245, 4, 12, 20, 60, 68, 204, 79, 209,
                 104, 184, 211, 110, 178, 205, 76, 212, 103, 169, 224, 59, 77, 215, 98, 166, 241, 8,
                 24, 40, 120, 136, 131, 158, 185, 208, 107, 189, 220, 127, 129, 152, 179, 206, 73,
                 219, 118, 154, 181, 196, 87, 249, 16, 48, 80, 240, 11, 29, 39, 105, 187, 214, 97,
                 163, 254, 25, 43, 125, 135, 146, 173, 236, 47, 113, 147, 174, 233, 32, 96, 160, 251,
                 22, 58, 78, 210, 109, 183, 194, 93, 231, 50, 86, 250, 21, 63, 65, 195, 94, 226, 61,
                 71, 201, 64, 192, 91, 237, 44, 116, 156, 191, 218, 117, 159, 186, 213, 100, 172,
                 239, 42, 126, 130, 157, 188, 223, 122, 142, 137, 128, 155, 182, 193, 88, 232, 35,
                 101, 175, 234, 37, 111, 177, 200, 67, 197, 84, 252, 31, 33, 99, 165, 244, 7, 9, 27,
                 45, 119, 153, 176, 203, 70, 202, 69, 207, 74, 222, 121, 139, 134, 145, 168, 227, 62,
                 66, 198, 81, 243, 14, 18, 54, 90, 238, 41, 123, 141, 140, 143, 138, 133, 148, 167,
                 242, 13, 23, 57, 75, 221, 124, 132, 151, 162, 253, 28, 36, 108, 180, 199, 82, 246],

                255
            ],
            [
                [0, 0, 7, 1, 14, 2, 8, 56, 21, 57, 9, 90, 15, 31, 63, 3, 28, 4, 64, 67, 16, 112, 97,
                 32, 22, 47, 38, 58, 70, 91, 10, 108, 35, 109, 11, 87, 71, 79, 74, 92, 23, 82, 119,
                 48, 104, 59, 39, 100, 29, 19, 54, 5, 45, 68, 65, 95, 77, 33, 98, 117, 17, 43, 115,
                 113, 42, 114, 116, 76, 18, 53, 94, 44, 78, 73, 86, 34, 81, 118, 99, 103, 30, 62, 89,
                 20, 126, 6, 55, 13, 111, 96, 66, 27, 46, 37, 107, 69, 36, 106, 26, 110, 61, 88, 12,
                 125, 52, 93, 75, 41, 72, 85, 102, 80, 84, 101, 40, 51, 105, 25, 124, 60, 24, 123, 50,
                 83, 122, 49, 120, 121],

                [1, 3, 5, 15, 17, 51, 85, 2, 6, 10, 30, 34, 102, 87, 4, 12, 20, 60, 68, 49, 83, 8, 24,
                 40, 120, 117, 98, 91, 16, 48, 80, 13, 23, 57, 75, 32, 96, 93, 26, 46, 114, 107, 64,
                 61, 71, 52, 92, 25, 43, 125, 122, 115, 104, 69, 50, 86, 7, 9, 27, 45, 119, 100, 81,
                 14, 18, 54, 90, 19, 53, 95, 28, 36, 108, 73, 38, 106, 67, 56, 72, 37, 111, 76, 41,
                 123, 112, 109, 74, 35, 101, 82, 11, 29, 39, 105, 70, 55, 89, 22, 58, 78, 47, 113,
                 110, 79, 44, 116, 97, 94, 31, 33, 99, 88, 21, 63, 65, 62, 66, 59, 77, 42, 126, 127,
                 124, 121, 118, 103, 84, 1, 3, 5, 15, 17, 51, 85, 2, 6, 10, 30, 34, 102, 87, 4, 12,
                 20, 60, 68, 49, 83, 8, 24, 40, 120, 117, 98, 91, 16, 48, 80, 13, 23, 57, 75, 32, 96,
                 93, 26, 46, 114, 107, 64, 61, 71, 52, 92, 25, 43, 125, 122, 115, 104, 69, 50, 86, 7,
                 9, 27, 45, 119, 100, 81, 14, 18, 54, 90, 19, 53, 95, 28, 36, 108, 73, 38, 106, 67,
                 56, 72, 37, 111, 76, 41, 123, 112, 109, 74, 35, 101, 82, 11, 29, 39, 105, 70, 55, 89,
                 22, 58, 78, 47, 113, 110, 79, 44, 116, 97, 94, 31, 33, 99, 88, 21, 63, 65, 62, 66,
                 59, 77, 42, 126, 127, 124, 121, 118, 103, 84],

                127
            ]
        ]

        for i, _ in enumerate(params):
            p                                                       = params[i]
            expected_log_t, expected_exp_t, expected_field_charac_t = expected[i]
            log_t, exp_t, field_charac_t                            = init_tables(prim=p[0], generator=p[1], c_exp=p[2])
            self.assertEqual(field_charac_t, expected_field_charac_t)
            self.assertEqual(list(log_t), expected_log_t)
            self.assertEqual(list(exp_t), expected_exp_t)


class TestBigReedSolomon(unittest.TestCase):

    def test_find_prime_polys(self) -> None:
        self.assertEqual(find_prime_polys(c_exp=4), [19, 25])
        self.assertEqual(find_prime_polys(),
                         [285, 299, 301, 333, 351, 355, 357, 361, 369, 391, 397, 425, 451, 463, 487, 501])

        self.assertEqual(find_prime_polys(fast_primes=True), [397, 463, 487])
        self.assertEqual(find_prime_polys(c_exp=9, fast_primes=True, single=True), 557)

    def test_c_exp_9(self) -> None:
        rsc  = RSCodec(12, c_exp=9)
        rsc2 = RSCodec(12, nsize=511)
        self.assertEqual(rsc.c_exp, rsc2.c_exp)
        self.assertEqual(rsc.nsize, rsc2.nsize)

        mes           = 'a'*((511-12)*2)
        mesecc        = rsc.encode(mes)
        mesecc[2]     = 1
        mesecc[-1]    = 1
        rmes, rmesecc = rsc.decode(mesecc)
        self.assertEqual(rsc.check(mesecc),  [False, False])
        self.assertEqual(rsc.check(rmesecc), [True,   True])
        self.assertEqual([x for x in rmes],  [ord(x) for x in mes])

    def test_c_exp_12(self) -> None:
        rsc  = RSCodec(12, c_exp=12)
        rsc2 = RSCodec(12, nsize=4095)
        self.assertEqual(rsc.c_exp, rsc2.c_exp)
        self.assertEqual(rsc.nsize, rsc2.nsize)

        mes           = 'a'*(4095-12)
        mesecc        = rsc.encode(mes)
        mesecc[2]     = 1
        mesecc[-1]    = 1
        rmes, rmesecc = rsc.decode(mesecc)
        self.assertEqual(rsc.check(mesecc),  [False])
        self.assertEqual(rsc.check(rmesecc), [True])
        self.assertEqual([x for x in rmes],  [ord(x) for x in mes])

    def test_multiple_rs_codec(self) -> None:
        """Test multiple RSCodec instances with different parameters."""
        mes     = 'A' * 30
        rs_256  = RSCodec(102)
        rs_1024 = RSCodec(900, c_exp=10)
        bytearray(rs_1024.decode(rs_1024.encode(mes))[0])
        rs_256.encode(mes)
        rs_1024.encode(mes)
        bytearray(rs_256.decode(rs_256.encode(mes))[0])
        # At this point, there should not have been any exception raised!


class TestGFArithmetics(unittest.TestCase):
    """Test Galois Field arithmetics."""

    def test_multiply_nolut(self) -> None:
        """\
        Try to multiply without look-up tables
        (necessary to build the look-up tables!)
        """
        a = 30
        b = 19

        generator = 2
        prim      = 0x11d

        # Compare the LUT multiplication and noLUT.
        init_tables(prim=prim, generator=generator)
        self.assertEqual(gf_mul(a, b), gf_mult_nolut(a, b, prim=prim))

        # More Galois Field multiplications
        self.assertEqual(gf_mult_nolut(5, 6,   prim=0x11b),  30)
        self.assertEqual(gf_mult_nolut(3, 125, prim=0x11b), 135)
        self.assertEqual(gf_mult_nolut(2, 200, prim=0x11d), 141)
        self.assertEqual(gf_mult_nolut_slow(2, 200, prim=0x11d), 141)

        # Multiplications in GF(2^7)
        self.assertEqual(gf_mult_nolut(3, 125, prim=0xfd,  field_charac_full=128), 122)

        # Multiplications outside of the finite field (we revert to
        # standard integer multiplications just to see if it works).
        self.assertEqual(gf_mult_nolut(3, 125, carryless=False), 375)

        # The second method, just to check that everything's alright
        self.assertEqual(gf_mult_nolut_slow(4, 125), 500)

    def test_gf_operations(self) -> None:
        """Try various Galois Field 2 operations"""
        init_tables()

        a = 30
        b = 19

        # Addition and subtraction (they are the same in GF(2^p)
        self.assertEqual(gf_add(0,   0), 0)
        self.assertEqual(gf_add(0,   0), gf_sub(0, 0))
        self.assertEqual(gf_add(1,   0), 1)
        self.assertEqual(gf_add(1,   0), gf_sub(1, 0))
        self.assertEqual(gf_add(0,   1), 1)
        self.assertEqual(gf_add(0,   1), gf_sub(0, 1))
        self.assertEqual(gf_add(1,   1), 0)
        self.assertEqual(gf_add(1,   1), gf_sub(1, 1))
        self.assertEqual(gf_add(a,   b), 13)
        self.assertEqual(gf_add(a,   b), gf_sub(a, b))
        self.assertEqual(gf_add(0,   b), b)
        self.assertEqual(gf_add(0,   b), gf_sub(0, b))
        self.assertEqual(gf_add(a,   0), a)
        self.assertEqual(gf_add(a,   0), gf_sub(a, 0))
        self.assertEqual(gf_add(a,   1), (a+1))
        self.assertEqual(gf_add(a,   1), gf_sub(a, 1))
        self.assertEqual(gf_add(1,   a), (a+1))
        self.assertEqual(gf_add(1,   a), gf_sub(1, a))
        self.assertEqual(gf_add(255, 1), 254)

        # Negation
        self.assertEqual(gf_neg(a), a)
        self.assertEqual(gf_neg(b), b)

        # Division
        self.assertEqual(gf_div(a,  1), a)
        self.assertEqual(gf_div(12, 3), 4)
        self.assertEqual(gf_div(a,  b), 222)
        self.assertEqual(gf_div(b,  a), 25)
        self.assertEqual(gf_div(0,  a), 0)
        self.assertRaises(ZeroDivisionError, gf_div, *[a, 0])


class TestSimpleFuncs(unittest.TestCase):
    """\
    Test simple functions and see if the results
    are equivalent with optimized functions
    """

    def test_gf_poly_mul_simple(self) -> None:
        a = [1, 12, 14,  9]
        b = [0, 23,  2, 15]
        self.assertEqual(gf_poly_mul(a, b), gf_poly_mul_simple(a, b))

    def test_gf_poly_neg(self) -> None:
        a = [1, 12, 14, 9]
        self.assertEqual(gf_poly_neg(a), a)

    def test_rs_simple_encode_msg(self) -> None:
        a    = bytearray("hello world", "latin1")
        nsym = 10
        init_tables()
        self.assertEqual(rs_simple_encode_msg(a, nsym),
                         rs_encode_msg(a, nsym))


class TestRSCodecUniversalCrossValidation(unittest.TestCase):
    """\
    Ultimate set of tests of a full set of different parameters for
    encoding and decoding. If this passes, the codec is universal and
    can correctly interface with any other RS codec!
    """

    def test_main(self) -> None:

        def cartesian_product_dict_items(dicts: Dict[str, Union[List[int], List[List[Union[int, bool]]]]]):
            """Return dictionary of cartesian products."""
            return (dict(zip(dicts, x)) for x in itertools.product(*dicts.values()))

        orig_mes = bytearray("hello world", "latin1")
        n        = len(orig_mes)*2
        k        = len(orig_mes)
        istart   = 0

        params = {"count":      5,
                  "fcr":        [120,       0,     1,    1,    1],
                  "prim":       [0x187, 0x11d, 0x11b, 0xfd, 0xfd],
                  "generator":  [2,         2,     3,    3,    2],
                  "c_exponent": [8,         8,     8,    7,    7]}

        cases = {
                 "errmode": [1, 2, 3, 4],
                 # Errata number (errors+erasures), erasures number and
                 # only_erasures: the last item is the value for only_erasures
                 # (True/False)
                 "erratasnb_errorsnb_onlyeras": [[8,  3, False],
                                                 [6,  5, False],
                                                 [5,  5, False],
                                                 [11, 0, True],
                                                 [11, 0, False],
                                                 [0,  0, False]]}

        results_br = []

        it = 0
        for p in range(params["count"]):
            fcr        = params["fcr"][p]
            prim       = params["prim"][p]
            generator  = params["generator"][p]
            c_exponent = params["c_exponent"][p]

            for case in cartesian_product_dict_items(cases):
                errmode       = case["errmode"]
                erratanb      = case["erratasnb_errorsnb_onlyeras"][0]
                errnb         = case["erratasnb_errorsnb_onlyeras"][1]
                only_erasures = case["erratasnb_errorsnb_onlyeras"][2]

                it += 1
                # Reed-Solomon

                # Init the RS codec
                init_tables(generator=generator, prim=prim, c_exp=c_exponent)
                g = rs_generator_poly_all(n, fcr=fcr, generator=generator)

                # Encode the message
                rmesecc = rs_encode_msg(orig_mes, n-k, gen=g[n-k])

                # Make a copy of the original message to check later if
                # fully corrected (because the syndrome may be wrong
                # sometimes).
                rmesecc_orig = rmesecc[:]

                # Tamper the message.

                if erratanb > 0:
                    if errmode == 1:
                        sl = slice(istart, istart+erratanb)
                    elif errmode == 2:
                        sl = slice(-istart-erratanb-(n-k), -(n-k))
                    elif errmode == 3:
                        sl = slice(-istart-erratanb-1, -1)
                    elif errmode == 4:
                        sl = slice(-istart-erratanb, None)
                    else:
                        raise ValueError

                    rmesecc[sl] = [0] * erratanb  # Replace with null bytes.

                # Generate the erasures positions (if any).
                erase_pos = [x for x in range(len(rmesecc)) if rmesecc[x] == 0]

                # Remove the errors positions (must not be known by definition).
                if errnb > 0:
                    erase_pos = erase_pos[:-errnb]

                # Decoding the corrupted codeword.

                # Forney syndrome method.
                try:
                    rmes, recc = rs_correct_msg(rmesecc,
                                                n-k,
                                                fcr=fcr,
                                                generator=generator,
                                                erase_pos=erase_pos,
                                                only_erasures=only_erasures)

                    # Check if correct by syndrome analysis (can be wrong).
                    results_br.append(rs_check(rmes + recc, n-k, fcr=fcr, generator=generator))

                    # Check if correct by comparing to the original message (always correct).
                    results_br.append(rmesecc_orig == (rmes+recc))

                except ReedSolomonError:
                    results_br.append(False)
                    results_br.append(False)

                # Without Forney syndrome method
                try:
                    rmes, recc = rs_correct_msg_nofsynd(rmesecc,
                                                        n-k,
                                                        fcr=fcr,
                                                        generator=generator,
                                                        erase_pos=erase_pos,
                                                        only_erasures=only_erasures)
                    results_br.append(rs_check(rmes + recc,
                                               n-k,
                                               fcr=fcr,
                                               generator=generator))
                    results_br.append(rmesecc_orig == (rmes+recc))
                except ReedSolomonError:
                    results_br.append(False)
                    results_br.append(False)

        self.assertTrue(results_br.count(True) == len(results_br))


if __name__ == "__main__":
    unittest.main()
