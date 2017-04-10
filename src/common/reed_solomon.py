#!/usr/bin/env python3.5
# -*- coding: utf-8 -*-

"""
# Copyright (c) 2012-2015 Tomer Filiba <tomerfiliba@gmail.com>
# Copyright (c) 2015 rotorgit
# Copyright (c) 2015 Stephen Larroque <LRQ3000@gmail.com>

The code below is edited and used under public domain license:
https://github.com/tomerfiliba/reedsolomon/blob/master/LICENSE

The comments/unused code have been intentionally removed. Original code's at
https://github.com/tomerfiliba/reedsolomon/blob/master/reedsolo.py
"""

import itertools


class ReedSolomonError(Exception):
    """Reed solomon error stub."""
    pass

gf_exp       = bytearray([1] * 512)
gf_log       = bytearray(256)
field_charac = int(2 ** 8 - 1)


def init_tables(prim=0x11d, generator=2, c_exp=8):
    """
    Precompute the logarithm and anti-log tables for faster computation
    later, using the provided primitive polynomial. These tables are
    used for multiplication/division since addition/substraction are
    simple XOR operations inside GF of characteristic 2. The basic idea
    is quite simple: since b**(log_b(x), log_b(y)) == x * y given any
    number b (the base or generator of the logarithm), then we can use
    any number b to precompute logarithm and anti-log (exponentiation)
    tables to use for multiplying two numbers x and y.

    That's why when we use a different base/generator number, the log and
    anti-log tables are drastically different, but the resulting
    computations are the same given any such tables. For more information, see
    https://en.wikipedia.org/wiki/Finite_field_arithmetic#Implementation_tricks
    """
    global gf_exp, gf_log, field_charac

    field_charac = int(2 ** c_exp - 1)
    gf_exp       = bytearray(field_charac * 2)
    gf_log       = bytearray(field_charac + 1)
    x            = 1
    for i in range(field_charac):
        gf_exp[i] = x
        gf_log[x] = i
        x         = fg_mult_nolut(x, generator, prim, field_charac + 1)

    for i in range(field_charac, field_charac * 2):
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
    return bytearray([gf_mul(p[i], x) for i in range(len(p))])


def gf_poly_add(p, q):
    r                         = bytearray(max(len(p), len(q)))
    r[len(r) - len(p):len(r)] = p
    for i in range(len(q)):
        r[i + len(r) - len(q)] ^= q[i]
    return r


def gf_poly_mul(p, q):
    """
    Multiply two polynomials, inside Galois Field (but the procedure
    is generic). Optimized function by precomputation of log.
    """
    r  = bytearray(len(p) + len(q) - 1)
    lp = [gf_log[p[i]] for i in range(len(p))]
    for j in range(len(q)):
        qj = q[j]
        if qj != 0:
            lq = gf_log[qj]
            for i in range(len(p)):
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
    for i in range(len(dividend) - (len(divisor) - 1)):
        coef = msg_out[i]
        if coef != 0:
            for j in range(1, len(divisor)):
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
    for i in range(1, len(poly)):
        y = gf_mul(y, x) ^ poly[i]
    return y


def rs_generator_poly(nsym, fcr=0, generator=2):
    """
    Generate an irreducible generator polynomial
    (necessary to encode a message into Reed-Solomon)
    """
    g = bytearray([1])
    for i in range(nsym):
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
        raise ValueError("Message is too long ({} when max is {})".format(len(msg_in) + nsym, field_charac))

    if gen is None:
        gen = rs_generator_poly(nsym, fcr, generator)

    msg_in  = bytearray(msg_in)
    msg_out = bytearray(msg_in) + bytearray(len(gen) - 1)
    lgen    = bytearray([gf_log[gen[j]] for j in range(len(gen))])

    for i in range(len(msg_in)):
        coef = msg_out[i]

        if coef != 0:
            lcoef = gf_log[coef]
            for j in range(1, len(gen)):
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
                  for i in range(nsym)]


def rs_correct_errata(msg_in, synd, err_pos, fcr=0, generator=2):
    """
    Forney algorithm, computes the values (error magnitude) to correct in_msg.
    """
    global field_charac
    msg      = bytearray(msg_in)
    coef_pos = [len(msg) - 1 - p for p in err_pos]
    err_loc  = rs_find_errata_locator(coef_pos, generator)
    err_eval = rs_find_error_evaluator(synd[::-1], err_loc, len(err_loc) - 1)[::-1]

    x = []
    for i in range(len(coef_pos)):
        l = field_charac - coef_pos[i]
        x.append(gf_pow(generator, -l))

    e_      = bytearray(len(msg))
    xlength = len(x)
    for i, Xi in enumerate(x):
        xi_inv            = gf_inverse(Xi)
        err_loc_prime_tmp = []
        for j in range(xlength):
            if j != i:
                err_loc_prime_tmp.append(gf_sub(1, gf_mul(xi_inv, x[j])))

        err_loc_prime = 1
        for coef in err_loc_prime_tmp:
            err_loc_prime = gf_mul(err_loc_prime, coef)

        y              = gf_poly_eval(err_eval[::-1], xi_inv)
        y              = gf_mul(gf_pow(Xi, 1 - fcr), y)
        magnitude      = gf_div(y, err_loc_prime)
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

    for i in range(nsym - erase_count):
        if erase_loc:
            k_ = erase_count + i + synd_shift
        else:
            k_ = i + synd_shift

        delta = synd[k_]
        for j in range(1, len(err_loc)):
            delta ^= gf_mul(err_loc[-(j + 1)], synd[k_ - j])
        old_loc += bytearray([0])

        if delta != 0:
            if len(old_loc) > len(err_loc):
                new_loc = gf_poly_scale(old_loc, delta)
                old_loc = gf_poly_scale(err_loc, gf_inverse(delta))
                err_loc = new_loc
            err_loc = gf_poly_add(err_loc, gf_poly_scale(old_loc, delta))

    err_loc = list(itertools.dropwhile(lambda x: x == 0, err_loc))
    errs    = len(err_loc) - 1
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

    if len(e_pos) > 0:
        print("\nWarning! Reed-Solomon erasure code\n"
              "detected and corrected {} errors in\n"
              "received packet. This might indicate\n"
              "eminent serial adapter or data diode\n"
              "HW failure, or that serial interface\n"
              "speed is set too high.\n".format(len(e_pos)))

    for i in e_pos:
        e_loc = gf_poly_mul(e_loc, gf_poly_add([1], [gf_pow(generator, i), 0]))
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
    _, remainder = gf_poly_div(gf_poly_mul(synd, err_loc), ([1] + [0] * (nsym + 1)))
    return remainder


def rs_find_errors(err_loc, nmess, generator=2):
    """
    Find the roots (ie, where evaluation = zero) of error polynomial by
    bruteforce trial, this is a sort of Chien's search (but less efficient,
    Chien's search is a way to evaluate the polynomial such that each
    evaluation only takes constant time).
    """
    errs    = len(err_loc) - 1
    err_pos = []
    for i in range(nmess):
        if gf_poly_eval(err_loc, gf_pow(generator, i)) == 0:
            err_pos.append(nmess - 1 - i)

    if len(err_pos) != errs:
        raise ReedSolomonError("Too many (or few) errors found by Chien "
                               "search for the errata locator polynomial!")
    return err_pos


def rs_forney_syndromes(synd, pos, nmess, generator=2):
    erase_pos_reversed = [nmess - 1 - p for p in pos]
    fsynd = list(synd[1:])
    for i in range(len(pos)):
        x = gf_pow(generator, erase_pos_reversed[i])
        for j in range(len(fsynd) - 1):
            fsynd[j] = gf_mul(fsynd[j], x) ^ fsynd[j + 1]
    return fsynd


def rs_correct_msg(msg_in, nsym, fcr=0, generator=2, erase_pos=None, only_erasures=False):
    """Reed-Solomon main decoding function."""
    global field_charac
    if len(msg_in) > field_charac:
        raise ValueError("Message is too long ({} when max is {})".format(len(msg_in), field_charac))

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
        fsynd   = rs_forney_syndromes(synd, erase_pos, len(msg_out), generator)
        err_loc = rs_find_error_locator(fsynd, nsym, erase_count=len(erase_pos))
        err_pos = rs_find_errors(err_loc[::-1], len(msg_out), generator)

        if err_pos is None:
            raise ReedSolomonError("Could not locate error")

    msg_out = rs_correct_errata(msg_out, synd, (erase_pos + err_pos), fcr, generator)
    synd    = rs_calc_syndromes(msg_out, nsym, fcr, generator)
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
        self.nsym      = nsym
        self.nsize     = nsize
        self.fcr       = fcr
        self.prim      = prim
        self.generator = generator
        self.c_exp     = c_exp
        init_tables(prim, generator, c_exp)

    def encode(self, data):
        """
        Encode a message (ie, add the ecc symbols) using Reed-Solomon,
        whatever the length of the message because we use chunking.
        """
        if isinstance(data, str):
            data = bytearray(data, "latin-1")
        chunk_size = self.nsize - self.nsym
        enc        = bytearray()

        for i in range(0, len(data), chunk_size):
            chunk = data[i:i + chunk_size]
            enc.extend(rs_encode_msg(chunk, self.nsym, fcr=self.fcr, generator=self.generator))
        return enc

    def decode(self, data, erase_pos=None, only_erasures=False):
        """Repair a message, whatever its size is, by using chunking."""
        if isinstance(data, str):
            data = bytearray(data, "latin-1")
        dec = bytearray()
        for i in range(0, len(data), self.nsize):
            chunk = data[i:i + self.nsize]
            e_pos = []
            if erase_pos:
                e_pos     = [x for x in erase_pos if x <= self.nsize]
                erase_pos = [x - (self.nsize + 1)
                             for x in erase_pos if x > self.nsize]

            dec.extend(rs_correct_msg(chunk, self.nsym, fcr=self.fcr,
                                      generator=self.generator,
                                      erase_pos=e_pos,
                                      only_erasures=only_erasures)[0])
        return dec
