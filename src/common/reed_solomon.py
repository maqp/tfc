#!/usr/bin/env python3.7
# -*- coding: utf-8 -*-

"""
# Copyright (c) 2012-2015 Tomer Filiba <tomerfiliba@gmail.com>
# Copyright (c) 2015 rotorgit
# Copyright (c) 2015-2017 Stephen Larroque <LRQ3000@gmail.com>

The Reed Solomon erasure code library has been released to the public domain.

https://github.com/lrq3000/reedsolomon/blob/master/LICENSE
https://github.com/tomerfiliba/reedsolomon/blob/master/LICENSE

Reed Solomon
============

A pure-python universal errors-and-erasures Reed-Solomon Codec
    https://en.wikipedia.org/wiki/Reed%E2%80%93Solomon_error_correction

based on the wonderful tutorial at
    https://en.wikiversity.org/wiki/Reed%E2%80%93Solomon_codes_for_coders
    written by "Bobmath" and "LRQ3000".

The code of wikiversity is here consolidated into a nice API with
exceptions handling. The algorithm can correct up to 2*e+v <= nsym,
where e is the number of errors, v the number of erasures and
nsym = n-k = the number of ECC (error correction code) symbols. This
means that you can either correct exactly floor(nsym/2) errors, or nsym
erasures (errors where you know the position), and a combination of
both errors and erasures. The code should work on pretty much any
reasonable version of python (2.4-3.5), but I'm only testing on 2.7-3.4.

.. note::
   The codec is universal, meaning that it can decode any message
   encoded by another RS encoder as long as you provide the correct
   parameters. Note however that if you use higher fields
   (i.e., bigger c_exp), the algorithms will be slower, first because
   we cannot then use the optimized bytearray() structure but only
   array.array('i', ...), and also because Reed-Solomon's complexity is
   quadratic (both in encoding and decoding), so this means that the
   longer your messages, the longer it will take to encode/decode
   (quadratically!).

   The algorithm itself can handle messages up to (2^c_exp)-1 symbols,
   including the ECC symbols, and each symbol can have a value of up to
   (2^c_exp)-1 (indeed, both the message length and the maximum value
   for one character is constrained by the same mathematical reason).
   By default, we use the field GF(2^8), which means that you are
   limited to values between 0 and 255 (perfect to represent a single
   hexadecimal symbol on computers, so you can encode any binary
   stream) and limited to messages+ecc of maximum length 255. However,
   you can "chunk" longer messages to fit them into the message length
   limit. The ``RSCodec`` class will automatically apply chunking, by
   splitting longer messages into chunks and encode/decode them
   separately; it shouldn't make a difference from an API perspective
   (i.e., from your POV).
::

    # Initialization
    # >>> from reedsolo import RSCodec
    # >>> rsc = RSCodec(10)  # 10 ecc symbols

    # # Encoding
    # >>> rsc.encode([1,2,3,4])
    # b'\x01\x02\x03\x04,\x9d\x1c+=\xf8h\xfa\x98M'
    # >>> rsc.encode(bytearray([1,2,3,4]))
    # bytearray(b'\x01\x02\x03\x04,\x9d\x1c+=\xf8h\xfa\x98M')
    # >>> rsc.encode(b'hello world')
    # b'hello world\xed%T\xc4\xfd\xfd\x89\xf3\xa8\xaa'
    # # Note that chunking is supported transparently to encode any string length.

    # # Decoding (repairing)
    # >>> rsc.decode(b'hello world\xed%T\xc4\xfd\xfd\x89\xf3\xa8\xaa')[0]
    # b'hello world'
    # >>> rsc.decode(b'heXlo worXd\xed%T\xc4\xfdX\x89\xf3\xa8\xaa')[0]     # 3 errors
    # b'hello world'
    # >>> rsc.decode(b'hXXXo worXd\xed%T\xc4\xfdX\x89\xf3\xa8\xaa')[0]     # 5 errors
    # b'hello world'
    # >>> rsc.decode(b'hXXXo worXd\xed%T\xc4\xfdXX\xf3\xa8\xaa')[0]        # 6 errors - fail
    # Traceback (most recent call last):
    #   ...
    # ReedSolomonError: Could not locate error

    # >>> rsc = RSCodec(12)  # using 2 more ecc symbols (to correct max 6 errors or 12 erasures)
    # >>> rsc.encode(b'hello world')
    # b'hello world?Ay\xb2\xbc\xdc\x01q\xb9\xe3\xe2='
    # >>> rsc.decode(b'hello worXXXXy\xb2XX\x01q\xb9\xe3\xe2=')[0]         # 6 errors - ok
    # b'hello world'
    # >>> rsc.decode(b'helXXXXXXXXXXy\xb2XX\x01q\xb9\xe3\xe2=', erase_pos=[3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 15, 16])[0]
    # b'hello world'

    # Checking
    >> rsc.check(b'hello worXXXXy\xb2XX\x01q\xb9\xe3\xe2=')
    [False]
    >> rmes, rmesecc = rsc.decode(b'hello worXXXXy\xb2XX\x01q\xb9\xe3\xe2=')
    >> rsc.check(rmesecc)
    [True]

    # To use longer chunks or bigger values than 255 (may be very slow)
    >> rsc = RSCodec(12, nsize=4095)  # always use a power of 2 minus 1
    >> rsc = RSCodec(12, c_exp=12)  # alternative way to set nsize=4095
    >> mes = 'a' * (4095-12)
    >> mesecc = rsc.encode(mes)
    >> mesecc[2] = 1
    >> mesecc[-1] = 1
    >> rmes, rmesecc = rsc.decode(mesecc)
    >> rsc.check(mesecc)
    [False]
    >> rsc.check(rmesecc)
    [True]

    If you want full control, you can skip the API and directly use the
    library as-is. Here's how:

    First you need to init the precomputed tables:
    >> import reedsolo as rs
    >> rs.init_tables(0x11d)

    Pro tip: if you get the error: ValueError: byte must be in
    range(0, 256), please check that your prime polynomial is correct
    for your field.

    Pro tip2: by default, you can only encode messages of max length
    and max symbol value = 256. If you want to encode bigger messages,
    please use the following (where c_exp is the exponent of your
    Galois Field, e.g., 12 = max length 2^12 = 4096):
    >> prim = rs.find_prime_polys(c_exp=12, fast_primes=True, single=True)
    >> rs.init_tables(c_exp=12, prim=prim)

    Let's define our RS message and ecc size:
    >> n = 255               # length of total message+ecc
    >> nsym = 12             # length of ecc
    >> mes = "a" * (n-nsym)  # generate a sample message

    To optimize, you can precompute the generator polynomial:
    >> gen = rs.rs_generator_poly_all(n)

    Then to encode:
    >> mesecc = rs.rs_encode_msg(mes, nsym, gen=gen[nsym])

    Let's tamper our message:
    >> mesecc[1] = 0

    To decode:
    >> rmes, recc = rs.rs_correct_msg(mesecc, nsym, erase_pos=erase_pos)

    Note that both the message and the ecc are corrected (if possible
    of course).

    Pro tip: if you know a few erasures positions, you can specify them
    in a list `erase_pos` to double the repair power. But you can also
    just specify an empty list.

    If the decoding fails, it will normally automatically check and
    raise a ReedSolomonError exception that you can handle. However
    if you want to manually check if the repaired message is correct,
    you can do so:
    >> rs.rs_check(rmes + recc, nsym)

    Note: if you want to use multiple Reed-Solomon with different
    parameters, you need to backup the globals and restore them before
    calling reedsolo functions:

    >> rs.init_tables()
    >> global gf_log, gf_exp, field_charac
    >> bak_gf_log, bak_gf_exp, bak_field_charac = gf_log, gf_exp, field_charac

    Then at anytime, you can do:
    >> global gf_log, gf_exp, field_charac
    >> gf_log, gf_exp, field_charac = bak_gf_log, bak_gf_exp, bak_field_charac
    >> mesecc = rs.rs_encode_msg(mes, nsym)
    >> rmes, recc = rs.rs_correct_msg(mesecc, nsym)

    The globals backup is not necessary if you use RSCodec, it will be
    automatically managed. Read the source code's comments for more info
    about how it works, and for the various parameters you can setup if
    you need to interface with other RS codecs.

TO DO IMPORTANT: try to keep the same convention for the ordering of
polynomials inside lists throughout the code and functions (because
for now, there are a lot of list reversing in order to make it work,
you never know the order of a polynomial, i.e., if the first coefficient
is the major degree or the constant term...).
"""

import itertools
import math
import shutil

from array  import array
from typing import Any, Dict, Iterator, List, Optional, Tuple, Union


class ReedSolomonError(Exception):
    """Reed-Solomon exception stub."""
    pass


"""
For efficiency, gf_exp[] has size 2*GF_SIZE, so that a simple 
multiplication of two numbers can be resolved without calling % 255. 
For more info on how to generate this extended exponentiation table, 
see paper: 
    "Fast software implementation of finite field operations", 
    Cheng Huang and Lihao Xu
    Washington University in St. Louis, Tech. Rep (2003).
"""
_bytearray   = bytearray  # type: Any
gf_exp       = _bytearray([1] * 512)
gf_log       = _bytearray(256)
field_charac = int(2 ** 8 - 1)  # type: int


# Galois Field elements maths

def rwh_primes1(n: int) -> List[int]:
    """Returns  a list of primes < n
        https://stackoverflow.com/questions/2068372/fastest-way-to-list-all-primes-below-n/3035188#3035188
    """
    sieve = [True] * int(n / 2)
    for i in range(3, int(n ** 0.5) + 1, 2):
        if sieve[int(i / 2)]:
            sieve[int((i * i) / 2)::i] = [False] * int((n - i * i - 1) / (2 * i) + 1)
    return [2] + [2 * i + 1 for i in range(1, int(n / 2)) if sieve[i]]


def find_prime_polys(generator:   int  = 2,
                     c_exp:       int  = 8,
                     fast_primes: bool = False,
                     single:      bool = False
                     ) -> Any:
    """
    Compute the list of prime polynomials for the given generator and
    Galois Field characteristic exponent.

    fast_primes will output less results but will be significantly faster.
    Single will output the first prime polynomial found, so if all you
    want is to just find one prime polynomial to generate the LUT for
    Reed-Solomon to work, then just use that.

    A prime polynomial (necessarily irreducible) is necessary to reduce
    the multiplications in the Galois Field, so as to avoid overflows.

    Why do we need a "prime polynomial"? Can't we just reduce modulo 255
    (for GF(2^8) for example)? Because we need the values to be unique.

    For example: if the generator (alpha) = 2 and c_exp = 8 (GF(2^8) == GF(256)),
    then the generated Galois Field (0, 1, α, α^1, α^2, ..., α^(p-1))
    will be Galois Field it becomes 0, 1, 2, 4, 8, 16, etc. However,
    upon reaching 128, the next value will be doubled (i.e., next power of
    2), which will give 256. Then we must reduce, because we have
    overflowed above the maximum value of 255. But, if we modulo 255,
    this will generate 256 == 1. Then 2, 4, 8, 16, etc. giving us a
    repeating pattern of numbers. This is very bad, as it's then not
    anymore a bijection (i.e., a non-zero value doesn't have a unique
    index). That's why we can't just modulo 255, but we need another
    number above 255, which is called the prime polynomial.
    # Why so much hassle? Because we are using precomputed look-up
    tables for multiplication: instead of multiplying a*b, we precompute
    alpha^a, alpha^b and alpha^(a+b), so that we can just use our lookup
    table at alpha^(a+b) and get our result. But just like in our
    original field we had 0,1,2,...,p-1 distinct unique values, in our
    "LUT" field using alpha we must have unique distinct values (we
    don't care that they are different from the original field as long
    as they are unique and distinct). That's why we need to avoid
    duplicated values, and to avoid duplicated values we need to use a
    prime irreducible polynomial.

    # Here is implemented a brute-force approach to find all these prime
    polynomials, by generating every possible prime polynomials (i.e.,
    every integers between field_charac+1 and field_charac*2), and then
    we build the whole Galois Field, and we reject the candidate prime
    polynomial if it duplicates even one value or if it generates a
    value above field_charac (i.e., cause an overflow).

    Note that this algorithm is slow if the field is too big (above 12),
    because it's an exhaustive search algorithm. There are probabilistic
    approaches, and almost surely prime approaches, but there is no
    deterministic polynomial time algorithm to find irreducible monic
    polynomials. More info can be found at:
        https://people.mpi-inf.mpg.de/~csaha/lectures/lec9.pdf

    Another faster algorithm may be found at
        "Finding irreducible polynomials over finite fields."
        Adleman, Leonard M., and Hendrik W. Lenstra.

        Proceedings of the eighteenth annual
        ACM Symposium on Theory of computing. ACM, 1986.
    """

    # Prepare the finite field characteristic (2^p - 1), this
    # also represent the maximum possible value in this field
    root_charac       = 2  # we're in GF(2)
    field_charac_     = int(root_charac ** c_exp - 1)
    field_charac_next = int(root_charac ** (c_exp + 1) - 1)

    if fast_primes:
        # Generate maybe prime polynomials and
        # check later if they really are irreducible
        prim_candidates = rwh_primes1(field_charac_next)
        prim_candidates = [x for x in prim_candidates if x > field_charac_]  # filter out too small primes
    else:
        # try each possible prime polynomial, but skip even numbers
        # (because divisible by 2 so necessarily not irreducible)
        prim_candidates = list(range(field_charac_ + 2, field_charac_next, root_charac))

    # Start of the main loop
    correct_primes = []  # type: List[int]

    # try potential candidates primitive irreducible polys
    for prim in prim_candidates:
        # memory variable to indicate if a value was already generated
        # in the field (value at index x is set to 1) or not (set to
        # 0 by default)
        seen     = _bytearray(field_charac_ + 1)
        conflict = False  # flag to know if there was at least one conflict

        # Second loop, build the whole Galois Field
        x = 1
        for i in range(field_charac_):
            # Compute the next value in the field
            # (i.e., the next power of alpha/generator)
            x = gf_mult_nolut(x, generator, prim, field_charac_ + 1)

            # Rejection criterion: if the value overflowed (above
            # field_charac) or is a duplicate of a previously generated
            # power of alpha, then we reject this polynomial (not prime)
            if x > field_charac_ or seen[x] == 1:
                conflict = True
                break

            # Else we flag this value as seen (to maybe detect future
            # duplicates), and we continue onto the next power of alpha
            else:
                seen[x] = 1

        # End of the second loop: if there's no conflict (no overflow
        # nor duplicated value), this is a prime polynomial!
        if not conflict:
            correct_primes.append(prim)
            if single:
                return prim

    # Return the list of all prime polynomials.
    return correct_primes

    # You can use the following to print the hexadecimal representation
    # of each prime polynomial: print [hex(i) for i in correct_primes]


def init_tables(prim:      int = 0x11d,
                generator: int = 2,
                c_exp:     int = 8
                ) -> List[Union[Any, Any, int]]:
    """\
    Precompute the logarithm and anti-log tables for faster computation
    later, using the provided primitive polynomial. These tables are
    used for multiplication/division since addition/substraction are
    simple XOR operations inside GF of characteristic 2.

    The basic idea is quite simple: since b**(log_b(x), log_b(y)) == x * y
    given any number b (the base or generator of the logarithm), then we
    can use any number b to precompute logarithm and anti-log
    (exponentiation) tables to use for multiplying two numbers x and y.
    That's why when we use a different base/generator number, the log
    and anti-log tables are drastically different, but the resulting
    computations are the same given any such tables.
    For more info, see
        https://en.wikipedia.org/wiki/Finite_field_arithmetic#Implementation_tricks

    Generator is the generator number (the "increment" that will be used
    to walk through the field by multiplication, this must be a prime
    number). This is basically the base of the logarithm/anti-log tables.
    Also often noted "alpha" in academic books.

    Prim is the primitive/prime (binary) polynomial and must be
    irreducible (i.e., it can't represented as the product of two smaller
    polynomials). It's a polynomial in the binary sense: each bit is a
    coefficient, but in fact it's an integer between field_charac+1 and
    field_charac*2, and not a list of gf values. The prime polynomial
    will be used to reduce the overflows back into the range of the
    Galois Field without duplicating values (all values should be
    unique). See the function find_prime_polys() and:
        https://research.swtch.com/field and https://www.pclviewer.com/rs2/galois.html

    Note that the choice of generator or prime polynomial doesn't matter
    very much: any two finite fields of size p^n have identical
    structure, even if they give the individual elements different names
    (i.e., the coefficients of the codeword will be different, but the
    final result will be the same: you can always correct as many
    errors/erasures with any choice for those parameters). That's why it
    makes sense to refer to all the finite fields, and all decoders
    based on Reed-Solomon, of size p^n as one concept: GF(p^n). It can
    however impact sensibly the speed (because some parameters will
    generate sparser tables).

    c_exp is the exponent for the field's characteristic GF(2^c_exp)
    """
    # Redefine _bytearray() in case we need to
    # support integers or messages of length > 256
    global _bytearray
    if c_exp <= 8:
        _bytearray = bytearray
    else:
        def _bytearray(obj: Union[str, bytes, int, List[int]] = 0, encoding: str = "latin-1") -> Any:
            """Fake bytearray replacement, supporting int values above 255"""
            # always use Latin-1 and not UTF8 because Latin-1 maps the
            # first 256 characters to their byte value equivalents. UTF8
            # may mangle your data (particularly at vale 128).
            if isinstance(obj, str):  # obj is a string, convert to list of ints
                obj = obj.encode(encoding)
                obj = [int(c) for c in obj]

            # Compatibility with list preallocation bytearray(int)
            elif isinstance(obj, int):
                obj = [0] * obj

            # Else obj is a list of int, it's ok
            return array("i", obj)

    # Init global tables
    global gf_exp, gf_log, field_charac

    field_charac = int(2 ** c_exp - 1)
    gf_exp       = _bytearray(field_charac * 2)

    # Anti-log (exponential) table. The first two
    # elements will always be [GF256int(1), generator]
    # log table, log[0] is impossible and thus unused
    gf_log = _bytearray(field_charac + 1)

    # For each possible value in the Galois Field 2^8, we will
    # pre-compute the logarithm and anti-logarithm (exponential) of this
    # value To do that, we generate the Galois Field F(2^p) by building
    # a list starting with the element 0 followed by the (p-1)
    # successive powers of the generator α : 1, α, α^1, α^2, ..., α^(p-1).
    x = 1

    # We could skip index 255 which is equal to index 0 because of modulo:
    # g^255==g^0 but either way, this does not change the later outputs
    # (i.e., the ecc symbols will be the same either way).
    for i in range(field_charac):
        gf_exp[i] = x  # compute anti-log for this value and store it in a table
        gf_log[x] = i  # compute log at the same time
        x         = gf_mult_nolut(x, generator, prim, field_charac + 1)

        # If you use only generator==2 or a power of 2, you can use the
        # following which is faster than gf_mult_noLUT():
        # x <<= 1 # multiply by 2 (change 1 by another number y to
        # multiply by a power of 2^y) if x & 0x100: # similar to x >= 256,
        # but a lot faster (because 0x100 == 256) x ^= prim substract the
        # primary polynomial to the current value (instead of 255, so
        # that we get a unique set made of coprime numbers), this is the
        # core of the tables generation

    # Optimization: double the size of the anti-log table so that we
    # don't need to mod 255 to stay inside the bounds (because we will
    # mainly use this table for the multiplication of two GF numbers,
    # no more).
    for i in range(field_charac, field_charac * 2):
        gf_exp[i] = gf_exp[i - field_charac]

    return [gf_log, gf_exp, field_charac]


def gf_add(x: int, y: int) -> int:
    """Do addition in binary Galois Field."""
    return x ^ y


def gf_sub(x: int, y: int) -> int:
    """Do substraction in binary Galois Field.

    In binary Galois Field, subtraction is just
    the same as addition (since we mod 2)
    """
    return x ^ y


def gf_neg(x: int) -> int:
    """Do negation in binary Galois Field."""
    return x


def gf_inverse(x: int) -> int:
    """Get the inverse of the value in binary Galois Field."""
    # gf_inverse(x) == gf_div(1, x)
    ret_val = gf_exp[field_charac - gf_log[x]]  # type: int
    return ret_val


def gf_mul(x: int, y: int) -> int:
    """Multiply two numbers in the binary Galois Field."""
    if x == 0 or y == 0:
        return 0
    ret_val = gf_exp[(gf_log[x] + gf_log[y]) % field_charac]  # type: int
    return ret_val


def gf_div(x: int, y: int) -> int:
    """Perform division in the binary Galois Field."""
    if y == 0:
        raise ZeroDivisionError()
    if x == 0:
        return 0
    ret_val = gf_exp[(gf_log[x] + field_charac - gf_log[y]) % field_charac]  # type: int
    return ret_val


def gf_pow(x: int, power: int) -> int:
    """Raise x to some power in the binary Galois Field."""
    ret_val = gf_exp[(gf_log[x] * power) % field_charac]  # type: int
    return ret_val


def gf_mult_nolut_slow(x: int, y: int, prim: int = 0) -> int:
    """\
    Multiplication in Galois Fields without using a precomputed look-up
    table (and thus it's slower) by using the standard carry-less
    multiplication + modular reduction using an irreducible prime
    polynomial.
    """

    # Define bitwise carry-less operations as inner functions
    def cl_mult(x_: int, y_: int) -> int:
        """Bitwise carry-less multiplication on integers"""
        z = 0
        i = 0
        while (y_ >> i) > 0:
            if y_ & (1 << i):
                z ^= x_ << i
            i += 1
        return z

    def bit_length(n: int) -> int:
        """\
        Compute the position of the most significant bit
        (1) of an integer. Equivalent to int.bit_length()
        """
        bits = 0
        while n >> bits:
            bits += 1
        return bits

    def cl_div(dividend: int, divisor: int) -> int:
        """\
        Bitwise carry-less long division on
        integers and returns the remainder
        """
        # Compute the position of the most
        # significant bit for each integers
        dl1 = bit_length(dividend)
        dl2 = bit_length(divisor)

        # If the dividend is smaller than the divisor, just exit
        if dl1 < dl2:  # pragma: no cover
            return dividend

        # Else, align the most significant 1 of the divisor to the
        # most significant 1 of the dividend (by shifting the divisor)
        for i in range(dl1 - dl2, -1, -1):
            # Check that the dividend is divisible (useless for the
            #  first iteration but important for the next ones)
            if dividend & (1 << i + dl2 - 1):
                # If divisible, then shift the divisor to align the most
                # significant bits and XOR (carry-less substraction)
                dividend ^= divisor << i
        return dividend

    # --- Main GF multiplication routine ---

    # Multiply the gf numbers
    result = cl_mult(x, y)

    # Then do a modular reduction (i.e., remainder from the division) with
    # an irreducible primitive polynomial so that it stays inside GF bounds
    if prim > 0:
        result = cl_div(result, prim)

    return result


def gf_mult_nolut(x:                 int,
                  y:                 int,
                  prim:              int  = 0,
                  field_charac_full: int  = 256,
                  carryless:         bool = True
                  ) -> int:
    """\
    Galois Field integer multiplication using Russian Peasant
    Multiplication algorithm (faster than the standard multiplication
    + modular reduction). If prim is 0 and carryless=False, then the
    function produces the result for a standard integers multiplication
    (no carry-less arithmetics nor modular reduction).
    """
    r = 0
    while y:  # while y is above 0
        if y & 1:
            # y is odd, then add the corresponding x to r (the sum of
            # all x's corresponding to odd y's will give the final
            # product). Note that since we're in GF(2), the addition is
            # in fact an XOR (very important because in GF(2) the
            # multiplication and additions are carry-less, thus it
            # changes the result!).
            r = r ^ x if carryless else r + x
        y >>= 1  # equivalent to y // 2
        x <<= 1  # equivalent to x*2
        if prim > 0 and x & field_charac_full:
            # GF modulo: if x >= 256 then apply modular reduction using
            # the primitive polynomial (we just substract, but since the
            # primitive number can be above 256 then we directly XOR).
            x ^= prim
    return r


# Galois Field polynomials maths

def gf_poly_scale(p: bytes, x: int) -> bytearray:
    """No docstring provided."""
    ret_val = _bytearray([gf_mul(p[i], x) for i in range(len(p))])  # type: bytearray
    return ret_val


def gf_poly_add(p: bytes, q: Union[bytearray, List[int]]) -> Any:
    """No docstring provided."""
    r = _bytearray(max(len(p), len(q)))  # type: bytearray

    r[len(r) - len(p):len(r)] = p

    for i in range(len(q)):
        r[i + len(r) - len(q)] ^= q[i]
    return r


def gf_poly_mul(p: Any,
                q: List[Any]
                ) -> Any:
    """\
    Multiply two polynomials, inside Galois Field (but the procedure
    is generic). Optimized function by precomputation of log.
    """
    # Pre-allocate the result array
    r = _bytearray(len(p) + len(q) - 1)

    # Precompute the logarithm of p
    lp = [gf_log[p[i]] for i in range(len(p))]

    # Compute the polynomial multiplication (just like the
    # outer product of two vectors, we multiply each
    # coefficients of p with all coefficients of q)
    for j in range(len(q)):
        # Optimization: load the coefficient once
        qj = q[j]
        # log(0) is undefined, we need to check that
        if qj != 0:
            # Optimization: precache the logarithm
            # of the current coefficient of q
            lq = gf_log[qj]
            for i in range(len(p)):
                # log(0) is undefined, need to check that...
                if p[i] != 0:
                    # Equivalent to:
                    # r[i + j] = gf_add(r[i+j], gf_mul(p[i], q[j]))
                    r[i + j] ^= gf_exp[lp[i] + lq]
    return r


def gf_poly_mul_simple(p: List[int],
                       q: List[int]
                       ) -> bytearray:
    """Multiply two polynomials, inside Galois Field

    Simple equivalent way of multiplying two polynomials
    without precomputation, but thus it's slower
    """
    # Pre-allocate the result array
    r = _bytearray(len(p) + len(q) - 1)  # type: bytearray

    # Compute the polynomial multiplication (just like the outer product
    # of two vectors, we multiply each coefficients of p with all
    # coefficients of q)
    for j in range(len(q)):
        for i in range(len(p)):
            # equivalent to: r[i + j] = gf_add(r[i+j], gf_mul(p[i], q[j]))
            # -- you can see it's your usual polynomial multiplication
            r[i + j] ^= gf_mul(p[i], q[j])
    return r


def gf_poly_neg(poly: List[int]) -> List[int]:
    """\
    Returns the polynomial with all coefficients negated. In GF(2^p),
    negation does not change the coefficient, so we return the
    polynomial as-is.
    """
    return poly


def gf_poly_div(dividend: bytearray,
                divisor:  Union[bytearray, List[int]]
                ) -> Tuple[bytearray, bytearray]:
    """Fast polynomial division by using Extended Synthetic Division and
    optimized for GF(2^p) computations (doesn't work with standard
    polynomials outside of this Galois Field).

    CAUTION: this function expects polynomials to follow the opposite
    convention at decoding: the terms must go from the biggest to lowest
    degree (while most other functions here expect a list from lowest to
    biggest degree). eg: 1 + 2x + 5x^2 = [5, 2, 1], NOT [1, 2, 5]
    """
    # Copy the dividend list and pad with 0
    # where the ecc bytes will be computed
    msg_out = _bytearray(dividend)

    # normalizer = divisor[0]  # precomputing for performance
    for i in range(len(dividend) - (len(divisor) - 1)):
        # For general polynomial division (when polynomials are
        # non-monic), the usual way of using synthetic division is to
        # divide the divisor g(x) with its leading coefficient (call it
        # a). In this implementation, this means we need to compute:
        #   coef = msg_out[i] / gen[0]. For more info, see
        #   https://en.wikipedia.org/wiki/Synthetic_division
        # msg_out[i] /= normalizer
        coef = msg_out[i]  # precaching

        # log(0) is undefined, so we need to avoid that case explicitly
        # (and it's also a good optimization). In fact if you remove it,
        # it should still work because gf_mul() will take care of the
        # condition. But it's still a good practice to put the condition
        # here.
        if coef != 0:
            # In synthetic division, we always skip the first coefficient
            # of the divisor, because it's only used to normalize the
            # dividend coefficient
            for j in range(1, len(divisor)):
                # log(0) is undefined
                if divisor[j] != 0:
                    # Equivalent to the more mathematically correct (but
                    # XORing directly is faster):
                    # msg_out[i + j] += -divisor[j] * coef
                    msg_out[i + j] ^= gf_mul(divisor[j], coef)

    # The resulting msg_out contains both the quotient and the remainder,
    # the remainder being the size of the divisor (the remainder has
    # necessarily the same degree as the divisor -- not length but
    # degree == length-1 -- since it's what we couldn't divide from the
    # dividend), so we compute the index where this separation is, and
    # return the quotient and remainder.
    separator = -(len(divisor) - 1)

    # Return quotient, remainder.
    return msg_out[:separator], msg_out[separator:]


def gf_poly_eval(poly: Union[bytearray, List[int]], x: int) -> int:
    """\
    Evaluates a polynomial in GF(2^p) given the value for x.
    This is based on Horner's scheme for maximum efficiency.
    """
    y = poly[0]
    for i in range(1, len(poly)):
        y = gf_mul(y, x) ^ poly[i]
    return y


# Reed-Solomon encoding

def rs_generator_poly(nsym:      int,
                      fcr:       int = 0,
                      generator: int = 2
                      ) -> bytearray:
    """\
    Generate an irreducible generator polynomial
    (necessary to encode a message into Reed-Solomon)
    """
    g = _bytearray([1])  # type: bytearray
    for i in range(nsym):
        g = gf_poly_mul(g, [1, gf_pow(generator, i + fcr)])
    return g


def rs_generator_poly_all(max_nsym:  int,
                          fcr:       int = 0,
                          generator: int = 2
                          ) -> Dict[int, bytearray]:
    """\
    Generate all irreducible generator polynomials up to max_nsym
    (usually you can use n, the length of the message+ecc). Very useful
    to reduce processing time if you want to encode using variable
    schemes and nsym rates.
    """
    g_all = {0: _bytearray([1]), 1: _bytearray([1])}
    for nsym in range(max_nsym):
        g_all[nsym] = rs_generator_poly(nsym, fcr, generator)
    return g_all


def rs_simple_encode_msg(msg_in:    bytearray,
                         nsym:      int,
                         fcr:       int = 0,
                         generator: int = 2
                         ) -> bytearray:
    """\
    Simple Reed-Solomon encoding (mainly an example for you to
    understand how it works, because it's slower than the in-lined
    function below)
    """
    global field_charac

    if (len(msg_in) + nsym) > field_charac:  # pragma: no cover
        raise ValueError("Message is too long (%i when max is %i)"
                         % (len(msg_in) + nsym, field_charac))

    gen = rs_generator_poly(nsym, fcr, generator)

    # Pad the message, then divide it by
    # the irreducible generator polynomial
    _, remainder = gf_poly_div(msg_in + _bytearray(len(gen) - 1), gen)

    # The remainder is our RS code! Just append it to our original
    # message to get our full codeword (this represents a polynomial
    # of max 256 terms)
    msg_out = msg_in + remainder  # type: bytearray

    # Return the codeword
    return msg_out


def rs_encode_msg(msg_in:    bytes,
                  nsym:      int,
                  fcr:       int = 0,
                  generator: int = 2,
                  gen:       Optional[bytearray] = None
                  ) -> bytearray:
    """\
    Reed-Solomon main encoding function, using polynomial division
    (Extended Synthetic Division, the fastest algorithm available to my
    knowledge), better explained at https://research.swtch.com/field
    """
    global field_charac
    if (len(msg_in) + nsym) > field_charac:  # pragma: no cover
        raise ValueError("Message is too long (%i when max is %i)"
                         % (len(msg_in) + nsym, field_charac))
    if gen is None:
        gen = rs_generator_poly(nsym, fcr, generator)
    msg_in = _bytearray(msg_in)

    # init msg_out with the values inside msg_in and pad with
    # len(gen)-1 bytes (which is the number of ecc symbols).
    msg_out = _bytearray(msg_in) + _bytearray(len(gen) - 1)  # type: bytearray

    # Precompute the logarithm of every items in the generator
    lgen = _bytearray([gf_log[gen[j]] for j in range(len(gen))])

    # Extended synthetic division main loop
    # Fastest implementation with PyPy (but the Cython
    # version in creedsolo.pyx is about 2x faster)
    for i in range(len(msg_in)):
        # Note that it's msg_out here, not msg_in. Thus, we reuse the
        # updated value at each iteration (this is how Synthetic Division
        # works: instead of storing in a temporary register the
        # intermediate values, we directly commit them to the output).
        coef = msg_out[i]

        # coef = gf_mul(msg_out[i], gf_inverse(gen[0]))  # for general
        # polynomial division (when polynomials are non-monic), the
        # usual way of using synthetic division is to divide the divisor
        # g(x) with its leading coefficient (call it a). In this
        # implementation, this means:we need to compute:
        # coef = msg_out[i] / gen[0]

        # log(0) is undefined, so we need to manually check for this
        # case. There's no need to check the divisor here because we
        # know it can't be 0 since we generated it.
        if coef != 0:
            lcoef = gf_log[coef]  # precaching

            # In synthetic division, we always skip the first
            # coefficient of the divisor, because it's only used to
            # normalize the dividend coefficient (which is here useless
            # since the divisor, the generator polynomial, is always
            # monic)
            for j in range(1, len(gen)):
                # If gen[j] != 0: # log(0) is undefined so we need to
                # check that, but it slows things down in fact and it's
                # useless in our case (Reed-Solomon encoding) since we
                # know that all coefficients in the generator are not 0

                # Optimization: equivalent to gf_mul(gen[j], msg_out[i])
                # and we just substract it to msg_out[i+j] (but since we
                # are in GF256, it's equivalent to an addition and to an
                # XOR). In other words, this is simply a
                # "multiply-accumulate operation"
                msg_out[i + j] ^= gf_exp[lcoef + lgen[j]]

    # Recopy the original message bytes (overwrites
    # the part where the quotient was computed)

    # Equivalent to c = mprime - b, where
    # mprime is msg_in padded with [0]*nsym
    msg_out[:len(msg_in)] = msg_in
    return msg_out


# Reed-Solomon decoding

def rs_calc_syndromes(msg:       bytearray,
                      nsym:      int,
                      fcr:       int = 0,
                      generator: int = 2
                      ) -> List[int]:
    """\
    Given the received codeword msg and the number of error correcting
    symbols (nsym), computes the syndromes polynomial. Mathematically,
    it's essentially equivalent to a Fourier Transform (Chien search
    being the inverse).

    Note the "[0] +" : we add a 0 coefficient for the lowest degree (the
    constant). This effectively shifts the syndrome, and will shift
    every computations depending on the syndromes (such as the errors
    locator polynomial, errors evaluator polynomial, etc. but not the
    errors positions).

    This is not necessary as anyway syndromes are defined such as there
    are only non-zero coefficients (the only 0 is the shift of the
    constant here) and subsequent computations will/must account for the
    shift by skipping the first iteration (e.g., the often seen
    range(1, n-k+1)), but you can also avoid prepending the 0 coeff and
    adapt every subsequent computations to start from 0 instead of 1.
    """
    return [0] + [gf_poly_eval(msg, gf_pow(generator, i + fcr)) for i in range(nsym)]


def rs_correct_errata(msg_in:    bytearray,
                      synd:      List[int],
                      err_pos:   List[int],
                      fcr:       int = 0,
                      generator: int = 2
                      ) -> bytearray:
    """\
    Forney algorithm, computes the values (error
    magnitude) to correct the input message.

    err_pos is a list of the positions of the errors/erasures/errata
    """
    global field_charac
    msg = _bytearray(msg_in)  # type: bytearray
    # Calculate errata locator polynomial to correct both errors and
    # erasures (by combining the errors positions given by the error
    # locator polynomial found by BM with the erasures positions given
    # by caller).

    # Need to convert the positions to coefficients degrees for the
    # errata locator algorithm to work (e.g. instead of [0, 1, 2] it
    # will become [len(msg)-1, len(msg)-2, len(msg) -3])
    coef_pos = [len(msg) - 1 - p for p in err_pos]
    err_loc  = rs_find_errata_locator(coef_pos, generator)

    # Calculate errata evaluator polynomial (often
    # called Omega or Gamma in academic papers)
    err_eval = rs_find_error_evaluator(synd[::-1], err_loc, len(err_loc) - 1)[::-1]

    # Second part of Chien search to get the error location polynomial X
    # from the error positions in err_pos (the roots of the error
    # locator polynomial, i.e., where it evaluates to 0)
    x = []  # will store the position of the errors
    for i in range(len(coef_pos)):
        pos = field_charac - coef_pos[i]
        x.append(gf_pow(generator, -pos))

    # Forney algorithm: Compute the magnitudes will store the values
    # that need to be corrected (subtracted) to the message containing
    # errors. This is sometimes called the error magnitude polynomial.
    e       = _bytearray(len(msg))
    xlength = len(x)
    for i, xi in enumerate(x):
        xi_inv = gf_inverse(xi)

        # Compute the formal derivative of the error locator polynomial
        # (see Blahut, Algebraic codes for data transmission, pp 196-197).
        # The formal derivative of the errata locator is used as the
        # denominator of the Forney Algorithm, which simply says that
        # the ith error value is given by error_evaluator(gf_inverse(Xi))
        # / error_locator_derivative(gf_inverse(Xi)). See Blahut,
        # Algebraic codes for data transmission, pp 196-197.
        err_loc_prime_tmp = []
        for j in range(xlength):
            if j != i:
                err_loc_prime_tmp.append(gf_sub(1, gf_mul(xi_inv, x[j])))

        # Compute the product, which is the denominator of
        # the Forney algorithm (errata locator derivative).
        err_loc_prime = 1
        for coef in err_loc_prime_tmp:
            err_loc_prime = gf_mul(err_loc_prime, coef)
            # Equivalent to:
            # err_loc_prime = functools.reduce(gf_mul, err_loc_prime_tmp, 1)

        # Compute y (evaluation of the errata evaluator polynomial)
        # This is a more faithful translation of the theoretical equation
        # contrary to the old Forney method. Here it is exactly
        # copy/pasted from the included presentation decoding_rs.pdf:
        # Yl = omega(Xl.inverse()) / prod(1 - Xj*Xl.inverse()) for j in len(X)
        # (in the paper it's for j in s, but it's useless when
        # len(X) < s because we compute neutral terms 1 for nothing, and
        # wrong when correcting more than s erasures or erasures+errors
        # since it prevents computing all required terms).

        # Thus here this method works with erasures too because firstly
        # we fixed the equation to be like the theoretical one (don't
        # know why it was modified in _old_forney(), if it's an
        # optimization, it doesn't enhance anything), and secondly
        # because we removed the product bound on s, which prevented
        # computing errors and erasures above the s=(n-k)//2 bound.

        # Numerator of the Forney algorithm (errata evaluator evaluated)
        y = gf_poly_eval(err_eval[::-1], xi_inv)
        y = gf_mul(gf_pow(xi, 1 - fcr), y)  # adjust to fcr parameter

        # Compute the magnitude

        # Magnitude value of the error, calculated by the Forney
        # algorithm (an equation in fact): Dividing the errata evaluator
        # with the errata locator derivative gives us the errata
        # magnitude (i.e., value to repair) the i'th symbol
        magnitude = gf_div(y, err_loc_prime)

        # Store the magnitude for this error into the magnitude polynomial
        e[err_pos[i]] = magnitude

    # Apply the correction of values to get our message corrected!
    # Note that the ecc bytes also gets corrected! This isn't the
    # Forney algorithm, we just apply the result of decoding here.
    msg = gf_poly_add(msg, e)

    # Equivalent to Ci = Ri - Ei where Ci is the correct message, Ri the
    # received (senseword) message, and Ei the errata magnitudes (minus
    # is replaced by XOR since it's equivalent in GF(2^p)). So in fact
    # here we subtract from the received message the error's magnitude,
    # which logically corrects the value to what it should be.

    return msg


def rs_find_error_locator(synd:        List[int],
                          nsym:        int,
                          erase_loc:   Optional[bytearray] = None,
                          erase_count: int                 = 0
                          ) -> List[int]:
    """\
    Find error/errata locator and evaluator
    polynomials with Berlekamp-Massey algorithm
    """
    # The idea is that BM will iteratively estimate the error locator
    # polynomial. To do this, it will compute a Discrepancy term called
    # Delta, which will tell us if the error locator polynomial needs an
    # update or not (hence why it's called discrepancy: it tells us when
    # we are getting off board from the correct value).

    # Init the polynomials

    # If the erasure locator polynomial is supplied, we init with its
    # value, so that we include erasures in the final locator polynomial
    if erase_loc:
        err_loc = _bytearray(erase_loc)  # type: bytearray
        old_loc = _bytearray(erase_loc)
    else:
        # This is the main variable we want to fill, also called Sigma
        # in other notations or more formally the errors/errata locator
        # polynomial.
        err_loc = _bytearray([1])

        # BM is an iterative algorithm, and we need the errata locator
        # polynomial of the previous iteration in order to update other
        # necessary variables.
        old_loc = _bytearray([1])

    # L = 0
    # Update flag variable, not needed here because we use an
    # alternative equivalent way of checking if update is needed (but
    # using the flag could potentially be faster depending on if using
    # length(list) is taking linear time in your language, here in
    # Python it's constant so it's as fast.

    # Fix the syndrome shifting: when computing the syndrome, some
    # implementations may prepend a 0 coefficient for the lowest degree
    # term (the constant). This is a case of syndrome shifting, thus the
    # syndrome will be bigger than the number of ecc symbols (I don't
    # know what purpose serves this shifting). If that's the case, then
    # we need to account for the syndrome shifting when we use the
    # syndrome such as inside BM, by skipping those prepended
    # coefficients. Another way to detect the shifting is to detect the
    # 0 coefficients: by definition, a syndrome does not contain any 0
    # coefficient (except if there are no errors/erasures, in this case
    # they are all 0). This however doesn't work with the modified
    # Forney syndrome, which set to 0 the coefficients corresponding to
    # erasures, leaving only the coefficients corresponding to errors.
    synd_shift = 0
    if len(synd) > nsym:
        synd_shift = len(synd) - nsym

    # Generally: nsym-erase_count == len(synd), except when you input a
    # partial erase_loc and using the full syndrome instead of the
    # Forney syndrome, in which case nsym-erase_count is more correct
    # (len(synd) will fail badly with IndexError).
    for i in range(nsym - erase_count):

        # If an erasures locator polynomial was provided to init the
        # errors locator polynomial, then we must skip the first
        # erase_count iterations (not the last iterations, this is very
        # important!)
        if erase_loc:
            k = erase_count + i + synd_shift

        # If erasures locator is not provided, then either there's no
        # erasures to account or we use the Forney syndromes, so we
        # don't need to use erase_count nor erase_loc (the erasures have
        # been trimmed out of the Forney syndromes).
        else:
            k = i + synd_shift

        # Compute the discrepancy Delta

        # Here is the close-to-the-books operation to compute the
        # discrepancy Delta: it's a simple polynomial multiplication of
        # error locator with the syndromes, and then we get the Kth
        # element. delta = gf_poly_mul(err_loc[::-1], synd)[k]
        # theoretically it should be gf_poly_add(synd[::-1], [1])[::-1]
        # instead of just synd, but it seems it's not absolutely
        # necessary to correctly decode. But this can be optimized:
        # Since we only need the K'th element, we don't need to compute
        # the polynomial multiplication for any other element but the
        # K'th. Thus to optimize, we compute the polymul only at the item
        # we need, skipping the rest (avoiding a nested loop, thus we
        # are linear time instead of quadratic). This optimization is
        # actually described in several figures of the book
        #   "Algebraic codes for data transmission"
        #   Blahut, Richard E., 2003, Cambridge university press.
        delta = synd[k]
        for j in range(1, len(err_loc)):
            # delta is also called discrepancy. Here we do a partial
            # polynomial multiplication (i.e., we compute the polynomial
            # multiplication only for the term of degree k). Should be
            # equivalent to brownanrs.polynomial.mul_at().
            delta ^= gf_mul(err_loc[-(j + 1)], synd[k - j])

        # Shift polynomials to compute the next degree
        old_loc += _bytearray([0])

        # Iteratively estimate the errata locator and evaluator polynomials
        if delta != 0:  # Update only if there's a discrepancy
            # Rule B (rule A is implicitly defined because rule A just
            # says that we skip any modification for this iteration)
            if len(old_loc) > len(err_loc):
                # `2*L <= k+erase_count` is equivalent to
                # `len(old_loc) > len(err_loc)` as long as L is
                # correctly computed Computing errata locator polynomial
                # Sigma.
                new_loc = gf_poly_scale(old_loc, delta)

                # Effectively we are doing err_loc * 1/delta = err_loc // delta
                old_loc = gf_poly_scale(err_loc, gf_inverse(delta))
                err_loc = new_loc

                # Update the update flag
                # L = k - L # the update flag L is tricky: in Blahut's
                # schema, it's mandatory to use `L = k - L - erase_count`
                # (and indeed in a previous draft of this function, if
                # you forgot to do `- erase_count` it would lead to
                # correcting only 2*(errors+erasures) <= (n-k) instead
                # of 2*errors+erasures <= (n-k)), but in this latest
                # draft, this will lead to a wrong decoding in some
                # cases where it should correctly decode! Thus you
                # should try with and without `- erase_count` to update
                # L on your own implementation and see which one works
                # OK without producing wrong decoding failures.

            # Update with the discrepancy
            err_loc = gf_poly_add(err_loc, gf_poly_scale(old_loc, delta))

    # Check if the result is correct, that there's not too many errors to
    # correct drop leading 0s, else errs will not be of the correct size
    err_loc_ = list(itertools.dropwhile(lambda x: x == 0, err_loc))  # type: List[int]
    errs     = len(err_loc_) - 1
    if (errs - erase_count) * 2 + erase_count > nsym:  # pragma: no cover
        raise ReedSolomonError("Too many errors to correct")

    return err_loc_


def rs_find_errata_locator(e_pos:     List[int],
                           generator: int = 2
                           ) -> List[int]:
    """\
    Compute the erasures/errors/errata locator polynomial from the
    erasures/errors/errata positions (the positions must be relative to
    the x coefficient, eg: "hello worldxxxxxxxxx" is tampered to
    "h_ll_ worldxxxxxxxxx" with xxxxxxxxx being the ecc of length n-k=9,
    here the string positions are [1, 4], but the coefficients are
    reversed since the ecc characters are placed as the first
    coefficients of the polynomial, thus the coefficients of the erased
    characters are n-1 - [1, 4] = [18, 15] = erasures_loc to be
    specified as an argument.

    See:
        http://ocw.usu.edu/Electrical_and_Computer_Engineering/Error_Control_Coding/lecture7.pdf
    and
        Blahut, Richard E. "Transform techniques for error control codes."
        IBM Journal of Research and development 23.3 (1979): 299-315.
        http://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.92.600&rep=rep1&type=pdf
    and also a MatLab implementation here:
        https://www.mathworks.com/matlabcentral/fileexchange/23567-reed-solomon-errors-and-erasures-decoder
    """

    # Just to init because we will multiply, so it must be 1 so that
    # the multiplication starts correctly without nulling any term.
    e_loc = [1]  # type: List[int]

    terminal_width = shutil.get_terminal_size()[0]

    def c_print(string: str) -> None:
        """Print to middle of the screen."""
        print(string.center(terminal_width))

    if len(e_pos) > 0:
        print('')
        for s in ["Warning! Reed-Solomon erasure code",
                  "detected and corrected {} errors in ".format(len(e_pos)),
                  "a received packet. This might indicate",
                  "bad connection, an eminent adapter or",
                  "data diode HW failure or that serial",
                  "interface's baud rate is set too high."]:
            c_print(s)
        print('')

    # erasures_loc is very simple to compute:
    # erasures_loc = prod(1 - x*alpha**i) for i in erasures_pos and
    # where alpha is the alpha chosen to evaluate polynomials (here in
    # this library it's gf(3)). To generate c*x where c is a constant,
    # we simply generate a Polynomial([c, 0]) where 0 is the constant
    # and c is positioned to be the coefficient for x^1.
    for i in e_pos:
        e_loc = gf_poly_mul(e_loc, gf_poly_add(_bytearray([1]), [gf_pow(generator, i), 0]))
    return e_loc


def rs_find_error_evaluator(synd:    List[int],
                            err_loc: List[int],
                            nsym: int) -> bytearray:
    """\
    Compute the error (or erasures if you supply sigma=erasures locator
    polynomial, or errata) evaluator polynomial Omega from the syndrome
    and the error/erasures/errata locator Sigma. Omega is already
    computed at the same time as Sigma inside the Berlekamp-Massey
    implemented above, but in case you modify Sigma, you can recompute
    Omega afterwards using this method, or just ensure that Omega
    computed by BM is correct given Sigma.
    """
    # Omega(x) = [ Synd(x) * Error_loc(x) ] mod x^(n-k+1)
    # first multiply syndromes * errata_locator, then do a polynomial
    # division to truncate the polynomial to the required length
    _, remainder = gf_poly_div(gf_poly_mul(synd, err_loc), ([1] + [0] * (nsym + 1)))

    # Faster way that is equivalent:
    # First multiply the syndromes with the errata locator polynomial
    # remainder = gf_poly_mul(synd, err_loc)
    #
    # then divide by a polynomial of the length we want, which is
    # equivalent to slicing the list (which represents the polynomial)
    # remainder = remainder[len(remainder)-(nsym+1):]
    return remainder


def rs_find_errors(err_loc:   Union[bytearray, List[int]],
                   nmess:     int,
                   generator: int = 2
                   ) -> List[int]:
    """\
    Find the roots (i.e., where evaluation = zero) of error polynomial by
    brute-force trial, this is a sort of Chien's search (but less
    efficient, Chien's search is a way to evaluate the polynomial such
    that each evaluation only takes constant time).
    """
    errs    = len(err_loc) - 1
    err_pos = []

    # Normally we should try all 2^8 possible values, but here
    # we optimize to just check the interesting symbols
    for i in range(nmess):
        if gf_poly_eval(err_loc, gf_pow(generator, i)) == 0:
            # It's a 0? Bingo, it's a root of the error locator
            # polynomial, in other terms this is the location of an error
            err_pos.append(nmess - 1 - i)

    # Sanity check: the number of errors/errata positions found should
    # be exactly the same as the length of the errata locator polynomial
    if len(err_pos) != errs:
        # (TO DO) to decode messages+ecc with length n > 255, we may try
        # to use a brute-force approach: the correct positions ARE in the
        # final array j, but the problem is because we are above the
        # Galois Field's range, there is a wraparound so that for
        # example if j should be [0, 1, 2, 3], we will also get
        # [255, 256, 257, 258] (because 258 % 255 == 3, same for the
        # other values), so we can't discriminate. The issue is that
        # fixing any errs_nb errors among those will always give a
        # correct output message (in the sense that the syndrome will be
        # all 0), so we may not even be able to check if that's correct
        # or not, so I'm not sure the brute-force approach may even be
        # possible.
        raise ReedSolomonError("Too many (or few) errors found by Chien"
                               " Search for the errata locator polynomial!")
    return err_pos


def rs_forney_syndromes(synd:      List[int],
                        pos:       List[int],
                        nmess:     int,
                        generator: int = 2
                        ) -> List[int]:
    """\
    Compute Forney syndromes, which computes a modified syndromes to
    compute only errors (erasures are trimmed out). Do not confuse this
    with Forney algorithm, which allows to correct the message based on
    the location of errors.
    """

    # Prepare the coefficient degree positions
    # (instead of the erasures positions)
    erase_pos_reversed = [nmess - 1 - p for p in pos]

    # Optimized method, all operations are in-lined make a copy and
    # trim the first coefficient which is always 0 by definition
    fsynd = list(synd[1:])
    for i in range(len(pos)):
        x = gf_pow(generator, erase_pos_reversed[i])
        for j in range(len(fsynd) - 1):
            fsynd[j] = gf_mul(fsynd[j], x) ^ fsynd[j + 1]
        # fsynd.pop() # useless? it doesn't change the
        # results of computations to leave it there

    # Theoretical way of computing the modified Forney syndromes:
    # fsynd = (erase_loc * synd) % x^(n-k) -- although the trimming by
    # using x^(n-k) is maybe not necessary as many books do not even
    # mention it (and it works without trimming)
    # See
    #   Shao, H. M., Truong, T. K., Deutsch, L. J., & Reed, I. S.
    #   (1986, April). A single chip VLSI Reed-Solomon decoder.
    #
    #   In Acoustics, Speech, and Signal Processing
    #   IEEE International Conference on ICASSP'86.
    #   (Vol. 11, pp. 2151-2154). IEEE.ISO 690
    #
    # Computing the erasures locator polynomial
    # erase_loc = rs_find_errata_locator(erase_pos_reversed, generator=generator)
    #
    # then multiply with the syndrome to get the untrimmed forney syndrome
    # fsynd = gf_poly_mul(erase_loc[::-1], synd[1:])
    #
    # then trim the first erase_pos coefficients which are useless.
    # Seems to be not necessary, but this reduces the computation time
    # later in BM (thus it's an optimization).
    # fsynd = fsynd[len(pos):]
    return fsynd


def rs_correct_msg(msg_in:        bytearray,
                   nsym:          int,
                   fcr:           int                 = 0,
                   generator:     int                 = 2,
                   erase_pos:     Optional[List[int]] = None,
                   only_erasures: bool                = False
                   ) -> Tuple[bytearray, bytearray]:
    """Reed-Solomon main decoding function"""
    global field_charac
    if len(msg_in) > field_charac:  # pragma: no cover
        # Note that it is in fact possible to encode/decode messages
        # that are longer than field_charac, but because this will be
        # above the field, this will generate more error positions
        # during Chien Search than it should, because this will generate
        # duplicate values, which should normally be prevented thank's
        # to the prime polynomial reduction (e.g., because it can't
        # discriminate between error at position 1 or 256, both being
        # exactly equal under Galois Field 2^8). So it's really not
        # advised to do it, but it's possible (but then you're not
        # guaranteed to be able to correct any error/erasure on symbols
        # with a position above the length of field_charac -- if you
        # really need a bigger message without chunking, then you should
        # better enlarge c_exp so that you get a bigger field).
        raise ValueError("Message is too long (%i when max is %i)"
                         % (len(msg_in), field_charac))

    msg_out = _bytearray(msg_in)  # copy of message

    # Erasures: set them to null bytes for easier decoding (but this is
    # not necessary, they will be corrected anyway, but debugging will
    # be easier with null bytes because the error locator polynomial
    # values will only depend on the errors locations, not their values).
    if erase_pos is None:  # pragma: no cover
        erase_pos = []
    else:
        for e_pos in erase_pos:
            msg_out[e_pos] = 0

    # Check if there are too many erasures to correct (beyond the
    # Singleton bound).
    if len(erase_pos) > nsym:  # pragma: no cover
        raise ReedSolomonError("Too many erasures to correct")

    # Prepare the syndrome polynomial using only errors (i.e., errors
    # = characters that were either replaced by null byte or changed to
    # another character, but we don't know their positions).
    synd = rs_calc_syndromes(msg_out, nsym, fcr, generator)

    # Check if there's any error/erasure in the input codeword. If not
    # (all syndromes coefficients are 0), then just return the codeword
    # as-is.
    if max(synd) == 0:
        return msg_out[:-nsym], msg_out[-nsym:]  # no errors

    # Find errors locations
    if only_erasures:
        err_pos = []  # type: List[int]
    else:
        # Compute the Forney syndromes, which hide the erasures from the
        # original syndrome (so that BM will just have to deal with
        # errors, not erasures).
        fsynd = rs_forney_syndromes(synd, erase_pos, len(msg_out), generator)

        # Compute the error locator polynomial using Berlekamp-Massey.
        err_loc = rs_find_error_locator(fsynd, nsym, erase_count=len(erase_pos))

        # Locate the message errors using Chien search (or brute-force search).
        err_pos = rs_find_errors(err_loc[::-1], len(msg_out), generator)
        if err_pos is None:  # pragma: no cover
            raise ReedSolomonError("Could not locate error")

    # Find errors values and apply them to correct the message compute
    # errata evaluator and errata magnitude polynomials, then correct
    # errors and erasures.

    # Note that we here use the original syndrome, not the Forney
    # syndrome (because we will correct both errors and erasures,
    # so we need the full syndrome).
    msg_out = rs_correct_errata(msg_out, synd, erase_pos + err_pos, fcr, generator)

    # Check if the final message is fully repaired.
    synd = rs_calc_syndromes(msg_out, nsym, fcr, generator)
    if max(synd) > 0:
        raise ReedSolomonError("Could not correct message")

    # Return the successfully decoded message. Also return the corrected
    # ecc block so that the user can check().
    return msg_out[:-nsym], msg_out[-nsym:]


def rs_correct_msg_nofsynd(msg_in:        bytearray,
                           nsym:          int,
                           fcr:           int                 = 0,
                           generator:     int                 = 2,
                           erase_pos:     Optional[List[int]] = None,
                           only_erasures: bool                = False
                           ) -> Tuple[bytearray, bytearray]:
    """\
    Reed-Solomon main decoding function, without using the modified
    Forney syndromes.
    """
    global field_charac
    if len(msg_in) > field_charac:  # pragma: no cover
        raise ValueError("Message is too long (%i when max is %i)"
                         % (len(msg_in), field_charac))

    msg_out = _bytearray(msg_in)  # copy of message

    # Erasures: set them to null bytes for easier decoding (but this is
    # not necessary, they will be corrected anyway, but debugging will
    # be easier with null bytes because the error locator polynomial
    # values will only depend on the errors locations, not their values).
    if erase_pos is None:  # pragma: no cover
        erase_pos = []
    else:
        for e_pos in erase_pos:
            msg_out[e_pos] = 0

    # Check if there are too many erasures.
    if len(erase_pos) > nsym:  # pragma: no cover
        raise ReedSolomonError("Too many erasures to correct")

    # Prepare the syndrome polynomial using only errors (i.e.,
    # errors = characters that were either replaced by null byte or
    # changed to another character, but we don't know their positions).
    synd = rs_calc_syndromes(msg_out, nsym, fcr, generator)

    # Check if there's any error/erasure in the input codeword. If not
    # (all syndromes coefficients are 0), then just return the codeword
    # as-is.
    if max(synd) == 0:
        return msg_out[:-nsym], msg_out[-nsym:]  # no errors

    # Prepare erasures locator and evaluator polynomials.
    erase_loc = bytearray()

    # erase_eval = None
    erase_count = 0
    if erase_pos:
        erase_count        = len(erase_pos)
        erase_pos_reversed = [len(msg_out) - 1 - eras for eras in erase_pos]
        erase_loc          = bytearray(rs_find_errata_locator(erase_pos_reversed, generator=generator))

    # Prepare errors/errata locator polynomial
    if only_erasures:
        err_loc = erase_loc[::-1]
    else:
        err_loc = bytearray(rs_find_error_locator(synd, nsym, erase_loc=erase_loc, erase_count=erase_count))
        err_loc = err_loc[::-1]

    # Locate the message errors

    # Find the roots of the errata locator polynomial (i.e., the
    # positions of the errors/errata).
    err_pos = rs_find_errors(err_loc, len(msg_out), generator)
    if err_pos is None:  # pragma: no cover
        raise ReedSolomonError("Could not locate error")

    # Compute errata evaluator and errata magnitude polynomials, then
    # correct errors and erasures.
    msg_out = rs_correct_errata(msg_out, synd, err_pos, fcr=fcr, generator=generator)

    # Check if the final message is fully repaired.
    synd = rs_calc_syndromes(msg_out, nsym, fcr, generator)
    if max(synd) > 0:  # pragma: no cover
        raise ReedSolomonError("Could not correct message")

    # Return the successfully decoded message. Also return the corrected
    # ecc block so that the user can check.
    return msg_out[:-nsym], msg_out[-nsym:]


def rs_check(msg:       bytearray,
             nsym:      int,
             fcr:       int = 0,
             generator: int = 2
             ) -> bool:
    """\
    Returns true if the message + ecc has no error of false otherwise
    (may not always catch a wrong decoding or a wrong message,
    particularly if there are too many errors -- above the Singleton
    bound --, but it usually does).
    """
    return max(rs_calc_syndromes(msg, nsym, fcr, generator)) == 0


class RSCodec(object):
    """\
    A Reed Solomon encoder/decoder. After initializing the object, use
    ``encode`` to encode a (byte)string to include the RS correction
    code, and pass such an encoded (byte)string to ``decode`` to extract
    the original message (if the number of errors allows for correct
    decoding). The ``nsym`` argument is the length of the correction
    code, and it determines the number of error bytes (if I understand
    this correctly, half of ``nsym`` is correctable).

    Modifications by rotorgit 2/3/2015:
    Added support for US FAA ADSB UAT RS FEC, by allowing user to
    specify different primitive polynomial and non-zero first
    consecutive root (fcr). For UAT/ADSB use, set fcr=120 and prim=0x187
    when instantiating the class; leaving them out will default for
    previous values (0 and 0x11d).
    """

    def __init__(self,
                 nsym:       int  = 10,
                 nsize:      int  = 255,
                 fcr:        int  = 0,
                 prim:       int  = 0x11d,
                 generator:  int  = 2,
                 c_exp:      int  = 8,
                 single_gen: bool = True
                 ) -> None:
        """\
        Initialize the Reed-Solomon codec. Note that different
        parameters change the internal values (the ecc symbols, look-up
        table values, etc) but not the output result (whether your
        message can be repaired or not, there is no influence of the
        parameters).

        nsym       : number of ecc symbols (you can repair nsym/2 errors
                     and nsym erasures.
        nsize      : maximum length of each chunk. If higher than 255,
                     will use a higher Galois Field, but the algorithm's
                     complexity and computational cost will raise
                     quadratically...
        single_gen : if you want to use the same RSCodec for different
                     nsym parameters (but nsize the same), then set
                     single_gen = False.
        """

        # Auto-setup if Galois Field or message length is different than
        # default (exponent 8).

        # If nsize (chunk size) is larger than the Galois Field, we
        # resize the Galois Field.
        if nsize > 255 and c_exp <= 8:
            # Get the next closest power of two
            c_exp = int(math.log(2 ** (math.floor(math.log(nsize) / math.log(2)) + 1), 2))

        # prim was not correctly defined, find one
        if c_exp != 8 and prim == 0x11d:
            prim = find_prime_polys(generator=generator, c_exp=c_exp, fast_primes=True, single=True)
            if nsize == 255:  # Resize chunk size if not set
                nsize = int(2 ** c_exp - 1)

        # Memorize variables

        # Number of ecc symbols (i.e., the repairing rate will be
        # r=(nsym/2)/nsize, so for example if you have nsym=5 and
        # nsize=10, you have a rate r=0.25, so you can correct up to
        # 0.25% errors (or exactly 2 symbols out of 10), and 0.5%
        # erasures (5 symbols out of 10).
        self.nsym = nsym

        # Maximum length of one chunk (i.e., message + ecc symbols after
        # encoding, for the message alone it's nsize-nsym)
        self.nsize = nsize

        # First consecutive root, can be any value between 0 and (2**c_exp)-1
        self.fcr = fcr

        # Prime irreducible polynomial, use find_prime_polys() to find a prime poly
        self.prim = prim

        # Generator integer, must be prime
        self.generator = generator

        # Exponent of the field's characteristic. This both defines the
        # maximum value per symbol and the maximum length of one chunk.
        # By default it's GF(2^8), do not change if you're not sure what
        # it means.
        self.c_exp = c_exp

        # Initialize the look-up tables for easy
        # and quick multiplication/division
        self.gf_log, self.gf_exp, self.field_charac = init_tables(prim, generator, c_exp)

        # Pre-compute the generator polynomials
        if single_gen:
            self.gen = {nsym: rs_generator_poly(nsym, fcr=fcr, generator=generator)}
        else:  # pragma: no cover
            self.gen = rs_generator_poly_all(nsize, fcr=fcr, generator=generator)

    @staticmethod
    def chunk(data:       bytes,
              chunk_size: int
              ) -> Iterator[Any]:
        """Split a long message into chunks"""
        for i in range(0, len(data), chunk_size):
            # Split the long message in a chunk.
            chunk = data[i:i + chunk_size]
            yield chunk

    def encode(self,
               data_: Union[bytes, str],
               nsym:  Optional[int] = None
               ) -> bytearray:
        """\
        Encode a message (i.e., add the ecc symbols) using Reed-Solomon,
        whatever the length of the message because we use chunking.
        """
        # Restore precomputed tables (allow to use multiple RSCodec in
        # one script).
        global gf_log, gf_exp, field_charac
        gf_log, gf_exp, field_charac = self.gf_log, self.gf_exp, self.field_charac

        if not nsym:
            nsym = self.nsym

        if isinstance(data_, str):
            data = _bytearray(data_)
        else:
            data = data_
        enc = _bytearray()  # type: bytearray
        for chunk in self.chunk(data, self.nsize - self.nsym):
            enc.extend(rs_encode_msg(chunk, self.nsym, fcr=self.fcr, generator=self.generator, gen=self.gen[nsym]))
        return enc

    def decode(self,
               data:          bytes,
               nsym:          Optional[int]       = None,
               erase_pos:     Optional[List[int]] = None,
               only_erasures: bool                = False
               ) -> Tuple[bytearray, bytearray]:
        """\
        Repair a message, whatever its size is, by using chunking. May
        return a wrong result if number of errors > nsym. Note that it
        returns a couple of vars: the repaired messages, and the
        repaired messages+ecc (useful for checking).

        Usage: rmes, rmesecc = RSCodec.decode(data).
        """
        # erase_pos is a list of positions where you know (or greatly
        # suspect at least) there is an erasure (i.e., wrong character but
        # you know it's at this position). Just input the list of all
        # positions you know there are errors, and this method will
        # automatically split the erasures positions to attach to the
        # corresponding data chunk.

        # Restore precomputed tables (allow to use multiple RSCodec in
        # one script)
        global gf_log, gf_exp, field_charac
        gf_log, gf_exp, field_charac = self.gf_log, self.gf_exp, self.field_charac

        if not nsym:
            nsym = self.nsym

        if isinstance(data, str):  # pragma: no cover
            data = _bytearray(data)
        dec      = _bytearray()
        dec_full = _bytearray()
        for chunk in self.chunk(data, self.nsize):
            # Extract the erasures for this chunk
            e_pos = []  # type: List[int]
            if erase_pos:  # pragma: no cover
                # First extract the erasures for this chunk
                # (all erasures below the maximum chunk length)
                e_pos = [x for x in erase_pos if x <= self.nsize]

                # Then remove the extract erasures from the big list and
                # also decrement all subsequent positions values by
                # nsize (the current chunk's size) so as to prepare the
                # correct alignment for the next iteration
                erase_pos = [x - (self.nsize + 1) for x in erase_pos if x > self.nsize]

            # Decode/repair this chunk!
            rmes, recc = rs_correct_msg(chunk, nsym, fcr=self.fcr, generator=self.generator,
                                        erase_pos=e_pos, only_erasures=only_erasures)
            dec.extend(rmes)
            dec_full.extend(rmes + recc)
        return dec, dec_full

    def check(self,
              data: bytearray,
              nsym: Optional[int] = None
              ) -> List[bool]:
        """\
        Check if a message+ecc stream is not corrupted (or fully repaired).
        Note: may return a wrong result if number of errors > nsym.
        """
        if not nsym:
            nsym = self.nsym
        if isinstance(data, str):  # pragma: no cover
            data = _bytearray(data)
        check = []
        for chunk in self.chunk(data, self.nsize):
            check.append(rs_check(chunk, nsym, fcr=self.fcr, generator=self.generator))
        return check
