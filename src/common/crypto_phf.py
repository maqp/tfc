import argon2

from src.common.exceptions import CriticalError
from src.common.statics import ARGON2_SALT_LENGTH, SYMMETRIC_KEY_LENGTH


def argon2_kdf(password:    str,    # Password to derive the key from
               salt:        bytes,  # Salt to derive the key from
               time_cost:   int,    # Number of iterations
               memory_cost: int,    # Amount of memory to use (in bytes)
               parallelism: int     # Number of threads to use
               ) -> bytes:          # The derived key
    """Derive an encryption key from password and salt using Argon2id.

    Argon2 is a password hashing function designed by Alex Biryukov,
    Daniel Dinu, and Dmitry Khovratovich from the University of
    Luxembourg. The algorithm is the winner of the 2015 Password Hashing
    Competition (PHC).

    For more details, see
        https://password-hashing.net/
        https://en.wikipedia.org/wiki/Argon2

    The reasons for using Argon2 in TFC include

        o PBKDF2 and bcrypt are not memory-hard, thus they are weak
          against massively parallel computing attacks with
          FPGAs/GPUs/ASICs.[1; p.2]

        o scrypt is very complex as it "combines two independent
          cryptographic primitives (the SHA256 hash function, and
          the Salsa20/8 core operation), and four generic operations
          (HMAC, PBKDF2, Block-Mix, and ROMix)."[2; p.10]
              Furthermore, scrypt is "vulnerable to trivial time-memory
          trade-off (TMTO) attacks that allows compact implementations
          with the same energy cost."[1; p.2]

        o Out of all the PHC finalists, only Catena and Argon2i offer
          complete cache-timing resistance by using data-independent
          memory access. Catena does not support parallelism[2; p.49],
          thus if it later turns out TFC needs stronger protection from
          cache-timing attacks, the selection of Argon2 (that always
          supports parallelism) is ideal, as switching from Argon2id
          to Argon2i is trivial.

        o More secure algorithms such as the Balloon hash function[3] do
          not have robust implementations.

    The purpose of Argon2 is to stretch a password into a 256-bit key.
    Argon2 features a slow, memory-hard hash function that consumes
    computational resources of an attacker that attempts a dictionary
    or a brute force attack.

    The function also takes a salt (256-bit random value in this case)
    that prevents rainbow-table attacks, and forces each attack to take
    place against an individual (physically compromised) TFC-endpoint,
    or PSK transmission media.

    The Argon2 version used is the Argon2id, that is the current
    recommendation of the draft RFC[4]. Argon2id uses data-independent
    memory access for the first half of the first iteration, and
    data-dependent memory access for the rest. This provides a lot of
    protection against TMTO attacks which is great because most of the
    expected attacks are against physically compromised data storage
    devices where the encrypted data is at rest.
        Argon2id also adds some security against side-channel attacks
    that malicious code injected to the Destination Computer might
    perform. Considering these two attacks, Argon2id is the most secure
    choice.

    The correctness of the Argon2id implementation[5] is tested by TFC
    unit tests. The testing is done by comparing the output of the
    argon2_cffi library with the output of the Argon2 reference
    command-line utility under randomized input parameters.

     [1] https://github.com/P-H-C/phc-winner-argon2/blob/master/argon2-specs.pdf
     [2] https://password-hashing.net/submissions/specs/Catena-v5.pdf
     [3] https://crypto.stanford.edu/balloon/
     [4] https://tools.ietf.org/html/draft-irtf-cfrg-argon2-12#section-7.4
     [5] https://github.com/P-H-C/phc-winner-argon2
         https://github.com/hynek/argon2_cffi
    """
    if len(salt) != ARGON2_SALT_LENGTH:
        raise CriticalError(f"Invalid salt length ({len(salt)} bytes).")

    try:
        key = argon2.low_level.hash_secret_raw(secret=password.encode(),
                                               salt=salt,
                                               time_cost=time_cost,
                                               memory_cost=memory_cost,
                                               parallelism=parallelism,
                                               hash_len=SYMMETRIC_KEY_LENGTH,
                                               type=argon2.Type.ID)  # type: bytes

    except argon2.exceptions.Argon2Error as e:
        raise CriticalError(str(e))

    if not isinstance(key, bytes):
        raise CriticalError(f"Argon2 returned an invalid type ({type(key)}) key.")

    if len(key) != SYMMETRIC_KEY_LENGTH:
        raise CriticalError(f"Derived an invalid length key from password ({len(key)} bytes).")

    return key
