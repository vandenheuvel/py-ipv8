from hashlib import sha512
from random import randint, shuffle
from threading import Lock

from .cryptosystem.boneh import decode, encode
from .cryptosystem.value import FP2Value
from .structs import Attestation, BitPairAttestation

multithread_update_lock = Lock()


def generate_modular_additive_inverse(p, n):
    """
    Generate a group of size n which is its own modular additive inverse modulo p + 1.
    """
    R = [randint(1, p - 1) for _ in range(n - 1)]
    # The additive inverse of sum(R) % (p + 1)
    R.append((-sum(R)) % (p + 1))
    # Change this to: R.append((-sum(R)) % (p + 1))
    # Now, we have sum(R) % (p + 1) = 0
    # For any subset, sum of the complement is the additive inverse of the sum of the subset
    shuffle(R)
    return R


def attest(PK, value, bitspace):
    """
    Create an attestation for a public key's value lying within a certain bitspace.

    :param PK: `BonehPublicKey` instance
    :param value: int
    :param bitspace: int describing bitspace size in bits
    :return: `Attestation` instance
    """
    # Convert `value` to binary and make a list of integer numbers of `0` and `1`
    A = [int(c) for c in str(bin(value))[2:]]
    # Pad this values with zero's such that the length is equal to the length of the bitspace
    while len(A) < bitspace:
        A.insert(0, 0)

    # ? - A bunch of random numbers
    R = generate_modular_additive_inverse(PK.p, bitspace)
    # Encode for PK the sum of a bit of A and a random number in R
    t_out_public = map(lambda a, b: encode(PK, a + b), A, R)
    t_out_private = list()
    for i in range(0, len(A) - 1, 2):
        # We probably do this to check if it adds to zero
        t_out_private.append((i, encode(PK, (-(R[i] + R[i + 1])) % (PK.p + 1))))

    # Assume len(t_out_public) % 2 == 0?
    t_out_public = [(i, t_out_public[i], t_out_public[i+1]) for i in range(0, len(t_out_public), 2)]
    ### Shuffle both t_out_private and t_out_public in the same way
    # Shuffle t_out_public first, we know the indices
    shuffle(t_out_public)
    #
    out_public = []
    #
    out_private = []
    #
    shuffle_map = {}
    #
    for (i, v1, v2) in t_out_public:
        shuffle_map[i] = len(out_public)
        out_public.append(v1)
        out_public.append(v2)
    # `e` is something encrypted
    for (i, e) in t_out_private:
        out_private.append((shuffle_map[i], e))
    # Do we lose
    shuffle(out_private)
    # Q: Formalize
    #
    bitpairs = []
    for (i, e) in out_private:
        bitpairs.append(BitPairAttestation(out_public[i], out_public[i+1], e))
    return Attestation(PK, bitpairs)


def sha512_as_int(value):
    """
    Convert a SHA512 hash to an integer.
    """
    out = 0
    for c in sha512(str(value)).digest():
        out <<= 8
        out |= ord(c)
    return out


def attest_sha512(PK, value):
    """
    Create an attestation for a value using a SHA512 hash.
    """
    return attest(PK, sha512_as_int(value), 512)


def create_empty_relativity_map():
    """
    Construct a map of possible challenge responses.
    """
    return {0: 0, 1: 0, 2: 0, 3: 0}


def binary_relativity(value, bitspace):
    """
    Create the inter-bitpair relativity map of a value.
    """
    out = {0: 0, 1: 0, 2: 0}
    A = list([int(c) for c in str(bin(value))[2:]])
    while len(A) < bitspace:
        A.insert(0, 0)
    for i in range(0, bitspace - 1, 2):
        out[A[i] + A[i + 1]] += 1
    out[3] = 0
    return out


def binary_relativity_sha512(value):
    """
    Create the inter-bitpair relativity map of a value using the SHA512 hash.
    """
    return binary_relativity(sha512_as_int(value), 512)


def binary_relativity_match(expected, value):
    """
    Get the matching percentage between relativity maps.
    Mismatches result in 0.0.
    """
    match = 0.0
    for k in expected:
        if expected[k] < value[k]:
            return 0.0
        if not expected[k]:
            continue
        match += float(value[k])/float(expected[k])
    return match/(len(expected)-1)


def binary_relativity_certainty(expected, value):
    """
    Give the chance of a current relativity map being the expected one.
    """
    cert = 1 - 0.5 ** (sum(value.values()))
    return binary_relativity_match(expected, value) * cert


def create_challenge(PK, bitpair):
    """
    Create a challenge for a bitpair attestation of a certain public key.
    """
    return bitpair.compress() * encode(PK, 0)


def create_honesty_check(PK, value):
    """
    Create a honesty check challenge.
    """
    return encode(PK, value)


def create_challenge_response_from_pair(SK, pair):
    """
    Respond to a bitpair challenge.
    """
    return create_challenge_response(SK, FP2Value(SK.p, pair[0], pair[1]))


def create_challenge_response(SK, challenge):
    """
    Respond to a bitpair challenge.
    """
    decoded = decode(SK, xrange(3), challenge)
    return 3 if decoded is None else decoded


def process_challenge_response(relativity_map, response):
    """
    Process a challenge response in a relativity map.
    """
    multithread_update_lock.acquire()
    relativity_map[response] += 1
    multithread_update_lock.release()
