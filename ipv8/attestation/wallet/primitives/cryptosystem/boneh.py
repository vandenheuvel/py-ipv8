"""
Implementation of the Boneh 2-DNF scheme ("Evaluating 2-DNF Formulas on Ciphertexts" by Boneh et al.).
"""
from random import randint

from ..structs import BonehPrivateKey, BonehPublicKey
from .primality import isLucasPseudoprime
from .value import FP2Value
from .ec import weilpairing


def generate_prime(n):
    """
    Generate p = l * n - 1 such that:
     - p is "prime"
     - p mod 3 = 2
     - l is an as small as possible positive integer
    """
    p = 1
    l = 0
    while (p % 3) != 2 or not isLucasPseudoprime(p):
        l += 1
        p = l * n - 1
    return p


def bilinear_group(n, p, g1x, g1y, g2x, g2y):
    """
    Generate a bilinear group for two generators.
    """
    try:
        wp = weilpairing(p,
                         n,
                         (FP2Value(p, g1x), FP2Value(p, g1y)),
                         (FP2Value(p, b=g2x), FP2Value(p, g2y)),
                         (FP2Value(p), FP2Value(p)))
        return wp
    except:
        return FP2Value(p)


def get_random_exponentiation(p, n):
    """
    Create a random exponentiation of p in message space n.
    """
    # Why `4`?
    # `n` should be big, or this will be a costly loop
    r = randint(4, n - 1)
    test = p.intpow(r)
    while test == FP2Value(p.mod, 1):
        test = p.intpow(randint(4, n - 1))
    return test


def get_random_base(n):
    """
    Create a generator for the EC.
    """
    x = randint(2, n - 1)
    y = randint(2, n - 1)
    return x, y


def is_good_wp(n, wp):
    """
    A good pairing is not 0 and has order n.
    """
    is_one = wp == FP2Value(wp.mod, 1)
    is_zero = wp == FP2Value(wp.mod)
    good_order = wp.intpow(n+1) == wp
    return good_order and not is_zero and not is_one


def get_good_wp(n, p=None):
    """
    Instead of inspecting torsion points and checking for co-primality:
    just brute force generate pairings until we a get a good one.
    :return: modulus, weil paring
    """
    if not p:
        p = generate_prime(n)
    wp = None
    while (wp is None) or not is_good_wp(n, wp):
        g1x, g1y = get_random_base(n)
        wp = bilinear_group(n, p, g1x, g1y, g1x, g1y)
        if not is_good_wp(n, wp):
            wp = wp.intpow((p+1)/n)
    return p, wp


def generate_primes(key_size=512):
    """
    Generate some primes. Key size in bits (minimum 512).
    """
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives.asymmetric import rsa
    private_key = rsa.generate_private_key(public_exponent=65537,key_size=key_size,backend=default_backend())
    private_numbers = private_key.private_numbers()
    return min(private_numbers.p, private_numbers.q), max(private_numbers.p, private_numbers.q)


def generate_keypair(key_size=512):
    """
    Generate a keypair for a certain prime bit space.
    """
    prime_1, prime_2 = generate_primes(key_size)
    n = prime_1 * prime_2
    p, g = get_good_wp(n)
    u = None
    while not u or (u.intpow(prime_2) == FP2Value(p, 1)):
        _, u = get_good_wp(n, p)
    h = u.intpow(prime_2)
    return BonehPublicKey(p, g, h), BonehPrivateKey(p, g, h, prime_1*prime_2, prime_1)


def encode(pubkey, m):
    """
    Encode a message m given a public key.
    """
    return pubkey.g.intpow(m) * get_random_exponentiation(pubkey.h, pubkey.p)


def decode(privkey, msgspace, c):
    """
    Decode a ciphertext c given a private key and the possible source messages.
    """
    d = c.intpow(privkey.t1)
    t = privkey.g.intpow(privkey.t1)
    for m in msgspace:
        if d == t.intpow(m):
            return m
    return None
