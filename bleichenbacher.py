"""
Chosen-ciphertext attack on PKCS #1 v1.5
http://archiv.infsec.ethz.ch/education/fs08/secsem/bleichenbacher98.pdf
"""
from math import log
import threading

import gmpy2
from numpy import long

import PKCS
import multiprocessing as mp

import olll
from bleichenbacher_oracle import get_public_constants, MangerOracle

from oracles import PKCS1_v1_5_Oracle
from os import urandom



def egcd(a, b):
    """
    Use Euclid's algorithm to find gcd of a and b
    """
    if a == 0:
        return b, 0, 1
    else:
        g, y, x = egcd(b % a, a)
        return g, x - (b // a) * y, y


def modinv(a, m):
    """
    Compute modular inverse of a over m
    """
    g, x, y = egcd(a, m)
    if g != 1:
        raise Exception('modular inverse does not exist')
    else:
        return x % m


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


def merge_intervals(intervals):
    """
    Given a list of intervals, merge them into equivalent non-overlapping intervals
    :param intervals: list of tuples (a, b), where a <= b
    :return: list of tuples (a, b), where a <= b and a_{i+1} > b_i
    """
    intervals.sort(key=lambda x: x[0])

    merged = []
    curr = intervals[0]
    high = intervals[0][1]

    for interval in intervals:
        if interval[0] > high:
            merged.append(curr)
            curr = interval
            high = interval[1]
        else:
            high = max(high, interval[1])
            curr = (curr[0], high)
    merged.append(curr)
    return merged


def blinding(k, key, c, oracle):
    """
    Step 1 of the attack
    :param k: length of block in bytes
    :param key: RSA key
    :param c: integer smaller than n
    :param oracle: oracle that checks ciphertext conformity
    :return: integers s_0, c_0 s.t. c_0 represents a conforming encryption and c_0 = (c * (s_0) ** e) mod n
    """
    if oracle.query(c):
        return 1, c
    print("inside blinding")
    while True:
        s_0 = urandom(k)
        s_0 = int.from_bytes(s_0, byteorder='big') % key.n
        c_0 = (c * pow(s_0, key.e, key.n)) % key.n
        if oracle.query(c_0):
            return s_0, c_0


def find_min_conforming(key, c_0, min_s, oracle):
    """
    Step 2.a and 2.b of the attack
    :param key: RSA key
    :param c_0: integer that represents a conforming ciphertext
    :param min_s: minimal s to run over
    :param oracle: oracle that checks ciphertext conformity
    :return: smallest s >= min_s s.t. (c_0 * (s ** e)) mod n represents a conforming ciphertext
    """
    counter = 0
    c = (c_0 * pow(min_s, key.e, key.n)) % key.n
    while not oracle.query(c):
        print(f'counter = {counter}')
        counter += 1
        min_s += 1
        c = (c_0 * pow(min_s, key.e, key.n)) % key.n

    return min_s


def search_single_interval(key, B, prev_s, a, b, c_0, oracle):
    """
    Step 2.c of the attack
    :param key: RSA key
    :param B: 2 ** (8 * (k - 2))
    :param prev_s: s value of previous round
    :param a: minimum of interval
    :param b: maximum of interval
    :param c_0: integer that represents a conforming ciphertext
    :param oracle: oracle that checks ciphertext conformity
    :return: s s.t. (c_0 * (s ** e)) mod n represents a conforming ciphertext
    """
    # ?
    r = divceil(2 * (b * prev_s - 2 * B), key.n)
    while True:
        for s in range(divceil(2 * B + r * key.n, b), divceil(3 * B + r * key.n, a)):
            c = (c_0 * pow(s, key.e, key.n)) % key.n
            if oracle.query(c):
                return s
        r += 1


def narrow_m(key, m_prev, s, B):
    """
    Step 3 of the attack
    :param key: RSA key
    :param m_prev: previous range
    :param s: s value of the current round
    :param B: 2 ** (8 * (k - 2))
    :return: New narrowed-down intervals
    """
    intervals = []
    for a, b in m_prev:
        min_r = divceil((a * s - 3 * B + 1), key.n)  # ?
        max_r = divfloor((b * s - 2 * B), key.n)  # ?
        for r in range(min_r, max_r + 1):
            start = max(a, divceil(2 * B + r * key.n, s))  # ?
            end = min(b, divfloor(3 * B - 1 + r * key.n, s))  # ?
            intervals.append((start, end))

    return merge_intervals(intervals)


def mulmod(a: long, b: long, mod: long):
    print("a: ", a)
    print("b: ", b)
    print("mod: ", mod)
    res = 0  # Initialize result
    a = a % mod
    while b > 0:

        # If b is odd, add 'a' to result
        if b % 2 == 1:
            res = (res + a) % mod

        # Multiply 'a' with 2
        a = (a * 2) % mod

        # Divide b by 2
        b //= 2

    # Return result
    return res % mod  # a_array = []


# b_array = []
# s_array = [] 
# s_0_global = 1
continue_threads = True
number_of_iterations = 2000


def bleichenbacher_attack(k, key, c, oracle, a_array, b_array, s_array, index, verbose=True):
    """
    Given an RSA public key and an oracle for conformity of PKCS #1 encryptions, along with a value c, calculate m = (c ** d) mod n
    :param k: length of ciphertext in bytes
    :param key: RSA public key
    :param c: input parameter
    :param oracle: oracle that checks ciphertext conformity
    :return: m s.t. m = (c ** d) mod n
    """
    # global s_0_global
    print("inside bleichenbacher_attack, index :", index)

    B = 2 ** (8 * (k - 2))

    c = int.from_bytes(c, byteorder='big')
    s_0, c_0 = blinding(k, key, c, oracle)

    if verbose:
        print("Blinding complete, index :", index)

    m = [(2 * B, 3 * B - 1)]

    a_array[index] = m[0][0]
    b_array[index] = m[0][1]
    result = 0
    i = 1
    # print("Blinding complete, index :", index)
    while i <= number_of_iterations:
        if verbose:
            print("Round ", i, " for index ", index)
        if i == 1:
            # print("\t1")
            s = find_min_conforming(key, c_0, divceil(key.n, 3 * B), oracle)
            # print("\t2")
        elif len(m) > 1:
            # print("\t3")
            s = find_min_conforming(key, c_0, s + 1, oracle)
            # print("\t4")
        else:
            a = m[0][0]
            b = m[0][1]
            # print("\t5")
            s = search_single_interval(key, B, s, a, b, c_0, oracle)
            # print("\t6")
            a_array[index] = m[0][0]
            b_array[index] = m[0][1]
            s_array[index] = s
        # print("inside bleichenbacher_attack, index :", index, ", a_array[index]: ",a_array[index])

        m = narrow_m(key, m, s, B)

        if len(m) == 1 and m[0][0] == m[0][1]:
            result = (m[0][0] * modinv(s_0, key.n)) % key.n  # ?
            break
        i += 1

    # print("End bleichenbacher_attack, index :", index, "a_array = " , a_array)

    # Test the result
    if pow(result, key.e, key.n) == c:
        print("inside bleichenbacher_attack, index :", index, "result = ", result.to_bytes(k, byteorder='big'))
        return result.to_bytes(k, byteorder='big')
    else:
        print("inside bleichenbacher_attack, index :", index, "wrong result")
        return None


class Bleich_Thread(threading.Thread):
    def __init__(self, k, key, c, index):
        threading.Thread.__init__(self)
        self.k = k
        self.key = key
        self.c = c
        self.oracle = PKCS1_v1_5_Oracle(key)
        self.index = index

    def run(self):
        print("inside run, index :", self.index)
        bleichenbacher_attack(self.k, self.key.public_key(), self.c, self.oracle, self.index)


class Blinding_Process(mp.Process):
    queue = mp.Queue()
    flag = True

    def __init__(self, k, key, c, oracle):
        mp.Process.__init__(self)
        self.k = k
        self.key = key
        self.c = c
        self.s_0 = -1
        self.c_0 = -1
        self.oracle = oracle

    def run(self):
        print("inside run, process: ", self.name)
        try:
            self.blinding()
            if not self.s_0 == -1:
                Blinding_Process.queue.put([self.s_0, self.c_0])
                print("finish run, process: ", self.name)
        except Exception as e:
            print(self.name, " : attack failed")
            raise e
        finally:
            Blinding_Process.flag = False

    def blinding(self):
        """
        Step 1 of the attack
        :param k: length of block in bytes
        :param key: RSA key
        :param c: integer smaller than n
        :param oracle: oracle that checks ciphertext conformity
        :return: integers s_0, c_0 s.t. c_0 represents a conforming encryption and c_0 = (c * (s_0) ** e) mod n
        """
        # if oracle.query(c.to_bytes(k, byteorder='big')):
        #     return 1, c
        print("inside blinding, ", self.name)
        while Blinding_Process.flag:
            s_0 = urandom(self.k)
            s_0 = int.from_bytes(s_0, byteorder='big') % self.key.n

            c_0 = (self.c * pow(s_0, self.key.e, self.key.n)) % self.key.n
            if self.oracle.query(c_0):
                self.s_0 = s_0
                self.c_0 = c_0
                Blinding_Process.flag = False


class Bleich_Process(mp.Process):
    queue = mp.Queue()

    def __init__(self, k, key, c, oracle):
        mp.Process.__init__(self)
        self.k = k
        self.key = key
        self.c = c
        self.oracle = oracle
        self.a = -1
        self.b = -1
        self.s = -1
        self.result = 0
        self.flag = True

    def run(self):
        print("inside run, process: ", self.name)
        try:
            self.bleichenbacher_attack_process(verbose=True)
            Bleich_Process.queue.put([self.a, self.b, self.s])
        except Exception as e:
            print(self.name, " : attack failed")
            raise e
        finally:
            self.flag = False

    def bleichenbacher_attack_process(self, verbose=True):
        """
        Given an RSA public key and an oracle for conformity of PKCS #1 encryptions, along with a value c, calculate m = (c ** d) mod n
        :return: m s.t. m = (c ** d) mod n
        """
        # global s_0_global
        print("inside bleichenbacher_attack, process :", self.name)

        B = 2 ** (8 * (self.k - 2))

        c = int.from_bytes(self.c, byteorder='big')
        # blinding_processes = list()
        # for index in range(10):
        #     blinding_processes.append(Blinding_Process(self.k, self.key, c, oracle))
        #
        # for blinding_process in blinding_processes:
        #     blinding_process.start()
        #
        # for blinding_process in blinding_processes:
        #     blinding_process.join()
        #
        # s_c = Blinding_Process.queue.get()
        # self.s, c_0 = s_c[0], s_c[1]
        self.s, c_0 = blinding(self.k, self.key, c, self.oracle)
        if verbose:
            print("Blinding complete, process :", self.name)

        m = [(2 * B, 3 * B - 1)]

        self.a = m[0][0]
        self.b = m[0][1]
        i = 1
        # print("Blinding complete, index :", index)
        while i <= number_of_iterations:
            if verbose:
                print("Round ", i, " for process :", self.name)
            if i == 1:
                # print("\t1")
                #s = find_min_conforming(self.key, c_0, divceil(self.key.n, 3 * B), self.oracle)
                first_round_min_conforming = 16411
                s = find_min_conforming(self.key, c_0, first_round_min_conforming, self.oracle)
                # print("\t2")
            elif len(m) > 1:
                # print("\t3")
                s = find_min_conforming(self.key, c_0, s + 1, self.oracle)
                # print("\t4")
            else:

                # print("\t5")
                s = search_single_interval(self.key, B, s, self.a, self.b, c_0, self.oracle)
                # print("\t6")

            # print("inside bleichenbacher_attack, index :", index, ", a_array[index]: ",a_array[index])

            m = narrow_m(self.key, m, s, B)
            self.a = m[0][0]
            self.b = m[0][1]
            if len(m) == 1 and m[0][0] == m[0][1]:
                self.result = (m[0][0] * modinv(self.s, self.key.n)) % self.key.n  # ?
                break
            i += 1

        # print("End bleichenbacher_attack, index :", index, "a_array = " , a_array)

        # Test the result
        if pow(self.result, self.key.e, self.key.n) == c:
            print("inside bleichenbacher_attack, proccess :", self.name, "result = ",
                  self.result.to_bytes(self.k, byteorder='big'))
            return self.result.to_bytes(self.k, byteorder='big')
        else:
            print("inside bleichenbacher_attack, proccess :", self.name, "wrong result")
            return None


def parallel_bleich_attack(k, key, c, number_of_attacks, oracle):
    bleich_processes = list()
    for index in range(number_of_attacks):
        bleich_processes.append(Bleich_Process(k, key, c, oracle))

    for bleich_process in bleich_processes:
        bleich_process.start()

    for bleich_process in bleich_processes:
        bleich_process.join()

    a_list = list()
    b_list = list()
    s_list = list()

    while not Bleich_Process.queue.empty():
        a_b_s = Bleich_Process.queue.get()
        a_list.append(a_b_s[0])
        b_list.append(a_b_s[1])
        s_list.append(a_b_s[2])

    s_list.append(0)
    # matrix = [s_list]
    matrix = []
    for i in range(number_of_attacks):
        arr = [0] * (number_of_attacks + 1)
        arr[i] = key.n
        matrix.append(arr.copy())

    a_list.append(key.n * ((number_of_attacks - 1) / number_of_attacks))

    for i in range(number_of_attacks):
        matrix[0][i] += s_list[i]

    matrix.append(a_list.copy())
    # for vec in matrix:
    #     vec.append(0)

    print(matrix)
    # matrix = [[158797302718887508739481208591648002, 263140227100263324256796028711445180, 0], [146846413769390244976608848259057201405519665366672409408768095972587701251406139189428316453600460678144374548391528508442083946479585622164441072640480078818912374797540503084065192522850610294896349093447535674399456848117265025305790953796393306797469303126679408324060892711826216496205767888070454667867, 0, 0], [0, 146846413769390244976608848259057201405519665366672409408768095972587701251406139189428316453600460678144374548391528508442083946479585622164441072640480078818912374797540503084065192522850610294896349093447535674399456848117265025305790953796393306797469303126679408324060892711826216496205767888070454667867, 0], [6867296937649804675330304143600800127086689870544326897060387158674476776137703898647694016602216531562546555861545156701226668559262814897142729818495918257758862771141799563425879839834827722484899754714919488903233676123477500696459482090269605616429621355077852324520261587871438174236205149188793014, 7059289188580529968155864048439542106749106256741341461340280444325180278206392011186975860986426819586019466754596153630428110127467232585713449902544890113463940723302881662804217323883464000935461313401720451266427171417777003991913692650475683469470095295121236844673987920615242308394311007753741057, 7.342320688469512e+307]]

    reduced_basis = olll.reduction(matrix, 0.75)
    # reduced_basis = LLL.lll(matrix).run()
    print("line 339")
    for i in range(len(reduced_basis)):
        for j in range(len(reduced_basis)):
            r = reduced_basis[i][j]
            if s_list[j] == 0:
                continue
            m = ((r + a_list[j]) * modinv(s_list[j], key.n)) % key.n
            print(m)
            print(m.to_bytes(k, 'big'))
            if pow(m, key.e, key.n) == c:
                return m

    return 0

    # with Manager() as manager:
    #     a_list = manager.list(range(number_of_attacks + 1))
    #     b_list = manager.list(range(number_of_attacks + 1))
    #     s_list = manager.list(range(number_of_attacks + 1))
    #
    #     start = time.time()
    #
    #     proccesses = list()
    #     for index in range(number_of_attacks):
    #         p = Process(target=bleichenbacher_attack, args=(k, key, c, oracle, a_list, b_list, s_list, index))
    #         p.start()
    #         proccesses.append(p)
    #
    #     for proccess in proccesses:
    #         proccess.join()
    #
    #     # global continue_threads
    #     # global a_array
    #     # global b_array
    #     # global s_array
    #     # for i in range(number_of_attacks + 1):
    #     #     a_array.append(None)
    #     #     b_array.append(None)
    #     #     s_array.append(None)
    #
    #     # bleich_processes = mp.Pool(mp.cpu_count())
    #     # print(273)
    #     # results = [bleich_processes.apply(bleichenbacher_attack, args=(k,key.public_key(),c,PKCS1_v1_5_Oracle(key), index)) for index in range(number_of_attacks)]
    #     # pool.close()
    #
    #     # for index in range(number_of_attacks):
    #     #     bleich_threads.append(Bleich_Thread(k, key, c, index))
    #     # print(254)
    #     # for bleich_thread in bleich_threads:
    #     #     # bleich_thread.deamon = True
    #     #     bleich_thread.start()
    #     # print(257)
    #     # for bleich_thread in bleich_threads:
    #     #     bleich_thread.join()
    #     # time.sleep(duration)
    #
    #     # end = time.time()
    #     # print("time: ", end-start)
    #     s_list[number_of_attacks] = 0
    #     print("line 321")
    #     matrix = [[s for s in s_list]]
    #     print("line 323")
    #     for i in range(number_of_attacks):
    #         arr = [0] * (number_of_attacks + 1)
    #         arr[i] = key.n
    #         matrix.append(arr.copy())
    #     print("line 328")
    #     a_list[number_of_attacks] = key.n * (number_of_attacks - 1) / number_of_attacks
    #     print("line 330")
    #     matrix.append(a for a in a_list)
    #     print("line 332")
    #     print("matrix:")
    #     print(matrix)
    #     # matrix = [[158797302718887508739481208591648002, 263140227100263324256796028711445180, 0], [146846413769390244976608848259057201405519665366672409408768095972587701251406139189428316453600460678144374548391528508442083946479585622164441072640480078818912374797540503084065192522850610294896349093447535674399456848117265025305790953796393306797469303126679408324060892711826216496205767888070454667867, 0, 0], [0, 146846413769390244976608848259057201405519665366672409408768095972587701251406139189428316453600460678144374548391528508442083946479585622164441072640480078818912374797540503084065192522850610294896349093447535674399456848117265025305790953796393306797469303126679408324060892711826216496205767888070454667867, 0], [6867296937649804675330304143600800127086689870544326897060387158674476776137703898647694016602216531562546555861545156701226668559262814897142729818495918257758862771141799563425879839834827722484899754714919488903233676123477500696459482090269605616429621355077852324520261587871438174236205149188793014, 7059289188580529968155864048439542106749106256741341461340280444325180278206392011186975860986426819586019466754596153630428110127467232585713449902544890113463940723302881662804217323883464000935461313401720451266427171417777003991913692650475683469470095295121236844673987920615242308394311007753741057, 7.342320688469512e+307]]
    #
    #     reduced_basis = olll.reduction(matrix, 1, key.n)
    #     print("line 339")
    #     r = reduced_basis[1][0]
    #     print("line 341")
    #     m = ((r + a_list[0]) * modinv(s_list[0], key.n)) % key.n
    #     print("line 343")
    #     print(m)
    #     return m

def bytes_needed(n):
    if n == 0:
        return 1
    return int(log(n, 256)) + 1

class PublicKey(object):
    def __init__(self, e, n):
        self.e = e
        self.n = n
        self.p = None
        self.q = None


if __name__ == "__main__":

    # # mp.set_start_method("fork")
    # red_basis = olll.reduction([[1, -1, 3], [1, 0, 5], [1, 2, 6]], 0.75)
    # print(red_basis)
    # n_length = 1024
    # key = RSA.generate(n_length)
    # k = int(n_length / 8)
    # data = b'secret message'
    # bt = 2
    #
    # # key = PKCS.key_gen(n_length)
    #
    # pkcs = PKCS.RSA_PKCS_1(bt, k, key)
    # oracle = PKCS1_v1_5_Oracle(key)
    #
    # # c = b'\x00' + (k - 1) * bytes([1])
    # c = pkcs.enc_PKCS_1(data)
    # # print(c)

    server_port = 11111
    path_to_server_public_key = "/home/lubuntu/wolfssl-3.12.0-stable/certificates/server-public-key.pem"
    public_constants = get_public_constants(path_to_server_public_key)
    modulus_bytes = public_constants["modulus_bytes"]

    manger_oracle = MangerOracle(server_port, public_constants)
    key = PublicKey(manger_oracle.e, manger_oracle.N)
    pkcs = PKCS.RSA_PKCS_1(2, modulus_bytes, key)
    rnd_pad = public_constants["rnd_pad"]


    #message = b'secret message'
    # c = cipher.encrypt(message)
    # c = pkcs.enc_PKCS_1(message)

    message = "aa112233445566778899112233445566778899112233445566778899112233445566778899112233445566778899"


    c = int("0002" + rnd_pad + "00" + "0303" + message, 16)
    c = int(gmpy2.powmod(c, key.e, key.n)).to_bytes(modulus_bytes, byteorder="big")

    result = parallel_bleich_attack(modulus_bytes, key, c, 1, manger_oracle)
    print(result.to_bytes(modulus_bytes, 'big'))
    if pow(result, key.e, key.n) == c:
        print("right result")
    else:
        print("wrong result")

    # ed = pkcs.enc_PKCS_1(data)
    # print(ed)

    # d = pkcs.dec_PKCS_1(c)
    # print(d)
