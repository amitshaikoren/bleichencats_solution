import multiprocessing as mp
from os import urandom

from gmpy2 import gmpy2


class BlindingProcess(mp.Process):

    def __init__(self, k, key, c, oracle, queue):
        mp.Process.__init__(self)
        self.k = k
        self.key = key
        self.c = c
        self.s_0 = 0
        self.c_0 = 0
        self.oracle = oracle
        self.queue = queue

    def run(self):
        try:
            self.blinding()
            if self.s_0 != 0:
                self.queue.put((self.s_0, self.c_0))
                print("finish run, process: ", self.name)
        except Exception as e:
            print(self.name, " : attack failed")
            self.queue.put((0, 0))
            raise e

    def blinding(self):
        """
        :return: integers s_0, c_0 s.t. c_0 represents a conforming encryption and c_0 = (c * (s_0) ** e) mod n
        """
        # if oracle.query(c.to_bytes(k, byteorder='big')):
        #     return 1, c
        c = int.from_bytes(self.c, byteorder='big')
        counter = 0
        s_0 = urandom(self.k)
        s_0 = int.from_bytes(s_0, byteorder='big') % self.key.n
        while self.queue.empty():
            counter += 1
            print(self.name, "counter = ", counter)
            c_0 = (c * pow(s_0, self.key.e, self.key.n)) % self.key.n
            if self.oracle.query(c_0):
                self.s_0 = s_0
                self.c_0 = c_0
                print(self.name, " found blinding")
                break
            s_0 = urandom(self.k)
