import multiprocessing as mp
from fractions import Fraction

from bleich_attack_process import divfloor, BleichAttackProcess, divceil
from blinding_process import BlindingProcess
from get_reduced_tattice import LLL_algorithm

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

def get_a_and_b_lists(attack_queue):
    a_list = list()
    b_list = list()
    while not attack_queue.empty():
        a_b = attack_queue.get()
        a_list.append(a_b[0])
        b_list.append(a_b[1])
    return a_list, b_list


def run_lll(lattice):
    return None


class BleichParallelAttack(object):
    def __init__(self, k, key, c, oracles, number_of_attacks=1, num_of_oracles_in_attack=None, number_of_rounds_each_attack=10000):
        self.k = k
        self.key = key
        self.c = c
        self.number_of_attacks = number_of_attacks
        self.number_of_rounds_each_attack = number_of_rounds_each_attack
        if num_of_oracles_in_attack is None:
            num_of_oracles_in_attack = divfloor(len(oracles), number_of_attacks)
        self.num_of_oracles_in_attack = num_of_oracles_in_attack
        self.oracles = oracles

    def run_blinding_processes(self, queue):
        blinding_processes = list()
        for oracle in self.oracles:
            blinding_processes.append(BlindingProcess(self.k, self.key, self.c, oracle, queue))

        for blinding_process in blinding_processes:
            blinding_process.start()

        for blinding_process in blinding_processes:
            blinding_process.join()

    def parallel_blinding(self):
        s_list = []
        c0_list = []
        if self.number_of_attacks == 1:
            s_list.append(1)
            c0_list.append(int.from_bytes(self.c, byteorder='big'))
        else:
            for index in range(self.number_of_attacks):
                blinding_queue = mp.Queue()
                self.run_blinding_processes(blinding_queue)
                s_c0 = blinding_queue.get()
                s_list.append(s_c0[0])
                c0_list.append(s_c0[1])

        return s_list, c0_list

    def run_parallel_processes(self, c0_list, queue):
        bleich_processes = []
        for index in range(self.number_of_attacks):
            bleich_processes.append(
                BleichAttackProcess(self.k,
                                    self.key,
                                    c0_list[index],
                                    self.oracles[index * self.num_of_oracles_in_attack:
                                                 (index + 1) * self.num_of_oracles_in_attack],
                                    self.number_of_rounds_each_attack,
                                    queue))

        for bleich_process in bleich_processes:
            bleich_process.start()

        for bleich_process in bleich_processes:
            bleich_process.join()

    def prepare_lattice(self, a_list, s_list):
        s_list.append(0)
        lattice = [s_list.copy()]

        for i in range(self.number_of_attacks):
            arr = [0] * (self.number_of_attacks + 1)
            arr[i] = self.key.n
            lattice.append(arr.copy())

        a_list.append(Fraction(self.key.n * (self.number_of_attacks - 1) / self.number_of_attacks))
        lattice.append(a_list.copy())
        return lattice

    def run(self):
        s_list, c0_list = self.parallel_blinding()
        attack_queue = mp.Queue()
        self.run_parallel_processes(c0_list, attack_queue)
        a_list, b_list = get_a_and_b_lists(attack_queue)
        lattice = self.prepare_lattice(a_list, s_list)
        lll = LLL_algorithm(lattice, self.key, self.number_of_attacks, self.c)
        return lll.get_secret_message_from_lattice()
