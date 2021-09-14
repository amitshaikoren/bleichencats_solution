import subprocess


from PKCS import modinv


class LLL_algorithm(object):
    def __init__(self, lattice, key, num_of_attacks, c):
        self.lattice = lattice
        self.num_of_attacks = num_of_attacks
        self.key = key
        self.c = c

    def get_secret_message_from_lattice(self):
        if self.num_of_attacks == 1:
            a = self.lattice[len(self.lattice) - 1][0]
            N = self.lattice[1][0]
            s = self.lattice[0][0]
            return (a * modinv(s, N)) % N
        else:
            subprocess.run(['sage', 'get_reduced_lattice.sage'])
            file = open("reduced_lattice.txt", 'r')
            reduced_basis_string = file.readlines()
            file.close()
            reduced_basis = []

            for line in reduced_basis_string:
                line = line[1: len(line) - 2].split()
                vector = list(map(int, line[:len(line) - 1]))
                reduced_basis.append(vector)

            return self.restore_secret_message_from_basis(reduced_basis, self.lattice[-1], self.lattice[0])

    def restore_secret_message_from_basis(self, reduced_basis, a_list, s_list):
        for j in range(len(reduced_basis) - 1):
            r = reduced_basis[j][0]
            if s_list[0] == 0:
                continue
            m = ((r + a_list[0]) * modinv(s_list[0], self.key.n)) % self.key.n
            if pow(m, self.key.e, self.key.n) == self.c:
                return m
        return 0

