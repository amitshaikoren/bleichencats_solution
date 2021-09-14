"""
Oracles for chosen-ciphertext attacks on PKCS #1
"""
from Crypto.Cipher import PKCS1_v1_5


class Oracle(object):
    def __init__(self):
        pass

    def query(self, input):
        raise NotImplementedError("Must override query")


class PKCS1_v1_5_Oracle(Oracle):
    """
    Oracle for RSA PKCS #1 v1.5
    """
    def __init__(self, key):
        self.cipher = PKCS1_v1_5.new(key)
        super(Oracle, self).__init__()

    def query(self, input):
        """
        Checks if input is a conforming encryption
        :param input: bytearray of size k, where k=n_length/8
        :return: True if input is a valid encryption, False else
        """
        if self.cipher.decrypt(input, None) is None:
            return False
        return True


class PKCS1_OAEP_Oracle(Oracle):
    """
    Oracle for RSA PKCS #1 OAEP
    """
    def __init__(self, k, key):
        self.n = key.n
        self.d = key.d
        self.B = 2 ** (8 * (k - 1))
        super(Oracle, self).__init__()

    def query(self, input):
        """
        Checks if the decryption of input is less than B
        :param input: bytearray of size k, where k=n_length/8
        :return: True if (input) ** d mod n is less than B, False else
        """
        c = int.from_bytes(input, byteorder='big')
        p = pow(c, self.d, self.n)
        if p < self.B:
            return True
        return False

