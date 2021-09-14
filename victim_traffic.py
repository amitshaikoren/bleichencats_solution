import wolfssl
import socket
import random
import multiprocessing

CLIENT_COOKIE = "cookie=bleichenCOOKIE1799cat"
SERVER_HOST = "127.0.0.1"
CIPHER_SUITE = "AES256-SHA"
PATH_TO_SERVER_PUBLIC_KEY = "/home/lubuntu/wolfssl-3.12.0-stable/certificates/server-public-key.pem"
PATH_TO_SERVER_PRIVATE_KEY = "/home/lubuntu/wolfssl-3.12.0-stable/certificates/server-private-key.pem"
PATH_TO_CA_PUBLIC_CERT = "/home/lubuntu/wolfssl-3.12.0-stable/certificates/ca-public-key.pem"
WOLFSSL_ROOT_DIR = "/home/lubuntu/wolfssl-3.12.0-stable"
MAX_PORT = 55555
MIN_PORT = 21111

class ClientProcess(multiprocessing.Process):
    def __init__(self, server_port):
        multiprocessing.Process.__init__(self)
        self.server_port = server_port

    def run(self):
        host = SERVER_HOST
        port = self.server_port

        bind_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)

        bind_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        context = wolfssl.SSLContext(wolfssl.PROTOCOL_TLSv1_2)

        context.verify_mode = wolfssl.CERT_REQUIRED
        context.load_verify_locations(cafile=PATH_TO_CA_PUBLIC_CERT)

        context.set_ciphers(CIPHER_SUITE)

        secure_socket = context.wrap_socket(bind_socket)

        connected_to_server = False

        while not connected_to_server:
            try:
                secure_socket.connect((host, port))
                connected_to_server = True
            except ConnectionRefusedError:
                continue

        secure_socket.write(CLIENT_COOKIE)
        secure_socket.close()


class ServerProcess(multiprocessing.Process):

    def __init__(self, child_conn):
        multiprocessing.Process.__init__(self)
        self.port = None
        self.child_conn = child_conn

    def run(self):
        host = SERVER_HOST
        port = random.randint(MIN_PORT, MAX_PORT)

        bind_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)

        bind_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        server_bound_to_socket = False

        while not server_bound_to_socket:
            try:
                bind_socket.bind((host, port))
                server_bound_to_socket = True
            except OSError:
                port = random.randint(MIN_PORT, MAX_PORT)
                continue

        self.child_conn.send(port)
        self.child_conn.close()

        bind_socket.listen(5)

        print("Listening on " + host + ":" + str(port))

        context = wolfssl.SSLContext(wolfssl.PROTOCOL_TLSv1_2, server_side=True)

        context.load_cert_chain(PATH_TO_SERVER_PUBLIC_KEY,
                                keyfile=PATH_TO_SERVER_PRIVATE_KEY)

        context.set_ciphers(CIPHER_SUITE)

        while True:
            try:
                secure_socket = None

                new_socket, from_addr = bind_socket.accept()

                print("accepted")

                secure_socket = context.wrap_socket(new_socket)

                print("Connection received from", from_addr)

                secure_socket.write(b"I hear you fa shizzle!")

                break

            except KeyboardInterrupt:
                break

            finally:
                if secure_socket:
                    secure_socket.close()

        bind_socket.close()


def main():
    parent_conn_server, child_conn_server = multiprocessing.Pipe()

    serverp = ServerProcess(child_conn_server)
    serverp.start()

    server_bound_port = parent_conn_server.recv()

    clientp = ClientProcess(server_bound_port)
    clientp.start()

    serverp.join()
    clientp.join()


if __name__ == "__main__":
    main()
