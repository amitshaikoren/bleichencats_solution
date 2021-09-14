import socket
import wolfssl


def run_server(host="127.0.0.1", port=11111):
    bind_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)

    bind_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    bind_socket.bind((host, port))
    bind_socket.listen(5)

    print("Listening on " + host + ":" + str(port))

    context = wolfssl.SSLContext(wolfssl.PROTOCOL_TLSv1_2, server_side=True)

    context.load_cert_chain("/home/lubuntu/testing/server-public-key.pem",
                            keyfile="/home/lubuntu/testing/server-private-key.pem")

    cipher_want = "AES256-SHA"

    context.set_ciphers(cipher_want)

    while True:
        try:
            secure_socket = None

            new_socket, from_addr = bind_socket.accept()

            secure_socket = context.wrap_socket(new_socket)

            print("Connection received from", from_addr)

            print("\n" + str(secure_socket.read()) + "\n")
            secure_socket.write(b"I hear you fa shizzle!")

        except KeyboardInterrupt:
            break

        finally:
            if secure_socket:
                secure_socket.close()

    bind_socket.close()


if __name__ == "__main__":
    run_server()
