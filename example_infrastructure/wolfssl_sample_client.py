import wolfssl
import socket


def run_client(data, host="127.0.0.1", port=11111):
    bind_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)

    context = wolfssl.SSLContext(wolfssl.PROTOCOL_TLSv1_2)

    context.verify_mode = wolfssl.CERT_REQUIRED
    context.load_verify_locations(cafile="/home/lubuntu/certificates/ca-public-key.pem")

    context.set_ciphers("AES256-SHA")

    secure_socket = context.wrap_socket(bind_socket)

    secure_socket.connect((host, port))

    secure_socket.write(data)

    print(secure_socket.read())

    secure_socket.close()
