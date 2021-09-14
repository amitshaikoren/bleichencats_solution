import multiprocessing
import subprocess
import threading

WOLFSSL_SERVER_HANDSHAKE_DONE_MESSAGE = b'I hear you fa shizzle!\x00'
VICTORY_MESSAGE = "VICTORY!!!\nYou preformed Bleichenbacher's attack successfully on a WolfSSL server!\nVery impressive!"
CLIENT_COOKIE = "cookie=bleichenCOOKIE1799cat"
ERROR_IN_CTF = "CTF ERROR"
SERVER_HOST = "127.0.0.1"
SERVER_PORT = 12345
PATH_TO_SERVER_PUBLIC_KEY = "/home/lubuntu/wolfssl-3.12.0-stable/certificates/server-public-key.pem"
PATH_TO_SERVER_PRIVATE_KEY = "/home/lubuntu/wolfssl-3.12.0-stable/certificates/server-private-key.pem"
PATH_TO_CA_PUBLIC_CERT = "/home/lubuntu/wolfssl-3.12.0-stable/certificates/ca-public-key.pem"

WOLFSSL_ROOT_DIR = "/home/lubuntu/wolfssl-3.12.0-stable"

server_run_command = ['stdbuf', '-oL', 'sh',
                      './examples/server/server', '-c', PATH_TO_SERVER_PUBLIC_KEY,
                      '-k', PATH_TO_SERVER_PRIVATE_KEY,
                      '-A', PATH_TO_CA_PUBLIC_CERT,
                      '-p', str(SERVER_PORT),
                      '-d', '-i']

victory_event = threading.Event()
fail_event = threading.Event()
HELLO_BOB = "Hello, BobMichelinStar1998."


class CTFException(Exception):
    def __init__(self, message="ERROR: there has been an error. Please rerun the ctf in order to continue."):
        self.message = message
        super().__init__(self.message)


def user_pass_loop():
    while True:
        if victory_event.is_set() or fail_event.is_set():
            break
        input("Username: ")
        if victory_event.is_set() or fail_event.is_set():
            break
        input("Password: ")
        if victory_event.is_set() or fail_event.is_set():
            break
        print("Wrong username or password. Please try again.")


class CLIProcess(multiprocessing.Process):
    def __init__(self, victory_event):
        multiprocessing.Process.__init__(self)
        self.victory_event = victory_event

    def run(self):
        while True:
            if self.victory_event.is_set():
                break
            input("Username: ")
            if self.victory_event.is_set():
                break
            input("Password: ")
            if self.victory_event.is_set():
                break
            print("Wrong username or password. Please try again.")
            if self.victory_event.is_set():
                break

def main():
    loop_thread = threading.Thread(target=user_pass_loop)
    loop_thread.start()
    victory = False

    server_output = str()

    try:
        server_process = subprocess.Popen(
            server_run_command, stdout=subprocess.PIPE, cwd=WOLFSSL_ROOT_DIR, bufsize=0, close_fds=True
        )
        while True:
            if server_process.poll() is not None:
                fail_event.set()
                break
            output = server_process.stdout.readline()
            if output == '':
                fail_event.set()
                break
            if output:
                server_output += output.decode('utf-8')
                if CLIENT_COOKIE in server_output:
                    victory_event.set()
                    break

    except Exception as e:
        print("Error running server:\n")
        print(str(e))
        raise CTFException

    victory = victory_event.is_set()

    server_process.terminate()
    server_process.wait()

    loop_thread.join()

    if not victory:
        raise CTFException

    else:
        print(HELLO_BOB)
        return HELLO_BOB


if __name__ == "__main__":
    main()