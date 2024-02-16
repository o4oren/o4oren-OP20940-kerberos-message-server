from common.file_utils import read_file_lines
from common.cryptography_utils import *


class AuthServer:

    def __init__(self, port):
        self.clients = []
        if not port.isnumeric() or not 1024 <= int(port) <= 65535:
            print("port must be a number between 1024 and 65535. Using default port 1256!")
            port = 1256
        self.port = int(port)

    def start_server(self):
        """
        Initializes the clients list from clients file
        Initializes message servers lisr from server.csv
        Starts listening on the port passed in initialization.
        """
        print(f'auth server started on port {self.port}!')
        self.clients = read_file_lines('clients')

        key = 'abcdabcdabcdabcd'.encode()
        text = 'my encrypted text'.encode()

        encrypted, iv = encrypt_aes_cbc(key, text, None)
        decrypted = decrypt_aes_cbc(key, encrypted, iv)
        print(f'decrypted: {decrypted}!')


