import socket
import threading

from auth_server import protocol_handler
from auth_server.protocol_handler import ProtocolHandler
from common.file_utils import read_file_lines


class AuthServer:

    def __init__(self, port):
        self.clients = []
        if not port.isnumeric() or not 1024 <= int(port) <= 65535:
            print("port must be a number between 1024 and 65535. Using default port 1256!")
            port = 1256
        self.port = int(port)
        self.host = '127.0.0.1'
        self.protocol_handler = ProtocolHandler()

    def handle_client(self, client_socket, client_address):
        """
        Gets the socket object and client address and handles the request
        :param client_socket:
        :param client_address:
        :return:
        """
        print(f"Connection from {client_address}")

        # Receiving data in chunks
        received_data = b''
        while True:
            chunk = client_socket.recv(1024)
            received_data += chunk
            if len(chunk) < 1024:
                break

        print(f"Received data from {client_address}: {received_data}")

        response = self.protocol_handler.process(received_data)
        # Send a response back to the client
        responseString = f"Hello, {response.name}! I received your password: {response.password}."
        client_socket.send(responseString.encode('utf-8'))

        print(f"Connection with {client_address} closed.")
        client_socket.close()

    def start_server(self):
        """
        Initializes the clients list from clients file
        Initializes message servers lisr from server.csv
        Starts listening on the port passed in initialization.
        """
        print(f'auth server started on port {self.port}!')
        self.clients = read_file_lines('clients')

        # Create a socket server
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.bind((self.host, self.port))
        server_socket.listen()

        print(f"Server listening on {self.host}:{self.port}")

        while True:
            client_socket, client_address = server_socket.accept()
            client_handler = threading.Thread(target=self.handle_client, args=(client_socket, client_address))
            client_handler.start()