import socket
import struct
import threading
import uuid

from common.cryptography_utils import sha256_hash
from common.date_utils import get_date_string, get_timestamp_string
from common.network_utils import is_valid_port
from common.file_utils import read_file_lines, write_to_file
from common.protocol.client_request import ClientRequest
from common.protocol.user_registration_request_1024 import UserRegistrationRequest
from .as_client import Client

CLIENT_REGISTRATION_CODE = 1024


class AuthServer:
    def __init__(self, server_port_file):
        """
        Initializes an auth server.
        :param server_port_file: The address of a file with the port to listen on.
        """
        lines = read_file_lines(server_port_file)
        port = lines[0]
        if is_valid_port(port):
            print("port must be a number between 1024 and 65535. Using default port 1256!")
        else:
            port = 1256
        self.port = int(port)
        self.host = '127.0.0.1'
        self.clients = dict()

        self.start_server()

    def handle_client_request(self, client_socket, client_address):
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

        try:
            response = self.process_request(received_data)
            # Send a response back to the client
            response_string = f"Hello, {response.name}! I received your password: {response.password}."
            client_socket.send(response_string.encode('utf-8'))

        except Exception as e:
            print(f"error an with responded server {e}")

        finally:
            print(f"Connection with {client_address} closed.")
            client_socket.close()

    def start_server(self):
        """
        Initializes the clients list from clients file
        Initializes message servers lisr from server.csv
        Starts listening on the port passed in initialization.
        """
        print(f'auth server started on port {self.port}!')
        lines = read_file_lines('clients')
        for line in lines:
            client = Client.from_line(line)
            self.clients[client.get_id_string()] = client

        # Create a socket server
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.bind((self.host, self.port))
        server_socket.listen()

        print(f"Server listening on {self.host}:{self.port}")

        while True:
            client_socket, client_address = server_socket.accept()
            client_handler = threading.Thread(target=self.handle_client_request, args=(client_socket, client_address))
            client_handler.start()

    def process_request(self, request):
        request_code = self.get_code(request)
        if request_code == CLIENT_REGISTRATION_CODE:
            return self.process_user_registration(request)
        else:
            return "unknown request"

    def get_code(self, request):
        bytes_18_19 = request[17:19]
        return struct.unpack('<h', bytes_18_19)[0]

    def process_user_registration(self, request):
        client_request = ClientRequest.unpack(request, payload_type=UserRegistrationRequest)
        payload = client_request.payload

        for client_val in self.clients.values():
            if client_val.name == payload.name:
                raise RuntimeError("User already exists!")

        client_id = uuid.uuid4()
        password_hash = sha256_hash(payload.password.encode('utf-8'))

        client = Client(client_id.bytes, payload.name, password_hash)
        self.add_client(client)

        return payload

    def add_client(self, client: Client):
        self.clients[client.get_id_string()] = client
        client_line = f"{client.client_id.hex()}:{client.name}:{client.password_hash.hex()}:{get_timestamp_string(client.last_seen)}"
        write_to_file("clients", client_line)


# TODO return response object


