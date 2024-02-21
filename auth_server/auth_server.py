import socket
import struct
import threading
import uuid

from common.cryptography_utils import sha256_hash
from common.date_utils import get_date_string, get_timestamp_string
from common.network_utils import is_valid_port
from common.file_utils import read_file_lines, write_line_to_file, write_lines_to_file, is_file_exists
from common.protocol.client_request import ClientRequest
from common.protocol.message_codes import CLIENT_REGISTRATION_CODE, CLIENT_REGISTRATION_SUCCESS_CODE, \
    CLIENT_REGISTRATION_FAIL_CODE, SERVER_REGISTRATION_CODE, SERVER_REGISTRATION_SUCCESS_CODE, GENERAL_SERVER_ERROR_CODE
from common.protocol.request_1024_user_registration import UserRegistrationRequest
from common.protocol.request_1025_server_registration import ServerRegistrationRequest
from common.protocol.response_1600_user_registration_success import UserRegistrationSuccessResponse
from common.protocol.response_1608_message_server_registration_success import MessageServerRegistrationSuccessResponse
from common.protocol.server_response import ServerResponse
from .client import Client
from .message_server import MessageServer

SERVERS = 'servers'

CLIENTS = 'clients'

VERSION = 24


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
        self.message_servers = dict()

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
            response = self.process_request(received_data, client_socket)
            # Send a response back to the client
            client_socket.send(response)

        except Exception as e:
            print(f"error an with responded server {e}")

        finally:
            print(f"Connection with {client_address} closed.")
            client_socket.close()

    def start_server(self):
        """
        Initializes the clients list from clients file
        Initializes message %s lisr from server.csv
        Starts listening on the port passed in initialization.
        """
        print(f'auth server started on port {self.port}!')
        if is_file_exists(CLIENTS):
            lines = read_file_lines(CLIENTS)
            for line in lines:
                client = Client.from_line(line)
                self.clients[client.get_id_string()] = client

            print(f'Loaded {len(lines)} clients from "clients" file')

        if is_file_exists(SERVERS):
            lines = read_file_lines(SERVERS)
            for line in lines:
                server = MessageServer.from_line(line)
                self.message_servers[server.get_id_string()] = server

        # Create a socket server
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.bind((self.host, self.port))
        server_socket.listen()

        print(f'Server listening on {self.host}:{self.port}')

        while True:
            client_socket, client_address = server_socket.accept()
            client_handler = threading.Thread(target=self.handle_client_request, args=(client_socket, client_address))
            client_handler.start()

    def process_request(self, request, client_socket):
        request_code = self.get_request_code(request)
        if request_code == CLIENT_REGISTRATION_CODE:
            return self.process_user_registration(request)
        elif request_code == SERVER_REGISTRATION_CODE:
            client_ip, client_port = client_socket.getpeername()
            return self.process_server_registration(request, client_ip, client_port)
        else:
            return "unknown request"

    @staticmethod
    def get_request_code(request):
        bytes_18_19 = request[17:19]
        return struct.unpack('<h', bytes_18_19)[0]

    def process_user_registration(self, request):
        try:
            client_request = ClientRequest.unpack(request, payload_type=UserRegistrationRequest)
            client_payload = client_request.payload

            for client_val in self.clients.values():
                if client_val.name == client_payload.name:
                    raise RuntimeError("User already exists!")

            client_id = uuid.uuid4()
            password_hash = sha256_hash(client_payload.password.encode('utf-8'))

            client = Client(client_id.bytes, client_payload.name, password_hash)
            self.add_client(client)

            user_registration_payload = UserRegistrationSuccessResponse(client_id.bytes)
            response = ServerResponse(VERSION, CLIENT_REGISTRATION_SUCCESS_CODE, user_registration_payload)
        except RuntimeError as e:
            response = ServerResponse(VERSION, CLIENT_REGISTRATION_FAIL_CODE, None)

        return response.pack()

    def add_client(self, client: Client):
        self.clients[client.get_id_string()] = client
        client_line = f"{client.client_id.hex()}:{client.name}:{client.password_hash.hex()}:{get_timestamp_string(client.last_seen)}"
        write_line_to_file(CLIENTS, client_line)

    def process_server_registration(self, request, client_ip, client_port):
        try:
            server_request = ClientRequest.unpack(request, payload_type=ServerRegistrationRequest)
            server_registration_payload = server_request.payload

            for message_server in self.message_servers.values():
                if message_server.name == server_registration_payload.name:
                    raise RuntimeError("Message server name already exists!")


            server_id = uuid.uuid4()
            server_name = server_registration_payload.name
            server_key = server_registration_payload.message_server_key
            server_ip = client_ip
            server_port = client_port

            message_server = MessageServer(server_id.bytes, server_name, server_key, server_ip, server_port)

            message_server_registration_payload = MessageServerRegistrationSuccessResponse(message_server.server_id)
            response = ServerResponse(VERSION, SERVER_REGISTRATION_SUCCESS_CODE, message_server_registration_payload)
        except RuntimeError as e:
            response = ServerResponse(VERSION, GENERAL_SERVER_ERROR_CODE, None)

        return response.pack()

# TODO return response object
