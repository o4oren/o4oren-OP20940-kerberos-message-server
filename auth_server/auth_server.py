import socket
import struct
import threading
import traceback
import uuid
from datetime import datetime, timedelta
from typing import cast

from common.cryptography_utils import sha256_hash, generate_aes_key, encrypt_aes_cbc
from common.date_utils import get_date_string, get_timestamp_string, datetime_to_timestamp_bytes
from common.network_utils import is_valid_port
from common.file_utils import read_file_lines, write_line_to_file, write_lines_to_file, is_file_exists
from common.protocol.client_request import ClientRequest
from common.protocol.encrypted_session_key import EncryptedSessionKey
from common.protocol.message_codes import CLIENT_REGISTRATION_CODE, CLIENT_REGISTRATION_SUCCESS_CODE, \
    CLIENT_REGISTRATION_FAIL_CODE, SERVER_REGISTRATION_CODE, SERVER_REGISTRATION_SUCCESS_CODE, \
    GENERAL_SERVER_ERROR_CODE, SERVER_LIST_REQUEST_CODE, MESSAGE_SERVER_LIST_RESPONSE_CODE, \
    SESSION_KEY_AND_TICKET_REQUEST_CODE, SESSION_KEY_AND_TICKET_SUCCESS_RESPONSE_CODE
from common.protocol.request_1024_user_registration import UserRegistrationRequest
from common.protocol.request_1025_server_registration import ServerRegistrationRequest
from common.protocol.request_1027_session_key import SessionKeyAndTicketRequest
from common.protocol.response_1600_user_registration_success import UserRegistrationSuccessResponse
from common.protocol.response_1603_key_and_token_success_response import KeyAndTokenResponse
from common.protocol.response_1608_message_server_registration_success import MessageServerRegistrationSuccessResponse
from common.protocol.server_response import ServerResponse
from common.protocol.ticket import Ticket
from .client import Client
from .message_server import MessageServer

SERVERS = 'servers'
CLIENTS = 'clients'
VERSION = 24
SESSION_KEY_LIFETIMEMINUTES = 5

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

        print(f"Received a request from {client_address}")

        try:
            response = self.process_request(received_data, client_socket)
            # Send a response back to the client
            client_socket.send(response)

        except Exception as e:
            print(f"error  {e}")
            traceback.print_exc()
            client_socket.send(ServerResponse(VERSION, GENERAL_SERVER_ERROR_CODE, None))

        finally:
            print(f"Connection with {client_address} closed.")
            client_socket.close()

    def start_server(self):
        """
        Initializes the clients list from clients file
        Initializes message %s list from server.csv
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
            print(f'Loaded {len(lines)} message servers from "servers" file')

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
        elif request_code == SERVER_LIST_REQUEST_CODE:
            return self.process_server_list_request(request)
        elif request_code == SESSION_KEY_AND_TICKET_REQUEST_CODE:
            return self.process_session_key_and_ticket_request(request)
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
            self.add_client_to_file(client)

            user_registration_payload = UserRegistrationSuccessResponse(client_id.bytes)
            response = ServerResponse(VERSION, CLIENT_REGISTRATION_SUCCESS_CODE, user_registration_payload)
        except RuntimeError as e:
            response = ServerResponse(VERSION, CLIENT_REGISTRATION_FAIL_CODE, None)

        return response.pack()

    def add_client_to_file(self, client: Client):
        self.clients[client.get_id_string()] = client
        client_line = f'{client.client_id.hex()}:{client.name}:{client.password_hash.hex()}:{get_timestamp_string(client.last_seen)}'
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
            server_port = server_registration_payload.port

            message_server = MessageServer(server_id.bytes, server_name, server_key, server_ip, server_port)
            self.add_message_server_to_file(message_server)

            message_server_registration_payload = MessageServerRegistrationSuccessResponse(message_server.message_server_id)
            response = ServerResponse(VERSION, SERVER_REGISTRATION_SUCCESS_CODE, message_server_registration_payload)
        except RuntimeError as e:
            response = ServerResponse(VERSION, GENERAL_SERVER_ERROR_CODE, None)

        return response.pack()

    def add_message_server_to_file(self, server: MessageServer):
        self.message_servers[server.get_id_string()] = server
        server_line = f'{server.message_server_id.hex()}:{server.name}:{server.key.hex()}:{server.ip_address}:{server.port}'
        write_line_to_file(SERVERS, server_line)

    def process_server_list_request(self, request):
        try:
            server_list = ''
            i = 1
            for message_server in self.message_servers.values():
                server_list += f'{i}) {message_server.name} ID: {message_server.message_server_id.hex()} at: {message_server.ip_address}:{message_server.port}\n'
                i = i + 1
            response = ServerResponse(VERSION, MESSAGE_SERVER_LIST_RESPONSE_CODE, server_list.encode('utf-8'))
        except RuntimeError as e:
            response = ServerResponse(VERSION, GENERAL_SERVER_ERROR_CODE, None)

        return response.pack()

    def process_session_key_and_ticket_request(self, request):
        response = None
        try:
            client_request = ClientRequest.unpack(request, payload_type=SessionKeyAndTicketRequest)
            session_key_and_ticket_request = cast(SessionKeyAndTicketRequest, client_request.payload)
            server = self.message_servers[session_key_and_ticket_request.message_server_id.hex()]
            if server is None:
                raise RuntimeError("Message server not found!")

            # Create the encrypted key field
            client = self.clients[client_request.client_id.hex()]
            session_key = generate_aes_key()
            print(f'Generated session key {session_key.hex()}')
            encrypted_key, iv = encrypt_aes_cbc(client.password_hash, session_key, None)
            encrypted_nonce, _ = encrypt_aes_cbc(client.password_hash, session_key_and_ticket_request.nonce, iv)

            session_key_bytes = EncryptedSessionKey(iv, encrypted_nonce, encrypted_key).pack()

            # create the ticket field
            creation_time = datetime.utcnow()
            creation_time_bytes = datetime_to_timestamp_bytes(creation_time)
            expiration_time = creation_time + timedelta(minutes=5)
            expiration_time_bytes = datetime_to_timestamp_bytes(expiration_time)
            ticket_encrypted_session_key, ticket_iv = encrypt_aes_cbc(server.key, session_key, None)
            ticket_encrypted_expiration_time, _ = encrypt_aes_cbc(server.key, expiration_time_bytes, ticket_iv)
            ticket_bytes = Ticket(VERSION, client_request.client_id, server.message_server_id, creation_time_bytes, ticket_iv, ticket_encrypted_session_key, ticket_encrypted_expiration_time).pack()

            response_payload = KeyAndTokenResponse(client.client_id, session_key_bytes, ticket_bytes)
            response = ServerResponse(VERSION, SESSION_KEY_AND_TICKET_SUCCESS_RESPONSE_CODE, response_payload)
        except Exception as e:
            print(e)
            response = ServerResponse(VERSION, GENERAL_SERVER_ERROR_CODE, None)
        finally:
            return response.pack()