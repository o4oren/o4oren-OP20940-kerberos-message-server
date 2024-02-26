import socket
from datetime import datetime
from typing import cast

from auth_server.auth_server import CLIENT_REGISTRATION_SUCCESS_CODE
from common.cryptography_utils import sha256_hash, generate_nonce_bytes, decrypt_aes_cbc, encrypt_aes_cbc
from common.date_utils import datetime_to_timestamp_bytes
from common.file_utils import is_file_exists, read_file_lines, write_lines_to_file
from common.protocol.authenticator import Authenticator
from common.protocol.client_request import ClientRequest
from common.protocol.encrypted_session_key import EncryptedSessionKey
from common.protocol.message_codes import CLIENT_REGISTRATION_CODE, SERVER_LIST_REQUEST_CODE, \
    MESSAGE_SERVER_LIST_RESPONSE_CODE, SESSION_KEY_AND_TICKET_REQUEST_CODE, \
    SESSION_KEY_AND_TICKET_SUCCESS_RESPONSE_CODE, SEND_SESSION_KEY_TO_SERVER_REQUEST_CODE, \
    SESSION_KEY_ACCEPTED_RESPONSE_CODE, SEND_MESSAGE_REQUEST_CODE, MESSAGE_ACCEPTED_RESPONSE_CODE
from common.protocol.request_1024_user_registration import UserRegistrationRequest
from common.protocol.request_1027_session_key import SessionKeyAndTicketRequest
from common.protocol.request_1028_send_session_key import SendSessionKeyRequest
from common.protocol.request_1029_send_message import SendMessageRequest
from common.protocol.response_1600_user_registration_success import UserRegistrationSuccessResponse
from common.protocol.response_1603_key_and_token_success_response import KeyAndTokenResponse
from common.protocol.server_response import ServerResponse
from common.protocol.ticket import Ticket
from common.string_utils import extract_substring_between


class Client:
    CONFIG_FILE = "me.info"
    VERSION = 24

    def __init__(self):
        self.nonce = None
        self.client_id = None
        self.password_hash = None
        self.name = None
        self.auth_server_ip = None
        self.auth_server_port = None
        self.message_server_name = None
        self.message_server_id = None
        self.message_server_ip = None
        self.message_server_port = None
        self.session_key = None
        self.packed_ticket = None

        self.start_client()

    def initialize_without_config(self):
        name = input("Please enter your name (or 'exit' to quit): ")
        if name == 'exit':
            print('Exiting the client.')
            exit(0)
        self.name = name
        password = input("Please enter a password (or 'exit' to quit): ")
        if password == 'exit':
            print('Exiting the client.')
            exit(0)
        self.password_hash = sha256_hash(password.encode('utf-8'))
        self.register_client(name, password)

    def initialize_with_me_info_file(self):
        lines = read_file_lines(self.CONFIG_FILE)
        if len(lines) != 2:
            raise RuntimeError('me.info does not contain 2 lines!')
        self.name = lines[0]
        self.client_id = bytes.fromhex(lines[1])
        password = input(f"Hello {self.name}!\nPlease enter a password (or 'exit' to quit): ")
        if password == 'exit':
            print('Exiting the client.')
            exit(0)
        self.password_hash = sha256_hash(password.encode('utf-8'))

    def start_client(self):
        self.set_auth_server()

        if is_file_exists(self.CONFIG_FILE):
            self.initialize_with_me_info_file()
        else:
            self.initialize_without_config()

        self.select_message_server()
        self.get_key_and_ticket()
        self.send_ticket_to_message_server()

        while True:
            print('\nSelect an action:\n1) Send message to server\n2) Select another server\n3) Exit program')
            actions = int(input())

            if actions == 1:
                print('Enter your message:\n')
                message = input()
                self.send_message_to_server(message)

            elif actions == 2:
                self.select_message_server()
                self.get_key_and_ticket()
                self.send_ticket_to_message_server()
            elif actions == 3:
                print('Exiting the client.')
                break

            # Process the user input (add your logic here)
            # TODO    process_command(message)

    def set_auth_server(self):
        self.auth_server_ip = '127.0.0.1'
        self.auth_server_port = 1234

    def register_client(self, name, password):
        # Create a socket object
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect((self.auth_server_ip, self.auth_server_port))

        try:
            payload = UserRegistrationRequest(name, password)
            request = ClientRequest(bytearray(16), 24, CLIENT_REGISTRATION_CODE, payload)
            client_socket.send(request.pack())
            print('Client registration request sent!')
            # Receive and print the response
            response_bytes = client_socket.recv(1024)

            response = ServerResponse.unpack(response_bytes, UserRegistrationSuccessResponse)
            if response.code == CLIENT_REGISTRATION_SUCCESS_CODE:
                print(f'User created - ID: {response.payload.client_id.hex()}')
                self.client_id = response.payload.client_id
                write_lines_to_file(self.CONFIG_FILE, [self.name, self.client_id.hex()])
            else:
                print(f'Error {response.code} - User creation failed!')

        finally:
            # Close the socket
            print('Closing the connection from client side')
            client_socket.close()

    def list_message_servers(self):
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect((self.auth_server_ip, self.auth_server_port))
        message_servers = ''
        try:
            payload = bytes(0)
            request = ClientRequest(bytearray(16), 24, SERVER_LIST_REQUEST_CODE, payload)
            client_socket.send(request.pack())
            print('Message servers list request sent!')
            # Receive and the response (which can be long)
            received_data_bytes = b''
            while True:
                chunk = client_socket.recv(1024)
                received_data_bytes += chunk
                if len(chunk) < 1024:
                    break

            response = ServerResponse.unpack(received_data_bytes, bytes)
            if response.code == MESSAGE_SERVER_LIST_RESPONSE_CODE:
                message_servers = response.payload.decode('utf-8')

            else:
                print(f'Error {response.code} - Could not fetch servers list!')

        finally:
            # Close the socket
            print("Closing the connection from client side")
            client_socket.close()
            return message_servers

    def select_message_server(self):
        message_servers = self.list_message_servers()

        if len(message_servers) == 0:
            print('There are no registered message servers!')
            exit(1)
        else:
            print('Message servers:\n')
            print(message_servers)

        lines = message_servers.split('\n')
        servers = []
        for line in lines:
            if not bool(line):
                break
            name = extract_substring_between(line, ') ', ' ID:')
            server_id = extract_substring_between(line, 'ID: ', " at:")
            ip_address = extract_substring_between(line, ' at: ', ':')
            port = int((line[line.rfind(':') + 1:len(line)]))
            servers.append((name, server_id, ip_address, port))

        server_index = int(input("Please select a server from the list: "))
        server = servers[server_index - 1]
        self.message_server_name = server[0]
        self.message_server_id = bytes.fromhex(server[1])
        self.message_server_ip = server[2]
        self.message_server_port = server[3]
        print(f'Selected {self.message_server_name}')

    def get_key_and_ticket(self):
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect((self.auth_server_ip, self.auth_server_port))
        try:
            self.nonce = generate_nonce_bytes()
            payload = SessionKeyAndTicketRequest(self.message_server_id, self.nonce)
            request = ClientRequest(self.client_id, 24, SESSION_KEY_AND_TICKET_REQUEST_CODE, payload)
            client_socket.send(request.pack())
            print(f'Session key and ticket request for communication with {self.message_server_name} sent!')
            response_bytes = client_socket.recv(1024)

            response = ServerResponse.unpack(response_bytes, KeyAndTokenResponse)
            if response.code != SESSION_KEY_AND_TICKET_SUCCESS_RESPONSE_CODE:
                raise RuntimeError(f'Error {response.code} - Could not get session key!')

            response_payload = cast(KeyAndTokenResponse, response.payload)
            encrypted_key = EncryptedSessionKey.unpack(response_payload.session_key)
            packed_ticket = response_payload.ticket
            iv = encrypted_key.iv
            self.session_key = decrypt_aes_cbc(self.password_hash, encrypted_key.session_key, iv)
            nonce = decrypt_aes_cbc(self.password_hash, encrypted_key.nonce, iv)
            if self.nonce != nonce:
                raise RuntimeError(f'Received nonce is incorrect')
            else:
                print(f'Nonce verified!')

            self.packed_ticket = packed_ticket
            print(f'Received a session key {self.session_key.hex()} and ticket from the auth server!')
        except ValueError as e:
            print(f'{type(e)} {e} - are you sure you typed the correct password?')
        finally:
            # Close the socket
            print("Closing the connection from client side")
            client_socket.close()

    def send_ticket_to_message_server(self):
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect((self.message_server_ip, self.message_server_port))
        try:
            encrypted_version, iv = encrypt_aes_cbc(self.session_key, self.VERSION.to_bytes(), None)
            encrypted_client_id, _ = encrypt_aes_cbc(self.session_key, self.client_id, iv)
            encrypted_server_id, _ = encrypt_aes_cbc(self.session_key, self.message_server_id, iv)
            now = datetime.now()
            creation_time_bytes = datetime_to_timestamp_bytes(now)
            encrypted_creation_time, _ = encrypt_aes_cbc(self.session_key, creation_time_bytes, iv)
            authenticator_bytes = Authenticator(iv, encrypted_version, encrypted_client_id, encrypted_server_id,
                                                encrypted_creation_time).pack()
            print(f'Authenticator created at {now}.')
            payload = SendSessionKeyRequest(authenticator_bytes, self.packed_ticket)
            request = ClientRequest(self.client_id, self.VERSION, SEND_SESSION_KEY_TO_SERVER_REQUEST_CODE, payload)
            client_socket.send(request.pack())
            print(
                f'Sent ticket to message server {self.message_server_name} at {self.message_server_ip}:{self.message_server_port}!')
            response_bytes = client_socket.recv(1024)
            response = ServerResponse.unpack(response_bytes, bytes)
            if response.code == SESSION_KEY_ACCEPTED_RESPONSE_CODE:
                print(f'{self.message_server_name} approved receiving the session key!')
            else:
                raise RuntimeError(f'{self.message_server_name} did not respond with a success message!')
        finally:
            # Close the socket
            print("Closing the connection from client side")
            client_socket.close()

    def send_message_to_server(self, message):
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect((self.message_server_ip, self.message_server_port))
        try:
            print(f'Sending message to {self.message_server_name}')
            encrypted_message, message_iv = encrypt_aes_cbc(self.session_key, message.encode('utf-8'), None)
            payload = SendMessageRequest(message_iv, encrypted_message)
            request = ClientRequest(self.client_id, self.VERSION, SEND_MESSAGE_REQUEST_CODE, payload)
            client_socket.send(request.pack())

            response_bytes = client_socket.recv(1024)
            response = ServerResponse.unpack(response_bytes, bytes)
            if response.code == MESSAGE_ACCEPTED_RESPONSE_CODE:
                print(f'{self.message_server_name} approved receiving, decrypting and printing the message!')
            else:
                raise RuntimeError(f'{self.message_server_name} did not respond with a success message!')

        finally:
            # Close the socket
            print("Closing the connection from client side")
            client_socket.close()
