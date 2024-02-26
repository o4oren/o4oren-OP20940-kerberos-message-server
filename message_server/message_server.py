import socket
import struct
import threading
import traceback
from datetime import datetime, timedelta
from typing import cast

from common.cryptography_utils import generate_aes_key, decrypt_aes_cbc
from common.date_utils import get_datetime_from_ts_bytes, get_datetime_from_ts
from common.file_utils import read_file_lines, write_lines_to_file
from common.network_utils import is_valid_port, is_valid_ip
from common.protocol.authenticator import Authenticator
from common.protocol.client_request import ClientRequest
from common.protocol.message_codes import SERVER_REGISTRATION_CODE, SERVER_REGISTRATION_SUCCESS_CODE, \
    GENERAL_SERVER_ERROR_CODE, SEND_SESSION_KEY_TO_SERVER_REQUEST_CODE, SESSION_KEY_ACCEPTED_RESPONSE_CODE, \
    SEND_MESSAGE_REQUEST_CODE, MESSAGE_ACCEPTED_RESPONSE_CODE
from common.protocol.request_1025_server_registration import ServerRegistrationRequest
from common.protocol.request_1028_send_session_key import SendSessionKeyRequest
from common.protocol.request_1029_send_message import SendMessageRequest
from common.protocol.response_1608_message_server_registration_success import MessageServerRegistrationSuccessResponse
from common.protocol.server_response import ServerResponse
from common.protocol.ticket import Ticket


class MessageServer:
    VERSION = 24

    def __init__(self, msg_server_config_file):
        """
        Initializes the message server. Requires the below parameters to be able to communicate with the auth server
        The server class expects a text file with at least 3 lines:
        1st line - message_server_ip:message_server_port
        2nd line - message server's name
        3rd line - auth_server_ip:auth_server_port
        4th line - the symmetrical key used to communicate with the auth server - if exists
        5th line - the server ID assigned by the auth server - if exists
        :param msg_server_config_file: path to config file
        """
        self.config_file = msg_server_config_file
        lines = read_file_lines(msg_server_config_file)
        my_ip = lines[0].split(':')[0]
        my_port = lines[0].split(':')[1]
        my_name = lines[1]
        auth_server_ip = lines[2].split(':')[0]
        auth_server_port = lines[2].split(':')[1]
        self.my_ip = my_ip
        self.my_port = my_port
        self.my_name = my_name
        self.auth_server_ip = auth_server_ip
        self.auth_server_port = auth_server_port
        self.sessions = dict()
        if len(lines) == 5:
            self.auth_server_key = bytes.fromhex(lines[3])
            self.message_server_id = bytes.fromhex(lines[4])
        else:
            self.auth_server_key = None
            self.message_server_id = None

        if (is_valid_port(self.my_port) and (is_valid_port(self.auth_server_port) and is_valid_ip(self.my_ip)) and
                is_valid_ip(self.auth_server_ip)):
            self.my_port = int(self.my_port)
            self.auth_server_port = int(self.auth_server_port)
            self.start_server()
        else:
            raise RuntimeError("Server configuration is incorrect!")

    def start_server(self):
        if self.auth_server_key is None:
            self.register_with_auth_server()

        # Create a socket server
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.bind((self.my_ip, self.my_port))
        server_socket.listen()

        print(f'Messaged server {self.my_name} server started on port {self.my_port}!')
        while True:
            client_socket, client_address = server_socket.accept()
            client_handler = threading.Thread(target=self.handle_client_request, args=(client_socket, client_address))
            client_handler.start()

    def register_with_auth_server(self):
        """
        If not registered with the auth server already, the message server will generate a symmetric key and
        register with the auth server with its name, ip, port, and key
        The auth server will respond with the server_id it assigned, and it will be saved in the config file
        :return:
        """
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect((self.auth_server_ip, int(self.auth_server_port)))

        try:
            auth_server_key = generate_aes_key()
            payload = ServerRegistrationRequest(self.my_name, auth_server_key, self.my_port)
            request = ClientRequest(bytes(16), self.VERSION, SERVER_REGISTRATION_CODE, payload)
            client_socket.send(request.pack())
            print("Server registration request sent!")
            # Receive and print the response
            response_bytes = client_socket.recv(1024)

            response = ServerResponse.unpack(response_bytes, MessageServerRegistrationSuccessResponse)
            if response.code == SERVER_REGISTRATION_SUCCESS_CODE:
                print(f"Server registered - ID: {response.payload.server_id.hex()}")
                self.message_server_id = response.payload.server_id
                self.auth_server_key = auth_server_key
                write_lines_to_file(self.config_file, [self.auth_server_key.hex(), self.message_server_id.hex()])
            else:
                print(f"Error {response.code} - Server creation failed!")

        finally:
            # Close the socket
            print("Closing the connection from client side")
            client_socket.close()

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
            client_socket.send(response.pack())

        except Exception as e:
            print(f"error  {e}")
            traceback.print_exc()
            client_socket.send(ServerResponse(self.VERSION, GENERAL_SERVER_ERROR_CODE, None).pack())

        finally:
            print(f"Connection with {client_address} closed.")
            client_socket.close()

    def process_request(self, request, client_socket):
        request_code = self.get_request_code(request)
        if request_code == SEND_SESSION_KEY_TO_SERVER_REQUEST_CODE:
            return self.process_session_key_received(request)
        elif request_code == SEND_MESSAGE_REQUEST_CODE:
            return self.process_message_send_request(request)
        else:
            print("Unknown request!")
            return ServerResponse(self.VERSION, GENERAL_SERVER_ERROR_CODE, None)

    def get_request_code(self, request):
        pass

    @staticmethod
    def get_request_code(request):
        bytes_18_19 = request[17:19]
        return struct.unpack('<h', bytes_18_19)[0]

    def process_session_key_received(self, request):
        client_request = ClientRequest.unpack(request, payload_type=SendSessionKeyRequest)
        client_payload = cast(SendSessionKeyRequest, client_request.payload)
        print(f'Received ticket from {client_request.client_id.hex()}')
        authenticator = Authenticator.unpack(client_payload.authenticator)
        ticket = Ticket.unpack(client_payload.ticket)
        if ticket.server_id != self.message_server_id:
            raise ValueError("The ticket is not for this message server!")
        now_time = datetime.now()
        ticket_time = get_datetime_from_ts_bytes(ticket.creation_time)
        if ticket_time > now_time:
            raise ValueError("Ticket creation time is in the future!")

        ticket_expiration_timestamp = decrypt_aes_cbc(self.auth_server_key, ticket.encrypted_expiration_time, ticket.iv)
        ticket_expiration_time = get_datetime_from_ts_bytes(ticket_expiration_timestamp)

        session_key = decrypt_aes_cbc(self.auth_server_key, ticket.encrypted_session_key, ticket.iv)

        # validate authenticator
        authenticator_server_id = decrypt_aes_cbc(session_key, authenticator.encrypted_server_id, authenticator.iv)
        authenticator_client_id = decrypt_aes_cbc(session_key, authenticator.encrypted_client_id, authenticator.iv)
        authenticator_creation_time = get_datetime_from_ts_bytes(
            decrypt_aes_cbc(session_key, authenticator.encrypted_creation_time, authenticator.iv))

        if authenticator_creation_time < now_time - timedelta(minutes=10):
            raise ValueError("Authenticator is older than 10 minutes!")
        if authenticator_server_id != self.message_server_id or authenticator_client_id != client_request.client_id:
            raise ValueError("Server or client IDs do not match!")

        print("Authenticator decrypted with session key, and validated! Sending accept to client.")
        self.sessions[ticket.client_id.hex()] = MessageServer.Session(session_key, ticket.iv, ticket_expiration_time)
        response = ServerResponse(self.VERSION, SESSION_KEY_ACCEPTED_RESPONSE_CODE, None)
        return response

    def process_message_send_request(self, request):
        client_request = ClientRequest.unpack(request, payload_type=SendMessageRequest)
        client_payload = cast(SendMessageRequest, client_request.payload)
        session = self.sessions[client_request.client_id.hex()]
        if session is None:
            raise RuntimeError(f'Could not find client session with client id {client_request.client_id.hex()}')
        now = datetime.now()
        if session.expiration_time < now:
            raise RuntimeError(f'Session key expired! Please get a new ticket from the auth server!')

        decrypted_message = decrypt_aes_cbc(session.key, client_payload.encrypted_message, client_payload.message_iv)

        print(f"Message from P{client_request.client_id.hex()}:\n{decrypted_message.decode('utf-8')}")
        response = ServerResponse(self.VERSION, MESSAGE_ACCEPTED_RESPONSE_CODE, None)
        return response

    class Session:
            def __init__(self, key, iv, expiration_time):
                self.expiration_time = expiration_time
                self.iv = iv
                self.key = key

