import socket

from common.cryptography_utils import generate_aes_key
from common.file_utils import read_file_lines, write_lines_to_file
from common.network_utils import is_valid_port, is_valid_ip
from common.protocol.client_request import ClientRequest
from common.protocol.message_codes import SERVER_REGISTRATION_CODE, SERVER_REGISTRATION_SUCCESS_CODE
from common.protocol.request_1025_server_registration import ServerRegistrationRequest
from common.protocol.response_1608_message_server_registration_success import MessageServerRegistrationSuccessResponse
from common.protocol.server_response import ServerResponse


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
        self.config_file = msg_server_config_file;
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
        if len(lines) == 5:
            self.auth_server_key = bytes.fromhex(lines[3])
            self.message_server_id = bytes.fromhex(lines[4])
        else:
            self.auth_server_key = None
            self.message_server_id = None

        if (is_valid_port(self.my_port) and (is_valid_port(self.auth_server_port) and is_valid_ip(self.my_ip)) and
                is_valid_ip(self.auth_server_ip)):
            self.start_server()
        else:
            raise RuntimeError("Server configuration is incorrect!")

    def start_server(self):
        if self.auth_server_key is not None:
            print("message server started!")
        else:
            self.register_with_auth_server()

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
            payload = ServerRegistrationRequest(self.my_name, auth_server_key)
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
                print(f"Error {response.code} - User creation failed!")

        finally:
            # Close the socket
            print("Closing the connection from client side")
            client_socket.close()
