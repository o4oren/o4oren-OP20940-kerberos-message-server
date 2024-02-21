import socket

from auth_server.auth_server import CLIENT_REGISTRATION_SUCCESS_CODE
from common.cryptography_utils import sha256_hash
from common.file_utils import is_file_exists, read_file_lines, write_line_to_file, write_lines_to_file
from common.protocol.client_request import ClientRequest
from common.protocol.request_1024_user_registration import UserRegistrationRequest
from common.protocol.response_1600_user_registration_success import UserRegistrationSuccessResponse
from common.protocol.server_response import ServerResponse


class Client:
    
    CONFIG_FILE = "me.info"

    def __init__(self):
        self.client_id = None
        self.passwordHash = None
        self.name = None
        if is_file_exists(self.CONFIG_FILE):
            self.initialize_with_me_info_file()
        else:
            self.initialize_without_config()

    def initialize_without_config(self):
        name = input("Please enter your name (or 'exit' to quit): ")
        if name == 'exit':
            print('Exiting the client.')
            exit(0)
        self.name = name;
        password = input("Please enter a password (or 'exit' to quit): ")
        if password == 'exit':
            print('Exiting the client.')
            exit(0)
        self.passwordHash = sha256_hash(password.encode('utf-8'))
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
        self.passwordHash = sha256_hash(password.encode('utf-8'))
    
    def start_client(self):
        while True:
            message = input("Enter a message (or 'exit' to quit): ")

            if message.lower() == 'exit':
                print('Exiting the client.')
                break

            # Process the user input (add your logic here)
            # TODO    process_command(message)



    def register_client(self, name, password):
            server_address = '127.0.0.1'
            server_port = 1234

            # Create a socket object
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client_socket.connect((server_address, server_port))

            try:
                payload = UserRegistrationRequest(name, password)
                request = ClientRequest(bytearray(16), 24, 1024, payload)
                client_socket.send(request.pack())
                print("message sent!")
                # Receive and print the response
                response_bytes = client_socket.recv(1024)

                response = ServerResponse.unpack(response_bytes, UserRegistrationSuccessResponse)
                if response.code == CLIENT_REGISTRATION_SUCCESS_CODE:
                    print(f"User created - ID: {response.payload.client_id.hex()}")
                    self.client_id = response.payload.client_id
                    write_lines_to_file(self.CONFIG_FILE, [self.name, self.client_id.hex()])
                else:
                    print(f"Error {response.code} - User creation failed!")

            finally:
                # Close the socket
                print("Closing the connection from client side")
                client_socket.close()



