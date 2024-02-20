import socket

from auth_server.auth_server import CLIENT_REGISTRATION_SUCCESS_CODE
from common.protocol.client_request import ClientRequest
from common.protocol.request_1024_user_registration import UserRegistrationRequest
from common.protocol.response_1600_user_registration_success import UserRegistrationSuccessResponse
from common.protocol.server_response import ServerResponse


class Client:

    def start_client(self):
        print("client started!")
        self.send_message("Hello!")
        print("message sent!")

    def send_message(self, message):
        server_address = '127.0.0.1'
        server_port = 1234

        # Create a socket object
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect((server_address, server_port))

        try:
            payload = UserRegistrationRequest("aUser9\0", "abcd12342\0")
            request = ClientRequest(bytearray(16), 24, 1024, payload)
            client_socket.send(request.pack())
            print("message sent!")
            # Receive and print the response
            response_bytes = client_socket.recv(1024)

            response = ServerResponse.unpack(response_bytes, UserRegistrationSuccessResponse)
            if response.code == CLIENT_REGISTRATION_SUCCESS_CODE:
                print(f"User created - ID: {response.payload.client_id.hex()}")
            else:
                print(f"Error {response.code} - User creation failed!")

        finally:
            # Close the socket
            print("Closing the connection from client side")
            client_socket.close()

