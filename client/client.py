import socket

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
            payload = UserRegistrationRequest("aUser15\0", "abcd12342\0")
            request = ClientRequest(bytearray(16), 24, 1024, payload)
            client_socket.send(request.pack())
            print("message sent!")
            # Receive and print the response
            response_bytes = client_socket.recv(1024)
            # TODO check response code
            response = ServerResponse.unpack(response_bytes, UserRegistrationSuccessResponse)
            print(f"User created - ID: {response.payload.client_id.hex()}")

        finally:
            # Close the socket
            print("Closing the connection from client side")
            client_socket.close()

