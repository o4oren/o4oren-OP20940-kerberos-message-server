import socket

from common.protocol.client_request import ClientRequest
from common.protocol.user_registration_request_1024 import UserRegistrationRequest


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
            payload = UserRegistrationRequest("aUser3\0", "abcd12342\0")
            request = ClientRequest(bytearray(16), 24, 1024, payload)
            client_socket.send(request.pack())
            print("message sent!")
            # Receive and print the response
            response = client_socket.recv(1024).decode('utf-8')
            print("Server response:", response)

        finally:
            # Close the socket
            print("Closing the connection from client side")
            client_socket.close()


def main():
    client = Client()
    client.start_client()


if __name__ == "__main__":
    main()
