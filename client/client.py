import socket


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
            client_socket.send(message.encode('utf-8'))
            print("message sent!")
            # Receive and print the response
            response = client_socket.recv(1024).decode('utf-8')
            print("Server response:", response)

        finally:
            # Close the socket
            print("Closing the connenction from client side")
            client_socket.close()
