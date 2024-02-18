from common.file_utils import read_file_lines
from common.network_utils import is_valid_port, is_valid_ip


class MessageServer:

    def __init__(self, msg_server_config_file):
        """
        Initializes the message server. Requires the below parameters to be able to communicate with the auth server
        The server class expects a text file with at least 3 lines:
        1st line - message_server_ip:message_server_port
        2nd line - message server's name
        3rd line - auth_server_ip:auth_server_port
        :param msg_server_config_file: path to config file
        """

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

        if (is_valid_port(self.my_port) and (is_valid_port(self.auth_server_port) and is_valid_ip(self.my_ip)) and
                is_valid_ip(self.auth_server_ip)):
            self.start_server()
        else:
            raise ValueError("Server configuration is incorrect!")

    def start_server(self):
            print("message server started!")

