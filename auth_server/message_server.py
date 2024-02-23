import uuid
from datetime import datetime

from common.date_utils import get_datetime_from_ts


class MessageServer:

    def __init__(self, message_server_id: bytes, name: str, key: bytes, ip_address: str, port: int):
        """
        This class represents a client in the AuthServer's memory.
        Do not confuse with the actual Client code.
        :param message_server_id: The ID assigned to this server
        :param name: the name the server registered with
        :param key: the symmetric key the server requested to use
        :param ip_address: server's ip address
        :param port:  communication port
        """

        if len(message_server_id) == 16:
            self.message_server_id = message_server_id
        else:
            raise ValueError("Illegal server id")

        if len(name) <= 255:
            self.name = name
        else:
            raise ValueError("Illegal server name")

        if len(key) == 32:
            self.key = key
        else:
            raise ValueError("Illegal server key")

        self.ip_address = ip_address
        self.port = port

    def get_id_string(self):
        return self.message_server_id.hex()

    @classmethod
    def from_line(cls, line: str):
        """
        This class represents a message server in the AuthServer's memory.
        Do not confuse with the actual MessageServer code.
        A MessageServer is initialized with a line string of the form: id:name:key:ip:port
        and is compatible with the auth server's clients file format
        :param line:
        """
        parts = line.split(":")
        if len(parts) != 5:
            raise ValueError("Illegal message server string was found!")

        return cls(bytes.fromhex(parts[0]), parts[1], bytes.fromhex(parts[2]), parts[3], int(parts[4]))
