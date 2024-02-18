import uuid
from datetime import datetime

from common.date_utils import get_datetime_from_ts


class Client:

    def __init__(self, client_id: bytes, name: str, password_hash: bytes, last_seen: datetime = None):
        """
        This class represents a client in the AuthServer's memory.
        Do not confuse with the actual Client code.
        :param client_id:
        :param name:
        :param password_hash:
        :param last_seen:
        """

        if len(client_id) == 16:
            self.id = client_id
        else:
            raise ValueError("Illegal client id")

        if len(name) <= 255:
            self.name = name
        else:
            raise ValueError("Illegal client name")

        if len(password_hash) == 32:
            self.password_hash = password_hash
        else:
            raise ValueError("Illegal client password hash")

        if last_seen is None:
            last_seen = datetime.now()
        self.last_seen = last_seen
        self.password_hash = password_hash
        self.name = name
        self.client_id = client_id

    def get_id_string(self):
        return self.client_id.hex()

    @classmethod
    def from_line(cls, line: str):
        """
        This class represents a client in the AuthServer's memory.
        Do not confuse with the actual Client code.
        A Client is initialized with a line string of the form: id:name:passwordHash:last_seen
        and is compatible with the auth server's clients file format
        :param line:
        """
        parts = line.split(":")
        if len(parts) != 4:
            raise ValueError("Illegal client string was found!")
        line_time = get_datetime_from_ts(parts[3])
        client_id = uuid.UUID(parts[0]).bytes

        return cls(client_id, parts[1], bytes.fromhex(parts[2]), line_time)
