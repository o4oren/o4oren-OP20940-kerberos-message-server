import struct


class UserRegistrationSuccessResponse:
    def __init__(self, client_id: bytes):
        """
        This class represents the body of a user registration success response.
        :param clinet_id: a 16 byte client id
        """
        self.client_id = client_id

    def pack(self):
        format_string = '<16s'
        return struct.pack(format_string, self.client_id)

    @classmethod
    def unpack(cls, packed_data):
        unpacked_data = struct.unpack('<16s', packed_data)
        client_id = unpacked_data[0]
        return cls(client_id)