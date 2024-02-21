import struct


class MessageServerRegistrationSuccessResponse:
    def __init__(self, server_id: bytes):
        """
        This class represents the body of a user registration success response.
        :param clinet_id: a 16 byte client id
        """
        self.server_id = server_id

    def pack(self):
        format_string = '<16s'
        return struct.pack(format_string, self.server_id)

    @classmethod
    def unpack(cls, packed_data):
        unpacked_data = struct.unpack('<16s', packed_data)
        server_id = unpacked_data[0]
        return cls(server_id)