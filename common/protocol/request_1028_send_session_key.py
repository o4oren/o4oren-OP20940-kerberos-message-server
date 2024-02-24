import struct


class SendSessionKeyRequest:
    def __init__(self, authenticator_bytes: bytes, ticket: bytes):
        self.authenticator = authenticator_bytes
        self.ticket = ticket

    def pack(self):
        format_string = '<112s121s'
        return struct.pack(format_string, self.authenticator, self.ticket)

    @classmethod
    def unpack(cls, packed_data):
        unpacked_data = struct.unpack('<112s121s', packed_data)
        authenticator_bytes, ticket = unpacked_data
        return cls(authenticator_bytes, ticket)