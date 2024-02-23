import struct


class SessionKeyAndTicketRequest:
    def __init__(self, message_server_id: str, nonce: bytes):
        self.message_server_id = message_server_id
        self.nonce = nonce

    def pack(self):
        format_string = '<16s8s'
        return struct.pack(format_string, bytes.fromhex(self.message_server_id), self.nonce)

    @classmethod
    def unpack(cls, packed_data):
        unpacked_data = struct.unpack('<16s8s', packed_data)
        message_server_id, nonce = unpacked_data
        return cls(message_server_id.hex(), nonce)