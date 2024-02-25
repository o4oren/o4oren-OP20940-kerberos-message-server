import struct


class SendMessageRequest:
    def __init__(self, message_iv: bytes, encrypted_message: bytes):
        self.message_iv = message_iv
        self.encrypted_message = encrypted_message
        self.message_size = len(encrypted_message)

    def pack(self):
        format_string = f'<I16s{self.message_size}s'
        return struct.pack(format_string, self.message_size, self.message_iv, self.encrypted_message)

    @classmethod
    def unpack(cls, packed_data):
        message_size, message_iv = struct.unpack('<I16s', packed_data[:20])
        payload_data = packed_data[20:20 + message_size]
        return cls(message_iv, payload_data)