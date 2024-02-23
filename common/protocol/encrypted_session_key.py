import struct


class EncryptedSessionKey:
    def __init__(self, iv: bytes, nonce: bytes, session_key: bytes):
        self.iv = iv
        self.nonce = nonce
        self.session_key = session_key

    def pack(self):
        format_string = '<16s16s48s'
        return struct.pack(format_string, self.iv, self.nonce, self.session_key)

    @classmethod
    def unpack(cls, packed_data):
        unpacked_data = struct.unpack('<16s16s48s', packed_data)
        iv, nonce, session_key = unpacked_data
        return cls(iv, nonce, session_key)