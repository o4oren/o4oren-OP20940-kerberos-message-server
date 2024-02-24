import struct
from datetime import datetime

from common.date_utils import get_datetime_from_ts_bytes, datetime_to_timestamp_bytes


class Ticket:
    def __init__(self, version: bytes, client_id: bytes, server_id: bytes, creation_time: bytes, iv: bytes, encrypted_session_key: bytes, encrypted_expiration_time: bytes):
        self.version = version
        self.client_id = client_id
        self.server_id = server_id
        self.creation_time = creation_time
        self.iv = iv
        self.encrypted_session_key = encrypted_session_key
        self.encrypted_expiration_time = encrypted_expiration_time

    def pack(self):
        format_string = '<B16s16s8s16s48s16s'
        return struct.pack(format_string, self.version, self.client_id, self.server_id, self.creation_time, self.iv, self.encrypted_session_key, self.encrypted_expiration_time)

    @classmethod
    def unpack(cls, packed_data):
        unpacked_data = struct.unpack('<B16s16s8s16s48s16s', packed_data)
        version, client_id, server_id, creation_time, iv, encrypted_session_key, expiration_time = unpacked_data
        return cls(version, client_id, server_id, creation_time, iv, encrypted_session_key, expiration_time)