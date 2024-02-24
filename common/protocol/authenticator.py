import struct
from datetime import datetime

from common.date_utils import get_datetime_from_ts_bytes, datetime_to_timestamp_bytes


class Authenticator:
    def __init__(self, iv: bytes, encrypted_version: bytes, encrypted_client_id: bytes, encrypted_server_id: bytes, encrypted_creation_time: bytes):
        self.iv = iv
        self.encrypted_version = encrypted_version
        self.encrypted_client_id = encrypted_client_id
        self.encrypted_server_id = encrypted_server_id
        self.encrypted_creation_time = encrypted_creation_time

    def pack(self):
        format_string = '<16s16s32s32s16s'
        return struct.pack(format_string, self.iv, self.encrypted_version, self.encrypted_client_id, self.encrypted_server_id, self.encrypted_creation_time)

    @classmethod
    def unpack(cls, packed_data):
        unpacked_data = struct.unpack('<<16s2s32s32s16s', packed_data)
        iv, encrypted_version, encrypted_client_id, encrypted_server_id, encrypted_creation_time = unpacked_data
        return cls(iv, encrypted_version, encrypted_client_id, encrypted_server_id, encrypted_creation_time)