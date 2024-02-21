import struct


class ServerRegistrationRequest:
    def __init__(self, name, key):
        """
        This class represents the body of a user registration request. 
        :param name:
        :param password:
        """
        self.name = name
        self.message_server_key = key

    def pack(self):
        format_string = '<255s32s'
        return struct.pack(format_string, self.name.encode('utf-8'), self.message_server_key)

    @classmethod
    def unpack(cls, packed_data):
        unpacked_data = struct.unpack('<255s32s', packed_data)
        name, message_server_key = unpacked_data
        return cls(name.decode('utf-8').rstrip('\x00'), message_server_key)