import struct


class ServerRegistrationRequest:
    def __init__(self, name, key, port):
        """
        This class represents the body of a user registration request. 
        :param name:
        :param password:
        """
        self.name = name
        self.message_server_key = key
        self.port = int(port)

    def pack(self):
        format_string = '<255s32sI'
        return struct.pack(format_string, self.name.encode('utf-8'), self.message_server_key, self.port)

    @classmethod
    def unpack(cls, packed_data):
        unpacked_data = struct.unpack('<255s32sI', packed_data)
        name, message_server_key, port = unpacked_data
        return cls(name.decode('utf-8').rstrip('\x00'), message_server_key, port)