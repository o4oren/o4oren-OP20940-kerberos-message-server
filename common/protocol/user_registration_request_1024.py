import struct


class UserRegistrationRequest:
    def __init__(self, name, password):
        """
        This class represents the body of a user registration request. 
        :param name:
        :param password:
        """
        self.name = name
        self.password = password

    def pack(self):
        format_string = '<255s255s'
        return struct.pack(format_string, self.name.encode('utf-8'), self.password.encode('utf-8'))

    @classmethod
    def unpack(cls, packed_data):
        unpacked_data = struct.unpack('<255s255s', packed_data)
        name, password = unpacked_data
        return cls(name.decode('utf-8').rstrip('\x00'), password.decode('utf-8').rstrip('\x00'))