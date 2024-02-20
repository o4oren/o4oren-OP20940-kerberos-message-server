import struct


class ServerResponse:
    def __init__(self, version, code, payload):
        """
        This class represents a server response. It encapsulates the header struct, and assumes the payload
        has a pack/unpack methods, that packs it into a struct to be sent as binary data.
        The class exposes an instance pack method that returns the packed binary bytes to be sent.
        The class exposes a class method to create the object from passed binary bytes
        :param version: the serber's version
        :param code: response code (the server knows how to parse it accordingly)
        :param payload: packed binary payload
        """
        self.version = version
        self.code = code

        # default value. Will be calculated from actual payload size when packing
        # It is not needed in my implementation, and only exists to support the protocol definition
        self.payload_size = 0
        self.payload = payload

    def pack(self):
        payload_data = self.payload.pack()
        format_string = '<BHI' + str(len(payload_data)) + 's'
        self.payload_size = len(payload_data)
        return struct.pack(format_string, self.version, self.code, self.payload_size,
                           payload_data)

    @classmethod
    def unpack(cls, packed_data, payload_type):
        """
        This method gets the packed data and payload type, and unpacks it into an object based on the passed
        payload type
        :param packed_data:
        :param payload_type:
        :return:
        """
        version, code, payload_size = struct.unpack('<BHI', packed_data[:7])
        payload_data = packed_data[7:7 + payload_size]
        payload = payload_type.unpack(payload_data)
        return cls(version, code, payload)
