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
        if self.payload is None:
            payload_data = bytes(0)
        elif isinstance(self.payload, bytes):
            payload_data = self.payload
        else:
            payload_data = self.payload.pack()

        self.payload_size = len(payload_data)

        format_string = '<BHI' + str(self.payload_size) + 's'
        return struct.pack(format_string, self.version, self.code, self.payload_size,
                           payload_data)

    @classmethod
    def unpack(cls, packed_data, payload_type):
        """
        This method gets the packed data and payload type, and unpacks it into an object based on the passed
        payload type
        :param packed_data: raw source bytes of the response
        :param payload_type: bytes - for raw data. Any other type that has an unpack method to create a data class
        :return:
        """
        version, code, payload_size = struct.unpack('<BHI', packed_data[:7])
        if payload_size > 0:
            payload_data = packed_data[7:7 + payload_size]
            if payload_type is bytes:  # treat payload as raw bytes
                payload = payload_data
            else:
                payload = payload_type.unpack(payload_data)
        else:
            payload = None
        return cls(version, code, payload)
