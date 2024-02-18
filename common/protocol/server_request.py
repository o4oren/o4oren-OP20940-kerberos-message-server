import struct

class ServerRequest:
    def __init__(self, client_id, version, code, payload):
        """
        This class represents a server request. It encapsulates the header struct, and assumes the payload
        has a pack/unpack methods, that packs it into a struct to be sent as binary data.
        The class exposes an instance pack method that returns the packed binary bytes to be sent.
        The class exposes a class method to create the object from passed binary bytes
        :param client_id: the client's id
        :param version: the client's version
        :param code: request code (the server knows how to parse it accordingly)
        :param payload: packed binary payload
        """
        self.client_id = client_id
        self.version = version
        self.code = code

        # default value. Will be calculated from actual payload size when packing
        # It is not needed in my implementation, and only exists to support the protocol definition
        self.payload_size = 0
        self.payload = payload

    def pack(self):
        payload_data = self.payload.pack()
        format_string = '<16sBHI' + str(len(payload_data)) + 's'
        self.payload_size = len(payload_data)
        return struct.pack(format_string, self.client_id, self.version, self.code, self.payload_size,
                           payload_data)

    @classmethod
    def unpack(cls, packed_data, payload_type):
        """
        This method gets the packed data and payload type, and unpacks it into an object
        :param packed_data:
        :param payload_type:
        :return:
        """
        client_id, version, code, payload_size = struct.unpack('<16sBHI', packed_data[:23])
        payload_data = packed_data[23:23 + payload_size]
        payload = payload_type.unpack(payload_data)  # TODO make this dynamic
        return cls(client_id, version, code, payload)
