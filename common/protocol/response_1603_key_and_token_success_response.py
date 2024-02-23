import struct


class KeyAndTokenResponse:
    def __init__(self, client_id: bytes, session_key: bytes, ticket: bytes):
        """
        This class contains the sesstion key and ticket fields. both are typed objects.
        :param client_id:
        :param session_key: EncryptedSessionKey object
        :param ticket: Ticket object
        """
        self.client_id = client_id
        self.session_key = session_key
        self.ticket = ticket

    def pack(self):
        format_string = f'<16s80s121s'
        return struct.pack(format_string, self.client_id, self.session_key, self.ticket)

    @classmethod
    def unpack(cls, packed_data):
        unpacked_data = struct.unpack('<16s80s121s', packed_data)
        client_id, session_key, ticket = unpacked_data
        return cls(client_id, session_key, ticket)

