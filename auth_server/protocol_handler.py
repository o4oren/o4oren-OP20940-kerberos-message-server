import struct

from common.protocol.server_request import ServerRequest
from common.protocol.user_registration_request_1024 import UserRegistrationRequest


class ProtocolHandler:

    def process(self, request):
        request_code = self.get_code(request)
        if request_code == 1024:
            return self.process_user_registration(request)
        else:
            return "unknown request"

    def get_code(self, request):
        bytes_18_19 = request[17:19]
        return struct.unpack('<h', bytes_18_19)[0]

    @staticmethod
    def process_user_registration(request):
        server_request = ServerRequest.unpack(request, payload_type=UserRegistrationRequest)
        return server_request.payload
# TODO return response object
