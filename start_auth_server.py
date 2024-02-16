from auth_server.auth_server import AuthServer
from common.file_utils import read_file_lines

lines = read_file_lines("port.info")
server = AuthServer(lines[0])
server.start_server()
