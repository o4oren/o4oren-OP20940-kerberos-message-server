from auth_server import auth_server
from auth_server.auth_server import AuthServer
from common.file_utils import read_file_lines


def main():
    server = AuthServer("port.info")

if __name__ == "__main__":
    main()