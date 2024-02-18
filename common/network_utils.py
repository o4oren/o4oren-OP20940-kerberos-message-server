import ipaddress


def is_valid_port(port_str: str) -> bool:
    try:
        port = int(port_str)
        return 0 <= port <= 65535
    except ValueError:
        return False


def is_valid_ip(ip_str: str) -> bool:
    try:
        ipaddress.ip_address(ip_str)
        return True
    except ValueError:
        return False
