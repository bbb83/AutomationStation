import ipaddress

def validate_cidr(cidr: str) -> str:
    try:
        net = ipaddress.ip_network(cidr, strict = False)
    except ValueError as e:
        raise ValueError(f"Invalid CIDR: {cidr}") from e
    if net.version != 4:
        raise ValueError("Only IPv4 is supported right now")
    return str(net)
       