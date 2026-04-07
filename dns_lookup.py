import socket

def reverse_lookup(ip):
    try:
        hostname, aliases, addresses = socket.gethostbyaddr(ip)
        return {
            "success": True,
            "hostname": hostname,
            "aliases": aliases,
            "addresses": addresses
        }
    except socket.herror:
        return {
            "success": False,
            "hostname": None,
            "aliases": [],
            "addresses": []
        }
    except Exception as e:
        return {
            "success": False,
            "hostname": None,
            "aliases": [],
            "addresses": [],
            "error": str(e)
        }

def forward_lookup(hostname):
    try:
        results = socket.getaddrinfo(hostname, None)
        ips = sorted({item[4][0] for item in results})
        return {
            "success": True,
            "hostname": hostname,
            "ips": ips
        }
    except socket.gaierror:
        return {
            "success": False,
            "hostname": hostname,
            "ips": []
        }
    except Exception as e:
        return {
            "success": False,
            "hostname": hostname,
            "ips": [],
            "error": str(e)
        }

def lookup_ip_dns(ip):
    reverse_result = reverse_lookup(ip)

    hostname = reverse_result.get("hostname")
    if hostname:
        forward_result = forward_lookup(hostname)
    else:
        forward_result = {
            "success": False,
            "hostname": None,
            "ips": []
        }

    return {
        "ip": ip,
        "reverse_dns": reverse_result,
        "forward_dns": forward_result
    }