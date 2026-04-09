import requests
from datetime import datetime
import ipaddress
import os
from dotenv import load_dotenv
from db import init_dhcp_db, save_dhcp_results 

load_dotenv()

def dhcp_scan():
    init_dhcp_db()
    url        = os.getenv("KEA_API_URL")
    username   = os.getenv("KEA_API_USERNAME")
    password   = os.getenv("KEA_API_PASSWORD")
    command    = os.getenv("KEA_COMMAND")
    service    = os.getenv("KEA_SERVICE")
    subnet     = os.getenv("SUBNET")
    pool_start = os.getenv("DHCP_POOL_START")
    pool_end   = os.getenv("DHCP_POOL_END")

    if not all([url, username, password, command, service, subnet, pool_start, pool_end]):
        raise ValueError("missing environment variables missing from .env")

    payload = {
        "command": command,
        "service": [service]
    }

    response = requests.post(
        url,
        json=payload,
        auth=(username, password),
        headers={"Content-Type": "application/json"}
    )
    response.raise_for_status()

    data = response.json()
    leases = data[0].get("arguments", {}).get("leases", [])

    network = ipaddress.IPv4Network(subnet, strict=False)

    pool_start_int = int(ipaddress.IPv4Address(pool_start))
    pool_end_int   = int(ipaddress.IPv4Address(pool_end))
    pool_ips = {
        str(ipaddress.IPv4Address(i))
        for i in range(pool_start_int, pool_end_int + 1)
    }

    results = []
    for lease in leases:
        ip = lease.get("ip-address", "")

        if ip not in pool_ips:
            continue

        expiry_ts = lease.get("expire", 0)
        expiry_str = (
            datetime.fromtimestamp(expiry_ts).strftime("%Y-%m-%d %H:%M:%S")
            if expiry_ts else "N/A"
        )

        device = {
            "ip":       ip,
            "mac":      lease.get("hw-address", "N/A"),
            "hostname": lease.get("hostname", "N/A"),
            "expiry":   expiry_str,
        }

        results.append(device)
        print(f"[+] Found: {device}")

    print(f"\n[*] {len(results)} lease(s) found in pool range "
            f"{pool_start}–"
            f"{pool_end}")
    save_dhcp_results(results)
    return results


if __name__ == "__main__":
    dhcp_scan()
