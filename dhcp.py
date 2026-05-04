import requests
from datetime import datetime
import time
import ipaddress
import os
from dotenv import load_dotenv
from db import init_dhcp_db, save_dhcp_results

MAX_RETRIES = 3
RETRY_DELAY = 2

# loads environment variables.
load_dotenv()
url        = os.getenv("KEA_API_URL")
username   = os.getenv("KEA_API_USERNAME")
password   = os.getenv("KEA_API_PASSWORD")
command    = os.getenv("KEA_COMMAND")
service    = os.getenv("KEA_SERVICE")
subnet     = os.getenv("SUBNET")
pool_start = os.getenv("DHCP_POOL_START")
pool_end   = os.getenv("DHCP_POOL_END")

# fetches leases from local Kea server API.
def fetch_kea_leases(url, username, password, command, service):
    print("[dhcp] Beginning to request from Kea API.")
    # Initializes payload to send
    payload = {
        "command": command,
        "service": [service]
    }

    # Tries to contact the server with credentials and return type
    for attempt in range(1, MAX_RETRIES + 1):
        print(f"[dhcp] Contacting Kea API (attempt {attempt}/{MAX_RETRIES})")
        try:
            response = requests.post(
                url,
                json=payload,
                auth=(username, password),
                headers={"Content-Type": "application/json"},
                timeout=15
            )
            print("[dhcp] Waiting for response")
            response.raise_for_status()
            break
    # fails to reach Kea
        except requests.exceptions.ConnectionError:
            print("[dhcp] Could not reach Kea API - check KEA_API_URL in .env")
            if attempt < MAX_RETRIES:
                time.sleep(RETRY_DELAY * attempt)
            else:
                return []
        # fails at http level
        except requests.exceptions.HTTPError as e:
            print(f"[dhcp] API returned an error: {e.response.status_code}")
            return []
        # request times out / other failure
        except requests.exceptions.Timeout:
            print("[dhcp] Request to Kea API timed out")
            if attempt < MAX_RETRIES:
                time.sleep(RETRY_DELAY * attempt)
            else:
                return []

    # collects response
    data = response.json()
    if not data: # validates data
        print("[dhcp] Empty response from Kea API")
        return []
    print("[dhcp] Response returned from Kea API")
    return data[0].get("arguments", {}).get("leases", [])


def dhcp_scan():
    # Initializes database for results
    print("[dhcp] Beginning dhcp scan.")
    init_dhcp_db()

    print("[dhcp] Fetching results from Kea")
    leases = fetch_kea_leases(url, username, password, command, service)

    print(f"[dhcp] preparing to look through IPs {pool_start} to {pool_end}")

    # Integer conversion of start and end for range()
    pool_start_int = int(ipaddress.IPv4Address(pool_start))
    pool_end_int   = int(ipaddress.IPv4Address(pool_end))
    # Converts to string
    pool_ips = {
        str(ipaddress.IPv4Address(i))
        for i in range(pool_start_int, pool_end_int + 1)
    }

    results = []
    print("[dhcp] Searching through leases:")
    for lease in leases:
        ip = lease.get("ip-address", "")
        # skips leases outside of range
        if ip not in pool_ips:
            continue
        # converts Kea expiry from unix to readable timestamp
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
        print(f"[dhcp] [+] Found: {device}")

    print(f"\n[*] {len(results)} lease(s) found in pool range "
            f"{pool_start}–"
            f"{pool_end}")
    save_dhcp_results(results) # save to database.
    return results


if __name__ == "__main__":
    dhcp_scan()
