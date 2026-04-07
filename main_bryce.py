#!/usr/bin/env python3
from dotenv import load_dotenv
load_dotenv()

import os, sys, json, asyncio, urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from cidr import validate_cidr
from runner import run_nmap_xml
from parser import live_ips_from_discovery, parse_hosts
from db import init_db, save_discovered_hosts
from snmpnetbox import run as run_snmp
from netbox_integration import push_hosts_to_netbox
from netbox_scoring import ensure_scoring_fields, apply_scoring

SUBNET       = os.getenv("SUBNET", "")
NETBOX_URL   = os.getenv("NETBOX_URL", "").rstrip("/")
NETBOX_TOKEN = os.getenv("NETBOX_TOKEN", "")


def run_scan(cidr):
    print(f"[1] Ping sweep on {cidr}...")
    xml1 = run_nmap_xml(["-sn", cidr])
    live_ips = live_ips_from_discovery(xml1)
    print(f"    {len(live_ips)} host(s) alive")

    if not live_ips:
        return []

    print(f"[2] Deep scan on {len(live_ips)} host(s)...")
    xml2 = run_nmap_xml(["-sS", "-sV", "--version-light", "--top-ports", "100", *live_ips])
    hosts = parse_hosts(xml2)
    print(f"    Done — {len(hosts)} host(s) parsed")
    return hosts


def check_netbox():
    import requests
    print("[4] Checking NetBox...")
    try:
        r = requests.get(f"{NETBOX_URL}/api/status/",
                         headers={"Authorization": f"Token {NETBOX_TOKEN}"},
                         timeout=10, verify=False)
        if r.status_code == 200:
            v = r.json().get("netbox-version", "?")
            print(f"    NetBox {v} — OK")
            return True
        else:
            print(f"    NetBox returned {r.status_code}")
            return False
    except Exception as e:
        print(f"    Could not reach NetBox: {e}")
        return False


if __name__ == "__main__":
    if not SUBNET:
        print("SUBNET not set in .env"); sys.exit(1)

    init_db()
    hosts = run_scan(validate_cidr(SUBNET))
    print(json.dumps(hosts, indent=2))
    save_discovered_hosts(hosts)

    print("[3] Running SNMP scan...")
    asyncio.run(run_snmp())

    if check_netbox():
        ensure_scoring_fields()

        print("[5] Pushing devices to NetBox...")
        stats = push_hosts_to_netbox(hosts)
        print(f"    Results: {stats['pushed']} pushed, "
              f"{stats['skipped']} skipped, {stats['failed']} failed")

        # ── temporary: fake scores to test tags + custom fields ──
        import requests
        print("[6] Applying test scores...")
        for h in hosts:
            name = (h.get("hostnames") or [None])[0] or f"host-{h['ip'].replace('.', '-')}"
            r = requests.get(f"{NETBOX_URL}/api/dcim/devices/",
                             params={"name": name},
                             headers={"Authorization": f"Token {NETBOX_TOKEN}",
                                      "Content-Type": "application/json"},
                             timeout=10, verify=False)
            if r.status_code == 200 and r.json().get("results"):
                device_id = r.json()["results"][0]["id"]
                fake_score = {
                    "existence": {
                        "snmp_response": True,
                        "nmap_open_ports": len([p for p in h.get("ports", []) if p.get("state") == "open"]) > 0,
                        "dhcp_active_lease": False,
                        "dns_resolves": len(h.get("hostnames", [])) > 0,
                        "score": 75,
                    },
                    "identity": {
                        "snmp_mac_match": False,
                        "dhcp_mac_match": False,
                        "dns_hostname_match": False,
                        "nmap_fingerprint_match": False,
                        "mac_mismatch_penalty": False,
                        "score": 0,
                    },
                    "classification": {
                        "snmp_sysobjectid": False,
                        "nmap_service_profile": True,
                        "ieee_oui_manufacturer": h.get("vendor") is not None,
                        "dns_naming_convention": False,
                        "score": 40,
                    },
                    "total": 55,
                }
                apply_scoring(device_id, fake_score)