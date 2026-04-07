#!/usr/bin/env python3
from dotenv import load_dotenv
load_dotenv()

import os, sys, json, asyncio, urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from cidr import validate_cidr
from runner import run_nmap_xml
from parser import live_ips_from_discovery, parse_hosts
from db import init_snmp_db, save_discovered_hosts
from snmpnetbox import run as run_snmp
from netbox_integration import push_hosts_to_netbox
from netbox_scoring import ensure_scoring_fields, apply_scoring

from models.evidence import EvidenceRecord
from models.correlate import correlate_evidence
from scoring.system import ScoringSystem

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


def hosts_to_evidence(hosts):
    """Convert parser.py host dicts into EvidenceRecord format for scoring."""
    evidence = []
    for h in hosts:
        open_ports = [p for p in h.get("ports", []) if p.get("state") == "open"]
        services = [p.get("service") for p in open_ports if p.get("service")]

        evidence.append(EvidenceRecord(
            source="nmap",
            ip=h.get("ip"),
            mac=h.get("mac"),
            hostname=(h.get("hostnames") or [None])[0],
            manufacturer=h.get("vendor"),
            attributes={
                "open_ports": open_ports,
                "service_profile": services if services else None,
                "os_name": (h.get("os") or {}).get("name"),
            },
        ))

        if h.get("vendor"):
            evidence.append(EvidenceRecord(
                source="oui",
                ip=h.get("ip"),
                mac=h.get("mac"),
                manufacturer=h.get("vendor"),
                attributes={"manufacturer_name": h.get("vendor")},
            ))

    return evidence


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

    init_snmp_db()
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

        print("[6] Scoring devices...")
        import requests
        evidence = hosts_to_evidence(hosts)
        devices = correlate_evidence(evidence)
        engine = ScoringSystem()

        for device in devices:
            result = engine.score(device)
            name = device.get_hostname() or f"host-{device.ip.replace('.', '-')}"
            r = requests.get(f"{NETBOX_URL}/api/dcim/devices/",
                             params={"name": name},
                             headers={"Authorization": f"Token {NETBOX_TOKEN}",
                                      "Content-Type": "application/json"},
                             timeout=10, verify=False)
            if r.status_code == 200 and r.json().get("results"):
                device_id = r.json()["results"][0]["id"]
                score_data = {
                    "existence": {"score": result.existence_score},
                    "identity": {"score": result.identity_score},
                    "classification": {"score": result.classification_score},
                    "total": result.overall_score,
                }
                for cat in ["existence", "identity", "classification"]:
                    cat_tests = [t for t in result.tests if t.category == cat]
                    for t in cat_tests:
                        score_data[cat][t.name.replace(" ", "_")] = t.passed
                apply_scoring(device_id, score_data)
            else:
                print(f"    Could not find device '{name}' in NetBox for scoring")