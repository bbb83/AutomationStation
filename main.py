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

from db import load_snmp_results, load_dhcp_results
from dhcp import dhcp_scan
from dns_lookup import lookup_ip_dns

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

def snmp_to_evidence(snmp_rows): #for snmp results to go from database to EvidenceRecord
    evidence = []

    for row in snmp_rows:
        evidence.append(EvidenceRecord(
            source="snmp",
            ip=row.get("ip"),
            hostname=row.get("Hostname"),
            attributes={
                "snmp_reachable": True,
                "sysName": row.get("Hostname"),
                "sysDescr": row.get("Description"),
                "sysUpTime": row.get("Uptime"),
                "ifNumber": row.get("Interfaces"),
            }
        ))

    return evidence

def dhcp_to_evidence(dhcp_rows):
    evidence = []

    for row in dhcp_rows:
        evidence.append(EvidenceRecord(
            source="dhcp",
            ip=row.get("ip"),
            mac=row.get("mac"),
            hostname=row.get("hostname"),
            attributes={
                "lease_active": True,
                "expiry": row.get("expiry"),
                "dhcp_hostname": row.get("hostname"),
            }
        ))

    return evidence

def dns_to_evidence(hosts):
    evidence = []

    for h in hosts:
        ip = h.get("ip")
        if not ip:
            continue

        dns_data = lookup_ip_dns(ip)
        reverse_dns = dns_data.get("reverse_dns", {})
        forward_dns = dns_data.get("forward_dns", {})

        hostname = reverse_dns.get("hostname")

        naming_hint = False
        if hostname:
            lower_name = hostname.lower()
            if any(word in lower_name for word in ["srv", "server", "printer", "switch", "router", "fw", "dns", "dhcp"]):
                naming_hint = True

        evidence.append(EvidenceRecord(
            source="dns",
            ip=ip,
            hostname=hostname,
            attributes={
                "forward_resolves": forward_dns.get("success", False),
                "reverse_resolves": reverse_dns.get("success", False),
                "forward_dns": forward_dns,
                "reverse_dns": reverse_dns,
                "naming_hint": naming_hint,
            }
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
        print("SUBNET not set in .env")
        sys.exit(1)

    init_snmp_db()
    hosts = run_scan(validate_cidr(SUBNET))
    print(json.dumps(hosts, indent=2))
    save_discovered_hosts(hosts)

    print("[3] Running SNMP scan...")
    asyncio.run(run_snmp())

    print("[3.5] Running DHCP scan...")
    dhcp_scan()

    print("[6] Scoring devices...")
    nmap_evidence = hosts_to_evidence(hosts)

    snmp_rows = load_snmp_results()
    print("[DEBUG] SNMP rows loaded:", len(snmp_rows))
    snmp_evidence = snmp_to_evidence(snmp_rows)

    dhcp_rows = load_dhcp_results()
    print("[DEBUG] DHCP rows loaded:", len(dhcp_rows))
    dhcp_evidence = dhcp_to_evidence(dhcp_rows)

    dns_evidence = dns_to_evidence(hosts)
    print("[DEBUG] DNS evidence count:", len(dns_evidence))

    evidence = []
    evidence.extend(nmap_evidence)
    evidence.extend(snmp_evidence)
    evidence.extend(dhcp_evidence)
    evidence.extend(dns_evidence)

    print("[DEBUG] Nmap evidence:", len(nmap_evidence))
    print("[DEBUG] SNMP evidence:", len(snmp_evidence))
    print("[DEBUG] DHCP evidence:", len(dhcp_evidence))
    print("[DEBUG] DNS evidence:", len(dns_evidence))
    print("[DEBUG] TOTAL evidence:", len(evidence))

    devices = correlate_evidence(evidence)

    print("[DEBUG] Total devices after correlation:", len(devices))
    for d in devices[:5]:
        print("[DEBUG] DEVICE IP:", d.ip)
        print("[DEBUG] SOURCES:", [e.source for e in d.evidence])

    engine = ScoringSystem()

    scored_results = []
    for device in devices:
        result = engine.score(device)
        print(f"\n[DEBUG] Device {device.ip}")
        print("[DEBUG] Sources:", [e.source for e in device.evidence])
        print("[DEBUG] Scores:", {
            "existence": result.existence_score,
            "identity": result.identity_score,
            "classification": result.classification_score,
            "total": result.overall_score,
        })
        scored_results.append((device, result))

    if check_netbox():
        ensure_scoring_fields()

        print("[5] Pushing devices to NetBox...")
        stats = push_hosts_to_netbox(hosts)
        print(f"    Results: {stats['pushed']} pushed, "
              f"{stats['skipped']} skipped, {stats['failed']} failed")

        import requests
        for device, result in scored_results:
            name = device.get_hostname() or f"host-{device.ip.replace('.', '-')}"
            r = requests.get(
                f"{NETBOX_URL}/api/dcim/devices/",
                params={"name": name},
                headers={
                    "Authorization": f"Token {NETBOX_TOKEN}",
                    "Content-Type": "application/json",
                },
                timeout=10,
                verify=False,
            )
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