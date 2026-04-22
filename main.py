#!/usr/bin/env python3
from dotenv import load_dotenv
from mail import send_issue_report
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

from ieeething.oui_lookup import OUILookup

SUBNET       = os.getenv("SUBNET", "")
NETBOX_URL   = os.getenv("NETBOX_URL", "").rstrip("/")
NETBOX_TOKEN = os.getenv("NETBOX_TOKEN", "")

# map Bryce's test names → netbox_scoring.py keys
TEST_NAME_MAP = {
    "snmp_response":                        "snmp_response",
    "nmap_open_ports_detected":             "nmap_open_ports",
    "dhcp_active_lease":                    "dhcp_active_lease",
    "dns_resolves_A/PTR":                   "dns_resolves",
    "snmp_mac/interface_matches_netbox":    "snmp_mac_match",
    "dhcp_mac_matches_netbox":              "dhcp_mac_match",
    "dns_hostname_matches_netbox":          "dns_hostname_match",
    "nmap_fingerprint_is_consistent":       "nmap_fingerprint_match",
    "mac_mismatch_with_netbox":             "mac_mismatch_penalty",
    "snmp_sysObjectID_and_sysDescr_found":  "snmp_sysobjectid",
    "nmap_service_profile":                 "nmap_service_profile",
    "ieee_oui_manufacturer_found":          "ieee_oui_manufacturer",
    "dns_gives_name_hints":                 "dns_naming_convention",
}


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


def hosts_to_evidence(hosts, oui_lookup):
    #Convert parser.py host dicts into EvidenceRecord format for scoring
    evidence = []

    for h in hosts:
        ip = h.get("ip")
        mac = h.get("mac")
        nmap_vendor = h.get("vendor")

        open_ports = [p for p in h.get("ports", []) if p.get("state") == "open"]
        services = [p.get("service") for p in open_ports if p.get("service")]

        # Initialize manufacturer safely
        manufacturer = nmap_vendor if nmap_vendor else None
        oui_result = None

        # Use IEEE OUI lookup if Nmap vendor is missing
        if not manufacturer and mac:
            oui_result = oui_lookup.lookup(mac)
            if oui_result:
                manufacturer = oui_result["manufacturer_name"]
                print(f"[DEBUG] OUI resolved {mac} → {manufacturer}")

        # Create Nmap evidence
        evidence.append(EvidenceRecord(
            source="nmap",
            ip=ip,
            mac=mac,
            hostname=(h.get("hostnames") or [None])[0],
            manufacturer=manufacturer,
            attributes={
                "open_ports": open_ports,
                "service_profile": services if services else None,
                "os_name": (h.get("os") or {}).get("name"),
                "vendor": manufacturer,
            },
        ))

        # Add separate OUI evidence if manufacturer is known
        if manufacturer:
            attributes = {"manufacturer_name": manufacturer}

            if oui_result:
                attributes["oui_prefix"] = oui_result["oui_prefix"]

            evidence.append(EvidenceRecord(
                source="oui",
                ip=ip,
                mac=mac,
                manufacturer=manufacturer,
                attributes=attributes,
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

        # prefer the hostname already resolved in step 3.7 so push and scoring agree
        cached_hostname = h.get("dns_hostname")
        dns_data = lookup_ip_dns(ip)
        reverse_dns = dns_data.get("reverse_dns", {})
        forward_dns = dns_data.get("forward_dns", {})

        hostname = cached_hostname or reverse_dns.get("hostname")

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

    print("[3.7] Resolving DNS hostnames for naming...")
    for h in hosts:
        if h.get("ip"):
            dns_data = lookup_ip_dns(h["ip"])
            dns_hostname = dns_data.get("reverse_dns", {}).get("hostname")
            if dns_hostname:
                h["dns_hostname"] = dns_hostname
                print(f"    {h['ip']} → {dns_hostname}")

    # Load OUI lookup once, reuse for both enrichment and scoring
    base_dir = os.path.dirname(os.path.abspath(__file__))
    oui_path = os.path.join(base_dir, "ieeething", "oui_file.csv")
    oui_lookup = OUILookup(oui_path)

    print("[3.8] Enriching hosts with SNMP + OUI data for NetBox push...")
    snmp_by_ip = {row["ip"]: row for row in load_snmp_results()}
    for h in hosts:
        # SNMP sysDescr + hostname (used in device description)
        snmp_row = snmp_by_ip.get(h.get("ip"))
        if snmp_row:
            h["snmp_description"] = snmp_row.get("Description")
            h["snmp_hostname"] = snmp_row.get("Hostname")

        # OUI vendor fallback if nmap didn't give one (fixes Manufacturer=Unknown in NetBox)
        if not h.get("vendor") and h.get("mac"):
            oui_result = oui_lookup.lookup(h["mac"])
            if oui_result:
                h["vendor"] = oui_result["manufacturer_name"]
                print(f"    {h['ip']} vendor → {h['vendor']} (from OUI)")

    print("[6] Scoring devices...")
    nmap_evidence = hosts_to_evidence(hosts, oui_lookup)

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
            # prefer DNS hostname, then nmap, then synthesized — matches netbox_integration.py's device_name()
            dns_ev = [e for e in device.evidence if e.source == "dns" and e.hostname]
            nmap_ev = [e for e in device.evidence if e.source == "nmap"]
            dns_hostname = dns_ev[0].hostname if dns_ev else None
            nmap_hostname = nmap_ev[0].hostname if nmap_ev else None
            name = dns_hostname or nmap_hostname or f"host-{device.ip.replace('.', '-')}"

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
                        key = TEST_NAME_MAP.get(t.name.replace(" ", "_"), t.name.replace(" ", "_"))
                        score_data[cat][key] = t.passed
                apply_scoring(device_id, score_data)
            else:
                print(f"    Could not find device '{name}' in NetBox for scoring")

        send_issue_report(scored_results)