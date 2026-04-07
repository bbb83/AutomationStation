#!/usr/bin/env python3
from dotenv import load_dotenv
import os

load_dotenv()

import argparse
import json
import sys
import dns_lookup

from cidr import validate_cidr
from runner import run_nmap_xml
from parser import live_ips_from_discovery, parse_hosts
from schema import make_scan_doc


def main() -> int:
    default_subnet = os.getenv("SUBNET")

    ap = argparse.ArgumentParser(prog="scan.py")
    ap.add_argument(
        "cidr",
        nargs="?",
        default=default_subnet,
        help="CIDR to scan, e.g. 192.168.1.0/24"
    )
    ap.add_argument("-o", "--out", help="Write JSON output to file instead of stdout")
    ap.add_argument("--top-ports", type=int, default=1000, help="Use --top-ports N instead of -p- (default 100)")
    ap.add_argument("--full-ports", action="store_true", help="Use -p- (all ports). Heavy.")
    ap.add_argument("--os", action="store_true", help="Enable OS fingerprinting (-O). Often requires sudo.")
    ap.add_argument("--pn", action="store_true", help="Treat hosts as online (-Pn). Useful when ICMP is blocked.")
    args = ap.parse_args()

    if not args.cidr:
        print("No CIDR provided. Pass one on the command line or set SUBNET in .env", file=sys.stderr)
        return 2

    try:
        cidr = validate_cidr(args.cidr)
    except ValueError as e:
        print(str(e), file=sys.stderr)
        return 2

    discovery_args = ["-sn", cidr]
    if args.pn:
        discovery_args.insert(0, "-Pn")

    try:
        print("[*] Starting discovery scan...")
        xml1 = run_nmap_xml(discovery_args)
        live_ips = live_ips_from_discovery(xml1)

        print(f"[+] Found {len(live_ips)} live host(s)")
        print("[*] Running DNS lookups...")

        dns_map = {}

        for i, ip in enumerate(live_ips, start=1):
            print(f"    [{i}/{len(live_ips)}] Resolving {ip}")
            try:
                dns_map[ip] = dns_lookup.lookup_ip_dns(ip)
            except Exception as e:
                dns_map[ip] = {
                    "ip": ip,
                    "reverse_dns": {"success": False},
                    "forward_dns": {"success": False},
                    "error": str(e)
                }

    except Exception as e:
        print(f"Discovery scan failed: {e}", file=sys.stderr)
        return 1

    hosts = []
    deep_args = ["-sS", "-sV", "-O", "--version-light"]

    if args.os:
        deep_args += ["-O", "--osscan-guess"]

    if args.full_ports:
        deep_args += ["-p-"]
    else:
        deep_args += ["--top-ports", str(args.top_ports)]

    if args.pn:
        deep_args.insert(0, "-Pn")

    if live_ips:
        try:
            print("[*] Running deep Nmap scan (this may take a while)...")
            xml2 = run_nmap_xml([*deep_args, *live_ips])
            hosts = parse_hosts(xml2)

            print(f"[+] Parsed {len(hosts)} host record(s)")
            print("[*] Attaching DNS results to hosts...")

            for host in hosts:
                ip = host.get("ip")
                if ip in dns_map:
                    host["dns"] = dns_map[ip]
                else:
                    host["dns"] = {
                        "ip": ip,
                        "reverse_dns": {"success": False},
                        "forward_dns": {"success": False}
                    }

        except Exception as e:
            print(f"Deep scan failed: {e}", file=sys.stderr)
            return 1

    print("[*] Building final output...")

    doc = make_scan_doc(
        cidr=cidr,
        live_count=len(live_ips),
        discovery_args=discovery_args,
        deep_args=deep_args,
        hosts=hosts
    )

    out_text = json.dumps(doc, indent=2)

    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(out_text + "\n")
        print(f"[+] Output written to {args.out}")
    else:
        print(out_text)

    return 0

if __name__ == "__main__":
    raise SystemExit(main())