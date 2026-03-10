#!/usr/bin/env python3
from dotenv import load_dotenv
import os

load_dotenv()

import argparse
import json
import sys

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
    ap.add_argument("--top-ports", type=int, default=1000, help="Use --top-ports N instead of -p- (default 100)") # change to smaller number for testing on Thursday
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
        xml1 = run_nmap_xml(discovery_args)
        live_ips = live_ips_from_discovery(xml1)
    except Exception as e:
        print(f"Discovery scan failed: {e}", file=sys.stderr)
        return 1

    hosts = []
    # deep_args = ["-sS"]
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
            xml2 = run_nmap_xml([*deep_args, *live_ips])
            hosts = parse_hosts(xml2)
        except Exception as e:
            print(f"Deep scan failed: {e}", file=sys.stderr)
            return 1

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
    else:
        print(out_text)

    return 0

if __name__ == "__main__":
    raise SystemExit(main())