#nmap collector to get nmap scan into scoring system with EvidenceRecord

from __future__ import annotations
import json
from pathlib import Path
from typing import Any
from models.evidence import EvidenceRecord

from cidr import validate_cidr
from runner import run_nmap_xml
from parser import live_ips_from_discovery, parse_hosts

class NmapCollector:
    name = "nmap"

    def collect_from_scan(self, cidr: str, top_ports: int = 1000, treat_hosts_online: bool = False) -> list[EvidenceRecord]:
        #convert results from nmap scan into EvidenceRecord object
        cidr = validate_cidr(cidr)

        discovery_args = ["-sn", cidr]
        if treat_hosts_online:
            discovery_args.insert(0, "-Pn")

        xml1 = run_nmap_xml(discovery_args)
        live_ips = live_ips_from_discovery(xml1)

        if not live_ips:
            return []

        deep_args = ["-sS", "-sV", "-O", "--version-light", "--top-ports", str(top_ports)]
        if treat_hosts_online:
            deep_args.insert(0, "-Pn")

        xml2 = run_nmap_xml([*deep_args, *live_ips])
        hosts = parse_hosts(xml2)

        return self._hosts_to_evidence(hosts)

    def collect_from_file(self, filepath: str | Path) -> list[EvidenceRecord]:
        #reads results.json and makes it into EvidenceRecord
        path = Path(filepath)
        with path.open("r", encoding="utf-8") as f:
            doc = json.load(f)

        hosts = doc.get("hosts", [])
        return self._hosts_to_evidence(hosts)
    
    def _hosts_to_evidence(self, hosts: list[dict[str, Any]]) -> list[EvidenceRecord]: #_ in front means private helper method
        evidence_records: list[EvidenceRecord] = []

        for host in hosts:
            ip = host.get("ip")
            status = host.get("status")
            hostnames = host.get("hostnames", [])
            mac = host.get("mac")
            vendor = host.get("vendor")
            os_info = host.get("os")
            ports = host.get("ports", [])

            open_ports = [
                p["port"]
                for p in ports
                if p.get("state") == "open" and isinstance(p.get("port"), int)
            ]

            open_services = [
                {
                    "port": p.get("port"),
                    "proto": p.get("proto"),
                    "service": p.get("service"),
                    "product": p.get("product"),
                    "version": p.get("version"),
                }
                for p in ports
                if p.get("state") == "open"
            ]

            service_profile = self.build_service_profile(open_services)
            fingerprint_consistent = self.guess_fingerprint_consistency(open_services, os_info)

            ev = EvidenceRecord(
                source = "nmap",
                ip = ip,
                mac = mac,
                hostname = hostnames[0] if hostnames else None,
                manufacturer = vendor, 
                attributes ={
                    "host_up": status == "up",
                    "status": status,
                    "all_hostnames": hostnames,
                    "vendor": vendor,
                    "os": os_info,
                    "open_ports": open_ports,
                    "ports": ports,
                    "open_services": open_services,
                    "service_profile": service_profile,
                    "fingerprint_consistent": fingerprint_consistent,
                },
            )
            evidence_records.append(ev)

        return evidence_records

    def build_service_profile(self, open_services: list[dict[str, Any]]) -> dict[str, Any]:
        #gives further classification for scoring engine

        service_names = {
            s["service"] for s in open_services if s.get("service")
        }

        profile = {
            "service_names": sorted(service_names),
            "likely_device_type": None,
        }

        if {"ssh", "http", "https"} & service_names:
            profile["likely_device_type"] = "server"
        if {"printer"} & service_names:
            profile["likely_device_type"] = "printer"
        if {"microsoft-ds", "msrpc", "netbios-ssn"} & service_names:
            profile["likely_device_type"] = "windows-host"
        if {"bgp", "ldp", "cisco-sccp"} & service_names:
            profile["likely_device_type"] = "network-device"

        return profile

    def guess_fingerprint_consistency(self, open_services: list[dict[str, Any]], os_info: dict[str, Any] | None) -> bool:
        #placeholder for identity score, checks if open services are consistent with os fingerprint

        if not os_info:
            return False

        os_name = (os_info.get("name") or "").lower()
        service_names = {s.get("service") for s in open_services if s.get("service")}

        if "windows" in os_name and {"msrpc", "microsoft-ds", "netbios-ssn"} & service_names:
            return True
        if "linux" in os_name and {"ssh", "http", "https"} & service_names:
            return True
        if "freebsd" in os_name and {"ssh", "http", "https", "ms-wbt-server"} & service_names:
            return True

        return False