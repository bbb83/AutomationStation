from __future__ import annotations

import asyncio
import ipaddress
import json
import os
from pathlib import Path
from typing import Any

from dotenv import load_dotenv

from pysnmp.hlapi.v3arch.asyncio import (
    SnmpEngine,
    CommunityData,
    UdpTransportTarget,
    ContextData,
    ObjectType,
    ObjectIdentity,
    get_cmd,
)

from models.evidence import EvidenceRecord


class SNMPCollector:
    name = "snmp"

    def __init__(self, env_file: str = "env-2") -> None:
        load_dotenv(env_file)

        self.oids = {
            "hostname": os.getenv("SNMP_OID_HOSTNAME"),
            "description": os.getenv("SNMP_OID_DESCRIPTION"),
            "uptime": os.getenv("SNMP_OID_UPTIME"),
            "interfaces": os.getenv("SNMP_OID_INTERFACES"),
        }

        self.target_subnet = os.getenv("SNMP_TARGET_SUBNET")
        self.community = os.getenv("SNMP_COMMUNITY")

        version = os.getenv("SNMP_VERSION")
        self.snmp_mp_model = 1 if version == "2c" else 0

    def collect_from_scan(
        self,
        subnet: str | None = None,
        batch_size: int = 50,
    ) -> list[EvidenceRecord]:
        #runs a live SNMP scan and return normalized EvidenceRecord objects
        target = subnet or self.target_subnet
        if not target:
            raise ValueError("No SNMP target subnet provided")

        print(f"[SNMP] Starting scan on subnet: {target}")
        print(f"[SNMP] Community set: {'yes' if self.community else 'no'}")
        print(f"[SNMP] OIDs loaded: {self.oids}")

        rows = asyncio.run(self._run_scan(target, batch_size=batch_size))
        return self._rows_to_evidence(rows)

    def collect_from_file(self, filepath: str | Path) -> list[EvidenceRecord]:
        #read previously saved SNMP JSON results and convert to EvidenceRecord
        #should look like: list[dict]
        path = Path(filepath)
        with path.open("r", encoding="utf-8") as f:
            rows = json.load(f)

        if not isinstance(rows, list):
            raise ValueError("SNMP results file must contain a list of row objects")

        return self._rows_to_evidence(rows)

    async def _run_scan(self, subnet: str, batch_size: int = 50) -> list[dict[str, Any]]:
        snmp_engine = SnmpEngine()
        network = ipaddress.ip_network(str(subnet), strict=False)
        hosts = list(network.hosts())

        results: list[dict[str, Any] | None] = []

        for i in range(0, len(hosts), batch_size):
            batch = hosts[i:i + batch_size]
            batch_results = await asyncio.gather(
                *[self._query(snmp_engine, ip) for ip in batch]
            )
            results.extend(batch_results)
            await asyncio.sleep(0.1)

        snmp_engine.close_dispatcher()

        return [r for r in results if r is not None]

    async def _query(self, snmp_engine: SnmpEngine, ip: ipaddress.IPv4Address) -> dict[str, Any] | None:
        try:
            object_types = [
                ObjectType(ObjectIdentity(oid))
                for oid in self.oids.values()
                if oid
            ]

            iterator = get_cmd(
                snmp_engine,
                CommunityData(str(self.community), mpModel=self.snmp_mp_model),
                await UdpTransportTarget.create((str(ip), 161), timeout=2, retries=0),
                ContextData(),
                *object_types,
            )

            error_indication, error_status, error_index, var_binds = await iterator

            if error_indication:
                return None

            if error_status:
                return None

            row: dict[str, Any] = {"ip": str(ip)}
            for label, var_bind in zip(self.oids.keys(), var_binds):
                row[label] = var_bind[1].prettyPrint()

            print(f"Found SNMP device: {ip}")
            return row

        except Exception:
            return None

    def _rows_to_evidence(self, rows: list[dict[str, Any]]) -> list[EvidenceRecord]:
        evidence_records: list[EvidenceRecord] = []

        for row in rows:
            ip = row.get("ip")
            hostname = self._clean_value(row.get("Hostname"))
            description = self._clean_value(row.get("Description"))
            uptime = self._clean_value(row.get("Uptime"))
            interfaces_raw = self._clean_value(row.get("Interfaces"))

            interface_count = self._parse_interface_count(interfaces_raw)

            ev = EvidenceRecord(
                source="snmp",
                ip=ip,
                hostname=hostname,
                attributes={
                    "snmp_reachable": True,
                    "sysName": hostname,
                    "sysDescr": description,
                    "sysUpTime": uptime,
                    "ifNumber": interface_count,
                    "raw_interfaces": interfaces_raw,
                    # booleans for scoring rules
                    "has_sysname": hostname is not None,
                    "has_sysdescr": description is not None,
                    "has_interface_count": interface_count is not None,
                },
            )
            evidence_records.append(ev)

        return evidence_records

    def _clean_value(self, value: Any) -> str | None:
        if value is None:
            return None
        value = str(value).strip()
        return value if value else None

    def _parse_interface_count(self, value: str | None) -> int | None:
        if value is None:
            return None

        digits = "".join(ch for ch in value if ch.isdigit())
        if digits:
            try:
                return int(digits)
            except ValueError:
                return None
        return None