#merges evidence from nmap, dhcp, snmp, dns, and oui into a single DeviceRecord

from __future__ import annotations
from models.device_record import DeviceRecord
from models.evidence import EvidenceRecord


def correlate_evidence(evidence_list: list[EvidenceRecord]) -> list[DeviceRecord]:
    #merge evidence records into device records.
    #priority: 1. MAC address 2. IP address
    devices: dict[str, DeviceRecord] = {}

    for ev in evidence_list:
        key = ev.mac or ev.ip
        if not key:
            continue

        if key not in devices:
            devices[key] = DeviceRecord()

        devices[key].add_evidence(ev)

    return list(devices.values())