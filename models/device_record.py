# combines multiple pieces of evidence into one device representation
#

from dataclasses import dataclass, field
from models.evidence import EvidenceRecord

@dataclass
class DeviceRecord:
    ip: str | None = None
    mac: str | None = None
    hostnames: set[str]= field(default_factory = set)
    manufacturer: str | None = None
    evidence: list[EvidenceRecord] = field(default_factory=list)

    def add_evidence(self, ev: EvidenceRecord)-> None:
        self.evidence.append(ev)

        if ev.ip and not self.ip:
            self.ip = ev.ip

        if ev.mac and not self.mac:
            self.mac = ev.mac

        if ev.hostname:
            self.hostnames.add(ev.hostname)

        if ev.manufacturer and not self.manufacturer:
            self.manufacturer= ev.manufacturer

    def get_evidence(self, source: str) -> list[EvidenceRecord]:
        return[e for e in self.evidence if e.source == source]

    def get_hostname(self) -> str | None:
        return next(iter(self.hostnames), None)

    def to_dict(self) -> dict:
        return{
            "ip": self.ip,
            "mac:": self.mac,
            "hostnames": list(self.hostnames),
            "manufacturer": self.manufacturer,
            "evidence": [e.to_dict() for e in self.evidence],
        }