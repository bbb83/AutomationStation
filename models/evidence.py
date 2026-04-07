# will represent a single piece of evidence collected from one of the sources.
# (DHCP, SNMP, DNS, NMAP, OUI)
# every collector needs to return one of these objects

from dataclasses import dataclass, field
from typing import Any

@dataclass
class EvidenceRecord:
    source: str  #this will be dhcp,snmp,dns,nmap, or oui
    ip: str | None = None
    mac: str | None = None
    hostname: str | None = None
    manufacturer: str | None = None
    attributes: dict[str, Any]= field(default_factory=dict)
    #a default_factory means to make a new dict or list everytime (from dataclasses py library) 
    #to prevent confusion from objects sharing same dict or list memory
    
    def to_dict(self) -> dict[str, Any]: #using python dict to make it easy to convert to JSON later
        return{
            "source": self.source,
            "ip": self.ip,
            "mac": self.mac,
            "hostname": self.hostname,
            "manufacturer": self.manufacturer,
            "attributes": self.attributes,
        }