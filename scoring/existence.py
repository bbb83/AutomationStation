# weights and rules for existence score

from models.device_record import DeviceRecord
from models.scoring_result import TestResult

max_existence_score = 100

def score_existence(device: DeviceRecord) -> tuple[int,list[TestResult]]:
    tests: list[TestResult] =[]

    #snmp respones +50
    snmp_response = any(e.source == "snmp" for e in device.evidence)
    tests.append(
        TestResult(
            name= "snmp response",
            category= "existence",
            source= "snmp",
            passed= snmp_response,
            weight= 50,
            explain= "snmp responded successfully" if snmp_response else "no snmp response detected",

        )
    )

    #nmap shows open ports +25
    nmap_open_ports = any(e.source == "nmap" and bool(e.attributes.get("open_ports")) for e in device.evidence)
    tests.append(
        TestResult(
            name= "nmap open ports detected",
            category= "existence",
            source= "nmap",
            passed= nmap_open_ports,
            weight= 25,
            explain= "nmap detected open ports" if nmap_open_ports else "open ports not detected by nmap",   
        )
    )

    #dhcp active lease +20
    dhcp_active_lease = any(e.source == "dhcp" and e.attributes.get("lease_active") is True for e in device.evidence)
    tests.append(
        TestResult(
            name= "dhcp active lease",
            category= "existence",
            source= "dhcp",
            passed= dhcp_active_lease,
            weight= 20,
            explain= "found active dhcp lease" if dhcp_active_lease else "no active dhcp lease found",
        )
    )

    #dns resolves A/PTR +5
    dns_resolve = any(e.source == "dns" and (e.attributes.get("forward_resolves")is True or e.attributes.get("reverse_resolves")is True) for e in device.evidence)
    tests.append(
        TestResult(
            name= "dns resolves A/PTR",
            category= "existence",
            source= "dns",
            passed= dns_resolve,
            weight= 5,
            explain= "dns forward or reverse lookup resolved" if dns_resolve else "no dns A/PTR resolution found",
        )
    )

    score = sum(t.weight for t in tests if t.passed)
    return min(score, max_existence_score), tests