#weights and rules for identity score

from models.device_record import DeviceRecord
from models.scoring_result import TestResult

max_identity_score = 100
min_identity_score = 0

def score_identity(device: DeviceRecord) -> tuple[int, list[TestResult]]:
    tests: list[TestResult]= []

    #snmp mac/interface matches netbox +55
    snmp_matches = any(e.source == "snmp" and e.attributes.get("netbox_mac_match") is True for e in device.evidence)
    tests.append(
        TestResult(
            name= "snmp mac/interface matches netbox",
            category= "identity",
            source= "snmp",
            passed= snmp_matches,
            weight= 55,
            explain= "snmp mac/interface matches netbox record"  if snmp_matches else "snmp cant confirm mac/interface matches netbox record",
        )
    )

    #dhcp mac matches netbox +30
    dhcp_matches = any(e.source == "dhcp" and e.attributes.get("netbox_mac_match") is True for e in device.evidence)
    tests.append(
        TestResult(
            name= "dhcp mac matches netbox",
            category= "identity",
            source = "dhcp",
            passed= dhcp_matches,
            weight= 30,
            explain= "dhcp mac matches netbox record" if dhcp_matches else "dhcp mac does not match netbox record",
        )
    )

    #dns hastname matches netbox +15
    dns_matches = any(e.source == "dns" and e.attributes.get("netbox_hostname_match") is True for e in device.evidence)
    tests.append(
        TestResult(
            name = "dns hostname matches netbox",
            category= "identity",
            source = "dns",
            passed= dns_matches,
            weight= 15,
            explain= "dns hostname matches netbox record" if dns_matches else "dns hostname doesn't match netbox record",
        )
    )

    #nmap fingerprint is consistent with netbox +10
    nmap_is_consistent = any(e.source == "nmap" and e.attributes.get("fingerprint_consistent")is True for e in device.evidence)
    tests.append(
        TestResult(
            name= "nmap fingerprint is consistent",
            category= "identity",
            source= "nmap",
            passed= nmap_is_consistent,
            weight= 10,
            explain= "nmap fingerprint is consistent with netbox" if nmap_is_consistent else "nmap fingerprint isn't consistent with netbox",

        )
    )

    #penalty for mac mismatch with netbox: -60
    mac_mismatch = any(e.attributes.get("netbox_mac_mismatch") is True for e in device.evidence)
    penalty = -60 if mac_mismatch else 0
    tests.append(
        TestResult(
            name= "mac mismatch with netbox",
            category= "identity",
            source = "correlation",
            passed= not mac_mismatch,
            weight= -60,
            explain= "mac mismatch with netbox, possible IP reuse" if mac_mismatch else "no mac mismatch with netbox detected",
        )
    )

    initial_score = sum(t.weight for t  in tests if t.weight > 0 and t.passed)
    score_with_penalty = initial_score + penalty
    score = max(min_identity_score, min(max_identity_score, score_with_penalty))
    return score, tests