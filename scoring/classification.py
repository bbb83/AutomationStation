#weights and rules for classification score

from models.device_record import DeviceRecord
from models.scoring_result import TestResult

max_classification_score = 100

def score_classification(device: DeviceRecord) -> tuple[int, list[TestResult]]:
    tests: list[TestResult] = []

    #snmp sysObjectID and sysDescr found: +60
    snmp_sysfound= any(e.source == "snmp" and (e.attributes.get("sysObjectID") or e.attributes.get("sysDescr")) for e in device.evidence)
    tests.append(
        TestResult(
            name= "snmp sysObjectID and sysDescr found",
            category= "classification",
            source= "snmp",
            passed= snmp_sysfound,
            weight= 60,
            explain= "snmp sysObjectID/sysDescr found" if snmp_sysfound else "snmp sysObjectID/sysDescr not found",
        )
    )

    #nmap service profile found +25
    nmap_sp = any(e.source == "nmap" and bool(e.attributes.get("service_profile")) for e in device.evidence)
    tests.append(
        TestResult(
            name="nmap service profile",
            category= "classification",
            source= "nmap",
            passed= nmap_sp,
            weight= 25,
            explain= "nmap service profile found" if nmap_sp else "nmap service profile not found",
        )
    )

    #ieee oui manufacturer found +15
    oui_found = any(e.attributes.get("manufacturer_name") or e.attributes.get("oui_prefix") for e in device.evidence)
    tests.append(
        TestResult(
            name= "ieee oui manufacturer found",
            category= "classification",
            source= "oui",
            passed= oui_found,
            weight= 15,
            explain= "ieee oui lookup found manufacturer" if oui_found else "iee oui lookup couldnt find manufacturer",

        )
    )

    #dns gives name hints +5
    dns_hints = any(e.source == "dns" and e.attributes.get("naming_hint")is True for e in device.evidence)
    tests.append(
        TestResult(
            name= "dns gives name hints",
            category= "classification",
            source= "dns",
            passed= dns_hints,
            weight = 5,
            explain= "dns hostname gives classification hints" if dns_hints else "dns hostname doesnt give classification hints",

        )
    )

    score = sum(t.weight for t in tests if t.passed)
    return min(score, max_classification_score), tests