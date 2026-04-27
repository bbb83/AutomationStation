# weights and rules for identity score

from models.device_record import DeviceRecord
from models.scoring_result import TestResult

max_identity_score = 100
min_identity_score = 0


def _norm(value):
    if value is None:
        return None

    value = str(value).strip().lower()

    if value in ["", "n/a", "none", "null"]:
        return None

    return value


def score_identity(device: DeviceRecord) -> tuple[int, list[TestResult]]:
    tests: list[TestResult] = []
    score = 0

    sources = {e.source for e in device.evidence}

    nmap_evs = [e for e in device.evidence if e.source == "nmap"]
    dhcp_evs = [e for e in device.evidence if e.source == "dhcp"]
    snmp_evs = [e for e in device.evidence if e.source == "snmp"]
    dns_evs = [e for e in device.evidence if e.source == "dns"]

    # tiered multi-source evidence
    source_count = len(sources)

    if source_count >= 4:
        source_score = 30
    elif source_count == 3:
        source_score = 20
    elif source_count == 2:
        source_score = 10
    else:
        source_score = 0

    multi_source = source_score > 0

    tests.append(
        TestResult(
            name="device seen by multiple sources",
            category="identity",
            source="correlation",
            passed=multi_source,
            weight=source_score,
            explain=f"device seen by {source_count} source(s): {sorted(sources)}"
            if multi_source else
            "device only seen by one source",
        )
    )

    score += source_score

    # DHCP lease exists +10
    dhcp_present = len(dhcp_evs) > 0

    tests.append(
        TestResult(
            name="dhcp lease exists",
            category="identity",
            source="dhcp",
            passed=dhcp_present,
            weight=10,
            explain="dhcp lease exists for this device"
            if dhcp_present else
            "no dhcp lease found for this device",
        )
    )

    if dhcp_present:
        score += 10

    # MAC address observed +10
    macs = {
        _norm(e.mac)
        for e in device.evidence
        if _norm(e.mac)
    }

    mac_present = len(macs) >= 1

    tests.append(
        TestResult(
            name="mac address observed",
            category="identity",
            source="correlation",
            passed=mac_present,
            weight=10,
            explain=f"mac address observed: {sorted(macs)}"
            if mac_present else
            "no mac address observed from any source",
        )
    )

    if mac_present:
        score += 10

    # Nmap/DHCP MAC match +25
    nmap_mac = next((_norm(e.mac) for e in nmap_evs if _norm(e.mac)), None)
    dhcp_mac = next((_norm(e.mac) for e in dhcp_evs if _norm(e.mac)), None)

    mac_match = bool(nmap_mac and dhcp_mac and nmap_mac == dhcp_mac)

    tests.append(
        TestResult(
            name="nmap dhcp mac match",
            category="identity",
            source="correlation",
            passed=mac_match,
            weight=25,
            explain=f"nmap mac matches dhcp mac: {nmap_mac}"
            if mac_match else
            f"no nmap/dhcp mac match found. nmap={nmap_mac}, dhcp={dhcp_mac}",
        )
    )

    if mac_match:
        score += 25

    # MAC conflict penalty -30
    mac_conflict = len(macs) > 1

    tests.append(
        TestResult(
            name="mac conflict detected",
            category="identity",
            source="correlation",
            passed=mac_conflict,
            weight=-30,
            explain=f"multiple mac addresses observed: {sorted(macs)}"
            if mac_conflict else
            "no mac conflict detected",
        )
    )

    if mac_conflict:
        score -= 30

    # Hostname evidence and agreement
    hostnames = []

    for e in device.evidence:
        if _norm(e.hostname):
            hostnames.append(_norm(e.hostname))

        if e.source == "snmp" and _norm(e.attributes.get("sysName")):
            hostnames.append(_norm(e.attributes.get("sysName")))

        if e.source == "dhcp" and _norm(e.attributes.get("dhcp_hostname")):
            hostnames.append(_norm(e.attributes.get("dhcp_hostname")))

        if e.source == "dns" and _norm(e.hostname):
            hostnames.append(_norm(e.hostname))

    unique_hostnames = sorted(set(hostnames))

    hostname_match = len(hostnames) >= 2 and len(unique_hostnames) < len(hostnames)
    hostname_present = len(unique_hostnames) >= 1
    hostname_conflict = len(unique_hostnames) > 1 and not hostname_match

    if hostname_match:
        hostname_score = 20
        hostname_passed = True
        hostname_explain = f"hostname agrees across sources: {unique_hostnames}"
    elif hostname_present:
        hostname_score = 10
        hostname_passed = True
        hostname_explain = f"hostname observed from one source: {unique_hostnames}"
    else:
        hostname_score = 0
        hostname_passed = False
        hostname_explain = "no hostname evidence observed"

    tests.append(
        TestResult(
            name="hostname observed",
            category="identity",
            source="correlation",
            passed=hostname_passed,
            weight=hostname_score,
            explain=hostname_explain,
        )
    )

    score += hostname_score

    # Hostname conflict penalty -15
    tests.append(
        TestResult(
            name="hostname conflict detected",
            category="identity",
            source="correlation",
            passed=hostname_conflict,
            weight=-15,
            explain=f"conflicting hostnames observed: {unique_hostnames}"
            if hostname_conflict else
            "no hostname conflict detected",
        )
    )

    if hostname_conflict:
        score -= 15

    # Manufacturer/vendor evidence +10
    manufacturer_present = any(
        e.manufacturer
        or e.attributes.get("manufacturer_name")
        or e.attributes.get("vendor")
        for e in device.evidence
    )

    tests.append(
        TestResult(
            name="manufacturer evidence exists",
            category="identity",
            source="oui",
            passed=manufacturer_present,
            weight=10,
            explain="manufacturer or vendor evidence exists"
            if manufacturer_present else
            "no manufacturer or vendor evidence found",
        )
    )

    if manufacturer_present:
        score += 10

    score = max(min_identity_score, min(max_identity_score, score))

    return score, tests