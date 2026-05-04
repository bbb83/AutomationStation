[33mcommit 57b05e207453bb5d779764302bbe2bca050df24d[m[33m ([m[1;36mHEAD -> [m[1;32mpayan[m[33m, [m[1;31morigin/main[m[33m, [m[1;31morigin/HEAD[m[33m)[m
Author: bbb83 <xlebronjamesxd@live.com>
Date:   Mon Apr 27 02:44:25 2026 +0000

    made identity tests better(work now) and added weight transparency to NetBox tags

[1mdiff --git a/scoring/identity.py b/scoring/identity.py[m
[1mindex f06ce8b..6d8d3f6 100644[m
[1m--- a/scoring/identity.py[m
[1m+++ b/scoring/identity.py[m
[36m@@ -1,4 +1,4 @@[m
[31m-#weights and rules for identity score[m
[32m+[m[32m# weights and rules for identity score[m
 [m
 from models.device_record import DeviceRecord[m
 from models.scoring_result import TestResult[m
[36m@@ -6,77 +6,233 @@[m [mfrom models.scoring_result import TestResult[m
 max_identity_score = 100[m
 min_identity_score = 0[m
 [m
[32m+[m
[32m+[m[32mdef _norm(value):[m
[32m+[m[32m    if value is None:[m
[32m+[m[32m        return None[m
[32m+[m
[32m+[m[32m    value = str(value).strip().lower()[m
[32m+[m
[32m+[m[32m    if value in ["", "n/a", "none", "null"]:[m
[32m+[m[32m        return None[m
[32m+[m
[32m+[m[32m    return value[m
[32m+[m
[32m+[m
 def score_identity(device: DeviceRecord) -> tuple[int, list[TestResult]]:[m
[31m-    tests: list[TestResult]= [][m
[32m+[m[32m    tests: list[TestResult] = [][m
[32m+[m[32m    score = 0[m
[32m+[m
[32m+[m[32m    sources = {e.source for e in device.evidence}[m
[32m+[m
[32m+[m[32m    nmap_evs = [e for e in device.evidence if e.source == "nmap"][m
[32m+[m[32m    dhcp_evs = [e for e in device.evidence if e.source == "dhcp"][m
[32m+[m[32m    snmp_evs = [e for e in device.evidence if e.source == "snmp"][m
[32m+[m[32m    dns_evs = [e for e in device.evidence if e.source == "dns"][m
[32m+[m
[32m+[m[32m    # tiered multi-source evidence[m
[32m+[m[32m    source_count = len(sources)[m
[32m+[m
[32m+[m[32m    if source_count >= 4:[m
[32m+[m[32m        source_score = 30[m
[32m+[m[32m    elif source_count == 3:[m
[32m+[m[32m        source_score = 20[m
[32m+[m[32m    elif source_count == 2:[m
[32m+[m[32m        source_score = 10[m
[32m+[m[32m    else:[m
[32m+[m[32m        source_score = 0[m
[32m+[m
[32m+[m[32m    multi_source = source_score > 0[m
[32m+[m
[32m+[m[32m    tests.append([m
[32m+[m[32m        TestResult([m
[32m+[m[32m            name="device seen by multiple sources",[m
[32m+[m[32m            category="identity",[m
[32m+[m[32m            source="correlation",[m
[32m+[m[32m            passed=multi_source,[m
[32m+[m[32m            weight=source_score,[m
[32m+[m[32m            explain=f"device seen by {source_count} source(s): {sorted(sources)}"[m
[32m+[m[32m            if multi_source else[m
[32m+[m[32m            "device only seen by one source",[m
[32m+[m[32m        )[m
[32m+[m[32m    )[m
[32m+[m
[32m+[m[32m    score += source_score[m
[32m+[m
[32m+[m[32m    # DHCP lease exists +10[m
[32m+[m[32m    dhcp_present = len(dhcp_evs) > 0[m
[32m+[m
[32m+[m[32m    tests.append([m
[32m+[m[32m        TestResult([m
[32m+[m[32m            name="dhcp lease exists",[m
[32m+[m[32m            category="identity",[m
[32m+[m[32m            source="dhcp",[m
[32m+[m[32m            passed=dhcp_present,[m
[32m+[m[32m            weight=10,[m
[32m+[m[32m            explain="dhcp lease exists for this device"[m
[32m+[m[32m            if dhcp_present else[m
[32m+[m[32m            "no dhcp lease found for this device",[m
[32m+[m[32m        )[m
[32m+[m[32m    )[m
[32m+[m
[32m+[m[32m    if dhcp_present:[m
[32m+[m[32m        score += 10[m
[32m+[m
[32m+[m[32m    # MAC address observed +10[m
[32m+[m[32m    macs = {[m
[32m+[m[32m        _norm(e.mac)[m
[32m+[m[32m        for e in device.evidence[m
[32m+[m[32m        if _norm(e.mac)[m
[32m+[m[32m    }[m
[32m+[m
[32m+[m[32m    mac_present = len(macs) >= 1[m
 [m
[31m-    #snmp mac/interface matches netbox +55[m
[31m-    snmp_matches = any(e.source == "snmp" and e.attributes.get("netbox_mac_match") is True for e in device.evidence)[m
     tests.append([m
         TestResult([m
[31m-            name= "snmp mac/interface matches netbox",[m
[31m-            category= "identity",[m
[31m-            source= "snmp",[m
[31m-            passed= snmp_matches,[m
[31m-            weight= 55,[m
[31m-            explain= "snmp mac/interface matches netbox record"  if snmp_matches else "snmp cant confirm mac/interface matches netbox record",[m
[32m+[m[32m            name="mac address observed",[m
[32m+[m[32m            category="identity",[m
[32m+[m[32m            source="correlation",[m
[32m+[m[32m            passed=mac_present,[m
[32m+[m[32m            weight=10,[m
[32m+[m[32m            explain=f"mac address observed: {sorted(macs)}"[m
[32m+[m[32m            if mac_present else[m
[32m+[m[32m            "no mac address observed from any source",[m
         )[m
     )[m
 [m
[31m-    #dhcp mac matches netbox +30[m
[31m-    dhcp_matches = any(e.source == "dhcp" and e.attributes.get("netbox_mac_match") is True for e in device.evidence)[m
[32m+[m[32m    if mac_present:[m
[32m+[m[32m        score += 10[m
[32m+[m
[32m+[m[32m    # Nmap/DHCP MAC match +25[m
[32m+[m[32m    nmap_mac = next((_norm(e.mac) for e in nmap_evs if _norm(e.mac)), None)[m
[32m+[m[32m    dhcp_mac = next((_norm(e.mac) for e in dhcp_evs if _norm(e.mac)), None)[m
[32m+[m
[32m+[m[32m    mac_match = bool(nmap_mac and dhcp_mac and nmap_mac == dhcp_mac)[m
[32m+[m
     tests.append([m
         TestResult([m
[31m-            name= "dhcp mac matches netbox",[m
[31m-            category= "identity",[m
[31m-            source = "dhcp",[m
[31m-            passed= dhcp_matches,[m
[31m-            weight= 30,[m
[31m-            explain= "dhcp mac matches netbox record" if dhcp_matches else "dhcp mac does not match netbox record",[m
[32m+[m[32m            name="nmap dhcp mac match",[m
[32m+[m[32m            category="identity",[m
[32m+[m[32m            source="correlation",[m
[32m+[m[32m            passed=mac_match,[m
[32m+[m[32m            weight=25,[m
[32m+[m[32m            explain=f"nmap mac matches dhcp mac: {nmap_mac}"[m
[32m+[m[32m            if mac_match else[m
[32m+[m[32m            f"no nmap/dhcp mac match found. nmap={nmap_mac}, dhcp={dhcp_mac}",[m
         )[m
     )[m
 [m
[31m-    #dns hastname matches netbox +15[m
[31m-    dns_matches = any(e.source == "dns" and e.attributes.get("netbox_hostname_match") is True for e in device.evidence)[m
[32m+[m[32m    if mac_match:[m
[32m+[m[32m        score += 25[m
[32m+[m
[32m+[m[32m    # MAC conflict penalty -30[m
[32m+[m[32m    mac_conflict = len(macs) > 1[m
[32m+[m
     tests.append([m
         TestResult([m
[31m-            name = "dns hostname matches netbox",[m
[31m-            category= "identity",[m
[31m-            source = "dns",[m
[31m-            passed= dns_matches,[m
[31m-            weight= 15,[m
[31m-            explain= "dns hostname matches netbox record" if dns_matches else "dns hostname doesn't match netbox record",[m
[32m+[m[32m            name="mac conflict detected",[m
[32m+[m[32m            category="identity",[m
[32m+[m[32m            source="correlation",[m
[32m+[m[32m            passed=mac_conflict,[m
[32m+[m[32m            weight=-30,[m
[32m+[m[32m            explain=f"multiple mac addresses observed: {sorted(macs)}"[m
[32m+[m[32m            if mac_conflict else[m
[32m+[m[32m            "no mac conflict detected",[m
         )[m
     )[m
 [m
[31m-    #nmap fingerprint is consistent with netbox +10[m
[31m-    nmap_is_consistent = any(e.source == "nmap" and e.attributes.get("fingerprint_consistent")is True for e in device.evidence)[m
[32m+[m[32m    if mac_conflict:[m
[32m+[m[32m        score -= 30[m
[32m+[m
[32m+[m[32m    # Hostname evidence and agreement[m
[32m+[m[32m    hostnames = [][m
[32m+[m
[32m+[m[32m    for e in device.evidence:[m
[32m+[m[32m        if _norm(e.hostname):[m
[32m+[m[32m            hostnames.append(_norm(e.hostname))[m
[32m+[m
[32m+[m[32m        if e.source == "snmp" and _norm(e.attributes.get("sysName")):[m
[32m+[m[32m            hostnames.append(_norm(e.attributes.get("sysName")))[m
[32m+[m
[32m+[m[32m        if e.source == "dhcp" and _norm(e.attributes.get("dhcp_hostname")):[m
[32m+[m[32m            hostnames.append(_norm(e.attributes.get("dhcp_hostname")))[m
[32m+[m
[32m+[m[32m        if e.source == "dns" and _norm(e.hostname):[m
[32m+[m[32m            hostnames.append(_norm(e.hostname))[m
[32m+[m
[32m+[m[32m    unique_hostnames = sorted(set(hostnames))[m
[32m+[m
[32m+[m[32m    hostname_match = len(hostnames) >= 2 and len(unique_hostnames) < len(hostnames)[m
[32m+[m[32m    hostname_present = len(unique_hostnames) >= 1[m
[32m+[m[32m    hostname_conflict = len(unique_hostnames) > 1 and not hostname_match[m
[32m+[m
[32m+[m[32m    if hostname_match:[m
[32m+[m[32m        hostname_score = 20[m
[32m+[m[32m        hostname_passed = True[m
[32m+[m[32m        hostname_explain = f"hostname agrees across sources: {unique_hostnames}"[m
[32m+[m[32m    elif hostname_present:[m
[32m+[m[32m        hostname_score = 10[m
[32m+[m[32m        hostname_passed = True[m
[32m+[m[32m        hostname_explain = f"hostname observed from one source: {unique_hostnames}"[m
[32m+[m[32m    else:[m
[32m+[m[32m        hostname_score = 0[m
[32m+[m[32m        hostname_passed = False[m
[32m+[m[32m        hostname_explain = "no hostname evidence observed"[m
[32m+[m
     tests.append([m
         TestResult([m
[31m-            name= "nmap fingerprint is consistent",[m
[31m-            category= "identity",[m
[31m-            source= "nmap",[m
[31m-            passed= nmap_is_consistent,[m
[31m-            weight= 10,[m
[31m-            explain= "nmap fingerprint is consistent with netbox" if nmap_is_consistent else "nmap fingerprint isn't consistent with netbox",[m
[32m+[m[32m            name="hostname observed",[m
[32m+[m[32m            category="identity",[m
[32m+[m[32m            source="correlation",[m
[32m+[m[32m            passed=hostname_passed,[m
[32m+[m[32m            weight=hostname_score,[m
[32m+[m[32m            explain=hostname_explain,[m
[32m+[m[32m        )[m
[32m+[m[32m    )[m
[32m+[m
[32m+[m[32m    score += hostname_score[m
 [m
[32m+[m[32m    # Hostname conflict penalty -15[m
[32m+[m[32m    tests.append([m
[32m+[m[32m        TestResult([m
[32m+[m[32m            name="hostname conflict detected",[m
[32m+[m[32m            category="identity",[m
[32m+[m[32m            source="correlation",[m
[32m+[m[32m            passed=hostname_conflict,[m
[32m+[m[32m            weight=-15,[m
[32m+[m[32m            explain=f"conflicting hostnames observed: {unique_hostnames}"[m
[32m+[m[32m            if hostname_conflict else[m
[32m+[m[32m            "no hostname conflict detected",[m
         )[m
     )[m
 [m
[31m-    #penalty for mac mismatch with netbox: -60[m
[31m-    mac_mismatch = any(e.attributes.get("netbox_mac_mismatch") is True for e in device.evidence)[m
[31m-    penalty = -60 if mac_mismatch else 0[m
[32m+[m[32m    if hostname_conflict:[m
[32m+[m[32m        score -= 15[m
[32m+[m
[32m+[m[32m    # Manufacturer/vendor evidence +10[m
[32m+[m[32m    manufacturer_present = any([m
[32m+[m[32m        e.manufacturer[m
[32m+[m[32m        or e.attributes.get("manufacturer_name")[m
[32m+[m[32m        or e.attributes.get("vendor")[m
[32m+[m[32m        for e in device.evidence[m
[32m+[m[32m    )[m
[32m+[m
     tests.append([m
         TestResult([m
[31m-            name= "mac mismatch with netbox",[m
[31m-            category= "identity",[m
[31m-            source = "correlation",[m
[31m-            passed= not mac_mismatch,[m
[31m-            weight= -60,[m
[31m-            explain= "mac mismatch with netbox, possible IP reuse" if mac_mismatch else "no mac mismatch with netbox detected",[m
[32m+[m[32m            name="manufacturer evidence exists",[m
[32m+[m[32m            category="identity",[m
[32m+[m[32m            source="oui",[m
[32m+[m[32m            passed=manufacturer_present,[m
[32m+[m[32m            weight=10,[m
[32m+[m[32m            explain="manufacturer or vendor evidence exists"[m
[32m+[m[32m            if manufacturer_present else[m
[32m+[m[32m            "no manufacturer or vendor evidence found",[m
         )[m
     )[m
 [m
[31m-    initial_score = sum(t.weight for t  in tests if t.weight > 0 and t.passed)[m
[31m-    score_with_penalty = initial_score + penalty[m
[31m-    score = max(min_identity_score, min(max_identity_score, score_with_penalty))[m
[32m+[m[32m    if manufacturer_present:[m
[32m+[m[32m        score += 10[m
[32m+[m
[32m+[m[32m    score = max(min_identity_score, min(max_identity_score, score))[m
[32m+[m
     return score, tests[m
\ No newline at end of file[m
